using System.Collections.Concurrent;
using DiskInspector.Core.Enums;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Analysis;

/// <summary>
/// Motor conservador de classificação semântica, avaliação de risco e recomendações de limpeza (Seções 3, 4, 5, 6 e 7).
/// Regra de ouro: Na dúvida, classifica como Desconhecido (CINZA) ou Alto Risco (VERMELHO) e jamais autoriza exclusão automática.
///
/// Três princípios desta versão:
/// 1. A classificação não abre nenhum arquivo: a análise é realmente somente leitura. A verificação de
///    "em uso" acontece na prévia e na execução da limpeza, sobre os itens que o usuário escolheu.
/// 2. Só o item de primeiro nível de cada regra é um achado (a pasta de cache, o item direto do Temp,
///    a node_modules do projeto). O conteúdo interno aponta para ele e nunca é selecionável sozinho.
/// 3. Artefatos de desenvolvimento só contam como "de projeto" com evidência de que há um projeto do
///    usuário ali, e nunca dentro de pastas de programas instalados.
/// </summary>
public sealed class StorageClassifier : IStorageClassifier
{
    private const string UnknownApp = "Desconhecido";

    // Quantos arquivos/pastas no máximo o cache de estrutura guarda antes de ser reiniciado
    private const int StructureCacheLimit = 400_000;

    private readonly IEnvironmentProvider _environmentProvider;
    private readonly ISystemPathProtector _systemPathProtector;
    private readonly Func<DateTime> _utcNow;
    private readonly string[] _ownApplicationPaths;

    private readonly ConcurrentDictionary<string, bool> _userProjectNodeModules = new(StringComparer.OrdinalIgnoreCase);
    private EnvironmentPaths? _normalizedSource;
    private NormalizedEnvironment? _normalized;

    // Resultado da detecção estrutural de aplicativos Electron/Chromium, por pasta. Alimentado pelo motor de
    // varredura (sem custo de disco) e, na falta dessa dica, por uma única consulta ao disco por pasta.
    private static readonly ConcurrentDictionary<string, bool> ElectronRootByPath = new(StringComparer.OrdinalIgnoreCase);

    // Subpastas de cache comprovadamente descartáveis SOMENTE quando dentro de aplicativos conhecidos ou estrutura Electron/Chromium verificada
    private static readonly HashSet<string> VerifiedBrowserOrElectronCacheFolderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Cache",
        "Cache_Data",
        "Code Cache",
        "GPUCache",
        "ShaderCache",
        "DawnCache",
        "DawnGraphiteCache",
        "DawnWebGPUCache",
        "GrShaderCache",
        "CachedData",
        "CachedExtensionVSIXs",
        "Crashpad"
    };

    // Todo nome de pasta que pode ser a raiz de um cache verificado (lista acima + regras específicas)
    private static readonly HashSet<string> PossibleCacheRootNames = new(VerifiedBrowserOrElectronCacheFolderNames, StringComparer.OrdinalIgnoreCase)
    {
        "TempState",
        "INetCache",
        "D3DSCache",
        "DXCache",
        "GLCache",
        "Data",
        "Storage",
        "SquirrelTemp"
    };

    // Marcadores estruturais que comprovam que um diretório pai é um aplicativo Electron / Chromium real
    private static readonly HashSet<string> ElectronStructuralMarkers = new(StringComparer.OrdinalIgnoreCase)
    {
        "GPUCache",
        "Code Cache",
        "DawnCache",
        "Local Storage",
        "Session Storage",
        "blob_storage",
        "Network"
    };

    // Subpastas críticas de sessão, autenticação, banco local e perfil em navegadores/Electron
    private static readonly HashSet<string> SensitiveSessionOrDatabaseFolderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Local Storage",
        "Session Storage",
        "IndexedDB",
        "databases",
        "Sync Data",
        "Sessions",
        "Network",
        "Local Extension Settings",
        "Managed Extension Settings",
        "User",
        "workspaceStorage",
        "globalStorage",
        "LocalState",
        "Settings",
        "RoamingState"
    };

    private static readonly HashSet<string> InstallerExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".msi", ".msix", ".msixbundle", ".appx", ".iso", ".img"
    };

    private static readonly HashSet<string> LogOrDumpExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".log", ".dmp", ".mdmp", ".hdmp", ".etl"
    };

    // Caches de GPU e de rede em locais fixos do perfil, descartáveis por definição
    private static readonly string[] FixedDisposableCacheSuffixes =
    [
        @"\AppData\Local\D3DSCache",
        @"\AppData\Local\NVIDIA\DXCache",
        @"\AppData\Local\NVIDIA\GLCache",
        @"\AppData\Local\AMD\DxCache",
        @"\AppData\Local\Microsoft\Windows\INetCache"
    ];

    private static readonly string[] NodeLockFiles =
    [
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lockb",
        "bun.lock"
    ];

    private static readonly string[] WorkspaceMarkerFiles =
    [
        "package.json",
        "Cargo.toml",
        "pyproject.toml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "go.mod",
        "composer.json"
    ];

    private static readonly string[] WorkspaceMarkerDirectories = [".git", ".vscode", ".idea", ".vs"];

    private static readonly DevCacheRule[] GlobalDevCacheRules =
    [
        new(@"\npm-cache", "Node.js / npm",
            "Cache global de pacotes JavaScript/TypeScript baixados pelo Node.js / npm.",
            "Nenhuma perda de código-fonte, mas os próximos 'npm/pnpm/yarn install' precisarão baixar pacotes novamente da internet.",
            RecommendedAction.UseOfficialDeveloperCommand,
            "Recomendado limpar pelo comando oficial (npm cache clean --force) ou mover cache antigo para a Lixeira.",
            "npm cache clean --force"),
        new(@"\pnpm\store", "pnpm",
            "Cache global de pacotes JavaScript/TypeScript baixados pelo pnpm.",
            "Nenhuma perda de código-fonte, mas os próximos 'npm/pnpm/yarn install' precisarão baixar pacotes novamente da internet.",
            RecommendedAction.UseOfficialDeveloperCommand,
            "Recomendado limpar pelo comando oficial (pnpm store prune) ou mover cache antigo para a Lixeira.",
            "pnpm store prune"),
        new(@"\pnpm-store", "pnpm",
            "Cache global de pacotes JavaScript/TypeScript baixados pelo pnpm.",
            "Nenhuma perda de código-fonte, mas os próximos 'npm/pnpm/yarn install' precisarão baixar pacotes novamente da internet.",
            RecommendedAction.UseOfficialDeveloperCommand,
            "Recomendado limpar pelo comando oficial (pnpm store prune) ou mover cache antigo para a Lixeira.",
            "pnpm store prune"),
        new(@"\Yarn\Cache", "Yarn",
            "Cache global de pacotes JavaScript/TypeScript baixados pelo Yarn.",
            "Nenhuma perda de código-fonte, mas os próximos 'npm/pnpm/yarn install' precisarão baixar pacotes novamente da internet.",
            RecommendedAction.UseOfficialDeveloperCommand,
            "Recomendado limpar pelo comando oficial (yarn cache clean) ou mover cache antigo para a Lixeira.",
            "yarn cache clean"),
        new(@"\AppData\Local\pip\cache", "Python / pip",
            "Cache global de pacotes wheels (.whl) e arquivos tar.gz baixados pelo gerenciador pip do Python.",
            "Não afeta ambientes virtuais já criados, mas futuras instalações 'pip install' baixarão os pacotes novamente.",
            RecommendedAction.UseOfficialDeveloperCommand,
            "Use 'pip cache purge' ou envie o diretório de cache para a Lixeira.",
            "pip cache purge"),
        new(@"\AppData\Local\pypa\virtualenv", "Python / pip",
            "Cache global de pacotes wheels (.whl) e arquivos tar.gz baixados pelo gerenciador pip do Python.",
            "Não afeta ambientes virtuais já criados, mas futuras instalações 'pip install' baixarão os pacotes novamente.",
            RecommendedAction.UseOfficialDeveloperCommand,
            "Use 'pip cache purge' ou envie o diretório de cache para a Lixeira.",
            "pip cache purge"),
        new(@"\AppData\Local\Composer", "PHP Composer",
            "Cache de pacotes PHP baixados pelo Composer.",
            "Futuras execuções de 'composer install/update' precisarão baixar dependências novamente.",
            RecommendedAction.UseOfficialDeveloperCommand,
            "Execute 'composer clear-cache' ou limpe via Lixeira.",
            "composer clear-cache"),
        new(@"\AppData\Roaming\Composer\cache", "PHP Composer",
            "Cache de pacotes PHP baixados pelo Composer.",
            "Futuras execuções de 'composer install/update' precisarão baixar dependências novamente.",
            RecommendedAction.UseOfficialDeveloperCommand,
            "Execute 'composer clear-cache' ou limpe via Lixeira.",
            "composer clear-cache"),
        new(@"\.nuget\packages", ".NET SDK / NuGet",
            "Cache global de pacotes NuGet e metadados utilizados por projetos C# / .NET.",
            "Projetos .NET precisarão executar 'dotnet restore' (novo download de pacotes) na próxima compilação.",
            RecommendedAction.UseOfficialDeveloperCommand,
            "Para limpar com segurança via CLI oficial, utilize 'dotnet nuget locals all --clear'.",
            "dotnet nuget locals all --clear"),
        new(@"\AppData\Local\NuGet\v3-cache", ".NET SDK / NuGet",
            "Cache global de pacotes NuGet e metadados utilizados por projetos C# / .NET.",
            "Projetos .NET precisarão executar 'dotnet restore' (novo download de pacotes) na próxima compilação.",
            RecommendedAction.UseOfficialDeveloperCommand,
            "Para limpar com segurança via CLI oficial, utilize 'dotnet nuget locals all --clear'.",
            "dotnet nuget locals all --clear"),
        new(@"\AppData\Local\NuGet\plugins-cache", ".NET SDK / NuGet",
            "Cache global de pacotes NuGet e metadados utilizados por projetos C# / .NET.",
            "Projetos .NET precisarão executar 'dotnet restore' (novo download de pacotes) na próxima compilação.",
            RecommendedAction.UseOfficialDeveloperCommand,
            "Para limpar com segurança via CLI oficial, utilize 'dotnet nuget locals all --clear'.",
            "dotnet nuget locals all --clear"),
        new(@"\.gradle\caches", "Java / Android Gradle",
            "Repositório/cache local de dependências e artefatos de build (Java / Android Gradle).",
            "Exigirá novo download de dependências e recompilação completa nos próximos builds.",
            RecommendedAction.SafeToCleanWhenAppClosed,
            "Pode ser limpo se o espaço em disco estiver crítico; o próximo build reconstruirá o cache.",
            null),
        new(@"\.m2\repository", "Java / Maven",
            "Repositório/cache local de dependências e artefatos de build (Java / Maven).",
            "Exigirá novo download de dependências e recompilação completa nos próximos builds.",
            RecommendedAction.SafeToCleanWhenAppClosed,
            "Pode ser limpo se o espaço em disco estiver crítico; o próximo build reconstruirá o cache.",
            null),
        new(@"\.cargo\registry", "Rust / Cargo",
            "Repositório/cache local de dependências e artefatos de build (Rust / Cargo).",
            "Exigirá novo download de dependências e recompilação completa nos próximos builds.",
            RecommendedAction.SafeToCleanWhenAppClosed,
            "Pode ser limpo se o espaço em disco estiver crítico; o próximo build reconstruirá o cache.",
            null)
    ];

    // Assinaturas de pastas do AppData. A ordem importa: a primeira que casar vence.
    // TrustCacheFolderNames só é verdadeiro quando o aplicativo segue o layout Chromium/Electron (ou já era
    // tratado assim): apenas nesses casos uma subpasta chamada "Cache", "GPUCache" etc. é considerada descartável.
    private static readonly AppSignature[] AppDataSignatures =
    [
        new(@"\Google\Chrome", "Google Chrome", "Google"),
        new(@"\Microsoft\EdgeWebView", "Microsoft Edge WebView2", "Microsoft"),
        new(@"\Microsoft\Edge", "Microsoft Edge", "Microsoft"),
        new(@"\BraveSoftware\Brave-Browser", "Brave Browser", "Brave Software"),
        new(@"\Mozilla\Firefox", "Mozilla Firefox", "Mozilla"),
        new(@"\Opera Software", "Opera Browser", "Opera"),
        new(@"\Vivaldi", "Vivaldi Browser", "Vivaldi"),
        new(@"\discord", "Discord", "Discord Inc. (Electron)"),
        new(@"\discordcanary", "Discord Canary", "Discord Inc. (Electron)"),
        new(@"\discordptb", "Discord PTB", "Discord Inc. (Electron)"),
        new(@"\Spotify", "Spotify", "Spotify AB"),
        new(@"\Code", "Visual Studio Code", "Microsoft (Electron)"),
        new(@"\Cursor", "Cursor IDE", "Anysphere (Electron)"),
        new(@"\Antigravity", "Google Antigravity IDE", "Google (Electron)"),
        new(@"\Windsurf", "Windsurf IDE", "Codeium (Electron)"),
        new(@"\JetBrains", "JetBrains IDEs (IntelliJ / Rider / PyCharm)", "JetBrains"),
        new(@"\Microsoft\VisualStudio", "Microsoft Visual Studio", "Microsoft"),
        new(@"\Slack", "Slack", "Salesforce / Slack (Electron)"),
        new(@"\Microsoft\Teams", "Microsoft Teams", "Microsoft"),
        new(@"\Packages\MSTeams", "Microsoft Teams (MSIX)", "Microsoft", PrefixOfSegment: true),
        new(@"\Zoom", "Zoom Workplace", "Zoom Video Communications"),
        new(@"\Steam", "Steam Client", "Valve"),
        new(@"\EpicGamesLauncher", "Epic Games Launcher", "Epic Games"),
        new(@"\npm-cache", "Node.js npm Cache", "OpenJS Foundation"),
        new(@"\pnpm", "pnpm Package Manager", "pnpm"),
        new(@"\Yarn", "Yarn Package Manager", "Yarn"),
        new(@"\pip", "Python pip", "PyPA"),
        new(@"\NuGet", "NuGet Package Manager", "Microsoft / .NET"),
        new(@"\Composer", "PHP Composer", "Composer"),
        new(@"\Docker", "Docker Desktop", "Docker Inc."),
        new(@"\Postman", "Postman", "Postman Inc. (Electron)"),
        new(@"\Notion", "Notion Desktop", "Notion Labs (Electron)"),
        new(@"\Obsidian", "Obsidian", "Obsidian (Electron)"),
        new(@"\WhatsApp", "WhatsApp Desktop", "Meta"),
        new(@"\Telegram Desktop", "Telegram Desktop", "Telegram"),
        new(@"\NVIDIA", "NVIDIA Graphics Driver / GeForce", "NVIDIA"),
        new(@"\AMD", "AMD Radeon Software", "AMD"),
        new(@"\D3DSCache", "Direct3D Shader Cache", "Microsoft Windows"),
        new(@"\CrashDumps", "Windows Application Crash Dumps", "Microsoft Windows"),

        // Aplicativos Electron adicionais (layout Chromium confirmado pela própria tecnologia)
        new(@"\Claude", "Claude Desktop", "Anthropic (Electron)"),
        new(@"\GitHubDesktop", "GitHub Desktop", "GitHub (Electron)"),
        new(@"\Signal", "Signal Desktop", "Signal (Electron)"),
        new(@"\Figma", "Figma Desktop", "Figma (Electron)"),
        new(@"\insomnia", "Insomnia", "Kong (Electron)"),

        // Identificação apenas informativa: explica de quem é a pasta, mas NÃO autoriza limpeza por nome de subpasta
        new(@"\Microsoft\Credentials", "Credenciais salvas do Windows", "Microsoft Windows", TrustCacheFolderNames: false),
        new(@"\Microsoft\Protect", "Chaves de proteção de dados do Windows (DPAPI)", "Microsoft Windows", TrustCacheFolderNames: false),
        new(@"\Microsoft\Crypto", "Chaves criptográficas do usuário", "Microsoft Windows", TrustCacheFolderNames: false),
        new(@"\Microsoft\Vault", "Cofre de credenciais do Windows", "Microsoft Windows", TrustCacheFolderNames: false),
        new(@"\Microsoft\SystemCertificates", "Certificados do usuário", "Microsoft Windows", TrustCacheFolderNames: false),
        new(@"\Microsoft\Office", "Microsoft Office", "Microsoft", TrustCacheFolderNames: false),
        new(@"\Microsoft\Outlook", "Microsoft Outlook (caixas de correio locais)", "Microsoft", TrustCacheFolderNames: false),
        new(@"\Microsoft\OneDrive", "Microsoft OneDrive", "Microsoft", TrustCacheFolderNames: false),
        new(@"\Microsoft\WindowsApps", "Atalhos de execução de aplicativos da Microsoft Store", "Microsoft Windows", TrustCacheFolderNames: false),
        new(@"\Microsoft\Windows", "Componentes do Windows no perfil do usuário", "Microsoft Windows", TrustCacheFolderNames: false),
        new(@"\Microsoft\dotnet", ".NET SDK / Runtime (instalação no perfil)", "Microsoft / .NET", TrustCacheFolderNames: false),
        new(@"\Microsoft\WinGet", "Gerenciador de Pacotes do Windows (winget)", "Microsoft", TrustCacheFolderNames: false),
        new(@"\Microsoft\PowerToys", "Microsoft PowerToys", "Microsoft", TrustCacheFolderNames: false),
        new(@"\AppData\Local\Programs", "Programas instalados para este usuário", "Diversos fabricantes", TrustCacheFolderNames: false),
        new(@"\Android\Sdk", "Android SDK", "Google", TrustCacheFolderNames: false),
        new(@"\Google\AndroidStudio", "Android Studio", "Google / JetBrains", TrustCacheFolderNames: false),
        new(@"\Google\DriveFS", "Google Drive para computador", "Google", TrustCacheFolderNames: false),
        new(@"\Adobe", "Aplicativos Adobe", "Adobe", TrustCacheFolderNames: false),
        new(@"\Dropbox", "Dropbox", "Dropbox", TrustCacheFolderNames: false),
        new(@"\Thunderbird", "Mozilla Thunderbird", "Mozilla", TrustCacheFolderNames: false),
        new(@"\obs-studio", "OBS Studio", "OBS Project", TrustCacheFolderNames: false),
        new(@"\vlc", "VLC media player", "VideoLAN", TrustCacheFolderNames: false),
        new(@"\Riot Games", "Riot Games", "Riot Games", TrustCacheFolderNames: false),
        new(@"\Battle.net", "Battle.net", "Blizzard Entertainment", TrustCacheFolderNames: false),
        new(@"\Blizzard Entertainment", "Jogos Blizzard", "Blizzard Entertainment", TrustCacheFolderNames: false),
        new(@"\UnrealEngine", "Unreal Engine", "Epic Games", TrustCacheFolderNames: false),
        new(@"\Unity", "Unity", "Unity Technologies", TrustCacheFolderNames: false),
        new(@"\Roblox", "Roblox", "Roblox Corporation", TrustCacheFolderNames: false),
        new(@"\Electronic Arts", "EA app / jogos Electronic Arts", "Electronic Arts", TrustCacheFolderNames: false),
        new(@"\Ubisoft Game Launcher", "Ubisoft Connect", "Ubisoft", TrustCacheFolderNames: false),
        new(@"\GOG.com", "GOG Galaxy", "CD Projekt", TrustCacheFolderNames: false),
        new(@"\qBittorrent", "qBittorrent", "qBittorrent Project", TrustCacheFolderNames: false),
        new(@"\TeamViewer", "TeamViewer", "TeamViewer", TrustCacheFolderNames: false),
        new(@"\AnyDesk", "AnyDesk", "AnyDesk Software", TrustCacheFolderNames: false),
        new(@"\Notepad++", "Notepad++", "Notepad++ Team", TrustCacheFolderNames: false),
        new(@"\Intel", "Software e drivers Intel", "Intel", TrustCacheFolderNames: false)
    ];

    public StorageClassifier(
        IEnvironmentProvider environmentProvider,
        ISystemPathProtector systemPathProtector,
        Func<DateTime>? utcNow = null)
    {
        _environmentProvider = environmentProvider;
        _systemPathProtector = systemPathProtector;
        _utcNow = utcNow ?? (static () => DateTime.UtcNow);
        _ownApplicationPaths = DiscoverOwnApplicationPaths();
    }

    public void ObserveDirectoryStructure(string directoryPath, IReadOnlyList<string> subdirectoryNames)
    {
        if (string.IsNullOrWhiteSpace(directoryPath) || subdirectoryNames is null)
        {
            return;
        }

        if (ElectronRootByPath.Count > StructureCacheLimit)
        {
            ElectronRootByPath.Clear();
        }

        ElectronRootByPath[TrimSeparators(directoryPath)] = CountElectronMarkers(subdirectoryNames) >= 2;
    }

    public void ResetObservations()
    {
        ElectronRootByPath.Clear();
        _userProjectNodeModules.Clear();
    }

    public void ClassifyItem(StorageItem item)
    {
        ArgumentNullException.ThrowIfNull(item);

        EnvironmentPaths env = _environmentProvider.GetEnvironmentPaths();
        NormalizedEnvironment paths = GetNormalized(env);
        string fullPath = item.FullPath;
        string path = SystemPathProtector.NormalizeForComparison(fullPath);

        item.OfficialMaintenanceCommand = null;

        // 0. Reparse points / Links simbólicos / Junctions são sempre protegidos contra travessia e exclusão
        if (item.IsReparsePoint)
        {
            item.IsProtectedSystemItem = true;
            item.Category = ItemCategory.SystemCritical;
            item.AssociatedAppOrComponent = "Sistema de Arquivos NTFS (Reparse Point / Link Simbólico)";
            item.PurposeExplanation = "Ponto de análise NTFS (atalho de diretório, junction ou link simbólico) que redireciona para outro local do disco.";
            item.DeletionConsequences = "Manipular links simbólicos ou junctions indevidamente pode afetar o diretório de destino ou quebrar compatibilidade do Windows.";
            item.RiskClassification = RiskLevel.Gray;
            item.Recommendation = RecommendedAction.NoneProtected;
            item.RecommendationDetails = "Ignorado intencionalmente para evitar ciclos e proteger destinos vinculados.";
            return;
        }

        // 1. Diretórios sem permissão de acesso
        if (item.AccessDeniedCount > 0 && item.LogicalSizeBytes == 0 && item.IsDirectory)
        {
            item.IsProtectedSystemItem = true;
            item.Category = ItemCategory.Unknown;
            item.AssociatedAppOrComponent = "Restrito por Permissões NTFS";
            item.PurposeExplanation = "Diretório inacessível com o nível de privilégio atual do usuário.";
            item.DeletionConsequences = "Diretórios protegidos por ACLs do sistema não devem ser modificados.";
            item.RiskClassification = RiskLevel.Gray;
            item.Recommendation = RecommendedAction.NoneProtected;
            item.RecommendationDetails = "Executar como Administrador apenas se desejar inspecionar o consumo deste diretório.";
            return;
        }

        // 2. Proteção estrita do Windows 11 (Seção 5)
        if (_systemPathProtector.IsProtectedSystemPath(fullPath, out string protectionReason, out string? officialGuidance))
        {
            item.IsProtectedSystemItem = true;
            item.Category = ItemCategory.SystemCritical;
            item.AssociatedAppOrComponent = "Microsoft Windows 11";
            item.PurposeExplanation = protectionReason;
            item.DeletionConsequences = "A exclusão direta pode corromper o sistema operacional Windows 11, impedir a inicialização (boot), quebrar atualizações ou inutilizar aplicativos instalados.";
            item.RiskClassification = RiskLevel.Gray;
            item.Recommendation = officialGuidance is not null
                ? RecommendedAction.UseOfficialWindowsTool
                : RecommendedAction.NoneProtected;
            item.RecommendationDetails = officialGuidance
                ?? "Diretório protegido do sistema operacional. Exclusão bloqueada pelo DiskInspector.";
            item.OfficialMaintenanceCommand = officialGuidance;
            return;
        }

        // 3. Proteção de pastas-raiz do perfil do usuário (Users, Perfil, AppData raiz, Desktop, Documents, Downloads raiz)
        if (_systemPathProtector.IsCriticalRootOrProfileFolder(fullPath, out string rootReason))
        {
            item.IsProtectedSystemItem = true;
            item.Category = ItemCategory.StandardDirectory;
            item.AssociatedAppOrComponent = "Perfil do Usuário Windows";
            item.PurposeExplanation = rootReason;
            item.DeletionConsequences = "Excluir a pasta-raiz estrutural do perfil quebraria o ambiente do usuário e causaria perda massiva de dados.";
            item.RiskClassification = RiskLevel.Gray;
            item.Recommendation = RecommendedAction.NoneProtected;
            item.RecommendationDetails = "Analise apenas os subitens internos; a pasta-raiz é bloqueada contra exclusão.";
            return;
        }

        // 3b. Arquivos do próprio DiskInspector em execução (ou qualquer pasta que os contenha).
        // Em executável de arquivo único o aplicativo roda de dentro de %TEMP%\.net, uma área que ele mesmo analisa.
        if (IsOwnApplicationPath(path))
        {
            item.IsProtectedSystemItem = true;
            item.Category = ItemCategory.StandardDirectory;
            item.AssociatedAppOrComponent = "DiskInspector (em execução)";
            item.PurposeExplanation = "Contém os arquivos do próprio DiskInspector que estão em uso neste momento.";
            item.DeletionConsequences = "Remover os arquivos do aplicativo em execução interromperia a análise e a limpeza em andamento.";
            item.RiskClassification = RiskLevel.Gray;
            item.Recommendation = RecommendedAction.NoneProtected;
            item.RecommendationDetails = "Protegido enquanto o DiskInspector estiver aberto.";
            return;
        }

        // 4. Itens no diretório Temp oficial do usuário (%LOCALAPPDATA%\Temp)
        if (IsUnder(path, paths.Temp))
        {
            if (IsDirectChild(path, paths.Temp))
            {
                ClassifyUserTempItem(item, env);
            }
            else
            {
                ClassifyNestedContent(
                    item,
                    ItemCategory.TemporaryFiles,
                    "Diretório Temporário do Usuário (%TEMP%)",
                    FirstLevelUnder(path, paths.Temp),
                    RiskLevel.Yellow);
            }

            return;
        }

        // 5. Verificação de ambientes de desenvolvimento, caches globais, Docker e WSL2 (Seção 7)
        if (TryClassifyDeveloperOrContainerItem(item, path, paths))
        {
            return;
        }

        // 6. Verificação profunda de AppData (Local, Roaming, LocalLow) (Seção 4)
        if (IsSameOrUnder(path, paths.LocalAppData) ||
            IsSameOrUnder(path, paths.RoamingAppData) ||
            IsSameOrUnder(path, paths.LocalLowAppData))
        {
            ClassifyAppDataItem(item, path);
            return;
        }

        // 7. Verificação da pasta Downloads do usuário (Downloads antigos e instaladores)
        if (IsUnder(path, paths.Downloads))
        {
            ClassifyDownloadsItem(item, path, paths);
            return;
        }

        // 8. Logs excessivamente grandes ou Crash Dumps fora do sistema
        if (!item.IsDirectory && LogOrDumpExtensions.Contains(Path.GetExtension(path)) && item.LogicalSizeBytes >= 10 * 1024 * 1024)
        {
            item.Category = ItemCategory.LargeLogs;
            item.AssociatedAppOrComponent = "Registro de Diagnóstico / Log";
            item.PurposeExplanation = "Arquivo de log ou despejo de memória (crash dump) de grande porte gerado para diagnóstico.";
            item.DeletionConsequences = "Perda do histórico de diagnóstico/auditoria contido neste arquivo específico; não afeta o funcionamento do software se não estiver em uso.";
            item.RiskClassification = RiskLevel.Yellow;
            item.Recommendation = RecommendedAction.SafeToMoveToRecycleBin;
            item.RecommendationDetails = "Pode ser movido para a Lixeira se você não precisar investigar falhas passadas. Se estiver em uso, a limpeza é recusada na prévia.";
            return;
        }

        // 9. Diretórios pessoais (Documents, Desktop) -> Sempre Alto Risco (VERMELHO)
        if (IsUnder(path, paths.Documents) || IsUnder(path, paths.Desktop))
        {
            item.Category = ItemCategory.LargeUserFile;
            item.AssociatedAppOrComponent = "Arquivos Pessoais do Usuário";
            item.PurposeExplanation = "Documento, projeto ou arquivo armazenado em pasta pessoal do usuário (Documentos / Área de Trabalho).";
            item.DeletionConsequences = "Risco elevado de perda permanente de documentos pessoais, trabalhos ou projetos.";
            item.RiskClassification = RiskLevel.Red;
            item.Recommendation = RecommendedAction.ManualReviewRequired;
            item.RecommendationDetails = "Protegido contra limpeza automática. Gerencie seus documentos manualmente.";
            return;
        }

        // 10. Diretórios com milhares de pequenos arquivos (Seção 3)
        if (item.IsDirectory && item.SmallFileCount >= 1000)
        {
            item.Category = ItemCategory.HighDensityDirectory;
            item.AssociatedAppOrComponent = UnknownApp;
            item.PurposeExplanation = $"Diretório contendo elevada densidade de pequenos arquivos ({item.FileCount:N0} arquivos totais, {item.SmallFileCount:N0} menores que 16 KB). Finalidade específica não determinada.";
            item.DeletionConsequences = "Como a finalidade exata da pasta não é conhecida com segurança, a exclusão pode comprometer aplicativos ou projetos locais.";
            item.RiskClassification = RiskLevel.Gray;
            item.Recommendation = RecommendedAction.ManualReviewRequired;
            item.RecommendationDetails = "Classificado como desconhecido por segurança. Verifique manualmente antes de qualquer ação.";
            return;
        }

        // 11. Regra padrão conservadora (Seção 3 e Seção 6):
        // "Não invente informações sobre a finalidade de uma pasta. Quando não for possível determinar com segurança, classifique-a como desconhecida."
        // "Um nome de pasta semelhante a 'cache' não é evidência suficiente para autorizar sua exclusão."
        item.Category = ItemCategory.Unknown;
        item.AssociatedAppOrComponent = UnknownApp;
        item.PurposeExplanation = "Finalidade desconhecida — não há assinatura verificada suficiente para determinar o papel deste item com segurança.";
        item.DeletionConsequences = "Risco indeterminado. Excluir arquivos ou pastas sem finalidade confirmada pode causar perda de dados ou falhas em programas.";
        item.RiskClassification = RiskLevel.Gray;
        item.Recommendation = RecommendedAction.ManualReviewRequired;
        item.RecommendationDetails = "Nenhuma ação automática permitida. Na dúvida, o DiskInspector bloqueia a remoção.";
    }

    /// <summary>
    /// Item diretamente dentro de %TEMP%. É VERDE apenas quando nada nele foi alterado desde antes do início da
    /// sessão atual do Windows (nenhum programa aberto agora pode tê-lo criado) e há pelo menos 24 horas.
    /// </summary>
    private void ClassifyUserTempItem(StorageItem item, EnvironmentPaths env)
    {
        DateTime now = _utcNow();
        DateTime latestWrite = item.EffectiveLatestWriteUtc;
        bool olderThanOneDay = latestWrite < now.AddHours(-24);
        bool olderThanSession = env.UserSessionStartUtc is null || latestWrite < env.UserSessionStartUtc.Value;

        item.Category = ItemCategory.TemporaryFiles;
        item.AssociatedAppOrComponent = "Diretório Temporário do Usuário (%TEMP%)";

        if (olderThanOneDay && olderThanSession)
        {
            item.PurposeExplanation = "Arquivo ou pasta temporária em %LOCALAPPDATA%\\Temp sem nenhuma alteração desde antes do início da sessão atual do Windows.";
            item.DeletionConsequences = "Nenhuma perda de dados persistentes. Se algum programa ainda estiver usando o item, a limpeza é recusada e ele permanece intacto.";
            item.RiskClassification = RiskLevel.Green;
            item.Recommendation = RecommendedAction.SafeToMoveToRecycleBin;
            item.RecommendationDetails = "Seguro enviar para a Lixeira do Windows.";
        }
        else
        {
            item.PurposeExplanation = env.UserSessionStartUtc is not null && !olderThanSession
                ? "Item temporário criado ou alterado durante a sessão atual do Windows: pode pertencer a um programa que ainda está aberto."
                : "Item temporário alterado nas últimas 24 horas em %TEMP%.";
            item.DeletionConsequences = "Se um instalador, editor ou outro programa aberto depender deste item, removê-lo pode causar falha nesse programa.";
            item.RiskClassification = RiskLevel.Yellow;
            item.Recommendation = RecommendedAction.SafeToCleanWhenAppClosed;
            item.RecommendationDetails = "Feche os programas abertos (ou reinicie o Windows) antes de enviar para a Lixeira.";
        }
    }

    private bool TryClassifyDeveloperOrContainerItem(StorageItem item, string path, NormalizedEnvironment paths)
    {
        string name = item.Name;

        // 1. Docker Desktop e WSL2 (Discos Virtuais .vhdx e diretórios de dados) — SEMPRE VERMELHO (Alto Risco)
        if (TryFindContainerRoot(item, path, out string containerRoot))
        {
            bool isDocker = path.Contains("Docker", StringComparison.OrdinalIgnoreCase);
            string owner = isDocker ? "Docker Desktop / WSL2" : "Windows Subsystem for Linux (WSL2)";

            if (!string.Equals(containerRoot, path, StringComparison.OrdinalIgnoreCase))
            {
                ClassifyNestedContent(item, ItemCategory.ContainerOrVirtualization, owner, containerRoot, RiskLevel.Red);
                return true;
            }

            item.Category = ItemCategory.ContainerOrVirtualization;
            item.AssociatedAppOrComponent = owner;
            item.PurposeExplanation = "Disco virtual (VHDX) ou estrutura de containers/volumes persistentes do Docker Desktop / WSL2.";
            item.DeletionConsequences = "PERDA CRÍTICA: Excluir arquivos .vhdx ou pastas de dados do Docker/WSL2 destrói todos os containers, bancos de dados em volumes e distribuições Linux inteiras!";
            item.RiskClassification = RiskLevel.Red;
            item.Recommendation = RecommendedAction.UseOfficialDeveloperCommand;
            item.RecommendationDetails = "NUNCA exclua o arquivo .vhdx diretamente. Use comandos oficiais do Docker para limpar apenas imagens/build cache órfãos.";
            item.OfficialMaintenanceCommand = "docker system df  |  docker builder prune  |  wsl --shutdown";
            return true;
        }

        // 2. Caches globais de pacotes (npm, pnpm, Yarn, pip, Composer, NuGet, Gradle, Maven, Cargo)
        foreach (DevCacheRule rule in GlobalDevCacheRules)
        {
            if (!TryFindMarkerRoot(path, rule.Marker, out string cacheRoot))
            {
                continue;
            }

            if (!string.Equals(cacheRoot, path, StringComparison.OrdinalIgnoreCase))
            {
                ClassifyNestedContent(item, ItemCategory.DeveloperCache, rule.Tool, cacheRoot, RiskLevel.Yellow);
                return true;
            }

            item.Category = ItemCategory.DeveloperCache;
            item.AssociatedAppOrComponent = rule.Tool;
            item.PurposeExplanation = rule.Purpose;
            item.DeletionConsequences = rule.Consequences;
            item.RiskClassification = RiskLevel.Yellow;
            item.Recommendation = rule.Action;
            item.RecommendationDetails = rule.Details;
            item.OfficialMaintenanceCommand = rule.Command;
            return true;
        }

        // 3. node_modules: só é artefato de projeto a pasta de primeiro nível de um projeto do usuário
        if (TryFindMarkerRoot(path, @"\node_modules", out string topNodeModules))
        {
            bool isUserProject = IsUserProjectNodeModules(topNodeModules, paths);

            if (!string.Equals(topNodeModules, path, StringComparison.OrdinalIgnoreCase))
            {
                if (isUserProject)
                {
                    ClassifyNestedContent(item, ItemCategory.DeveloperBuildArtifact, "Node.js (Dependências de Projeto)", topNodeModules, RiskLevel.Yellow);
                    return true;
                }

                // Dentro da node_modules de um programa instalado, extensão ou ferramenta: nada aqui é artefato de projeto
                return false;
            }

            if (isUserProject && item.IsDirectory)
            {
                item.Category = ItemCategory.DeveloperBuildArtifact;
                item.AssociatedAppOrComponent = "Node.js (Dependências de Projeto)";
                item.PurposeExplanation = "Diretório 'node_modules' com as dependências instaladas de um projeto JavaScript/TypeScript seu (package.json e controle de versão ou lockfile encontrados ao lado).";
                item.DeletionConsequences = "O projeto não executará até que 'npm install', 'pnpm install' ou 'yarn' seja rodado novamente na pasta do projeto.";
                item.RiskClassification = RiskLevel.Yellow;
                item.Recommendation = RecommendedAction.SafeToCleanWhenAppClosed;
                item.RecommendationDetails = "Seguro remover em projetos inativos; basta rodar 'npm install' quando voltar a trabalhar no projeto.";
                item.OfficialMaintenanceCommand = "npm install (para restaurar posteriormente)";
                return true;
            }

            return false;
        }

        if (!item.IsDirectory)
        {
            return false;
        }

        string parentDir = Path.GetDirectoryName(path) ?? string.Empty;

        // 4. Diretórios de build do Rust / Maven: target (somente com Cargo.toml ou pom.xml no diretório pai)
        if (string.Equals(name, "target", StringComparison.OrdinalIgnoreCase) && IsEligibleProjectLocation(parentDir, paths))
        {
            if (File.Exists(Path.Combine(parentDir, "Cargo.toml")))
            {
                item.Category = ItemCategory.DeveloperBuildArtifact;
                item.AssociatedAppOrComponent = "Rust / Cargo (Artefatos de Compilação)";
                item.PurposeExplanation = "Diretório 'target' de compilação incremental do Rust (Cargo.toml verificado no diretório do projeto).";
                item.DeletionConsequences = "Nenhuma perda de código-fonte, porém a próxima compilação ('cargo build') levará mais tempo para recompilar todas as crates.";
                item.RiskClassification = RiskLevel.Yellow;
                item.Recommendation = RecommendedAction.UseOfficialDeveloperCommand;
                item.RecommendationDetails = "Pode ser limpo com 'cargo clean' ou movido para a Lixeira em projetos inativos.";
                item.OfficialMaintenanceCommand = "cargo clean";
                return true;
            }

            if (File.Exists(Path.Combine(parentDir, "pom.xml")))
            {
                item.Category = ItemCategory.DeveloperBuildArtifact;
                item.AssociatedAppOrComponent = "Java / Maven (Artefatos de Build)";
                item.PurposeExplanation = "Diretório 'target' de saída de compilação de projeto Java Maven (pom.xml verificado).";
                item.DeletionConsequences = "Exigirá recompilação ('mvn compile' / 'mvn package') no próximo uso.";
                item.RiskClassification = RiskLevel.Yellow;
                item.Recommendation = RecommendedAction.UseOfficialDeveloperCommand;
                item.RecommendationDetails = "Use 'mvn clean' ou envie para a Lixeira.";
                item.OfficialMaintenanceCommand = "mvn clean";
                return true;
            }
        }

        // 5. Diretórios de build Java / Gradle: build ou .gradle (somente quando há build.gradle ou settings.gradle ao lado)
        if ((string.Equals(name, "build", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(name, ".gradle", StringComparison.OrdinalIgnoreCase)) &&
            IsEligibleProjectLocation(parentDir, paths) &&
            (File.Exists(Path.Combine(parentDir, "build.gradle")) ||
             File.Exists(Path.Combine(parentDir, "build.gradle.kts")) ||
             File.Exists(Path.Combine(parentDir, "settings.gradle")) ||
             File.Exists(Path.Combine(parentDir, "settings.gradle.kts"))))
        {
            item.Category = ItemCategory.DeveloperBuildArtifact;
            item.AssociatedAppOrComponent = "Java / Kotlin / Gradle";
            item.PurposeExplanation = $"Diretório '{name}' de artefatos de compilação ou cache local de projeto Gradle.";
            item.DeletionConsequences = "Exigirá recompilação ('./gradlew build') na próxima execução.";
            item.RiskClassification = RiskLevel.Yellow;
            item.Recommendation = RecommendedAction.UseOfficialDeveloperCommand;
            item.RecommendationDetails = "Use 'gradle clean' ou envie para a Lixeira se o projeto estiver inativo.";
            item.OfficialMaintenanceCommand = "gradle clean";
            return true;
        }

        // 6. Diretórios bin e obj do .NET (somente quando há arquivo .csproj, .fsproj ou .vbproj no diretório pai)
        if ((string.Equals(name, "bin", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(name, "obj", StringComparison.OrdinalIgnoreCase)) &&
            IsEligibleProjectLocation(parentDir, paths) &&
            HasDotNetProjectFile(parentDir))
        {
            item.Category = ItemCategory.DeveloperBuildArtifact;
            item.AssociatedAppOrComponent = ".NET SDK / MSBuild";
            item.PurposeExplanation = $"Diretório '{name}' de saída intermediária/final de compilação de um projeto .NET (.csproj detectado).";
            item.DeletionConsequences = "Exigirá recompilação ('dotnet build') na próxima vez que o projeto for aberto ou executado.";
            item.RiskClassification = RiskLevel.Yellow;
            item.Recommendation = RecommendedAction.UseOfficialDeveloperCommand;
            item.RecommendationDetails = "Use 'dotnet clean' ou envie para a Lixeira se o projeto estiver fechado.";
            item.OfficialMaintenanceCommand = "dotnet clean";
            return true;
        }

        // 7. Ambientes virtuais Python (.venv / venv com pyvenv.cfg) -> VERMELHO (Alto risco se excluído sem querer)
        if ((string.Equals(name, ".venv", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(name, "venv", StringComparison.OrdinalIgnoreCase)) &&
            File.Exists(Path.Combine(path, "pyvenv.cfg")))
        {
            item.Category = ItemCategory.DeveloperBuildArtifact;
            item.AssociatedAppOrComponent = "Python Virtual Environment (venv)";
            item.PurposeExplanation = "Ambiente virtual isolado do Python contendo interpretador e bibliotecas instaladas para um projeto.";
            item.DeletionConsequences = "Desativa o ambiente Python do projeto; se não houver requirements.txt ou pyproject.toml atualizado, você perderá a lista exata de pacotes.";
            item.RiskClassification = RiskLevel.Red;
            item.Recommendation = RecommendedAction.ManualReviewRequired;
            item.RecommendationDetails = "Ambientes virtuais não são excluídos automaticamente pelo DiskInspector.";
            return true;
        }

        return false;
    }

    private void ClassifyAppDataItem(StorageItem item, string path)
    {
        AppSignature? signature = MatchSignature(path);
        string appName = signature?.AppName ?? UnknownApp;
        string publisher = signature?.Publisher ?? string.Empty;

        // Detecção estrutural de aplicativo Electron / Chromium mesmo que não esteja na lista estática de nomes
        bool electronDetected = false;
        if (signature is null)
        {
            if (item.IsDirectory && IsElectronAppRootDirectory(path))
            {
                appName = $"Aplicativo Electron ({item.Name})";
                publisher = "Chromium / Electron Runtime";
                electronDetected = true;
            }
            else if (IsParentElectronAppDirectory(path, out string parentAppName))
            {
                appName = $"Aplicativo Electron ({parentAppName})";
                publisher = "Chromium / Electron Runtime";
                electronDetected = true;
            }
        }

        bool appIsKnown = !string.Equals(appName, UnknownApp, StringComparison.OrdinalIgnoreCase);

        // Só aplicativos de layout confirmado autorizam limpeza por nome de subpasta (cache, logs)
        bool appLayoutIsTrusted = electronDetected || signature is { TrustCacheFolderNames: true };

        item.AssociatedAppOrComponent = string.IsNullOrWhiteSpace(publisher)
            ? appName
            : $"{appName} ({publisher})";

        // 1. Cache técnico descartável verificado (pacote UWP/MSIX, navegador, Electron, IDE, GPU)
        string? cacheRoot = FindVerifiedCacheRoot(path);
        if (cacheRoot is not null)
        {
            if (!string.Equals(cacheRoot, path, StringComparison.OrdinalIgnoreCase))
            {
                ClassifyNestedContent(item, ItemCategory.ApplicationCache, item.AssociatedAppOrComponent, cacheRoot, RiskLevel.Green);
                return;
            }

            bool isUwpPackage = path.Contains(@"\AppData\Local\Packages\", StringComparison.OrdinalIgnoreCase);
            item.Category = ItemCategory.ApplicationCache;
            item.PurposeExplanation = isUwpPackage
                ? $"Diretório de estado temporário ou cache de rede ({item.Name}) de pacote UWP/MSIX do Windows 11."
                : $"Cache técnico descartável (HTTP/GPU/Shaders/Code Cache) do aplicativo {appName}. Não armazena senhas, sessões ou documentos.";
            item.DeletionConsequences = isUwpPackage
                ? "Nenhuma perda de configurações ou bancos locais do aplicativo UWP."
                : $"Nenhuma perda de dados pessoais ou login. O {appName} reconstruirá este cache automaticamente na próxima execução.";
            item.RiskClassification = RiskLevel.Green;
            item.Recommendation = RecommendedAction.SafeToCleanWhenAppClosed;
            item.RecommendationDetails = appIsKnown
                ? $"Seguro enviar para a Lixeira com o {appName} fechado. Se ele estiver aberto, a limpeza é recusada e nada é alterado."
                : "Seguro mover para a Lixeira com o aplicativo fechado. Se ele estiver aberto, a limpeza é recusada e nada é alterado.";
            return;
        }

        // 2. Relatórios de falha (CrashDumps / Crashpad) e pastas de log de aplicativos conhecidos
        string? logRoot = FindLogOrCrashRoot(path, appLayoutIsTrusted);
        if (logRoot is not null)
        {
            if (!string.Equals(logRoot, path, StringComparison.OrdinalIgnoreCase))
            {
                ClassifyNestedContent(item, ItemCategory.LargeLogs, item.AssociatedAppOrComponent, logRoot, RiskLevel.Green);
                return;
            }

            item.Category = ItemCategory.LargeLogs;
            item.PurposeExplanation = $"Relatórios de falha (CrashDumps) ou registros de log em AppData associados a {appName}.";
            item.DeletionConsequences = "Remove apenas relatórios antigos de travamento; não afeta configurações nem sessões do usuário.";
            item.RiskClassification = RiskLevel.Green;
            item.Recommendation = RecommendedAction.SafeToMoveToRecycleBin;
            item.RecommendationDetails = "Seguro mover para a Lixeira se não precisar depurar falhas antigas.";
            return;
        }

        // 3. Sessões, perfis, cookies, autenticação ou bancos de dados locais (VERMELHO — Alto Risco)
        if (SensitiveSessionOrDatabaseFolderNames.Contains(item.Name) ||
            path.Contains(@"\User Data\Default", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\Mozilla\Firefox\Profiles", StringComparison.OrdinalIgnoreCase))
        {
            item.Category = ItemCategory.AppDataSessionOrProfile;
            item.PurposeExplanation = $"Armazena sessões ativas, autenticação, perfis, bancos de dados locais (IndexedDB/SQLite), extensões ou configurações de {appName}.";
            item.DeletionConsequences = $"ALTO RISCO: Apagar este diretório causará desconexão de contas (logout), perda de perfis, histórico, favoritos, extensões ou bancos de dados locais no {appName}.";
            item.RiskClassification = RiskLevel.Red;
            item.Recommendation = RecommendedAction.NoneProtected;
            item.RecommendationDetails = "Protegido contra exclusão. Limpe apenas as subpastas específicas de Cache quando necessário.";
            return;
        }

        // 4. Caso geral dentro do AppData: a pasta de um aplicativo conhecido mistura configurações + dados + cache -> VERMELHO
        if (appIsKnown)
        {
            item.Category = ItemCategory.AppDataPersistent;
            item.PurposeExplanation = $"Diretório de dados de aplicativo ({appName}) no AppData contendo configurações, estado persistente, bibliotecas e possíveis subpastas de cache.";
            item.DeletionConsequences = $"Apagar a pasta inteira de {appName} removerá configurações personalizadas, contas conectadas, licenças locais e dados salvos.";
            item.RiskClassification = RiskLevel.Red;
            item.Recommendation = RecommendedAction.ManualReviewRequired;
            item.RecommendationDetails = "Não exclua a pasta inteira do aplicativo! Utilize a aba 'Raio-X do AppData' para inspecionar apenas subpastas comprovadamente descartáveis.";
            return;
        }

        // 5. Pasta no AppData cujo aplicativo não pôde ser identificado com segurança -> CINZA (Desconhecido)
        item.Category = ItemCategory.Unknown;
        item.AssociatedAppOrComponent = "Desconhecido (AppData)";
        item.PurposeExplanation = "Diretório em AppData cuja finalidade específica ou aplicativo proprietário não pôde ser determinado com segurança.";
        item.DeletionConsequences = "Como AppData armazena configurações, bancos locais e chaves de aplicativos, excluir sem confirmação pode causar perda de dados.";
        item.RiskClassification = RiskLevel.Gray;
        item.Recommendation = RecommendedAction.ManualReviewRequired;
        item.RecommendationDetails = "Classificado como desconhecido (CINZA). Exclusão bloqueada por segurança.";
    }

    private void ClassifyDownloadsItem(StorageItem item, string path, NormalizedEnvironment paths)
    {
        const string owner = "Pasta Downloads do Usuário";

        // Só o item de primeiro nível de Downloads é avaliado; o conteúdo interno acompanha a decisão do item pai
        if (!IsDirectChild(path, paths.Downloads))
        {
            string firstLevel = FirstLevelUnder(path, paths.Downloads);
            item.Category = ItemCategory.LargeUserFile;
            item.AssociatedAppOrComponent = owner;
            item.PurposeExplanation = $"Conteúdo dentro de '{firstLevel}', na pasta Downloads.";
            item.DeletionConsequences = "Pode conter arquivos pessoais ou de trabalho baixados pelo usuário.";
            item.RiskClassification = RiskLevel.Red;
            item.Recommendation = RecommendedAction.ManualReviewRequired;
            item.RecommendationDetails = "O conteúdo interno não é sugerido para limpeza. Avalie o item de primeiro nível na pasta Downloads.";
            return;
        }

        if (item.IsDirectory && LooksLikeWorkspace(path))
        {
            item.Category = ItemCategory.LargeUserFile;
            item.AssociatedAppOrComponent = owner;
            item.PurposeExplanation = "Pasta de trabalho dentro de Downloads: contém um repositório Git ou arquivos de projeto de desenvolvimento.";
            item.DeletionConsequences = "ALTO RISCO: pode conter código-fonte ou trabalho em andamento que não existe em nenhum outro lugar.";
            item.RiskClassification = RiskLevel.Red;
            item.Recommendation = RecommendedAction.ManualReviewRequired;
            item.RecommendationDetails = "Projetos nunca são sugeridos para limpeza, mesmo quando estão há muito tempo na pasta Downloads.";
            return;
        }

        string ext = Path.GetExtension(path);
        DateTime latestWrite = item.EffectiveLatestWriteUtc;
        double ageDays = latestWrite == DateTime.MinValue
            ? 0
            : Math.Max(0, (_utcNow() - latestWrite).TotalDays);

        if (!item.IsDirectory && InstallerExtensions.Contains(ext))
        {
            item.Category = ItemCategory.InstallerResidue;
            item.AssociatedAppOrComponent = owner;
            item.PurposeExplanation = $"Instalador ou imagem de disco ({ext}) baixado pelo usuário há {ageDays:0} dias.";
            item.DeletionConsequences = "Se o programa já foi instalado, o instalador geralmente não é mais necessário; caso precise reinstalar offline, terá de baixá-lo novamente.";
            item.RiskClassification = RiskLevel.Yellow;
            item.Recommendation = RecommendedAction.SafeToMoveToRecycleBin;
            item.RecommendationDetails = "Verifique se a instalação já foi concluída antes de mover para a Lixeira.";
            return;
        }

        if (ageDays >= 30 && item.LogicalSizeBytes >= 25 * 1024 * 1024)
        {
            item.Category = ItemCategory.OldDownloads;
            item.AssociatedAppOrComponent = owner;
            item.PurposeExplanation = $"Arquivo ou pasta volumosa na pasta Downloads sem nenhuma modificação (nem no conteúdo interno) há {ageDays:0} dias.";
            item.DeletionConsequences = "Pode conter documentos ou mídias baixadas pelo usuário. Revise o nome do arquivo antes de enviar para a Lixeira.";
            item.RiskClassification = RiskLevel.Yellow;
            item.Recommendation = RecommendedAction.SafeToMoveToRecycleBin;
            item.RecommendationDetails = "Download antigo — revise manualmente e utilize a Lixeira caso não precise mais dele.";
            return;
        }

        item.Category = ItemCategory.LargeUserFile;
        item.AssociatedAppOrComponent = owner;
        item.PurposeExplanation = "Item recente ou pessoal localizado na pasta Downloads do usuário.";
        item.DeletionConsequences = "Pode ser um arquivo pessoal baixado recentemente.";
        item.RiskClassification = RiskLevel.Red;
        item.Recommendation = RecommendedAction.ManualReviewRequired;
        item.RecommendationDetails = "Mantido como alto risco por ser um download recente ou pessoal.";
    }

    /// <summary>
    /// Conteúdo interno de um achado de primeiro nível. Herda a categoria, mas nunca é selecionável sozinho.
    /// </summary>
    private static void ClassifyNestedContent(StorageItem item, ItemCategory category, string owner, string rootPath, RiskLevel risk)
    {
        item.Category = category;
        item.AssociatedAppOrComponent = owner;
        item.PurposeExplanation = $"Faz parte de '{rootPath}'. O conteúdo interno não é avaliado separadamente.";
        item.DeletionConsequences = "A limpeza deste conteúdo acontece pelo item de primeiro nível, que é verificado por inteiro (idade, uso por outros programas e possibilidade de desfazer).";
        item.RiskClassification = risk;
        item.Recommendation = RecommendedAction.CleanViaParentItem;
        item.RecommendationDetails = $"Para limpar, selecione o item de primeiro nível: {rootPath}";
    }

    /// <summary>
    /// Informa se a pasta é, ela própria, um cache descartável verificado (o item de primeiro nível da regra).
    /// O parâmetro identifiedApp é mantido por compatibilidade: o aplicativo é sempre deduzido do caminho.
    /// </summary>
    public static bool IsVerifiedDisposableAppDataCache(string fullPath, string folderName, string identifiedApp)
    {
        if (string.IsNullOrWhiteSpace(fullPath))
        {
            return false;
        }

        return IsVerifiedCacheFolder(TrimSeparators(fullPath), folderName);
    }

    private static bool IsVerifiedCacheFolder(string folderPath, string folderName)
    {
        // Pacotes UWP / MSIX: estado temporário e caches de rede do contêiner do aplicativo
        if (folderPath.Contains(@"\AppData\Local\Packages\", StringComparison.OrdinalIgnoreCase) &&
            (string.Equals(folderName, "TempState", StringComparison.OrdinalIgnoreCase) ||
             folderPath.EndsWith(@"\AC\INetCache", StringComparison.OrdinalIgnoreCase) ||
             folderPath.EndsWith(@"\LocalCache\Cache", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        // Caches de GPU / rede em locais fixos do perfil
        foreach (string suffix in FixedDisposableCacheSuffixes)
        {
            if (folderPath.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        AppSignature? signature = MatchSignature(folderPath);

        // Aplicativo desconhecido: um nome "Cache" isolado NÃO é evidência suficiente (Seção 6).
        // Exige a estrutura Electron/Chromium comprovada na pasta pai.
        if (signature is null)
        {
            return VerifiedBrowserOrElectronCacheFolderNames.Contains(folderName) &&
                   IsParentElectronAppDirectory(folderPath, out _);
        }

        if (!signature.TrustCacheFolderNames)
        {
            return false;
        }

        if (VerifiedBrowserOrElectronCacheFolderNames.Contains(folderName))
        {
            // Dentro de uma área de dados sensíveis (armazenamento de extensões, perfil, bancos locais), o nome
            // sozinho não basta: uma extensão pode guardar o que quiser numa pasta chamada "cache".
            // Ali só vale a estrutura Chromium comprovada na pasta pai.
            return !HasSensitiveAncestor(folderPath) || IsParentElectronAppDirectory(folderPath, out _);
        }

        // Spotify armazena seu cache de streaming em AppData\Local\Spotify\Data e AppData\Local\Spotify\Storage
        if (signature.AppName.Contains("Spotify", StringComparison.OrdinalIgnoreCase) &&
            (folderPath.EndsWith(@"\Spotify\Data", StringComparison.OrdinalIgnoreCase) ||
             folderPath.EndsWith(@"\Spotify\Storage", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return string.Equals(folderName, "SquirrelTemp", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verdadeiro quando alguma pasta acima (dentro do AppData) tem nome de área sensível:
    /// "User", "workspaceStorage", "globalStorage", "LocalState", "IndexedDB" etc.
    /// </summary>
    private static bool HasSensitiveAncestor(string folderPath)
    {
        int appDataIndex = folderPath.IndexOf(@"\AppData\", StringComparison.OrdinalIgnoreCase);
        if (appDataIndex < 0)
        {
            return false;
        }

        int lastSeparator = folderPath.LastIndexOf('\\');
        int segmentStart = appDataIndex + 1;
        while (segmentStart < lastSeparator)
        {
            int segmentEnd = folderPath.IndexOf('\\', segmentStart);
            if (segmentEnd < 0 || segmentEnd > lastSeparator)
            {
                break;
            }

            if (SensitiveSessionOrDatabaseFolderNames.Contains(folderPath[segmentStart..segmentEnd]))
            {
                return true;
            }

            segmentStart = segmentEnd + 1;
        }

        return false;
    }

    /// <summary>
    /// Procura, do nível mais alto para o mais baixo, a primeira pasta do caminho que é um cache verificado.
    /// Retorna null se o item não é nem está dentro de um.
    /// </summary>
    private static string? FindVerifiedCacheRoot(string path)
    {
        int appDataIndex = path.IndexOf(@"\AppData\", StringComparison.OrdinalIgnoreCase);
        if (appDataIndex < 0)
        {
            return null;
        }

        int segmentStart = appDataIndex + 1;
        while (segmentStart < path.Length)
        {
            int segmentEnd = path.IndexOf('\\', segmentStart);
            if (segmentEnd < 0)
            {
                segmentEnd = path.Length;
            }

            // Só vale a verificação completa para nomes que podem ser a raiz de um cache
            string name = path[segmentStart..segmentEnd];
            if (PossibleCacheRootNames.Contains(name))
            {
                string prefix = path[..segmentEnd];
                if (IsVerifiedCacheFolder(prefix, name))
                {
                    return prefix;
                }
            }

            segmentStart = segmentEnd + 1;
        }

        return null;
    }

    private static string? FindLogOrCrashRoot(string path, bool appLayoutIsTrusted)
    {
        if (TryFindMarkerRoot(path, @"\AppData\Local\CrashDumps", out string crashDumps))
        {
            return crashDumps;
        }

        if (TryFindMarkerRoot(path, @"\Crashpad", out string crashpad))
        {
            return crashpad;
        }

        if (appLayoutIsTrusted && TryFindMarkerRoot(path, @"\logs", out string logs))
        {
            return logs;
        }

        return null;
    }

    private static bool TryFindContainerRoot(StorageItem item, string path, out string rootPath)
    {
        // Cada disco virtual é sempre um item próprio, mesmo dentro da pasta de dados do Docker/WSL
        if (!item.IsDirectory && path.EndsWith(".vhdx", StringComparison.OrdinalIgnoreCase))
        {
            rootPath = path;
            return true;
        }

        if (TryFindMarkerRoot(path, @"\AppData\Local\Docker\wsl", out rootPath) ||
            TryFindMarkerRoot(path, @"\.docker", out rootPath))
        {
            return true;
        }

        // Distribuições Linux da Microsoft Store: AppData\Local\Packages\CanonicalGroupLimited...
        const string wslPackagePrefix = @"\AppData\Local\Packages\CanonicalGroupLimited";
        int index = path.IndexOf(wslPackagePrefix, StringComparison.OrdinalIgnoreCase);
        if (index >= 0)
        {
            int end = path.IndexOf('\\', index + wslPackagePrefix.Length);
            rootPath = end < 0 ? path : path[..end];
            return true;
        }

        rootPath = string.Empty;
        return false;
    }

    /// <summary>
    /// Uma node_modules só pertence a um projeto do usuário quando há package.json ao lado, evidência de
    /// projeto (lockfile ou repositório Git) e a pasta não fica em uma área de programas instalados.
    /// </summary>
    private bool IsUserProjectNodeModules(string nodeModulesPath, NormalizedEnvironment paths)
    {
        return _userProjectNodeModules.GetOrAdd(nodeModulesPath, static (key, state) =>
        {
            try
            {
                string? projectDir = Path.GetDirectoryName(key);
                if (string.IsNullOrEmpty(projectDir) || !IsEligibleProjectLocation(projectDir, state))
                {
                    return false;
                }

                if (!File.Exists(Path.Combine(projectDir, "package.json")))
                {
                    return false;
                }

                foreach (string lockFile in NodeLockFiles)
                {
                    if (File.Exists(Path.Combine(projectDir, lockFile)))
                    {
                        return true;
                    }
                }

                return HasGitRepositoryAtOrAbove(projectDir, state);
            }
            catch
            {
                return false;
            }
        }, paths);
    }

    /// <summary>
    /// Áreas onde ficam programas instalados, extensões e ferramentas, e não projetos do usuário:
    /// AppData, pastas iniciadas por ponto na raiz do perfil (.vscode, .cache, .cursor...) e o conteúdo
    /// empacotado de aplicativos Electron (resources\app).
    /// </summary>
    private static bool IsEligibleProjectLocation(string projectDir, NormalizedEnvironment paths)
    {
        if (string.IsNullOrWhiteSpace(projectDir))
        {
            return false;
        }

        if (IsSameOrUnder(projectDir, paths.LocalAppData) ||
            IsSameOrUnder(projectDir, paths.RoamingAppData) ||
            IsSameOrUnder(projectDir, paths.LocalLowAppData))
        {
            return false;
        }

        if (IsUnder(projectDir, paths.Profile))
        {
            string firstSegment = FirstSegmentUnder(projectDir, paths.Profile);
            if (firstSegment.StartsWith('.'))
            {
                return false;
            }
        }

        if (projectDir.Contains(@"\resources\app", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    private static bool HasGitRepositoryAtOrAbove(string directory, NormalizedEnvironment paths)
    {
        string? current = directory;
        for (int level = 0; level < 8 && !string.IsNullOrEmpty(current); level++)
        {
            // Um repositório na raiz do perfil ou da unidade (dotfiles) não prova que isto é um projeto
            if (string.Equals(current, paths.Profile, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(TrimSeparators(Path.GetPathRoot(current) ?? string.Empty), current, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string gitPath = Path.Combine(current, ".git");
            if (Directory.Exists(gitPath) || File.Exists(gitPath))
            {
                return true;
            }

            current = Path.GetDirectoryName(current);
        }

        return false;
    }

    /// <summary>
    /// Indica se a pasta (ou uma subpasta direta) tem cara de pasta de trabalho: repositório Git,
    /// configuração de IDE ou arquivos de projeto.
    /// </summary>
    private static bool LooksLikeWorkspace(string directoryPath)
    {
        try
        {
            if (HasWorkspaceMarkers(directoryPath))
            {
                return true;
            }

            int inspected = 0;
            foreach (string subdirectory in Directory.EnumerateDirectories(directoryPath))
            {
                if (HasWorkspaceMarkers(subdirectory))
                {
                    return true;
                }

                if (++inspected >= 40)
                {
                    break;
                }
            }
        }
        catch
        {
            // Pasta inacessível: sem evidência
        }

        return false;
    }

    private static bool HasWorkspaceMarkers(string directoryPath)
    {
        foreach (string markerDirectory in WorkspaceMarkerDirectories)
        {
            string candidate = Path.Combine(directoryPath, markerDirectory);
            if (Directory.Exists(candidate) || File.Exists(candidate))
            {
                return true;
            }
        }

        foreach (string markerFile in WorkspaceMarkerFiles)
        {
            if (File.Exists(Path.Combine(directoryPath, markerFile)))
            {
                return true;
            }
        }

        try
        {
            foreach (string file in Directory.EnumerateFiles(directoryPath))
            {
                if (file.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) ||
                    file.EndsWith(".slnx", StringComparison.OrdinalIgnoreCase) ||
                    file.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Ignora erro de leitura
        }

        return false;
    }

    /// <summary>
    /// Verifica se o diretório possui a assinatura estrutural típica de um aplicativo Electron / Chromium
    /// (presença de pelo menos 2 marcadores como GPUCache, Code Cache, Local Storage, Session Storage).
    /// </summary>
    public static bool IsElectronAppRootDirectory(string directoryPath)
    {
        if (string.IsNullOrWhiteSpace(directoryPath))
        {
            return false;
        }

        string key = TrimSeparators(directoryPath);
        if (ElectronRootByPath.TryGetValue(key, out bool known))
        {
            return known;
        }

        bool detected = false;
        try
        {
            if (Directory.Exists(key))
            {
                // Uma única listagem da pasta em vez de uma consulta ao disco por marcador
                int hits = 0;
                foreach (string subdirectory in Directory.EnumerateDirectories(key))
                {
                    if (ElectronStructuralMarkers.Contains(Path.GetFileName(subdirectory)) && ++hits >= 2)
                    {
                        detected = true;
                        break;
                    }
                }
            }
        }
        catch
        {
            // Ignora diretórios inacessíveis
        }

        if (ElectronRootByPath.Count > StructureCacheLimit)
        {
            ElectronRootByPath.Clear();
        }

        ElectronRootByPath[key] = detected;
        return detected;
    }

    private static bool IsParentElectronAppDirectory(string childPath, out string parentAppName)
    {
        parentAppName = string.Empty;
        try
        {
            string? parentDir = Path.GetDirectoryName(childPath);
            if (!string.IsNullOrWhiteSpace(parentDir) && IsElectronAppRootDirectory(parentDir))
            {
                parentAppName = Path.GetFileName(parentDir);
                return true;
            }
        }
        catch
        {
            // Ignora erros de caminho
        }

        return false;
    }

    private static int CountElectronMarkers(IReadOnlyList<string> subdirectoryNames)
    {
        int hits = 0;
        for (int i = 0; i < subdirectoryNames.Count; i++)
        {
            if (ElectronStructuralMarkers.Contains(subdirectoryNames[i]))
            {
                hits++;
            }
        }

        return hits;
    }

    public static string IdentifyAppDataOwner(string fullPath, out string publisher)
    {
        AppSignature? signature = string.IsNullOrWhiteSpace(fullPath) ? null : MatchSignature(TrimSeparators(fullPath));
        publisher = signature?.Publisher ?? string.Empty;
        return signature?.AppName ?? UnknownApp;
    }

    private static AppSignature? MatchSignature(string path)
    {
        foreach (AppSignature signature in AppDataSignatures)
        {
            if (signature.PrefixOfSegment
                    ? path.Contains(signature.Pattern, StringComparison.OrdinalIgnoreCase)
                    : TryFindMarkerRoot(path, signature.Pattern, out _))
            {
                return signature;
            }
        }

        foreach (AppDataRuleDefinition rule in AppDataRulesCatalog.GetRules())
        {
            if (rule.PrefixOfSegment
                    ? path.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase)
                    : TryFindMarkerRoot(path, rule.Pattern, out _))
            {
                return new AppSignature(rule.Pattern, rule.AppName, rule.Publisher, rule.TrustCacheFolderNames, rule.PrefixOfSegment);
            }
        }

        return null;
    }

    /// <summary>
    /// Procura o marcador como sequência de segmentos completos do caminho e devolve o caminho até o fim dele.
    /// "\Code" casa com "...\Code" e "...\Code\User", mas não com "...\Code Cache".
    /// </summary>
    private static bool TryFindMarkerRoot(string path, string marker, out string rootPath)
    {
        int index = path.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        while (index >= 0)
        {
            int end = index + marker.Length;
            if (end == path.Length || path[end] == '\\' || path[end] == '/')
            {
                rootPath = path[..end];
                return true;
            }

            index = path.IndexOf(marker, index + 1, StringComparison.OrdinalIgnoreCase);
        }

        rootPath = string.Empty;
        return false;
    }

    private static bool HasDotNetProjectFile(string directoryPath)
    {
        try
        {
            foreach (string file in Directory.EnumerateFiles(directoryPath))
            {
                if (file.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) ||
                    file.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase) ||
                    file.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Ignora erro de leitura
        }

        return false;
    }

    private bool IsOwnApplicationPath(string path)
    {
        foreach (string own in _ownApplicationPaths)
        {
            if (IsSameOrUnder(own, path) || IsUnder(path, own))
            {
                return true;
            }
        }

        return false;
    }

    private static string[] DiscoverOwnApplicationPaths()
    {
        HashSet<string> own = new(StringComparer.OrdinalIgnoreCase);

        void Add(string? candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                return;
            }

            string normalized = SystemPathProtector.NormalizeForComparison(candidate);

            // Nunca registra a raiz de uma unidade: isso protegeria o disco inteiro por engano
            if (normalized.Length > 3)
            {
                own.Add(normalized);
            }
        }

        try
        {
            // Em executável de arquivo único, BaseDirectory é a pasta de extração dentro de %TEMP%\.net
            Add(AppContext.BaseDirectory);
            Add(Path.GetDirectoryName(Environment.ProcessPath));
        }
        catch
        {
            // Sem informação do processo: nenhuma proteção adicional
        }

        return [.. own];
    }

    private NormalizedEnvironment GetNormalized(EnvironmentPaths env)
    {
        NormalizedEnvironment? current = _normalized;
        if (current is not null && ReferenceEquals(_normalizedSource, env))
        {
            return current;
        }

        NormalizedEnvironment computed = new(
            Profile: NormalizeOrEmpty(env.UserProfileDir),
            LocalAppData: NormalizeOrEmpty(env.LocalAppDataDir),
            RoamingAppData: NormalizeOrEmpty(env.RoamingAppDataDir),
            LocalLowAppData: NormalizeOrEmpty(env.LocalLowAppDataDir),
            Temp: NormalizeOrEmpty(env.UserTempDir),
            Downloads: NormalizeOrEmpty(env.DownloadsDir),
            Documents: NormalizeOrEmpty(env.DocumentsDir),
            Desktop: NormalizeOrEmpty(env.DesktopDir));

        _normalized = computed;
        _normalizedSource = env;
        return computed;
    }

    private static string NormalizeOrEmpty(string? path) =>
        string.IsNullOrWhiteSpace(path) ? string.Empty : SystemPathProtector.NormalizeForComparison(path);

    private static string TrimSeparators(string path) =>
        path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    /// <summary>Verdadeiro quando path está estritamente dentro de basePath (ambos já normalizados).</summary>
    private static bool IsUnder(string path, string basePath)
    {
        return basePath.Length > 0 &&
               path.Length > basePath.Length &&
               (path[basePath.Length] == '\\' || path[basePath.Length] == '/') &&
               path.StartsWith(basePath, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSameOrUnder(string path, string basePath)
    {
        return basePath.Length > 0 &&
               (string.Equals(path, basePath, StringComparison.OrdinalIgnoreCase) || IsUnder(path, basePath));
    }

    private static bool IsDirectChild(string path, string basePath)
    {
        return IsUnder(path, basePath) && path.IndexOf('\\', basePath.Length + 1) < 0;
    }

    private static string FirstSegmentUnder(string path, string basePath)
    {
        int start = basePath.Length + 1;
        int end = path.IndexOf('\\', start);
        return end < 0 ? path[start..] : path[start..end];
    }

    private static string FirstLevelUnder(string path, string basePath)
    {
        int end = path.IndexOf('\\', basePath.Length + 1);
        return end < 0 ? path : path[..end];
    }

    private sealed record NormalizedEnvironment(
        string Profile,
        string LocalAppData,
        string RoamingAppData,
        string LocalLowAppData,
        string Temp,
        string Downloads,
        string Documents,
        string Desktop);

    private sealed record DevCacheRule(
        string Marker,
        string Tool,
        string Purpose,
        string Consequences,
        RecommendedAction Action,
        string Details,
        string? Command);

    private sealed record AppSignature(
        string Pattern,
        string AppName,
        string Publisher,
        bool TrustCacheFolderNames = true,
        bool PrefixOfSegment = false);
}
