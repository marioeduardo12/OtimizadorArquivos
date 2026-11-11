using DiskInspector.Core.Enums;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Analysis;

/// <summary>
/// Analisador especializado em ambientes de programação, caches de pacotes, diretórios de build,
/// IDEs, Docker Desktop e WSL2 (Seção 7).
/// </summary>
public sealed class DeveloperEnvironmentAnalyzer
{
    private readonly IEnvironmentProvider _environmentProvider;
    private readonly IStorageClassifier _classifier;

    public DeveloperEnvironmentAnalyzer(IEnvironmentProvider environmentProvider, IStorageClassifier classifier)
    {
        _environmentProvider = environmentProvider;
        _classifier = classifier;
    }

    public IReadOnlyList<DeveloperArtifactItem> Analyze(
        StorageItem rootNode,
        IReadOnlyList<StorageItem> discoveredDevNodes)
    {
        EnvironmentPaths env = _environmentProvider.GetEnvironmentPaths();
        Dictionary<string, DeveloperArtifactItem> itemsByPath = new(StringComparer.OrdinalIgnoreCase);

        // 1. Verificar locais globais conhecidos caso façam parte da árvore escaneada
        (string Path, string Ecosystem, string Kind, bool IsGlobalCache, bool IsPersistentVm, string Purpose, string Impact, string ActionText, string? Cli)[] globalCandidates =
        [
            (
                Path.Combine(env.LocalAppDataDir, "npm-cache"),
                "Node.js / npm",
                "Cache Global npm",
                true,
                false,
                "Cache de tarballs HTTP e pacotes baixados pelo npm.",
                "Remover exigirá novos downloads da internet nos próximos 'npm install'.",
                "Limpar via comando oficial 'npm cache clean --force' ou enviar para a Lixeira.",
                "npm cache clean --force"
            ),
            (
                Path.Combine(env.LocalAppDataDir, "pnpm", "store"),
                "Node.js / pnpm",
                "Content-Addressable Store (pnpm)",
                true,
                false,
                "Armazenamento endereçado por conteúdo do pnpm (utiliza hard links para node_modules).",
                "Pacotes não referenciados podem ser podados com 'pnpm store prune'; apagar tudo exige novo download.",
                "Execute 'pnpm store prune' para remover apenas pacotes órfãos.",
                "pnpm store prune"
            ),
            (
                Path.Combine(env.LocalAppDataDir, "Yarn", "Cache"),
                "Node.js / Yarn",
                "Cache Global Yarn",
                true,
                false,
                "Cache global de pacotes baixados pelo gerenciador Yarn.",
                "Remover exigirá novo download de dependências em futuros projetos Yarn.",
                "Execute 'yarn cache clean' ou envie para a Lixeira.",
                "yarn cache clean"
            ),
            (
                Path.Combine(env.LocalAppDataDir, "pip", "cache"),
                "Python / pip",
                "Cache Global pip",
                true,
                false,
                "Cache de pacotes wheels (.whl) e código-fonte baixados pelo pip.",
                "Ambientes virtuais existentes continuam funcionando; novos 'pip install' farão download novamente.",
                "Execute 'pip cache purge' ou envie para a Lixeira.",
                "pip cache purge"
            ),
            (
                Path.Combine(env.LocalAppDataDir, "Composer"),
                "PHP / Composer",
                "Cache Global Composer",
                true,
                false,
                "Cache de pacotes PHP baixados pelo Composer.",
                "Futuros 'composer install' precisarão baixar pacotes novamente.",
                "Execute 'composer clear-cache'.",
                "composer clear-cache"
            ),
            (
                Path.Combine(env.UserProfileDir, ".nuget", "packages"),
                ".NET / NuGet",
                "Cache Global de Pacotes NuGet",
                true,
                false,
                "Repositório global de pacotes NuGet utilizados pelas soluções .NET/C# na máquina.",
                "Compilações futuras ('dotnet build' / Visual Studio) precisarão restaurar/baixar pacotes novamente.",
                "Utilize 'dotnet nuget locals all --clear' apenas se precisar recuperar espaço significativo.",
                "dotnet nuget locals all --clear"
            ),
            (
                Path.Combine(env.LocalAppDataDir, "NuGet", "v3-cache"),
                ".NET / NuGet",
                "Cache HTTP NuGet v3",
                true,
                false,
                "Cache de respostas HTTP da API NuGet v3.",
                "Nenhum impacto em projetos compilados; apenas novas consultas HTTP ao nuget.org.",
                "Limpar com 'dotnet nuget locals http-cache --clear' ou via Lixeira.",
                "dotnet nuget locals http-cache --clear"
            ),
            (
                Path.Combine(env.UserProfileDir, ".gradle", "caches"),
                "Java / Kotlin / Gradle",
                "Cache Global Gradle",
                true,
                false,
                "Cache de dependências JAR e artefatos de build incremental do Gradle.",
                "Próximo build Gradle/Android Studio fará download de dependências e recompilação completa.",
                "Feche IDEs Java/Android antes de limpar.",
                "gradle --stop"
            ),
            (
                Path.Combine(env.UserProfileDir, ".m2", "repository"),
                "Java / Maven",
                "Repositório Local Maven (.m2)",
                true,
                false,
                "Repositório local de dependências JAR baixadas pelo Apache Maven.",
                "Exigirá novo download de artefatos em builds Maven futuros.",
                "Limpar apenas se houver versões antigas acumuladas.",
                "mvn dependency:purge-local-repository"
            ),
            (
                Path.Combine(env.UserProfileDir, ".cargo", "registry"),
                "Rust / Cargo",
                "Cache de Crates Cargo",
                true,
                false,
                "Índice e arquivos .crate baixados pelo gerenciador Cargo do Rust.",
                "Próximas compilações 'cargo build' precisarão baixar as crates novamente.",
                "Revisar manualmente ou usar utilitário cargo-cache.",
                "cargo cache -a"
            ),
            (
                Path.Combine(env.RoamingAppDataDir, "Code", "Cache"),
                "IDE / Visual Studio Code",
                "Cache do VS Code",
                true,
                false,
                "Cache técnico de renderização do Visual Studio Code.",
                "Seguro remover com o VS Code fechado; não apaga configurações nem extensões.",
                "Limpar com o VS Code fechado.",
                null
            ),
            (
                Path.Combine(env.RoamingAppDataDir, "Code", "CachedData"),
                "IDE / Visual Studio Code",
                "CachedData V8 do VS Code",
                true,
                false,
                "Bytecode JavaScript pré-compilado de versões do VS Code.",
                "Recriado automaticamente na abertura do VS Code.",
                "Seguro enviar para a Lixeira com o VS Code fechado.",
                null
            ),
            (
                Path.Combine(env.LocalAppDataDir, "JetBrains"),
                "IDE / JetBrains",
                "Caches e Índices de IDEs JetBrains",
                true,
                false,
                "Índices de código, caches de análise estática e logs das IDEs JetBrains (Rider, IntelliJ, PyCharm).",
                "Exige reindexação dos projetos na próxima abertura da IDE.",
                "Use 'File > Invalidate Caches' na IDE ou remova pastas de versões antigas.",
                null
            ),
            (
                Path.Combine(env.LocalAppDataDir, "Docker", "wsl"),
                "Docker Desktop / WSL2",
                "Discos Virtuais e Volumes Docker (VHDX)",
                false,
                true,
                "Contém os discos virtuais (.vhdx) do Docker Desktop no WSL2, onde ficam imagens, containers, build cache e VOLUMES PERSISTENTES.",
                "ALTO RISCO: Excluir os arquivos .vhdx diretamente apaga TODOS os volumes de bancos de dados e containers!",
                "NUNCA exclua arquivos .vhdx diretamente. Use os comandos oficiais do Docker para remover apenas cache/imagens não utilizadas.",
                "docker system df  |  docker builder prune  |  docker image prune -a"
            )
        ];

        foreach (var candidate in globalCandidates)
        {
            StorageItem? found = AppDataAnalyzer.FindNodeByPath(rootNode, candidate.Path);
            if (found is not null && found.LogicalSizeBytes > 0)
            {
                _classifier.ClassifyItem(found);
                if (candidate.IsPersistentVm)
                {
                    found.RiskClassification = RiskLevel.Red;
                    found.Recommendation = RecommendedAction.UseOfficialDeveloperCommand;
                }

                itemsByPath[found.FullPath] = new DeveloperArtifactItem
                {
                    Ecosystem = candidate.Ecosystem,
                    ArtifactKind = candidate.Kind,
                    Name = found.Name,
                    FullPath = found.FullPath,
                    LogicalSizeBytes = found.LogicalSizeBytes,
                    AllocatedSizeBytes = found.AllocatedSizeBytes,
                    FileCount = found.FileCount,
                    LastModifiedUtc = found.LastModifiedUtc,
                    IsGlobalCache = candidate.IsGlobalCache,
                    IsProjectBuildOutput = false,
                    IsPersistentVolumeOrVirtualDisk = candidate.IsPersistentVm,
                    RiskClassification = found.RiskClassification,
                    PurposeExplanation = candidate.Purpose,
                    RebuildOrRedownloadImpact = candidate.Impact,
                    RecommendedActionText = candidate.ActionText,
                    OfficialCliCommand = candidate.Cli,
                    UnderlyingItem = found
                };
            }
        }

        // 2. Inspecionar Docker CLI e discos virtuais WSL2 (.vhdx) via DockerAndWslInspector
        DockerAndWslInspector dockerInspector = new(_environmentProvider);
        foreach (DeveloperArtifactItem dockerOrWslItem in dockerInspector.InspectDockerAndWsl(discoveredDevNodes))
        {
            itemsByPath.TryAdd(dockerOrWslItem.FullPath, dockerOrWslItem);
        }

        // 3. Adicionar diretórios de projetos e discos virtuais descobertos durante a varredura (node_modules, target, bin/obj, .gradle, .vhdx)
        foreach (StorageItem devNode in discoveredDevNodes)
        {
            if (itemsByPath.ContainsKey(devNode.FullPath) || devNode.LogicalSizeBytes <= 0)
            {
                continue;
            }

            _classifier.ClassifyItem(devNode);
            DeveloperArtifactItem mapped = MapDiscoveredNode(devNode);
            itemsByPath[devNode.FullPath] = mapped;
        }

        return itemsByPath.Values
            .OrderByDescending(i => i.LogicalSizeBytes)
            .ToList();
    }

    private static DeveloperArtifactItem MapDiscoveredNode(StorageItem node)
    {
        string name = node.Name;
        string path = node.FullPath;

        if (path.EndsWith(".vhdx", StringComparison.OrdinalIgnoreCase))
        {
            bool isDocker = path.Contains("Docker", StringComparison.OrdinalIgnoreCase);
            return new DeveloperArtifactItem
            {
                Ecosystem = isDocker ? "Docker Desktop / WSL2" : "WSL2 / Hyper-V Virtual Disk",
                ArtifactKind = "Disco Virtual Persistente (.vhdx)",
                Name = name,
                FullPath = path,
                LogicalSizeBytes = node.LogicalSizeBytes,
                AllocatedSizeBytes = node.AllocatedSizeBytes,
                FileCount = 1,
                LastModifiedUtc = node.LastModifiedUtc,
                IsGlobalCache = false,
                IsProjectBuildOutput = false,
                IsPersistentVolumeOrVirtualDisk = true,
                RiskClassification = RiskLevel.Red,
                PurposeExplanation = isDocker
                    ? "Imagem de disco virtual ext4.vhdx do Docker Desktop contendo camadas de imagens, build cache, containers e volumes persistentes."
                    : "Disco virtual ext4.vhdx de uma distribuição Linux WSL2 ou máquina virtual contendo todo o sistema de arquivos Linux.",
                RebuildOrRedownloadImpact = "NÃO EXCLUIR: Apagar este arquivo destrói todos os dados persistentes, volumes e arquivos dentro do ambiente Linux/Docker!",
                RecommendedActionText = isDocker
                    ? "Para reduzir o tamanho sem perder volumes, execute 'docker builder prune' e 'docker system prune' (sem --volumes) e depois compacte o VHDX com 'wsl --shutdown'."
                    : "Para recuperar espaço não alocado dentro do WSL2 sem perder arquivos, desligue o WSL ('wsl --shutdown') e utilize a compactação oficial de VHD.",
                OfficialCliCommand = isDocker
                    ? "docker system df  |  docker builder prune"
                    : "wsl --list --verbose  |  wsl --shutdown",
                UnderlyingItem = node
            };
        }

        if (string.Equals(name, "node_modules", StringComparison.OrdinalIgnoreCase))
        {
            return new DeveloperArtifactItem
            {
                Ecosystem = "Node.js / JavaScript / TypeScript",
                ArtifactKind = "Dependências de Projeto (node_modules)",
                Name = name,
                FullPath = path,
                LogicalSizeBytes = node.LogicalSizeBytes,
                AllocatedSizeBytes = node.AllocatedSizeBytes,
                FileCount = node.FileCount,
                LastModifiedUtc = node.LastModifiedUtc,
                IsGlobalCache = false,
                IsProjectBuildOutput = true,
                IsPersistentVolumeOrVirtualDisk = false,
                RiskClassification = node.RiskClassification,
                PurposeExplanation = "Pacotes npm/pnpm/yarn instalados localmente para este projeto.",
                RebuildOrRedownloadImpact = "Exigirá executar 'npm install' (ou pnpm/yarn install) antes de rodar ou compilar o projeto novamente.",
                RecommendedActionText = "Seguro enviar para a Lixeira em projetos antigos ou inativos.",
                OfficialCliCommand = "npm install (para recriar quando necessário)",
                UnderlyingItem = node
            };
        }

        if (string.Equals(name, "target", StringComparison.OrdinalIgnoreCase))
        {
            return new DeveloperArtifactItem
            {
                Ecosystem = "Rust / Cargo",
                ArtifactKind = "Artefatos de Build Rust (target)",
                Name = name,
                FullPath = path,
                LogicalSizeBytes = node.LogicalSizeBytes,
                AllocatedSizeBytes = node.AllocatedSizeBytes,
                FileCount = node.FileCount,
                LastModifiedUtc = node.LastModifiedUtc,
                IsGlobalCache = false,
                IsProjectBuildOutput = true,
                IsPersistentVolumeOrVirtualDisk = false,
                RiskClassification = node.RiskClassification,
                PurposeExplanation = "Binários compilados e cache incremental de crates do compilador Rust (rustc/Cargo).",
                RebuildOrRedownloadImpact = "A próxima execução de 'cargo build' recompilará todas as dependências do zero.",
                RecommendedActionText = "Execute 'cargo clean' ou envie para a Lixeira se o projeto estiver inativo.",
                OfficialCliCommand = "cargo clean",
                UnderlyingItem = node
            };
        }

        if (string.Equals(name, "bin", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(name, "obj", StringComparison.OrdinalIgnoreCase))
        {
            return new DeveloperArtifactItem
            {
                Ecosystem = ".NET / C# / MSBuild",
                ArtifactKind = $"Saída de Compilação .NET ({name})",
                Name = name,
                FullPath = path,
                LogicalSizeBytes = node.LogicalSizeBytes,
                AllocatedSizeBytes = node.AllocatedSizeBytes,
                FileCount = node.FileCount,
                LastModifiedUtc = node.LastModifiedUtc,
                IsGlobalCache = false,
                IsProjectBuildOutput = true,
                IsPersistentVolumeOrVirtualDisk = false,
                RiskClassification = node.RiskClassification,
                PurposeExplanation = $"Arquivos intermediários e binários compilados pelo SDK do .NET na pasta '{name}'.",
                RebuildOrRedownloadImpact = "Exigirá recompilação ('dotnet build') na próxima vez que a solução for utilizada.",
                RecommendedActionText = "Use 'dotnet clean' ou envie para a Lixeira com a IDE fechada.",
                OfficialCliCommand = "dotnet clean",
                UnderlyingItem = node
            };
        }

        return new DeveloperArtifactItem
        {
            Ecosystem = node.AssociatedAppOrComponent,
            ArtifactKind = "Ambiente / Cache de Desenvolvimento",
            Name = name,
            FullPath = path,
            LogicalSizeBytes = node.LogicalSizeBytes,
            AllocatedSizeBytes = node.AllocatedSizeBytes,
            FileCount = node.FileCount,
            LastModifiedUtc = node.LastModifiedUtc,
            IsGlobalCache = node.Category == ItemCategory.DeveloperCache,
            IsProjectBuildOutput = node.Category == ItemCategory.DeveloperBuildArtifact,
            IsPersistentVolumeOrVirtualDisk = node.RiskClassification == RiskLevel.Red,
            RiskClassification = node.RiskClassification,
            PurposeExplanation = node.PurposeExplanation,
            RebuildOrRedownloadImpact = node.DeletionConsequences,
            RecommendedActionText = node.RecommendationDetails,
            OfficialCliCommand = node.OfficialMaintenanceCommand,
            UnderlyingItem = node
        };
    }

    private static readonly HashSet<string>ArtifactFolderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "node_modules", "bin", "obj", "target", "build", ".gradle", ".venv", "venv"
    };

    /// <summary>
    /// Agrupa artefatos de build e dependências por projeto do usuário e calcula a data da última atividade
    /// para destacar projetos parados há mais de 90 dias (Diferencial 5).
    /// </summary>
    public static IReadOnlyList<ProjectActivitySummary> AggregateProjects(
        IReadOnlyList<DeveloperArtifactItem> artifacts,
        Func<DateTime>? utcNowProvider = null)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        DateTime now = (utcNowProvider ?? (static () => DateTime.UtcNow))();

        Dictionary<string, List<DeveloperArtifactItem>> byProjectRoot = new(StringComparer.OrdinalIgnoreCase);

        foreach (DeveloperArtifactItem item in artifacts)
        {
            if (item.IsGlobalCache || item.IsPersistentVolumeOrVirtualDisk || string.IsNullOrWhiteSpace(item.FullPath))
            {
                continue;
            }

            if (!item.IsProjectBuildOutput && !ArtifactFolderNames.Contains(item.Name))
            {
                continue;
            }

            string? projectDir = Path.GetDirectoryName(item.FullPath.TrimEnd('\\', '/'));
            if (string.IsNullOrWhiteSpace(projectDir))
            {
                continue;
            }

            if (!byProjectRoot.TryGetValue(projectDir, out List<DeveloperArtifactItem>? list))
            {
                list = [];
                byProjectRoot[projectDir] = list;
            }

            list.Add(item);
        }

        List<ProjectActivitySummary> projects = [];

        foreach ((string projectDir, List<DeveloperArtifactItem> projArtifacts) in byProjectRoot)
        {
            DateTime latestSourceWrite = DetectLatestProjectSourceActivityUtc(projectDir, projArtifacts);
            int inactiveDays = latestSourceWrite == DateTime.MinValue
                ? 0
                : (int)Math.Max(0, Math.Floor((now - latestSourceWrite).TotalDays));

            long totalBytes = projArtifacts.Sum(a => a.LogicalSizeBytes);
            long reclaimableBytes = projArtifacts
                .Where(a => a.RiskClassification == RiskLevel.Yellow || (a.UnderlyingItem?.CanSelectForCleanup ?? false))
                .Sum(a => a.LogicalSizeBytes);

            string ecosystems = string.Join(" + ", projArtifacts
                .Select(a => a.Ecosystem.Split('/')[0].Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase));

            projects.Add(new ProjectActivitySummary
            {
                ProjectName = Path.GetFileName(projectDir),
                ProjectRootPath = projectDir,
                EcosystemsSummary = string.IsNullOrWhiteSpace(ecosystems) ? "Desenvolvimento" : ecosystems,
                LastSourceActivityUtc = latestSourceWrite,
                InactiveDays = inactiveDays,
                IsDormantOver90Days = inactiveDays >= 90,
                TotalArtifactBytes = totalBytes,
                ReclaimableArtifactBytes = reclaimableBytes,
                Artifacts = projArtifacts.OrderByDescending(a => a.LogicalSizeBytes).ToList()
            });
        }

        return projects
            .OrderByDescending(p => p.IsDormantOver90Days)
            .ThenByDescending(p => p.TotalArtifactBytes)
            .ToList();
    }

    private static DateTime DetectLatestProjectSourceActivityUtc(
        string projectDir,
        List<DeveloperArtifactItem> projArtifacts)
    {
        DateTime latest = DateTime.MinValue;

        try
        {
            if (Directory.Exists(projectDir))
            {
                foreach (FileInfo fi in new DirectoryInfo(projectDir).EnumerateFiles())
                {
                    if (fi.LastWriteTimeUtc > latest)
                    {
                        latest = fi.LastWriteTimeUtc;
                    }
                }

                // Inspeciona subpastas diretas de código-fonte (ex.: src, app, lib, pages, components), ignorando pastas de build/git
                foreach (DirectoryInfo sub in new DirectoryInfo(projectDir).EnumerateDirectories())
                {
                    if (ArtifactFolderNames.Contains(sub.Name) ||
                        sub.Name.StartsWith('.'))
                    {
                        continue;
                    }

                    if (sub.LastWriteTimeUtc > latest)
                    {
                        latest = sub.LastWriteTimeUtc;
                    }

                    int sampled = 0;
                    foreach (FileInfo subFile in sub.EnumerateFiles("*", SearchOption.AllDirectories))
                    {
                        if (subFile.LastWriteTimeUtc > latest)
                        {
                            latest = subFile.LastWriteTimeUtc;
                        }

                        if (++sampled >= 60)
                        {
                            break;
                        }
                    }
                }
            }
        }
        catch
        {
            // Se não for possível ler arquivos do projeto, usa a data dos próprios artefatos
        }

        if (latest == DateTime.MinValue)
        {
            foreach (DeveloperArtifactItem a in projArtifacts)
            {
                DateTime candidate = a.UnderlyingItem?.EffectiveLatestWriteUtc ?? a.LastModifiedUtc;
                if (candidate > latest)
                {
                    latest = candidate;
                }
            }
        }

        return latest;
    }
}

