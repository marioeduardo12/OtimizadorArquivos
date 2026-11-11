using System.Diagnostics;
using DiskInspector.Analysis;
using DiskInspector.Cleanup;
using DiskInspector.Core.Enums;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;
using DiskInspector.Infrastructure;
using Xunit;

namespace DiskInspector.Tests;

/// <summary>
/// Ambiente isolado compartilhado pelos testes desta etapa: um "perfil de usuário" simulado dentro de uma
/// pasta temporária exclusiva, sem tocar em arquivos reais.
/// </summary>
internal sealed class IsolatedProfile : IDisposable
{
    public IsolatedProfile(DateTime? sessionStartUtc = null)
    {
        Root = Path.Combine(Path.GetTempPath(), "DiskInspectorTrust_" + Guid.NewGuid().ToString("N"));
        Profile = Path.Combine(Root, "Users", "Ana");
        string local = Path.Combine(Profile, "AppData", "Local");

        foreach (string dir in new[]
                 {
                     local,
                     Path.Combine(Profile, "AppData", "Roaming"),
                     Path.Combine(Profile, "AppData", "LocalLow"),
                     Path.Combine(local, "Temp"),
                     Path.Combine(Profile, "Downloads"),
                     Path.Combine(Profile, "Documents"),
                     Path.Combine(Profile, "Desktop")
                 })
        {
            Directory.CreateDirectory(dir);
        }

        Env = new EnvironmentPaths
        {
            WindowsDir = @"C:\Windows",
            System32Dir = @"C:\Windows\System32",
            SysWow64Dir = @"C:\Windows\SysWOW64",
            WinSxSDir = @"C:\Windows\WinSxS",
            ProgramFilesDir = @"C:\Program Files",
            ProgramFilesX86Dir = @"C:\Program Files (x86)",
            ProgramDataDir = @"C:\ProgramData",
            UserProfileDir = Profile,
            LocalAppDataDir = local,
            RoamingAppDataDir = Path.Combine(Profile, "AppData", "Roaming"),
            LocalLowAppDataDir = Path.Combine(Profile, "AppData", "LocalLow"),
            UserTempDir = Path.Combine(local, "Temp"),
            SystemTempDir = @"C:\Windows\Temp",
            DownloadsDir = Path.Combine(Profile, "Downloads"),
            DocumentsDir = Path.Combine(Profile, "Documents"),
            DesktopDir = Path.Combine(Profile, "Desktop"),
            IsElevatedAdmin = false,
            MachineName = "TESTE",
            CurrentUserName = "Ana",
            OsVersionDescription = "Windows 11 (simulado)",
            UserSessionStartUtc = sessionStartUtc
        };

        Provider = new WindowsEnvironmentProvider(Env);
        Protector = new SystemPathProtector(Provider);
        Classifier = new StorageClassifier(Provider, Protector);
        LockDetector = new FileLockDetector();
        History = new OperationHistoryRepository(Provider, Path.Combine(Root, "historico", "historico.json"));
    }

    public string Root { get; }
    public string Profile { get; }
    public EnvironmentPaths Env { get; }
    public IEnvironmentProvider Provider { get; }
    public ISystemPathProtector Protector { get; }
    public StorageClassifier Classifier { get; }
    public IFileLockDetector LockDetector { get; }
    public OperationHistoryRepository History { get; }

    public string Temp => Env.UserTempDir;

    /// <summary>Cria um arquivo com o tamanho e a idade pedidos.</summary>
    public string WriteFile(string path, int bytes, double daysOld = 10)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, new byte[bytes]);
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddDays(-daysOld));
        return path;
    }

    /// <summary>Monta um item como o motor de varredura faria, lendo tamanho e datas reais do disco.</summary>
    public StorageItem ItemFromDisk(string path)
    {
        bool isDirectory = Directory.Exists(path);
        long size = 0;
        long files = 0;
        long directories = 0;
        DateTime latest = DateTime.MinValue;

        if (isDirectory)
        {
            foreach (FileSystemInfo entry in new DirectoryInfo(path).EnumerateFileSystemInfos("*", SearchOption.AllDirectories))
            {
                if (entry is FileInfo file)
                {
                    size += file.Length;
                    files++;
                }
                else
                {
                    directories++;
                }

                if (entry.LastWriteTimeUtc > latest)
                {
                    latest = entry.LastWriteTimeUtc;
                }
            }
        }
        else
        {
            FileInfo file = new(path);
            size = file.Length;
            latest = file.LastWriteTimeUtc;
        }

        return new StorageItem
        {
            Name = Path.GetFileName(path),
            FullPath = path,
            LogicalSizeBytes = size,
            AllocatedSizeBytes = size,
            FileCount = files,
            DirectoryCount = directories,
            LastModifiedUtc = isDirectory ? Directory.GetLastWriteTimeUtc(path) : File.GetLastWriteTimeUtc(path),
            LatestContentWriteUtc = latest,
            IsDirectory = isDirectory
        };
    }

    public StorageItem Classify(string path)
    {
        StorageItem item = ItemFromDisk(path);
        Classifier.ClassifyItem(item);
        return item;
    }

    public DiskScannerService CreateScanner() => new(Provider, Protector, Classifier, History);

    public DriveMetadata FakeDrive() => new()
    {
        Name = "X:",
        RootDirectory = Root,
        VolumeLabel = "Teste",
        FileSystem = "NTFS",
        DriveTypeDescription = "Disco Fixo Local",
        TotalBytes = 500_000_000_000,
        AvailableFreeBytes = 250_000_000_000,
        IsSystemDrive = false,
        IsReady = true
    };

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(Root))
            {
                foreach (string file in Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                }

                Directory.Delete(Root, recursive: true);
            }
        }
        catch
        {
            // Ignora falha de limpeza de pasta temporária de teste
        }
    }
}

/// <summary>Lixeira simulada: registra o que foi enviado e permite configurar capacidade e falhas.</summary>
internal sealed class FakeRecycleBin : IRecycleBin
{
    public RecycleBinStatus Status { get; set; } = new()
    {
        IsAvailable = true,
        CapacityBytes = 10L * 1024 * 1024 * 1024,
        UsedBytes = 0,
        ItemCount = 0
    };

    public Func<string, RecycleAttemptResult>? OnSend { get; set; }
    public List<string> Sent { get; } = [];

    public RecycleBinStatus GetStatus(string anyPathOnVolume) => Status;

    public RecycleAttemptResult SendToRecycleBin(string fullPath)
    {
        Sent.Add(fullPath);
        if (OnSend is not null)
        {
            return OnSend(fullPath);
        }

        if (Directory.Exists(fullPath))
        {
            Directory.Delete(fullPath, recursive: true);
        }
        else
        {
            File.Delete(fullPath);
        }

        return new RecycleAttemptResult { Succeeded = true, ConfirmedRecycled = true, Message = "Movido para a Lixeira (simulada)." };
    }

    public bool Empty(string? driveRoot, IntPtr ownerWindow) => true;
}

/// <summary>
/// Teste que envia um arquivo para a Lixeira REAL do Windows. Fica desligado por padrão para a suíte
/// não deixar rastros fora da pasta temporária; ligue com DISKINSPECTOR_TESTAR_LIXEIRA=1.
/// </summary>
public sealed class RealRecycleBinFactAttribute : FactAttribute
{
    public RealRecycleBinFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("DISKINSPECTOR_TESTAR_LIXEIRA") != "1")
        {
            Skip = "Envia um arquivo de teste para a Lixeira real. Defina DISKINSPECTOR_TESTAR_LIXEIRA=1 para executar.";
        }
    }
}

public sealed class ClassificationTrustTests : IDisposable
{
    private readonly IsolatedProfile _p = new();

    public void Dispose() => _p.Dispose();

    [Fact]
    public void Percentages_AreFormattedWithOneDecimal_NotWithALiteralDigit()
    {
        StorageDistributionSlice slice = new()
        {
            Label = "Teste",
            ColorHex = "#000000",
            Bytes = 100,
            PercentageOfScanned = 12.34,
            ItemCount = 1
        };

        // O formato antigo "0.1" produzia "121%" para 12,34
        Assert.Equal($"{12.3:0.0}%", slice.FormattedPercentage);
        Assert.NotEqual("121%", slice.FormattedPercentage);
    }

    [Fact]
    public void NodeModules_OfAnInstalledExtension_IsNeverOfferedForCleanup()
    {
        // Extensão de IDE instalada em uma pasta de ferramenta na raiz do perfil, com package.json e até lockfile
        string extension = Path.Combine(_p.Profile, ".antigravity-ide", "extensions", "fabricante.extensao-1.0.0");
        _p.WriteFile(Path.Combine(extension, "package.json"), 200);
        _p.WriteFile(Path.Combine(extension, "package-lock.json"), 200);
        string nodeModules = Path.Combine(extension, "node_modules");
        _p.WriteFile(Path.Combine(nodeModules, "dep", "index.js"), 5_000);

        StorageItem item = _p.Classify(nodeModules);

        Assert.False(item.CanSelectForCleanup);
        Assert.NotEqual(ItemCategory.DeveloperBuildArtifact, item.Category);
        Assert.NotEqual(RiskLevel.Green, item.RiskClassification);
        Assert.NotEqual(RiskLevel.Yellow, item.RiskClassification);
    }

    [Fact]
    public void NodeModules_InsideAppData_IsNeverOfferedForCleanup()
    {
        // Pacotes globais do npm: apagá-los remove as ferramentas de linha de comando instaladas
        string globalNpm = Path.Combine(_p.Env.RoamingAppDataDir, "npm");
        _p.WriteFile(Path.Combine(globalNpm, "package.json"), 200);
        _p.WriteFile(Path.Combine(globalNpm, "package-lock.json"), 200);
        string nodeModules = Path.Combine(globalNpm, "node_modules");
        _p.WriteFile(Path.Combine(nodeModules, "typescript", "bin", "tsc"), 5_000);

        StorageItem item = _p.Classify(nodeModules);

        Assert.False(item.CanSelectForCleanup);
        Assert.NotEqual(ItemCategory.DeveloperBuildArtifact, item.Category);
    }

    [Fact]
    public void NodeModules_OfARealProject_WithLockfile_IsYellowAndSelectable()
    {
        string project = Path.Combine(_p.Root, "Projetos", "loja");
        _p.WriteFile(Path.Combine(project, "package.json"), 200);
        _p.WriteFile(Path.Combine(project, "package-lock.json"), 200);
        string nodeModules = Path.Combine(project, "node_modules");
        _p.WriteFile(Path.Combine(nodeModules, "react", "index.js"), 5_000);

        StorageItem item = _p.Classify(nodeModules);

        Assert.Equal(ItemCategory.DeveloperBuildArtifact, item.Category);
        Assert.Equal(RiskLevel.Yellow, item.RiskClassification);
        Assert.True(item.CanSelectForCleanup);
    }

    [Fact]
    public void NodeModules_InsideAGitRepository_IsRecognizedEvenWithoutLockfileBeside()
    {
        // Monorepo: o lockfile e o .git ficam na raiz, o pacote fica dois níveis abaixo
        string repo = Path.Combine(_p.Root, "Projetos", "monorepo");
        Directory.CreateDirectory(Path.Combine(repo, ".git"));
        string package = Path.Combine(repo, "packages", "web");
        _p.WriteFile(Path.Combine(package, "package.json"), 200);
        string nodeModules = Path.Combine(package, "node_modules");
        _p.WriteFile(Path.Combine(nodeModules, "vite", "index.js"), 5_000);

        StorageItem item = _p.Classify(nodeModules);

        Assert.Equal(ItemCategory.DeveloperBuildArtifact, item.Category);
        Assert.True(item.CanSelectForCleanup);
    }

    [Fact]
    public void NodeModules_WithoutLockfileOrGit_IsNotTreatedAsAProject()
    {
        // Aplicativo portátil descompactado: tem package.json e node_modules, mas ninguém vai rodar "npm install"
        string portable = Path.Combine(_p.Root, "Ferramentas", "utilitario-portatil");
        _p.WriteFile(Path.Combine(portable, "package.json"), 200);
        string nodeModules = Path.Combine(portable, "node_modules");
        _p.WriteFile(Path.Combine(nodeModules, "dep", "index.js"), 5_000);

        StorageItem item = _p.Classify(nodeModules);

        Assert.False(item.CanSelectForCleanup);
        Assert.Equal(RiskLevel.Gray, item.RiskClassification);
    }

    [Fact]
    public void NodeModules_NestedInsideAnother_PointsToTheTopLevelOne()
    {
        string project = Path.Combine(_p.Root, "Projetos", "api");
        _p.WriteFile(Path.Combine(project, "package.json"), 200);
        _p.WriteFile(Path.Combine(project, "yarn.lock"), 200);
        string nested = Path.Combine(project, "node_modules", "express", "node_modules");
        _p.WriteFile(Path.Combine(project, "node_modules", "express", "package.json"), 200);
        _p.WriteFile(Path.Combine(nested, "debug", "index.js"), 5_000);

        StorageItem item = _p.Classify(nested);

        Assert.Equal(RecommendedAction.CleanViaParentItem, item.Recommendation);
        Assert.False(item.CanSelectForCleanup);
        Assert.Contains(Path.Combine(project, "node_modules"), item.RecommendationDetails, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DotNetBuildOutput_InsideAToolFolder_IsNotTreatedAsAProject()
    {
        string tool = Path.Combine(_p.Profile, ".ferramenta", "modelos", "console");
        _p.WriteFile(Path.Combine(tool, "console.csproj"), 200);
        string bin = Path.Combine(tool, "bin");
        _p.WriteFile(Path.Combine(bin, "console.dll"), 5_000);

        StorageItem item = _p.Classify(bin);

        Assert.NotEqual(ItemCategory.DeveloperBuildArtifact, item.Category);
        Assert.False(item.CanSelectForCleanup);
    }

    [Fact]
    public void GlobalPackageCache_OnlyTheRootIsAFinding_SubfoldersPointToIt()
    {
        string cacheRoot = Path.Combine(_p.Profile, ".m2", "repository");
        string nested = Path.Combine(cacheRoot, "org", "apache", "commons");
        _p.WriteFile(Path.Combine(nested, "commons.jar"), 5_000);

        StorageItem root = _p.Classify(cacheRoot);
        StorageItem inner = _p.Classify(nested);

        Assert.Equal(ItemCategory.DeveloperCache, root.Category);
        Assert.NotEqual(RecommendedAction.CleanViaParentItem, root.Recommendation);
        Assert.True(root.CanSelectForCleanup);

        Assert.Equal(ItemCategory.DeveloperCache, inner.Category);
        Assert.Equal(RecommendedAction.CleanViaParentItem, inner.Recommendation);
        Assert.False(inner.CanSelectForCleanup);
    }

    [Fact]
    public void BrowserCache_ContentInsideTheCacheFolder_IsNotClassifiedAsPersistentData()
    {
        string cache = Path.Combine(_p.Env.LocalAppDataDir, "Google", "Chrome", "User Data", "Default", "Cache");
        string inner = Path.Combine(cache, "Cache_Data");
        _p.WriteFile(Path.Combine(inner, "f_000001"), 5_000);

        StorageItem root = _p.Classify(cache);
        StorageItem nested = _p.Classify(inner);

        Assert.Equal(RiskLevel.Green, root.RiskClassification);
        Assert.True(root.CanSelectForCleanup);

        // Antes, o conteúdo do cache aparecia como "dados persistentes" (vermelho) ou como outro item verde sobreposto
        Assert.Equal(ItemCategory.ApplicationCache, nested.Category);
        Assert.Equal(RecommendedAction.CleanViaParentItem, nested.Recommendation);
        Assert.False(nested.CanSelectForCleanup);
    }

    [Fact]
    public void ShaderCacheInFixedLocation_IsRecognizedAsDisposable()
    {
        // A regra existia, mas nunca era alcançada: a pasta era identificada como "aplicativo conhecido" antes
        string shaderCache = Path.Combine(_p.Env.LocalAppDataDir, "D3DSCache");
        _p.WriteFile(Path.Combine(shaderCache, "abc123", "shader.bin"), 5_000);

        StorageItem item = _p.Classify(shaderCache);

        Assert.Equal(ItemCategory.ApplicationCache, item.Category);
        Assert.Equal(RiskLevel.Green, item.RiskClassification);
        Assert.True(item.CanSelectForCleanup);
    }

    [Theory]
    [InlineData(@"C:\Users\x\AppData\Roaming\Slack\Code Cache", "Slack")]
    [InlineData(@"C:\Users\x\AppData\Roaming\Code\User", "Visual Studio Code")]
    [InlineData(@"C:\Users\x\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache", "Microsoft Teams (MSIX)")]
    [InlineData(@"C:\Users\x\AppData\Local\Codeium", "Desconhecido")]
    public void AppIdentification_MatchesWholeFolderNames(string path, string expectedApp)
    {
        // "\Code" casava com qualquer pasta começada por "Code" (ex.: "Code Cache" de outro aplicativo)
        Assert.Equal(expectedApp, StorageClassifier.IdentifyAppDataOwner(path, out _));
    }

    [Fact]
    public void InformationalSignature_ExplainsTheFolder_ButDoesNotAuthorizeCacheCleanup()
    {
        string adobeCache = Path.Combine(_p.Env.RoamingAppDataDir, "Adobe", "Produto", "Cache");
        _p.WriteFile(Path.Combine(adobeCache, "dados.bin"), 5_000);

        StorageItem item = _p.Classify(adobeCache);

        Assert.Contains("Adobe", item.AssociatedAppOrComponent, StringComparison.OrdinalIgnoreCase);
        Assert.False(item.CanSelectForCleanup);
        Assert.Equal(RiskLevel.Red, item.RiskClassification);
    }

    [Fact]
    public void CacheNamedFolder_InsideExtensionStorage_IsNotTrustedByNameAlone()
    {
        // Uma extensão pode guardar o que quiser numa pasta chamada "cache" dentro do seu armazenamento
        string extensionCache = Path.Combine(_p.Env.RoamingAppDataDir, "Code", "User", "workspaceStorage", "abc123", "fabricante.extensao", "dados", "cache");
        _p.WriteFile(Path.Combine(extensionCache, "indice.bin"), 5_000);

        StorageItem item = _p.Classify(extensionCache);

        Assert.False(item.CanSelectForCleanup);
        Assert.NotEqual(RiskLevel.Green, item.RiskClassification);

        // O cache técnico do próprio VS Code continua reconhecido
        string editorCache = Path.Combine(_p.Env.RoamingAppDataDir, "Code", "Cache");
        _p.WriteFile(Path.Combine(editorCache, "data_0"), 5_000);
        Assert.Equal(RiskLevel.Green, _p.Classify(editorCache).RiskClassification);
    }

    [Fact]
    public void OwnRunningApplicationFolder_IsProtected()
    {
        StorageItem item = new()
        {
            Name = "app",
            FullPath = AppContext.BaseDirectory,
            LogicalSizeBytes = 1_000_000,
            LastModifiedUtc = DateTime.UtcNow.AddDays(-100),
            IsDirectory = true
        };

        _p.Classifier.ClassifyItem(item);

        Assert.True(item.IsProtectedSystemItem);
        Assert.False(item.CanSelectForCleanup);
        Assert.Contains("DiskInspector", item.AssociatedAppOrComponent, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Downloads_FolderWithGitRepository_IsNeverSuggested_EvenWhenOld()
    {
        string folder = Path.Combine(_p.Env.DownloadsDir, "MeuProjeto");
        Directory.CreateDirectory(Path.Combine(folder, "app", ".git"));
        _p.WriteFile(Path.Combine(folder, "app", "dados.bin"), 30 * 1024 * 1024, daysOld: 200);
        Directory.SetLastWriteTimeUtc(Path.Combine(folder, "app", ".git"), DateTime.UtcNow.AddDays(-200));
        Directory.SetLastWriteTimeUtc(Path.Combine(folder, "app"), DateTime.UtcNow.AddDays(-200));
        Directory.SetLastWriteTimeUtc(folder, DateTime.UtcNow.AddDays(-200));

        StorageItem item = _p.Classify(folder);

        Assert.Equal(RiskLevel.Red, item.RiskClassification);
        Assert.False(item.CanSelectForCleanup);
    }

    [Fact]
    public void Downloads_AgeUsesNewestContent_NotTheFolderDate()
    {
        // A data da pasta é antiga, mas um arquivo interno foi alterado ontem: não é um "download antigo"
        string folder = Path.Combine(_p.Env.DownloadsDir, "Curso");
        _p.WriteFile(Path.Combine(folder, "aula.mp4"), 30 * 1024 * 1024, daysOld: 1);
        Directory.SetLastWriteTimeUtc(folder, DateTime.UtcNow.AddDays(-200));

        StorageItem recent = _p.Classify(folder);
        Assert.Equal(RiskLevel.Red, recent.RiskClassification);
        Assert.False(recent.CanSelectForCleanup);

        string oldFolder = Path.Combine(_p.Env.DownloadsDir, "Instaladores2019");
        _p.WriteFile(Path.Combine(oldFolder, "pacote.zip"), 30 * 1024 * 1024, daysOld: 200);
        Directory.SetLastWriteTimeUtc(oldFolder, DateTime.UtcNow.AddDays(-200));

        StorageItem old = _p.Classify(oldFolder);
        Assert.Equal(ItemCategory.OldDownloads, old.Category);
        Assert.Equal(RiskLevel.Yellow, old.RiskClassification);
    }

    [Fact]
    public void Downloads_ContentInsideAFolder_IsNotSuggestedIndependently()
    {
        string file = _p.WriteFile(Path.Combine(_p.Env.DownloadsDir, "Fotos", "viagem.zip"), 30 * 1024 * 1024, daysOld: 200);

        StorageItem item = _p.Classify(file);

        Assert.Equal(RiskLevel.Red, item.RiskClassification);
        Assert.False(item.CanSelectForCleanup);
    }
}

public sealed class TempAgeRuleTests
{
    [Fact]
    public void TempItem_UntouchedSinceBeforeTheSession_IsGreen()
    {
        using IsolatedProfile p = new(sessionStartUtc: DateTime.UtcNow.AddDays(-3));
        string file = p.WriteFile(Path.Combine(p.Temp, "instalador_antigo.tmp"), 8_192, daysOld: 10);

        StorageItem item = p.Classify(file);

        Assert.Equal(RiskLevel.Green, item.RiskClassification);
        Assert.True(item.CanSelectForCleanup);
    }

    [Fact]
    public void TempItem_ChangedDuringTheCurrentSession_IsYellow_EvenIfDaysOld()
    {
        // Sessão aberta há 3 dias; item alterado há 2: algum programa ainda aberto pode ser o dono
        using IsolatedProfile p = new(sessionStartUtc: DateTime.UtcNow.AddDays(-3));
        string file = p.WriteFile(Path.Combine(p.Temp, "rascunho_aberto.tmp"), 8_192, daysOld: 2);

        StorageItem item = p.Classify(file);

        Assert.Equal(RiskLevel.Yellow, item.RiskClassification);
        Assert.Equal(RecommendedAction.SafeToCleanWhenAppClosed, item.Recommendation);
    }

    [Fact]
    public void TempItem_FromTheLastDay_IsYellow_EvenRightAfterAReboot()
    {
        using IsolatedProfile p = new(sessionStartUtc: DateTime.UtcNow.AddMinutes(-5));
        string file = p.WriteFile(Path.Combine(p.Temp, "de_duas_horas_atras.tmp"), 8_192, daysOld: 2.0 / 24);

        StorageItem item = p.Classify(file);

        Assert.Equal(RiskLevel.Yellow, item.RiskClassification);
    }

    [Fact]
    public void TempFolder_WithOldDateButRecentContent_IsYellow()
    {
        using IsolatedProfile p = new(sessionStartUtc: DateTime.UtcNow.AddDays(-3));
        string folder = Path.Combine(p.Temp, "extracao");
        p.WriteFile(Path.Combine(folder, "dados.bin"), 8_192, daysOld: 0);
        Directory.SetLastWriteTimeUtc(folder, DateTime.UtcNow.AddDays(-30));

        StorageItem item = p.Classify(folder);

        Assert.Equal(RiskLevel.Yellow, item.RiskClassification);
    }

    [Fact]
    public void TempContent_BelowTheFirstLevel_PointsToTheFirstLevelItem()
    {
        using IsolatedProfile p = new();
        string firstLevel = Path.Combine(p.Temp, "pacote_extraido");
        string nested = Path.Combine(firstLevel, "sub", "mais");
        p.WriteFile(Path.Combine(nested, "arquivo.bin"), 8_192);

        StorageItem item = p.Classify(nested);

        Assert.Equal(ItemCategory.TemporaryFiles, item.Category);
        Assert.Equal(RecommendedAction.CleanViaParentItem, item.Recommendation);
        Assert.False(item.CanSelectForCleanup);
        Assert.Contains(firstLevel, item.RecommendationDetails, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EnvironmentDiscovery_IsComputedOnce_AndKnowsTheSessionStart()
    {
        WindowsEnvironmentProvider provider = new();

        EnvironmentPaths first = provider.GetEnvironmentPaths();
        EnvironmentPaths second = provider.GetEnvironmentPaths();

        // Era recalculado a cada chamada (~75 µs), três vezes por pasta varrida
        Assert.Same(first, second);
        Assert.NotNull(first.UserSessionStartUtc);
        Assert.True(first.UserSessionStartUtc <= DateTime.UtcNow);
    }
}

public sealed class ScanCompletenessTests : IDisposable
{
    private readonly IsolatedProfile _p = new();

    public void Dispose() => _p.Dispose();

    [Fact]
    public async Task LargePackageCache_DoesNotCrowdOutProjectsAndTempItems()
    {
        // Cache NuGet com 600 subpastas: antes, elas esgotavam os limites de 250/400 itens e escondiam o resto
        string nugetRoot = Path.Combine(_p.Profile, ".nuget", "packages");
        for (int i = 0; i < 150; i++)
        {
            _p.WriteFile(Path.Combine(nugetRoot, $"pacote{i:D3}", "1.0.0", "lib", "net8.0", "lib.dll"), 20_000, daysOld: 40);
        }

        string webProject = Path.Combine(_p.Profile, "Projetos", "loja");
        _p.WriteFile(Path.Combine(webProject, "package.json"), 200, daysOld: 40);
        _p.WriteFile(Path.Combine(webProject, "package-lock.json"), 200, daysOld: 40);
        _p.WriteFile(Path.Combine(webProject, "node_modules", "react", "index.js"), 5_000_000, daysOld: 40);

        string apiProject = Path.Combine(_p.Profile, "Projetos", "api");
        _p.WriteFile(Path.Combine(apiProject, "api.csproj"), 200, daysOld: 40);
        _p.WriteFile(Path.Combine(apiProject, "bin", "Debug", "api.dll"), 3_000_000, daysOld: 40);
        _p.WriteFile(Path.Combine(apiProject, "obj", "Debug", "api.pdb"), 2_000_000, daysOld: 40);

        for (int t = 0; t < 20; t++)
        {
            string tempDir = Path.Combine(_p.Temp, $"instalador_antigo_{t:D2}");
            _p.WriteFile(Path.Combine(tempDir, "interno", "setup.tmp"), 1_000_000, daysOld: 10);
            Directory.SetLastWriteTimeUtc(Path.Combine(tempDir, "interno"), DateTime.UtcNow.AddDays(-10));
            Directory.SetLastWriteTimeUtc(tempDir, DateTime.UtcNow.AddDays(-10));
        }

        ScanResult result = await _p.CreateScanner().ScanAsync(_p.FakeDrive(), _p.Root, progress: null, CancellationToken.None);

        string nugetPrefix = nugetRoot + Path.DirectorySeparatorChar;

        // Aba Dev: os artefatos dos projetos aparecem e nenhuma subpasta interna do cache é listada
        Assert.Contains(result.DeveloperArtifacts, d => d.Name == "node_modules");
        Assert.Contains(result.DeveloperArtifacts, d => d.Name == "bin");
        Assert.Contains(result.DeveloperArtifacts, d => d.Name == "obj");
        Assert.DoesNotContain(result.DeveloperArtifacts, d => d.FullPath.StartsWith(nugetPrefix, StringComparison.OrdinalIgnoreCase));
        Assert.Single(result.DeveloperArtifacts, d => string.Equals(d.FullPath, nugetRoot, StringComparison.OrdinalIgnoreCase));

        // Aba Classificação: o cache aparece uma vez (a raiz) e os 20 itens do Temp estão todos lá
        Assert.DoesNotContain(result.ClassifiedFindings, f => f.FullPath.StartsWith(nugetPrefix, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(20, result.ClassifiedFindings.Count(f =>
            f.IsDirectory &&
            string.Equals(Path.GetDirectoryName(f.FullPath), _p.Temp, StringComparison.OrdinalIgnoreCase) &&
            f.RiskClassification == RiskLevel.Green));
        Assert.DoesNotContain(result.ClassifiedFindings, f => f.Recommendation == RecommendedAction.CleanViaParentItem);

        // A estimativa cobre o Temp inteiro (20 MB), não uma fração dele
        Assert.Equal(20_000_000L, result.EstimatedSafeGreenRecoverableBytes);
        Assert.Equal(5_000_000L, result.EstimatedAttentionYellowRecoverableBytes);
    }

    [Fact]
    public async Task Scan_RecordsNewestContentWrite_SoAFolderInUseIsNotGreen()
    {
        string busy = Path.Combine(_p.Temp, "sessao_em_andamento");
        _p.WriteFile(Path.Combine(busy, "dados.bin"), 500_000, daysOld: 0);
        Directory.SetLastWriteTimeUtc(busy, DateTime.UtcNow.AddDays(-30));

        string idle = Path.Combine(_p.Temp, "resto_antigo");
        _p.WriteFile(Path.Combine(idle, "dados.bin"), 500_000, daysOld: 30);
        Directory.SetLastWriteTimeUtc(idle, DateTime.UtcNow.AddDays(-30));

        ScanResult result = await _p.CreateScanner().ScanAsync(_p.FakeDrive(), _p.Root, progress: null, CancellationToken.None);

        StorageItem busyItem = Assert.Single(result.ClassifiedFindings, f => f.FullPath == busy);
        StorageItem idleItem = Assert.Single(result.ClassifiedFindings, f => f.FullPath == idle);

        Assert.Equal(RiskLevel.Yellow, busyItem.RiskClassification);
        Assert.Equal(RiskLevel.Green, idleItem.RiskClassification);
        Assert.True(busyItem.LatestContentWriteUtc > DateTime.UtcNow.AddHours(-1));
    }

    [Fact]
    public async Task Scan_DoesNotDisturbFilesHeldOpenByOtherPrograms()
    {
        // Um "programa" mantém um arquivo do Temp aberto com acesso exclusivo durante toda a análise
        string folder = Path.Combine(_p.Temp, "app_em_uso");
        string held = _p.WriteFile(Path.Combine(folder, "banco.db"), 100_000, daysOld: 10);
        using FileStream exclusive = new(held, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        ScanResult result = await _p.CreateScanner().ScanAsync(_p.FakeDrive(), _p.Root, progress: null, CancellationToken.None);

        // A análise conclui, enxerga o item e o dono do arquivo continua com o acesso intacto
        Assert.Contains(result.ClassifiedFindings, f => f.FullPath == folder);
        exclusive.WriteByte(1);
        exclusive.Flush();
    }

    [Fact]
    public async Task AppData_StorePackages_AreListedPerApplication()
    {
        string packages = Path.Combine(_p.Env.LocalAppDataDir, "Packages");
        _p.WriteFile(Path.Combine(packages, "Empresa.AppUm_abc123", "LocalState", "dados.db"), 400_000);
        _p.WriteFile(Path.Combine(packages, "Empresa.AppUm_abc123", "TempState", "tmp.bin"), 100_000);
        _p.WriteFile(Path.Combine(packages, "Outra.AppDois_xyz789", "LocalState", "dados.db"), 200_000);

        ScanResult result = await _p.CreateScanner().ScanAsync(_p.FakeDrive(), _p.Root, progress: null, CancellationToken.None);

        AppDataEntry appUm = Assert.Single(result.AppDataEntries, a => a.DirectoryName == "Empresa.AppUm_abc123");
        Assert.Equal("Empresa.AppUm", appUm.IdentifiedApplication);
        Assert.Equal(100_000L, appUm.SafeDisposableCacheBytes);
        Assert.Contains(result.AppDataEntries, a => a.DirectoryName == "Outra.AppDois_xyz789");
        Assert.DoesNotContain(result.AppDataEntries, a => a.DirectoryName == "Packages");
    }

    [Fact]
    public async Task DuplicateSearch_SkipsApplicationFolders()
    {
        byte[] library = new byte[200_000];
        Random.Shared.NextBytes(library);

        // A mesma biblioteca em dois programas instalados: não são "cópias sobrando"
        string appA = Path.Combine(_p.Env.LocalAppDataDir, "Programs", "AppA", "ffmpeg.dll");
        string appB = Path.Combine(_p.Env.LocalAppDataDir, "Programs", "AppB", "ffmpeg.dll");
        string tool = Path.Combine(_p.Profile, ".ferramenta", "ffmpeg.dll");
        foreach (string path in new[] { appA, appB, tool })
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllBytesAsync(path, library);
        }

        // A mesma foto em duas pastas pessoais: essa sim é uma duplicata de verdade
        byte[] photo = new byte[150_000];
        Random.Shared.NextBytes(photo);
        string photoA = Path.Combine(_p.Env.DocumentsDir, "foto.jpg");
        string photoB = Path.Combine(_p.Env.DesktopDir, "foto (1).jpg");
        await File.WriteAllBytesAsync(photoA, photo);
        await File.WriteAllBytesAsync(photoB, photo);

        DuplicateFileDetector detector = new(_p.Protector, _p.Provider);
        IReadOnlyList<DuplicateGroup> groups = await detector.FindDuplicatesAsync(_p.Profile, 1_000, statusProgress: null, CancellationToken.None);

        DuplicateGroup group = Assert.Single(groups);
        Assert.All(group.Entries, e => Assert.EndsWith(".jpg", e.FullPath));
    }
}

public sealed class PathNestingTests
{
    private static StorageItem Dir(string path, long size) => new()
    {
        Name = Path.GetFileName(path),
        FullPath = path,
        LogicalSizeBytes = size,
        IsDirectory = true
    };

    [Fact]
    public void TopMost_HandlesSiblingsWhoseNamesShareAPrefix()
    {
        // "C:\a b" não está dentro de "C:\a", mas fica entre "C:\a" e "C:\a\x" numa ordenação simples
        List<StorageItem> top = PathNesting.SelectTopMost(
        [
            Dir(@"C:\dados\a\x", 10),
            Dir(@"C:\dados\a b", 20),
            Dir(@"C:\dados\a", 100),
            Dir(@"C:\dados\a\x\y", 5),
            Dir(@"C:\DADOS\A", 100)
        ]);

        Assert.Equal(2, top.Count);
        Assert.Contains(top, i => i.FullPath == @"C:\dados\a b");
        Assert.Contains(top, i => i.FullPath.Equals(@"C:\dados\a", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void NonOverlappingSize_CountsNestedItemsOnce()
    {
        long total = PathNesting.ComputeNonOverlappingSize(
        [
            Dir(@"C:\t\pai", 1_000),
            Dir(@"C:\t\pai\filho", 400),
            Dir(@"C:\t\outro", 250)
        ]);

        Assert.Equal(1_250, total);
    }

    [Fact]
    public void AFileNeverContainsOtherItems()
    {
        StorageItem file = new() { Name = "a", FullPath = @"C:\t\a", LogicalSizeBytes = 1, IsDirectory = false };

        List<StorageItem> top = PathNesting.SelectTopMost([file, Dir(@"C:\t\a\b", 2)], onlyDirectoriesContain: true);

        Assert.Equal(2, top.Count);
    }

    [Fact]
    public void LargeSelections_AreComputedQuickly()
    {
        // Com o algoritmo antigo, 800 itens já congelavam a janela por 30 s; aqui são 20.000
        List<StorageItem> items = [];
        for (int i = 0; i < 20_000; i++)
        {
            items.Add(Dir($@"C:\Users\ana\AppData\Local\Temp\item{i:D6}", 1_000 + i));
        }

        Stopwatch watch = Stopwatch.StartNew();
        long total = PathNesting.ComputeNonOverlappingSize(items);
        watch.Stop();

        Assert.Equal(items.Sum(i => i.LogicalSizeBytes), total);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"Levou {watch.Elapsed.TotalSeconds:0.0}s");
    }
}

public sealed class CleanupGuaranteeTests : IDisposable
{
    private readonly IsolatedProfile _p = new();

    public void Dispose() => _p.Dispose();

    private StorageItem GreenTempItem(string name, int bytes)
    {
        string path = _p.WriteFile(Path.Combine(_p.Temp, name), bytes, daysOld: 10);
        StorageItem item = _p.Classify(path);
        Assert.Equal(RiskLevel.Green, item.RiskClassification);
        return item;
    }

    [Fact]
    public void WithRecycleBinOn_ItemLargerThanTheBin_IsBlocked_NotPermanentlyDeleted()
    {
        FakeRecycleBin bin = new()
        {
            Status = new RecycleBinStatus { IsAvailable = true, CapacityBytes = 4_000, UsedBytes = 0, ItemCount = 0 }
        };
        CleanupSafetyValidator validator = new(_p.Protector, _p.LockDetector, bin);
        StorageItem item = GreenTempItem("grande_demais.tmp", 8_192);

        SafetyValidationDecision withBin = validator.ValidateForCleanup(item, preferRecycleBin: true);
        Assert.False(withBin.IsAllowed);
        Assert.Contains("Lixeira", withBin.Reason, StringComparison.OrdinalIgnoreCase);

        // Só com a opção desmarcada, por decisão explícita do usuário, a exclusão definitiva é permitida
        SafetyValidationDecision withoutBin = validator.ValidateForCleanup(item, preferRecycleBin: false);
        Assert.True(withoutBin.IsAllowed);
        Assert.Equal(CleanupOperationMethod.DirectPermanentDelete, withoutBin.AllowedMethod);
    }

    [Fact]
    public void WithRecycleBinOn_VolumeWithoutRecycleBin_IsBlocked()
    {
        FakeRecycleBin bin = new()
        {
            Status = new RecycleBinStatus { IsAvailable = false, UnavailableReason = "A Lixeira deste volume está configurada para excluir os arquivos imediatamente." }
        };
        CleanupSafetyValidator validator = new(_p.Protector, _p.LockDetector, bin);

        SafetyValidationDecision decision = validator.ValidateForCleanup(GreenTempItem("sem_lixeira.tmp", 4_096), preferRecycleBin: true);

        Assert.False(decision.IsAllowed);
        Assert.Contains("excluir os arquivos imediatamente", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Preview_NeverApprovesMoreThanTheFreeSpaceOfTheRecycleBin()
    {
        // Cabem 10 KB livres: o Windows descartaria itens antigos da Lixeira para abrir espaço ao excedente
        FakeRecycleBin bin = new()
        {
            Status = new RecycleBinStatus { IsAvailable = true, CapacityBytes = 100_000, UsedBytes = 90_000, ItemCount = 3 }
        };
        CleanupSafetyValidator validator = new(_p.Protector, _p.LockDetector, bin);
        SafeCleanupService service = new(validator, _p.History, recycleBin: bin);

        StorageItem first = GreenTempItem("a.tmp", 8_000);
        StorageItem second = GreenTempItem("b.tmp", 8_000);
        StorageItem small = GreenTempItem("c.tmp", 1_500);

        CleanupPreviewReport preview = service.BuildPreview([first, second, small], preferRecycleBin: true);

        Assert.Equal(2, preview.ApprovedItems.Count);
        Assert.Contains(preview.ApprovedItems, a => a.Item == first);
        Assert.Contains(preview.ApprovedItems, a => a.Item == small);
        CleanupPreviewItem refused = Assert.Single(preview.BlockedItems);
        Assert.Same(second, refused.Item);
        Assert.Contains("Lixeira sem espaço", refused.ValidationMessage, StringComparison.OrdinalIgnoreCase);
        Assert.True(preview.ApprovedItems.Sum(a => a.Item.LogicalSizeBytes) <= 10_000);
    }

    [Fact]
    public async Task Execution_WhenWindowsRefusesToRecycle_LeavesTheItemIntactAndReportsIt()
    {
        FakeRecycleBin bin = new()
        {
            OnSend = _ => new RecycleAttemptResult
            {
                Succeeded = false,
                ConfirmedRecycled = false,
                Message = "O Windows excluiria este item em definitivo. A operação foi recusada."
            }
        };
        CleanupSafetyValidator validator = new(_p.Protector, _p.LockDetector, bin);
        SafeCleanupService service = new(validator, _p.History, recycleBin: bin);
        StorageItem item = GreenTempItem("recusado.tmp", 4_096);

        CleanupPreviewReport preview = service.BuildPreview([item], preferRecycleBin: true);
        CleanupExecutionResult result = await service.ExecuteCleanupAsync(preview, progress: null, CancellationToken.None);

        Assert.Equal(0, result.TotalSucceeded);
        Assert.Equal(1, result.TotalFailedOrLocked);
        Assert.Equal(0L, result.TotalBytesMovedToRecycleBin);
        Assert.Equal(0L, result.TotalBytesPermanentlyDeleted);
        Assert.True(File.Exists(item.FullPath));
    }

    [Fact]
    public async Task Execution_SeparatesRecycledFromPermanentlyDeleted_AndWritesAFullManifest()
    {
        FakeRecycleBin bin = new();
        CleanupSafetyValidator validator = new(_p.Protector, _p.LockDetector, bin);
        SafeCleanupService service = new(validator, _p.History, recycleBin: bin);

        List<StorageItem> items = [];
        for (int i = 0; i < 25; i++)
        {
            items.Add(GreenTempItem($"resto_{i:D2}.tmp", 2_000));
        }

        CleanupPreviewReport preview = service.BuildPreview(items, preferRecycleBin: true);
        CleanupExecutionResult result = await service.ExecuteCleanupAsync(preview, progress: null, CancellationToken.None);

        Assert.Equal(25, result.TotalSucceeded);
        Assert.Equal(50_000L, result.TotalBytesMovedToRecycleBin);
        Assert.Equal(0L, result.TotalBytesPermanentlyDeleted);
        Assert.Equal(25, bin.Sent.Count);

        // O histórico antigo guardava só o nome de 10 itens; o registro agora tem o caminho completo de todos
        Assert.NotNull(result.ManifestFilePath);
        string manifest = await File.ReadAllTextAsync(result.ManifestFilePath!);
        foreach (StorageItem item in items)
        {
            Assert.Contains(item.FullPath.Replace(@"\", @"\\"), manifest);
        }
    }

    [Fact]
    public void Validator_BlocksItemsThatChangedAfterTheAnalysis()
    {
        CleanupSafetyValidator validator = new(_p.Protector, _p.LockDetector, new FakeRecycleBin());

        // Pasta analisada como antiga...
        string folder = Path.Combine(_p.Temp, "extracao_antiga");
        _p.WriteFile(Path.Combine(folder, "a.bin"), 4_096, daysOld: 10);
        Directory.SetLastWriteTimeUtc(folder, DateTime.UtcNow.AddDays(-10));
        StorageItem folderItem = _p.Classify(folder);
        Assert.True(validator.ValidateForCleanup(folderItem, preferRecycleBin: true).IsAllowed);

        // ...e um programa grava nela antes de o usuário confirmar a limpeza
        File.WriteAllBytes(Path.Combine(folder, "novo.bin"), new byte[100]);
        SafetyValidationDecision afterWrite = validator.ValidateForCleanup(folderItem, preferRecycleBin: true, CleanupValidationStage.Execution);
        Assert.False(afterWrite.IsAllowed);
        Assert.Contains("após a análise", afterWrite.Reason, StringComparison.OrdinalIgnoreCase);

        // Arquivo que cresceu depois da análise
        StorageItem fileItem = GreenTempItem("registro.tmp", 4_096);
        File.WriteAllBytes(fileItem.FullPath, new byte[9_000]);
        File.SetLastWriteTimeUtc(fileItem.FullPath, DateTime.UtcNow.AddDays(-10));
        Assert.False(validator.ValidateForCleanup(fileItem, preferRecycleBin: true).IsAllowed);
    }

    [Fact]
    public void Validator_BlocksNestedContentAndOfficialToolItems_EvenIfForcedIntoTheSelection()
    {
        CleanupSafetyValidator validator = new(_p.Protector, _p.LockDetector, new FakeRecycleBin());

        string nested = Path.Combine(_p.Temp, "pacote", "interno");
        _p.WriteFile(Path.Combine(nested, "x.bin"), 4_096);
        StorageItem nestedItem = _p.Classify(nested);
        Assert.False(validator.ValidateForCleanup(nestedItem, preferRecycleBin: true).IsAllowed);

        string nuget = Path.Combine(_p.Profile, ".nuget", "packages");
        _p.WriteFile(Path.Combine(nuget, "pacote", "lib.dll"), 4_096);
        StorageItem nugetItem = _p.Classify(nuget);
        Assert.Equal(RiskLevel.Yellow, nugetItem.RiskClassification);
        Assert.False(validator.ValidateForCleanup(nugetItem, preferRecycleBin: true).IsAllowed);
    }

    [Fact]
    public void PermanentDelete_OfAFolderWithAFileInUse_ChangesNothing()
    {
        // 150 arquivos; só o último está aberto. A verificação antiga olhava os 30 primeiros e seguia em frente.
        string folder = Path.Combine(_p.Temp, "cache_grande");
        for (int i = 0; i < 150; i++)
        {
            _p.WriteFile(Path.Combine(folder, $"bloco_{i:D3}.bin"), 512);
        }

        string held = Path.Combine(folder, "bloco_149.bin");
        using (FileStream inUse = new(held, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            Assert.Throws<IOException>(() => SafeCleanupService.DeleteDirectoryAllOrNothing(folder));

            Assert.True(Directory.Exists(folder));
            Assert.Equal(150, Directory.GetFiles(folder).Length);
        }

        // Sem ninguém usando, a mesma chamada remove tudo, inclusive arquivos somente leitura
        File.SetAttributes(Path.Combine(folder, "bloco_000.bin"), FileAttributes.ReadOnly);
        SafeCleanupService.DeleteDirectoryAllOrNothing(folder);
        Assert.False(Directory.Exists(folder));
        Assert.Empty(Directory.GetDirectories(_p.Temp, "cache_grande*"));
    }
}

public sealed class WindowsRecycleBinTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "DiskInspectorLixeira_" + Guid.NewGuid().ToString("N"));

    public WindowsRecycleBinTests() => Directory.CreateDirectory(_folder);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_folder, recursive: true);
        }
        catch
        {
            // Ignora falha de limpeza
        }
    }

    [Fact]
    public void Status_ReportsCapacityOfTheVolume()
    {
        RecycleBinStatus status = new WindowsRecycleBin().GetStatus(_folder);

        Assert.True(status.IsAvailable, status.UnavailableReason);
        Assert.True(status.CapacityBytes > 0);
        Assert.True(status.UsedBytes >= 0);
    }

    [Fact]
    public void Guard_RefusesAnOperationThatWouldDeletePermanently()
    {
        // Pede ao Windows uma exclusão SEM Lixeira com a guarda ligada: a guarda deve abortar e o arquivo ficar intacto.
        // É o mesmo caminho que o Windows segue quando o item não cabe na Lixeira.
        string file = Path.Combine(_folder, "nao_pode_sumir.tmp");
        File.WriteAllBytes(file, new byte[2_048]);

        RecycleAttemptResult result = new WindowsRecycleBin().AttemptDeleteWithoutRecycleFlagsForGuardTest(file);

        Assert.False(result.Succeeded);
        Assert.False(result.ConfirmedRecycled);
        Assert.True(File.Exists(file), "A guarda deveria ter impedido a exclusão definitiva.");
        Assert.Contains("definitivo", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [RealRecycleBinFact]
    public void Send_MovesAFileToTheRealRecycleBin_AndConfirmsIt()
    {
        string file = Path.Combine(_folder, "diskinspector_teste_lixeira.tmp");
        File.WriteAllBytes(file, new byte[2_048]);

        RecycleAttemptResult result = new WindowsRecycleBin().SendToRecycleBin(file);

        Assert.True(result.Succeeded, result.Message);
        Assert.True(result.ConfirmedRecycled);
        Assert.False(File.Exists(file));
    }

    [RealRecycleBinFact]
    public void Send_FolderWithAFileInUse_FailsCleanly_AndNothingIsMoved()
    {
        string folder = Path.Combine(_folder, "diskinspector_teste_pasta_em_uso");
        Directory.CreateDirectory(folder);
        for (int i = 0; i < 40; i++)
        {
            File.WriteAllBytes(Path.Combine(folder, $"arquivo_{i:D2}.bin"), new byte[256]);
        }

        using (FileStream inUse = new(Path.Combine(folder, "arquivo_39.bin"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            RecycleAttemptResult result = new WindowsRecycleBin().SendToRecycleBin(folder);

            Assert.False(result.Succeeded);
            Assert.True(Directory.Exists(folder));
            Assert.Equal(40, Directory.GetFiles(folder).Length);
        }
    }
}

/// <summary>
/// Testes automatizados dos 8 Diferenciais (Achados por Grupo, Mapa de Blocos por Risco, O que Cresceu,
/// Comando Oficial 1 Clique, Projetos Parados > 90d, Liberar Sem Apagar, Restart Manager + Desfazer Lixeira
/// e Catálogo JSON do AppData).
/// </summary>
public sealed class DifferentialsTests : IDisposable
{
    private readonly IsolatedProfile _p = new();

    public void Dispose() => _p.Dispose();

    [Fact]
    public async Task Diff1And2_ScanBuildsFindingGroups_AndRiskColoredTreemapBlocks()
    {
        _p.WriteFile(Path.Combine(_p.Temp, "antigo_sessao_passada.tmp"), 300_000, daysOld: 12);
        _p.WriteFile(Path.Combine(_p.Env.LocalAppDataDir, @"Google\Chrome\User Data\Default\Cache\data_0"), 500_000, daysOld: 5);

        string proj = Path.Combine(_p.Profile, "projetos", "app-web");
        _p.WriteFile(Path.Combine(proj, "package.json"), 256, daysOld: 120);
        _p.WriteFile(Path.Combine(proj, "package-lock.json"), 512, daysOld: 120);
        _p.WriteFile(Path.Combine(proj, "src", "index.ts"), 1_024, daysOld: 120);
        _p.WriteFile(Path.Combine(proj, "node_modules", "react", "index.js"), 700_000, daysOld: 120);

        ScanResult result = await _p.CreateScanner().ScanAsync(_p.FakeDrive(), _p.Profile, progress: null, CancellationToken.None);

        Assert.NotEmpty(result.FindingGroups);
        Assert.Contains(result.FindingGroups, g => g.RiskClassification == RiskLevel.Green && g.CanSelectForCleanup);
        Assert.Contains(result.FindingGroups, g => g.RiskClassification == RiskLevel.Yellow && g.CanSelectForCleanup);

        Assert.NotEmpty(result.RiskTreemapBlocks);
        Assert.All(result.RiskTreemapBlocks, b =>
        {
            Assert.InRange(b.X, 0, RiskTreemapBuilder.DefaultCanvasWidth);
            Assert.InRange(b.Y, 0, RiskTreemapBuilder.DefaultCanvasHeight);
            Assert.True(b.Width > 0);
            Assert.True(b.Height > 0);
            Assert.NotEmpty(b.BackgroundHex);
        });
    }

    [Fact]
    public async Task Diff3_ScanSnapshotService_DetectsWhichFolderGrewBetweenScans()
    {
        ScanSnapshotService snapshotService = new(_p.Provider);
        DiskScannerService scanner = new(_p.Provider, _p.Protector, _p.Classifier, _p.History, snapshotService);

        string growingFolder = Path.Combine(_p.Profile, "DockerData");
        _p.WriteFile(Path.Combine(growingFolder, "layer1.bin"), 200_000);

        ScanResult firstScan = await scanner.ScanAsync(_p.FakeDrive(), _p.Profile, progress: null, CancellationToken.None);
        Assert.Null(firstScan.PreviousSnapshotUtc);

        // A pasta cresce +600 KB antes da segunda análise
        _p.WriteFile(Path.Combine(growingFolder, "layer2.bin"), 600_000);

        ScanResult secondScan = await scanner.ScanAsync(_p.FakeDrive(), _p.Profile, progress: null, CancellationToken.None);
        Assert.NotNull(secondScan.PreviousSnapshotUtc);
        Assert.Contains(secondScan.GrowthDeltas, d =>
            string.Equals(d.Name, "DockerData", StringComparison.OrdinalIgnoreCase) &&
            d.DeltaBytes == 600_000);
    }

    [Fact]
    public async Task Diff4_OfficialMaintenanceExecutor_RunsWhitelistedCommand_AndMeasuresSpaceFreed()
    {
        string npmCache = Path.Combine(_p.Env.LocalAppDataDir, "npm-cache");
        string cacheFile = _p.WriteFile(Path.Combine(npmCache, "_cacache", "bloco.tar"), 450_000);

        OfficialMaintenanceExecutor executor = new(
            _p.History,
            customProcessRunner: (fileName, args, workingDir, ct) =>
            {
                if (File.Exists(cacheFile))
                {
                    File.Delete(cacheFile);
                }
                return Task.FromResult((0, "Cache limpo com sucesso", string.Empty));
            });

        Assert.True(executor.CanExecuteCommand("npm cache clean --force", npmCache, out string desc));
        Assert.False(executor.CanExecuteCommand("rm -rf /", npmCache, out _));
        Assert.NotEmpty(desc);

        OfficialCommandExecutionResult execResult = await executor.ExecuteOfficialCommandAsync(
            "npm cache clean --force",
            npmCache,
            progress: null,
            CancellationToken.None);

        Assert.True(execResult.Succeeded);
        Assert.Equal(450_000L, execResult.BytesBefore);
        Assert.Equal(0L, execResult.BytesAfter);
        Assert.Equal(450_000L, execResult.BytesFreed);
    }

    [Fact]
    public async Task Diff5_DeveloperProjects_DistinguishesDormantOver90Days_FromActiveProjects()
    {
        string dormantProj = Path.Combine(_p.Profile, "repos", "projeto-antigo");
        _p.WriteFile(Path.Combine(dormantProj, "package.json"), 256, daysOld: 180);
        _p.WriteFile(Path.Combine(dormantProj, "package-lock.json"), 256, daysOld: 180);
        _p.WriteFile(Path.Combine(dormantProj, "src", "main.ts"), 1_024, daysOld: 150);
        _p.WriteFile(Path.Combine(dormantProj, "node_modules", "lodash", "index.js"), 400_000, daysOld: 180);
        Directory.SetLastWriteTimeUtc(Path.Combine(dormantProj, "src"), DateTime.UtcNow.AddDays(-150));
        Directory.SetLastWriteTimeUtc(dormantProj, DateTime.UtcNow.AddDays(-150));

        string activeProj = Path.Combine(_p.Profile, "repos", "projeto-ativo");
        _p.WriteFile(Path.Combine(activeProj, "package.json"), 256, daysOld: 2);
        _p.WriteFile(Path.Combine(activeProj, "package-lock.json"), 256, daysOld: 2);
        _p.WriteFile(Path.Combine(activeProj, "src", "main.ts"), 1_024, daysOld: 1);
        _p.WriteFile(Path.Combine(activeProj, "node_modules", "vite", "index.js"), 300_000, daysOld: 2);

        ScanResult result = await _p.CreateScanner().ScanAsync(_p.FakeDrive(), _p.Profile, progress: null, CancellationToken.None);

        ProjectActivitySummary dormant = Assert.Single(result.DeveloperProjects, p => p.ProjectName == "projeto-antigo");
        Assert.True(dormant.IsDormantOver90Days);
        Assert.True(dormant.InactiveDays >= 90);
        Assert.Equal(400_000L, dormant.ReclaimableArtifactBytes);

        ProjectActivitySummary active = Assert.Single(result.DeveloperProjects, p => p.ProjectName == "projeto-ativo");
        Assert.False(active.IsDormantOver90Days);
    }

    [Fact]
    public void Diff6_NonDestructiveSpaceAdvisor_RecommendsVhdxCompaction()
    {
        string vhdxPath = Path.Combine(_p.Env.LocalAppDataDir, @"Docker\wsl\data\ext4.vhdx");
        StorageItem rootNode = new()
        {
            Name = "Profile",
            FullPath = _p.Profile,
            IsDirectory = true,
            LogicalSizeBytes = 200 * 1024 * 1024L,
            AllocatedSizeBytes = 200 * 1024 * 1024L
        };

        DeveloperArtifactItem vhdxArtifact = new()
        {
            Ecosystem = "Docker / WSL2",
            ArtifactKind = "Disco Virtual Linux (.vhdx)",
            Name = "ext4.vhdx",
            FullPath = vhdxPath,
            LogicalSizeBytes = 200 * 1024 * 1024L,
            AllocatedSizeBytes = 200 * 1024 * 1024L,
            FileCount = 1,
            LastModifiedUtc = DateTime.UtcNow.AddDays(-5),
            IsGlobalCache = false,
            IsProjectBuildOutput = false,
            IsPersistentVolumeOrVirtualDisk = true,
            RiskClassification = RiskLevel.Red,
            PurposeExplanation = "Disco virtual WSL2",
            RebuildOrRedownloadImpact = "Perda total se apagado",
            RecommendedActionText = "Não excluir"
        };

        NonDestructiveSpaceAdvisor advisor = new(_p.Provider, _p.Protector);
        IReadOnlyList<NonDestructiveOption> options = advisor.AnalyzeOptions(rootNode, [vhdxArtifact], []);

        NonDestructiveOption vhdxOpt = Assert.Single(options, o => o.ActionKind == "CompactacaoVhdx");
        Assert.Equal(vhdxPath, vhdxOpt.TargetPath);
        Assert.True(vhdxOpt.EstimatedSavingsBytes > 0);
    }

    [Fact]
    public void Diff7A_RestartManager_DetectsCurrentProcessHoldingFileOpen()
    {
        string lockedFile = _p.WriteFile(Path.Combine(_p.Temp, "segurado_pelo_teste.txt"), 1_024);
        using FileStream stream = new(lockedFile, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);

        FileLockDetector detector = new();
        IReadOnlyList<LockingProcessInfo> processes = detector.GetLockingProcesses(lockedFile);

        int currentPid = Environment.ProcessId;
        Assert.Contains(processes, p => p.ProcessId == currentPid);
    }

    [Fact]
    public void Diff7B_RecycleBinRestore_ParsesWin11Header_AndRestoresFileToOriginalLocation()
    {
        string fakeRecycleDir = Path.Combine(_p.Root, "FakeRecycleBin");
        Directory.CreateDirectory(fakeRecycleDir);

        string originalPath = Path.Combine(_p.Profile, "Downloads", "relatorio_recuperado.pdf");
        byte[] payloadBytes = [0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37]; // "%PDF-1.7"
        string rFile = Path.Combine(fakeRecycleDir, "$R123456.pdf");
        string iFile = Path.Combine(fakeRecycleDir, "$I123456.pdf");
        File.WriteAllBytes(rFile, payloadBytes);

        // Monta cabeçalho $I versão 2 (Windows 10/11): [version=2 (8B)][size (8B)][filetime (8B)][pathLen (4B)][UTF-16 path\0]
        using (MemoryStream ms = new())
        using (BinaryWriter bw = new(ms))
        {
            bw.Write(2L);
            bw.Write((long)payloadBytes.Length);
            bw.Write(DateTime.UtcNow.ToFileTimeUtc());
            string nullTerminated = originalPath + "\0";
            bw.Write(nullTerminated.Length);
            bw.Write(System.Text.Encoding.Unicode.GetBytes(nullTerminated));
            File.WriteAllBytes(iFile, ms.ToArray());
        }

        Assert.True(WindowsRecycleBin.TryParseRecycleBinMetadataFile(iFile, out WindowsRecycleBin.RecycleBinEntryMetadata? meta));
        Assert.NotNull(meta);
        Assert.Equal(originalPath, meta!.OriginalFullPath);
        Assert.Equal(payloadBytes.Length, meta.OriginalSizeBytes);

        RecycleRestoreResult result = WindowsRecycleBin.RestoreFromRecycleBinDirectory(fakeRecycleDir, [originalPath]);

        Assert.Equal(1, result.TotalRestored);
        Assert.Single(result.RestoredPaths);
        Assert.Empty(result.NotFoundOrFailedMessages);
        Assert.True(File.Exists(originalPath));
        Assert.Equal(payloadBytes, File.ReadAllBytes(originalPath));
        Assert.False(File.Exists(iFile));
    }

    [Fact]
    public void Diff8_AppDataRulesCatalog_LoadsEmbeddedRules_AndIdentifiesKnownApps()
    {
        IReadOnlyList<AppDataRuleDefinition> rules = AppDataRulesCatalog.GetRules();
        Assert.True(rules.Count >= 40, $"Esperava pelo menos 40 regras no catálogo JSON, mas carregou {rules.Count}.");

        string obsDir = Path.Combine(_p.Env.RoamingAppDataDir, "obs-studio");
        _p.WriteFile(Path.Combine(obsDir, "basic", "profiles", "config.ini"), 2_048);
        StorageItem obsItem = _p.Classify(obsDir);

        Assert.Contains("OBS Studio", obsItem.AssociatedAppOrComponent, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(RiskLevel.Red, obsItem.RiskClassification);
    }
}
