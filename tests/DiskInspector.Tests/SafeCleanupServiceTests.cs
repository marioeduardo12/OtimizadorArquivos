using DiskInspector.Analysis;
using DiskInspector.Cleanup;
using DiskInspector.Core.Enums;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;
using DiskInspector.Infrastructure;
using Xunit;

namespace DiskInspector.Tests;

/// <summary>
/// Testes automatizados de limpeza controlada, falha/interrupção parcial e varredura completa em diretório temporário isolado (Seção 12).
/// </summary>
public sealed class SafeCleanupServiceTests : IDisposable
{
    private readonly string _isolatedRoot;
    private readonly EnvironmentPaths _simulatedEnv;
    private readonly IEnvironmentProvider _envProvider;
    private readonly ISystemPathProtector _protector;
    private readonly IFileLockDetector _lockDetector;
    private readonly IStorageClassifier _classifier;
    private readonly ICleanupSafetyValidator _validator;
    private readonly IOperationHistoryRepository _historyRepo;

    public SafeCleanupServiceTests()
    {
        _isolatedRoot = Path.Combine(Path.GetTempPath(), "DiskInspectorCleanupTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_isolatedRoot);

        string userProfile = Path.Combine(_isolatedRoot, "Users", "DevUser");
        string localAppData = Path.Combine(userProfile, "AppData", "Local");
        string roamingAppData = Path.Combine(userProfile, "AppData", "Roaming");
        string localLowAppData = Path.Combine(userProfile, "AppData", "LocalLow");
        string userTemp = Path.Combine(localAppData, "Temp");
        string downloads = Path.Combine(userProfile, "Downloads");
        string documents = Path.Combine(userProfile, "Documents");
        string desktop = Path.Combine(userProfile, "Desktop");

        Directory.CreateDirectory(localAppData);
        Directory.CreateDirectory(roamingAppData);
        Directory.CreateDirectory(localLowAppData);
        Directory.CreateDirectory(userTemp);
        Directory.CreateDirectory(downloads);
        Directory.CreateDirectory(documents);
        Directory.CreateDirectory(desktop);

        _simulatedEnv = new EnvironmentPaths
        {
            WindowsDir = @"C:\Windows",
            System32Dir = @"C:\Windows\System32",
            SysWow64Dir = @"C:\Windows\SysWOW64",
            WinSxSDir = @"C:\Windows\WinSxS",
            ProgramFilesDir = @"C:\Program Files",
            ProgramFilesX86Dir = @"C:\Program Files (x86)",
            ProgramDataDir = @"C:\ProgramData",
            UserProfileDir = userProfile,
            LocalAppDataDir = localAppData,
            RoamingAppDataDir = roamingAppData,
            LocalLowAppDataDir = localLowAppData,
            UserTempDir = userTemp,
            SystemTempDir = @"C:\Windows\Temp",
            DownloadsDir = downloads,
            DocumentsDir = documents,
            DesktopDir = desktop,
            IsElevatedAdmin = false,
            MachineName = "DEV-TEST-PC",
            CurrentUserName = "DevUser",
            OsVersionDescription = "Microsoft Windows 11 25H2"
        };

        _envProvider = new WindowsEnvironmentProvider(_simulatedEnv);
        _protector = new SystemPathProtector(_envProvider);
        _lockDetector = new FileLockDetector();
        _classifier = new StorageClassifier(_envProvider, _protector);
        _validator = new CleanupSafetyValidator(_protector, _lockDetector);
        _historyRepo = new OperationHistoryRepository(_envProvider, Path.Combine(_isolatedRoot, "cleanup_history.json"));
    }

    [Fact]
    public async Task SafeCleanup_AllowsVerifiedTempFiles_AndBlocksProtectedOrRedItemsInMixedSelection()
    {
        string safeTempFile = Path.Combine(_simulatedEnv.UserTempDir, "old_cache_1.tmp");
        await File.WriteAllBytesAsync(safeTempFile, new byte[8192]);
        File.SetLastWriteTimeUtc(safeTempFile, DateTime.UtcNow.AddDays(-5));

        string personalDocFile = Path.Combine(_simulatedEnv.DocumentsDir, "contrato_importante.pdf");
        await File.WriteAllBytesAsync(personalDocFile, new byte[16384]);

        StorageItem tempItem = new()
        {
            Name = "old_cache_1.tmp",
            FullPath = safeTempFile,
            LogicalSizeBytes = 8192,
            LastModifiedUtc = DateTime.UtcNow.AddDays(-5),
            IsDirectory = false
        };
        _classifier.ClassifyItem(tempItem);

        StorageItem docItem = new()
        {
            Name = "contrato_importante.pdf",
            FullPath = personalDocFile,
            LogicalSizeBytes = 16384,
            LastModifiedUtc = DateTime.UtcNow.AddDays(-1),
            IsDirectory = false
        };
        _classifier.ClassifyItem(docItem);

        StorageItem systemItem = new()
        {
            Name = "System32",
            FullPath = @"C:\Windows\System32",
            LogicalSizeBytes = 1_000_000_000,
            LastModifiedUtc = DateTime.UtcNow,
            IsDirectory = true
        };
        _classifier.ClassifyItem(systemItem);

        // Executor isolado de teste que remove apenas arquivos dentro da pasta _isolatedRoot
        SafeCleanupService cleanupService = new(_validator, _historyRepo, (path, isDir, _) =>
        {
            Assert.StartsWith(_isolatedRoot, path, StringComparison.OrdinalIgnoreCase);
            if (isDir)
            {
                Directory.Delete(path, recursive: true);
            }
            else
            {
                File.Delete(path);
            }
        });

        CleanupPreviewReport preview = cleanupService.BuildPreview([tempItem, docItem, systemItem], preferRecycleBin: true);

        Assert.Single(preview.ApprovedItems);
        Assert.Equal(2, preview.BlockedItems.Count);
        Assert.Equal(8192L, preview.TotalEstimatedBytesToRecover);

        CleanupExecutionResult result = await cleanupService.ExecuteCleanupAsync(preview, progress: null, CancellationToken.None);

        Assert.Equal(1, result.TotalSucceeded);
        Assert.Equal(2, result.TotalSkippedOrBlocked);
        Assert.Equal(0, result.TotalFailedOrLocked);
        Assert.Equal(8192L, result.TotalBytesRecovered);

        Assert.False(File.Exists(safeTempFile));
        Assert.True(File.Exists(personalDocFile)); // Arquivo pessoal permanece 100% intacto!
        Assert.NotEmpty(_historyRepo.GetHistory());
    }

    [Fact]
    public async Task SafeCleanup_HandlesFailureOrLockDuringCleanupGracefullyWithoutCrashing()
    {
        string tempFile1 = Path.Combine(_simulatedEnv.UserTempDir, "temp_ok.tmp");
        string tempFile2 = Path.Combine(_simulatedEnv.UserTempDir, "temp_becomes_locked.tmp");

        await File.WriteAllBytesAsync(tempFile1, new byte[4096]);
        await File.WriteAllBytesAsync(tempFile2, new byte[4096]);
        File.SetLastWriteTimeUtc(tempFile1, DateTime.UtcNow.AddDays(-3));
        File.SetLastWriteTimeUtc(tempFile2, DateTime.UtcNow.AddDays(-3));

        StorageItem item1 = new()
        {
            Name = "temp_ok.tmp",
            FullPath = tempFile1,
            LogicalSizeBytes = 4096,
            LastModifiedUtc = DateTime.UtcNow.AddDays(-3),
            IsDirectory = false
        };
        _classifier.ClassifyItem(item1);

        StorageItem item2 = new()
        {
            Name = "temp_becomes_locked.tmp",
            FullPath = tempFile2,
            LogicalSizeBytes = 4096,
            LastModifiedUtc = DateTime.UtcNow.AddDays(-3),
            IsDirectory = false
        };
        _classifier.ClassifyItem(item2);

        SafeCleanupService cleanupService = new(_validator, _historyRepo, (path, _, _) => File.Delete(path));

        // 1. Gera a prévia quando ambos estão livres
        CleanupPreviewReport preview = cleanupService.BuildPreview([item1, item2], preferRecycleBin: false);
        Assert.Equal(2, preview.ApprovedItems.Count);

        // 2. Simula um processo bloqueando o segundo arquivo exatamente entre a prévia e a execução!
        using FileStream midExecutionLock = new(tempFile2, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        CleanupExecutionResult execResult = await cleanupService.ExecuteCleanupAsync(preview, progress: null, CancellationToken.None);

        Assert.Equal(1, execResult.TotalSucceeded);
        Assert.Equal(1, execResult.TotalSkippedOrBlocked);
        Assert.Equal(4096L, execResult.TotalBytesRecovered);
        Assert.False(File.Exists(tempFile1));
        Assert.True(File.Exists(tempFile2));
    }

    [Fact]
    public async Task EndToEndDiskScan_DetectsHeavyFolders_AppData_DevArtifacts_AndHighDensityFolders()
    {
        // 1. Cria estrutura do Chrome no AppData\Local (Cache + Local Storage)
        string chromeCache = Path.Combine(_simulatedEnv.LocalAppDataDir, "Google", "Chrome", "User Data", "Default", "Cache");
        string chromeSessions = Path.Combine(_simulatedEnv.LocalAppDataDir, "Google", "Chrome", "User Data", "Default", "Local Storage");
        Directory.CreateDirectory(chromeCache);
        Directory.CreateDirectory(chromeSessions);
        await File.WriteAllBytesAsync(Path.Combine(chromeCache, "cache_block.bin"), new byte[32768]);
        await File.WriteAllBytesAsync(Path.Combine(chromeSessions, "session_db.ldb"), new byte[16384]);

        // 2. Cria projeto Node.js com package.json, lockfile e node_modules (um projeto de verdade tem lockfile ou Git)
        string nodeProject = Path.Combine(_isolatedRoot, "Projetos", "WebPortal");
        string nodeModules = Path.Combine(nodeProject, "node_modules");
        Directory.CreateDirectory(nodeModules);
        await File.WriteAllTextAsync(Path.Combine(nodeProject, "package.json"), "{ \"name\": \"web-portal\" }");
        await File.WriteAllTextAsync(Path.Combine(nodeProject, "package-lock.json"), "{ \"lockfileVersion\": 3 }");
        await File.WriteAllBytesAsync(Path.Combine(nodeModules, "bundle.js"), new byte[65536]);

        // 3. Cria diretório denso com 120 pequenos arquivos (< 16 KB)
        string denseDir = Path.Combine(_isolatedRoot, "Projetos", "SmallFilesCluster");
        Directory.CreateDirectory(denseDir);
        for (int i = 0; i < 120; i++)
        {
            await File.WriteAllBytesAsync(Path.Combine(denseDir, $"tiny_{i:D4}.dat"), new byte[256]);
        }

        DiskScannerService scanner = new(_envProvider, _protector, _classifier, _historyRepo);
        DriveMetadata drive = new()
        {
            Name = "C:",
            RootDirectory = _isolatedRoot,
            VolumeLabel = "SimulatedDrive",
            FileSystem = "NTFS",
            DriveTypeDescription = "Disco Fixo Local",
            TotalBytes = 500_000_000,
            AvailableFreeBytes = 250_000_000,
            IsSystemDrive = false,
            IsReady = true
        };

        ScanResult result = await scanner.ScanAsync(drive, _isolatedRoot, progress: null, CancellationToken.None);

        Assert.True(result.TotalFilesScanned >= 123);
        Assert.True(result.TotalLogicalBytes > 100_000);
        Assert.NotEmpty(result.TopHeavyFolders);
        Assert.NotEmpty(result.HighDensityFolders);
        Assert.Contains(result.HighDensityFolders, d => d.Name == "SmallFilesCluster" && d.SmallFileCount >= 120);

        Assert.NotEmpty(result.AppDataEntries);
        AppDataEntry? chromeEntry = result.AppDataEntries.FirstOrDefault(a => a.IdentifiedApplication.Contains("Chrome", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(chromeEntry);
        Assert.Equal(32768L, chromeEntry!.SafeDisposableCacheBytes);
        Assert.Equal(16384L, chromeEntry.PersistentOrSensitiveBytes);

        Assert.NotEmpty(result.DeveloperArtifacts);
        Assert.Contains(result.DeveloperArtifacts, d => d.Name == "node_modules");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_isolatedRoot))
            {
                Directory.Delete(_isolatedRoot, recursive: true);
            }
        }
        catch
        {
            // Ignora falha na remoção da pasta temporária
        }
    }
}

