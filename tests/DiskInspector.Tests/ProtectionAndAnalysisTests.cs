using System.Text;
using DiskInspector.Analysis;
using DiskInspector.Cleanup;
using DiskInspector.Core.Enums;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;
using DiskInspector.Infrastructure;
using Xunit;

namespace DiskInspector.Tests;

/// <summary>
/// Suite de testes automatizados de Segurança, Proteção do Windows 11, Classificação Conservadora e Análise (Seção 12).
/// Utiliza exclusivamente diretórios temporários isolados, nunca tocando em arquivos reais do sistema.
/// </summary>
public sealed class ProtectionAndAnalysisTests : IDisposable
{
    private readonly string _isolatedRoot;
    private readonly EnvironmentPaths _simulatedEnv;
    private readonly IEnvironmentProvider _envProvider;
    private readonly ISystemPathProtector _protector;
    private readonly IFileLockDetector _lockDetector;
    private readonly IStorageClassifier _classifier;
    private readonly ICleanupSafetyValidator _validator;
    private readonly IOperationHistoryRepository _historyRepo;

    public ProtectionAndAnalysisTests()
    {
        _isolatedRoot = Path.Combine(Path.GetTempPath(), "DiskInspectorTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_isolatedRoot);

        string userProfile = Path.Combine(_isolatedRoot, "Users", "TestUser");
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
            MachineName = "TEST-MACHINE",
            CurrentUserName = "TestUser",
            OsVersionDescription = "Microsoft Windows 11 25H2 (Simulated Test Env)"
        };

        _envProvider = new WindowsEnvironmentProvider(_simulatedEnv);
        _protector = new SystemPathProtector(_envProvider);
        _lockDetector = new FileLockDetector();
        _classifier = new StorageClassifier(_envProvider, _protector);
        _validator = new CleanupSafetyValidator(_protector, _lockDetector);
        _historyRepo = new OperationHistoryRepository(_envProvider, Path.Combine(_isolatedRoot, "test_history.json"));
    }

    [Theory]
    [InlineData(@"C:\Windows")]
    [InlineData(@"C:\Windows\System32")]
    [InlineData(@"C:\Windows\System32\kernel32.dll")]
    [InlineData(@"C:\Windows\WinSxS")]
    [InlineData(@"C:\Windows\System32\DriverStore\FileRepository")]
    [InlineData(@"C:\Windows\SoftwareDistribution\Download")]
    [InlineData(@"C:\Program Files\Common Files")]
    [InlineData(@"C:\Program Files (x86)\Microsoft")]
    [InlineData(@"C:\ProgramData\Microsoft\Windows Defender")]
    [InlineData(@"C:\Recovery")]
    [InlineData(@"C:\$Recycle.Bin")]
    [InlineData(@"C:\System Volume Information")]
    [InlineData(@"C:\EFI")]
    [InlineData(@"C:\pagefile.sys")]
    [InlineData(@"C:\hiberfil.sys")]
    public void CriticalWindows11Paths_MustAlwaysBeProtectedAndBlockedFromCleanup(string criticalPath)
    {
        bool isProtected = _protector.IsProtectedSystemPath(criticalPath, out string reason, out _);
        Assert.True(isProtected);
        Assert.False(string.IsNullOrWhiteSpace(reason));

        StorageItem item = new()
        {
            Name = Path.GetFileName(criticalPath),
            FullPath = criticalPath,
            LogicalSizeBytes = 1024 * 1024,
            LastModifiedUtc = DateTime.UtcNow.AddDays(-100),
            IsDirectory = !Path.HasExtension(criticalPath)
        };

        _classifier.ClassifyItem(item);

        Assert.Equal(RiskLevel.Gray, item.RiskClassification);
        Assert.True(item.IsProtectedSystemItem);
        Assert.False(item.CanSelectForCleanup);

        // Tenta forçar seleção na propriedade e garante que continua false
        item.IsSelectedForCleanup = true;
        Assert.False(item.IsSelectedForCleanup);

        SafetyValidationDecision decision = _validator.ValidateForCleanup(item, preferRecycleBin: true);
        Assert.False(decision.IsAllowed);
        Assert.Contains("BLOQUEADO", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ConservativeClassification_FolderNamedCacheInUnknownLocation_MustNotBeAuthorizedForDeletion()
    {
        // Seção 6: "A análise de risco deve ser conservadora. Um nome de pasta semelhante a 'cache' não é evidência suficiente para autorizar sua exclusão."
        string customProjectCache = Path.Combine(_isolatedRoot, "MeusProjetos", "SistemaFinanceiro", "cache");
        Directory.CreateDirectory(customProjectCache);

        StorageItem item = new()
        {
            Name = "cache",
            FullPath = customProjectCache,
            LogicalSizeBytes = 50 * 1024 * 1024,
            LastModifiedUtc = DateTime.UtcNow.AddDays(-30),
            IsDirectory = true
        };

        _classifier.ClassifyItem(item);

        Assert.Equal(RiskLevel.Gray, item.RiskClassification);
        Assert.Equal(ItemCategory.Unknown, item.Category);
        Assert.False(item.CanSelectForCleanup);

        SafetyValidationDecision decision = _validator.ValidateForCleanup(item, preferRecycleBin: true);
        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public void AppDataClassification_SeparatesVerifiedBrowserCacheFromSensitiveSessionsAndDatabases()
    {
        string chromeCacheDir = Path.Combine(_simulatedEnv.LocalAppDataDir, "Google", "Chrome", "User Data", "Default", "Cache");
        string chromeLocalStorageDir = Path.Combine(_simulatedEnv.LocalAppDataDir, "Google", "Chrome", "User Data", "Default", "Local Storage");
        Directory.CreateDirectory(chromeCacheDir);
        Directory.CreateDirectory(chromeLocalStorageDir);
        File.WriteAllText(Path.Combine(chromeCacheDir, "data_0"), "cached_http_payload");
        File.WriteAllText(Path.Combine(chromeLocalStorageDir, "leveldb.ldb"), "user_session_tokens");

        StorageItem cacheItem = new()
        {
            Name = "Cache",
            FullPath = chromeCacheDir,
            LogicalSizeBytes = 10240,
            LastModifiedUtc = DateTime.UtcNow.AddDays(-5),
            IsDirectory = true
        };

        StorageItem sessionItem = new()
        {
            Name = "Local Storage",
            FullPath = chromeLocalStorageDir,
            LogicalSizeBytes = 20480,
            LastModifiedUtc = DateTime.UtcNow.AddDays(-5),
            IsDirectory = true
        };

        _classifier.ClassifyItem(cacheItem);
        _classifier.ClassifyItem(sessionItem);

        // Cache verificado do Chrome -> Verde (Baixo Risco)
        Assert.Equal(RiskLevel.Green, cacheItem.RiskClassification);
        Assert.True(cacheItem.CanSelectForCleanup);
        Assert.True(_validator.ValidateForCleanup(cacheItem, preferRecycleBin: true).IsAllowed);

        // Local Storage (Sessões/Bancos) -> Vermelho (Alto Risco) e Bloqueado!
        Assert.Equal(RiskLevel.Red, sessionItem.RiskClassification);
        Assert.False(sessionItem.CanSelectForCleanup);
        Assert.False(_validator.ValidateForCleanup(sessionItem, preferRecycleBin: true).IsAllowed);
    }

    [Fact]
    public void DockerAndWslVirtualDisks_MustAlwaysBeClassifiedAsRedHighRiskAndBlocked()
    {
        string vhdxPath = Path.Combine(_simulatedEnv.LocalAppDataDir, "Docker", "wsl", "data", "ext4.vhdx");
        Directory.CreateDirectory(Path.GetDirectoryName(vhdxPath)!);
        File.WriteAllBytes(vhdxPath, [1, 2, 3, 4]);

        StorageItem vhdxItem = new()
        {
            Name = "ext4.vhdx",
            FullPath = vhdxPath,
            LogicalSizeBytes = 20L * 1024 * 1024 * 1024,
            LastModifiedUtc = DateTime.UtcNow,
            IsDirectory = false
        };

        _classifier.ClassifyItem(vhdxItem);

        Assert.Equal(RiskLevel.Red, vhdxItem.RiskClassification);
        Assert.Equal(ItemCategory.ContainerOrVirtualization, vhdxItem.Category);
        Assert.False(vhdxItem.CanSelectForCleanup);
        Assert.False(_validator.ValidateForCleanup(vhdxItem, preferRecycleBin: true).IsAllowed);
    }

    [Fact]
    public void LockedFileInUse_MustBeDetectedAndBlockedFromCleanup()
    {
        string lockedFilePath = Path.Combine(_simulatedEnv.UserTempDir, "active_session.tmp");
        using FileStream activeLock = new(lockedFilePath, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        activeLock.Write("em_uso"u8);
        activeLock.Flush();

        Assert.True(_lockDetector.IsFileLocked(lockedFilePath));

        StorageItem tempItem = new()
        {
            Name = "active_session.tmp",
            FullPath = lockedFilePath,
            LogicalSizeBytes = 100,
            LastModifiedUtc = DateTime.UtcNow.AddDays(-2),
            IsDirectory = false
        };

        // A classificação (análise) não abre arquivos: quem detecta o uso é a validação da limpeza.
        _classifier.ClassifyItem(tempItem);
        Assert.Equal(ItemCategory.TemporaryFiles, tempItem.Category);

        SafetyValidationDecision decision = _validator.ValidateForCleanup(tempItem, preferRecycleBin: true);
        Assert.False(decision.IsAllowed);
        Assert.Contains("em Uso", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SymbolicLinksAndReparsePoints_MustNeverBeDeletedOrSelected()
    {
        string reparsePath = Path.Combine(_isolatedRoot, "SimulatedJunction");
        StorageItem reparseItem = new()
        {
            Name = "SimulatedJunction",
            FullPath = reparsePath,
            LogicalSizeBytes = 4096,
            LastModifiedUtc = DateTime.UtcNow,
            IsDirectory = true,
            IsReparsePoint = true
        };

        _classifier.ClassifyItem(reparseItem);

        Assert.Equal(RiskLevel.Gray, reparseItem.RiskClassification);
        Assert.False(reparseItem.CanSelectForCleanup);

        SafetyValidationDecision decision = _validator.ValidateForCleanup(reparseItem, preferRecycleBin: true);
        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public void NonExistentPath_MustBeRejectedByValidator()
    {
        string missingPath = Path.Combine(_simulatedEnv.UserTempDir, "arquivo_que_nao_existe_12345.tmp");
        StorageItem item = new()
        {
            Name = "arquivo_que_nao_existe_12345.tmp",
            FullPath = missingPath,
            LogicalSizeBytes = 1024,
            LastModifiedUtc = DateTime.UtcNow.AddDays(-10),
            IsDirectory = false,
            RiskClassification = RiskLevel.Green,
            Recommendation = RecommendedAction.SafeToMoveToRecycleBin
        };

        SafetyValidationDecision decision = _validator.ValidateForCleanup(item, preferRecycleBin: true);
        Assert.False(decision.IsAllowed);
        Assert.Contains("não existe", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InaccessibleDirectoryWithoutAdminPrivileges_IsClassifiedAsGrayWithoutCrashing()
    {
        StorageItem restrictedDir = new()
        {
            Name = "PastaRestritaACL",
            FullPath = Path.Combine(_isolatedRoot, "PastaRestritaACL"),
            LogicalSizeBytes = 0,
            AccessDeniedCount = 1,
            LastModifiedUtc = DateTime.UtcNow,
            IsDirectory = true
        };

        _classifier.ClassifyItem(restrictedDir);

        Assert.Equal(RiskLevel.Gray, restrictedDir.RiskClassification);
        Assert.False(restrictedDir.CanSelectForCleanup);
    }

    [Fact]
    public async Task DuplicateFileDetector_IdentifiesExactSha256DuplicatesAndProtectsCanonicalOriginal()
    {
        string dupRoot = Path.Combine(_isolatedRoot, "DupTest");
        string folderA = Path.Combine(dupRoot, "FolderA");
        string folderB = Path.Combine(dupRoot, "FolderB");
        Directory.CreateDirectory(folderA);
        Directory.CreateDirectory(folderB);

        byte[] payload = Encoding.UTF8.GetBytes(new string('X', 4096) + "_CONTEUDO_DUPLICADO_EXATO");
        string fileOriginal = Path.Combine(folderA, "relatorio_original.bin");
        string fileCopy = Path.Combine(folderB, "relatorio_copia.bin");
        string fileDifferent = Path.Combine(folderB, "relatorio_diferente.bin");

        await File.WriteAllBytesAsync(fileOriginal, payload);
        File.SetLastWriteTimeUtc(fileOriginal, DateTime.UtcNow.AddDays(-10));

        await File.WriteAllBytesAsync(fileCopy, payload);
        File.SetLastWriteTimeUtc(fileCopy, DateTime.UtcNow.AddDays(-1));

        await File.WriteAllBytesAsync(fileDifferent, Encoding.UTF8.GetBytes(new string('Y', 4096) + "_DIFERENTE"));

        DuplicateFileDetector detector = new(_protector);
        IReadOnlyList<DuplicateGroup> groups = await detector.FindDuplicatesAsync(
            dupRoot,
            minimumFileSizeBytes: 100,
            statusProgress: null,
            CancellationToken.None);

        Assert.Single(groups);
        DuplicateGroup group = groups[0];
        Assert.Equal(2, group.Entries.Count);

        DuplicateFileEntry originalEntry = group.Entries.First(e => e.IsCanonicalOriginal);
        DuplicateFileEntry duplicateEntry = group.Entries.First(e => !e.IsCanonicalOriginal);

        Assert.Equal(fileOriginal, originalEntry.FullPath);
        Assert.False(originalEntry.StorageItem.CanSelectForCleanup);
        Assert.False(_validator.ValidateForCleanup(originalEntry.StorageItem, preferRecycleBin: true).IsAllowed);

        Assert.Equal(fileCopy, duplicateEntry.FullPath);
        Assert.True(duplicateEntry.StorageItem.CanSelectForCleanup);
        Assert.True(_validator.ValidateForCleanup(duplicateEntry.StorageItem, preferRecycleBin: true).IsAllowed);
    }

    [Fact]
    public async Task DiskScannerService_HonorsCancellationTokenImmediately()
    {
        DiskScannerService scanner = new(_envProvider, _protector, _classifier, _historyRepo);
        DriveMetadata fakeDrive = new()
        {
            Name = "C:",
            RootDirectory = _isolatedRoot,
            VolumeLabel = "TestDrive",
            FileSystem = "NTFS",
            DriveTypeDescription = "Disco Fixo Local",
            TotalBytes = 100_000_000,
            AvailableFreeBytes = 50_000_000,
            IsSystemDrive = false,
            IsReady = true
        };

        using CancellationTokenSource cts = new();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            scanner.ScanAsync(fakeDrive, _isolatedRoot, progress: null, cts.Token));
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
            // Ignora falha de limpeza de pasta temporária de teste
        }
    }
}

