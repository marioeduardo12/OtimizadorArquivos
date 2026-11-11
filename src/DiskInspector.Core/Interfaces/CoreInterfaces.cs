using DiskInspector.Core.Enums;
using DiskInspector.Core.Models;

namespace DiskInspector.Core.Interfaces;

/// <summary>
/// Provedor de descoberta dinâmica de diretórios do sistema operacional e status de privilégio.
/// </summary>
public interface IEnvironmentProvider
{
    EnvironmentPaths GetEnvironmentPaths();
}

/// <summary>
/// Serviço especializado para descoberta das unidades de armazenamento disponíveis.
/// </summary>
public interface IDriveDiscoveryService
{
    IReadOnlyList<DriveMetadata> GetAvailableDrives();
}

/// <summary>
/// Serviço especializado para verificação de bloqueio de arquivos em uso e identificação do processo dono (Restart Manager).
/// </summary>
public interface IFileLockDetector
{
    bool IsFileLocked(string filePath);
    bool ContainsLockedFiles(string directoryPath, int maxSampleCount = 50);

    /// <summary>
    /// Identifica quais processos estão segurando um arquivo ou arquivos dentro de uma pasta usando
    /// o Windows Restart Manager (rstrtmgr.dll), sem abrir nem travar os arquivos.
    /// </summary>
    IReadOnlyList<LockingProcessInfo> GetLockingProcesses(string fileOrDirectoryPath, int maxSampleFiles = 25) => [];
}

/// <summary>
/// Guardião centralizado de proteção de caminhos críticos do Windows 11 (Seção 5).
/// </summary>
public interface ISystemPathProtector
{
    bool IsProtectedSystemPath(string fullPath, out string protectionReason, out string? officialToolGuidance);
    bool IsCriticalRootOrProfileFolder(string fullPath, out string reason);
}

/// <summary>
/// Serviço especializado de classificação semântica, análise de risco e recomendação (Seções 3 e 6).
/// </summary>
public interface IStorageClassifier
{
    void ClassifyItem(StorageItem item);

    /// <summary>
    /// Dica opcional do motor de varredura: nomes das subpastas diretas de um diretório que acabou de ser
    /// enumerado. Permite reconhecer a estrutura de um aplicativo sem consultar o disco de novo.
    /// </summary>
    void ObserveDirectoryStructure(string directoryPath, IReadOnlyList<string> subdirectoryNames)
    {
    }

    /// <summary>
    /// Descarta as dicas acumuladas (chamado ao final de cada varredura).
    /// </summary>
    void ResetObservations()
    {
    }
}

/// <summary>
/// Acesso à Lixeira do Windows: capacidade, ocupação e envio com garantia de que nada é excluído em definitivo.
/// </summary>
public interface IRecycleBin
{
    /// <summary>
    /// Situação da Lixeira do volume que contém o caminho informado.
    /// </summary>
    RecycleBinStatus GetStatus(string anyPathOnVolume);

    /// <summary>
    /// Move um arquivo ou pasta para a Lixeira. Se o Windows for excluir em definitivo
    /// (item grande demais, Lixeira desativada), a operação é recusada e o item permanece intacto.
    /// </summary>
    RecycleAttemptResult SendToRecycleBin(string fullPath);

    /// <summary>
    /// Esvazia a Lixeira (de um volume ou de todos). O Windows pede a confirmação ao usuário.
    /// </summary>
    bool Empty(string? driveRoot, IntPtr ownerWindow);

    /// <summary>
    /// Restaura da Lixeira do Windows os itens cujos caminhos originais correspondem à lista informada ("Desfazer limpeza").
    /// </summary>
    RecycleRestoreResult RestoreItems(IEnumerable<string> originalFullPaths) => new()
    {
        TotalRequested = 0,
        TotalRestored = 0,
        BytesRestored = 0,
        RestoredPaths = [],
        NotFoundOrFailedMessages = ["A restauração automática não está disponível nesta implementação."]
    };
}

/// <summary>
/// Serviço de snapshots por análise para responder "O que cresceu desde a última análise?" (Diferencial 3).
/// </summary>
public interface IScanSnapshotService
{
    IReadOnlyList<FolderGrowthDelta> CompareAndSaveSnapshot(
        string targetRootPath,
        DateTime scanCompletedUtc,
        long rootLogicalBytes,
        IEnumerable<StorageItem> trackedFolders,
        out DateTime? previousScanUtc,
        out long? previousRootBytes);
}

/// <summary>
/// Executor seguro de comandos oficiais de manutenção/limpeza e otimização sem exclusão, com medição antes e depois (Diferenciais 4 e 6).
/// </summary>
public interface IOfficialMaintenanceExecutor
{
    bool CanExecuteCommand(string? officialCommand, string? targetPath, out string executableActionDescription);

    Task<OfficialCommandExecutionResult> ExecuteOfficialCommandAsync(
        string officialCommand,
        string targetPath,
        IProgress<string>? progress,
        CancellationToken cancellationToken);

    Task<OfficialCommandExecutionResult> ExecuteNonDestructiveOptionAsync(
        NonDestructiveOption option,
        IProgress<string>? progress,
        CancellationToken cancellationToken);
}

/// <summary>
/// Serviço especializado para varredura profunda e assíncrona de unidades ou diretórios.
/// </summary>
public interface IDiskScannerService
{
    Task<ScanResult> ScanAsync(
        DriveMetadata drive,
        string? customRootPath,
        IProgress<ScanProgressReport>? progress,
        CancellationToken cancellationToken);
}

/// <summary>
/// Serviço especializado para detecção de arquivos duplicados por tamanho, pré-hash e SHA-256.
/// </summary>
public interface IDuplicateFileDetector
{
    Task<IReadOnlyList<DuplicateGroup>> FindDuplicatesAsync(
        string rootPath,
        long minimumFileSizeBytes,
        IProgress<string>? statusProgress,
        CancellationToken cancellationToken);
}

/// <summary>
/// Validador estrito de segurança antes de qualquer operação de limpeza (Seções 5, 6, 8 e 12).
/// </summary>
public interface ICleanupSafetyValidator
{
    SafetyValidationDecision ValidateForCleanup(
        StorageItem item,
        bool preferRecycleBin,
        CleanupValidationStage stage = CleanupValidationStage.Preview);
}

/// <summary>
/// Serviço de limpeza segura com prévia obrigatória, suporte à Lixeira e auditoria (Seção 8).
/// </summary>
public interface ISafeCleanupService
{
    CleanupPreviewReport BuildPreview(IEnumerable<StorageItem> selectedItems, bool preferRecycleBin);

    Task<CleanupExecutionResult> ExecuteCleanupAsync(
        CleanupPreviewReport approvedPreview,
        IProgress<string>? progress,
        CancellationToken cancellationToken);
}

/// <summary>
/// Repositório de registro de histórico de operações (varreduras e limpezas).
/// </summary>
public interface IOperationHistoryRepository
{
    IReadOnlyList<OperationLogEntry> GetHistory();
    void RecordOperation(OperationLogEntry entry);
    void ExportHistoryToJson(string outputFilePath);

    /// <summary>
    /// Grava o registro completo de uma limpeza (todos os itens, com caminho, tamanho, método e resultado).
    /// Retorna o caminho do arquivo gravado, ou null se não foi possível gravar.
    /// </summary>
    string? SaveCleanupManifest(CleanupExecutionResult result);
}

