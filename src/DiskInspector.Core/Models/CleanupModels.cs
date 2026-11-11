using DiskInspector.Core.Enums;
using DiskInspector.Core.Formatting;

namespace DiskInspector.Core.Models;

/// <summary>
/// Resultado da validação de segurança individual antes da limpeza.
/// </summary>
public sealed record SafetyValidationDecision
{
    public required bool IsAllowed { get; init; }
    public required string Reason { get; init; }
    public required CleanupOperationMethod AllowedMethod { get; init; }
    public required bool IsRecycleBinSupported { get; init; }
}

/// <summary>
/// Item individual na prévia detalhada de limpeza (Seção 8).
/// </summary>
public sealed record CleanupPreviewItem
{
    public required StorageItem Item { get; init; }
    public required bool IsApprovedForExecution { get; init; }
    public required CleanupOperationMethod PlannedMethod { get; init; }
    public required string ValidationMessage { get; init; }
    public required bool IsReversibleViaRecycleBin { get; init; }

    public string FormattedSize => ByteSizeFormatter.FormatBytes(Item.LogicalSizeBytes);
    public string MethodDisplayName => ByteSizeFormatter.GetCleanupMethodDisplayName(PlannedMethod);
}

/// <summary>
/// Relatório completo da prévia de limpeza antes da confirmação do usuário.
/// </summary>
public sealed class CleanupPreviewReport
{
    public required DateTime GeneratedAtUtc { get; init; }
    public required bool PreferRecycleBin { get; init; }
    public required IReadOnlyList<CleanupPreviewItem> ApprovedItems { get; init; }
    public required IReadOnlyList<CleanupPreviewItem> BlockedItems { get; init; }
    public required long TotalEstimatedBytesToRecover { get; init; }
    public required IReadOnlyList<string> SafetyWarnings { get; init; }

    public bool HasApprovedItems => ApprovedItems.Count > 0;
    public string FormattedEstimatedRecovery => ByteSizeFormatter.FormatBytes(TotalEstimatedBytesToRecover);
}

/// <summary>
/// Situação da Lixeira do Windows em um volume.
/// </summary>
public sealed record RecycleBinStatus
{
    /// <summary>False quando o volume não tem Lixeira (rede, removível) ou ela está desativada.</summary>
    public required bool IsAvailable { get; init; }
    public string? UnavailableReason { get; init; }

    /// <summary>Tamanho máximo configurado para a Lixeira do volume (null quando desconhecido).</summary>
    public long? CapacityBytes { get; init; }
    public long UsedBytes { get; init; }
    public long ItemCount { get; init; }

    /// <summary>
    /// Espaço que ainda cabe na Lixeira sem que o Windows descarte itens antigos (null quando desconhecido).
    /// </summary>
    public long? FreeBytes => CapacityBytes is null ? null : Math.Max(0L, CapacityBytes.Value - UsedBytes);

    public string FormattedUsed => ByteSizeFormatter.FormatBytes(UsedBytes);
    public string FormattedCapacity => CapacityBytes is null ? "desconhecida" : ByteSizeFormatter.FormatBytes(CapacityBytes.Value);
}

/// <summary>
/// Resultado de uma tentativa de envio para a Lixeira.
/// </summary>
public sealed record RecycleAttemptResult
{
    public required bool Succeeded { get; init; }

    /// <summary>
    /// True quando o Windows confirmou que o item iria para a Lixeira. Se for false e Succeeded também,
    /// algo está errado: a operação é abortada antes de qualquer exclusão definitiva.
    /// </summary>
    public required bool ConfirmedRecycled { get; init; }
    public required string Message { get; init; }
    public int HResult { get; init; }
}

/// <summary>
/// Resultado individual após a tentativa de limpeza de um arquivo ou diretório.
/// </summary>
public sealed record CleanupItemOutcome
{
    public required string FullPath { get; init; }
    public required bool Succeeded { get; init; }
    public required CleanupOperationMethod ExecutedMethod { get; init; }
    public required long BytesRecovered { get; init; }
    public required string StatusMessage { get; init; }

    // Contexto para auditoria: o que o item era e por que foi considerado elegível
    public bool IsDirectory { get; init; }
    public string RiskLabel { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string AssociatedApp { get; init; } = string.Empty;
}

/// <summary>
/// Resultado consolidado de uma sessão de limpeza controlada.
/// </summary>
public sealed class CleanupExecutionResult
{
    public required Guid ExecutionId { get; init; }
    public required DateTime TimestampUtc { get; init; }
    public required int TotalRequested { get; init; }
    public required int TotalSucceeded { get; init; }
    public required int TotalSkippedOrBlocked { get; init; }
    public required int TotalFailedOrLocked { get; init; }
    public required long TotalBytesRecovered { get; init; }
    public required IReadOnlyList<CleanupItemOutcome> Outcomes { get; init; }

    /// <summary>
    /// Bytes movidos para a Lixeira: ainda ocupam o disco até a Lixeira ser esvaziada.
    /// </summary>
    public long TotalBytesMovedToRecycleBin { get; init; }

    /// <summary>
    /// Bytes excluídos em definitivo: espaço já liberado no disco.
    /// </summary>
    public long TotalBytesPermanentlyDeleted { get; init; }

    /// <summary>
    /// Arquivo com o registro completo desta limpeza (todos os caminhos), quando gravado.
    /// </summary>
    public string? ManifestFilePath { get; set; }

    public string FormattedBytesRecovered => ByteSizeFormatter.FormatBytes(TotalBytesRecovered);
    public string FormattedBytesMovedToRecycleBin => ByteSizeFormatter.FormatBytes(TotalBytesMovedToRecycleBin);
    public string FormattedBytesPermanentlyDeleted => ByteSizeFormatter.FormatBytes(TotalBytesPermanentlyDeleted);
}

/// <summary>
/// Registro persistente no histórico de operações (varreduras e limpezas realizadas).
/// </summary>
public sealed record OperationLogEntry
{
    public required Guid Id { get; init; }
    public required DateTime TimestampUtc { get; init; }
    public required string OperationType { get; init; } // "Análise de Armazenamento", "Prévia de Limpeza", "Limpeza Controlada", "Bloqueio de Segurança"
    public required string TargetPath { get; init; }
    public required string Summary { get; init; }
    public required long AffectedBytes { get; init; }
    public required bool Succeeded { get; init; }
    public required string Details { get; init; }

    public string FormattedTimestamp => TimestampUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss");
    public string FormattedBytes => ByteSizeFormatter.FormatBytes(AffectedBytes);
    public string StatusBadge => Succeeded ? "Concluído" : "Atenção / Parcial";
}

/// <summary>
/// Processo que mantém um arquivo aberto, identificado via Windows Restart Manager (rstrtmgr.dll) sem travar o arquivo (Diferencial 7).
/// </summary>
public sealed record LockingProcessInfo
{
    public required int ProcessId { get; init; }
    public required string ProcessName { get; init; }
    public required string ApplicationTitle { get; init; }
    public required string LockedFilePath { get; init; }

    public string DisplaySummary => string.IsNullOrWhiteSpace(ApplicationTitle) ||
                                    string.Equals(ApplicationTitle, ProcessName, StringComparison.OrdinalIgnoreCase)
        ? $"{ProcessName} (PID {ProcessId})"
        : $"{ApplicationTitle} — {ProcessName} (PID {ProcessId})";
}

/// <summary>
/// Resultado da restauração ("Desfazer limpeza") de itens enviados para a Lixeira do Windows (Diferencial 7).
/// </summary>
public sealed record RecycleRestoreResult
{
    public required int TotalRequested { get; init; }
    public required int TotalRestored { get; init; }
    public required long BytesRestored { get; init; }
    public required IReadOnlyList<string> RestoredPaths { get; init; }
    public required IReadOnlyList<string> NotFoundOrFailedMessages { get; init; }

    public bool Succeeded => TotalRestored > 0 && NotFoundOrFailedMessages.Count == 0;
    public string FormattedBytesRestored => ByteSizeFormatter.FormatBytes(BytesRestored);
}

/// <summary>
/// Resultado da execução assistida de um comando oficial de limpeza/otimização com medição antes e depois (Diferenciais 4 e 6).
/// </summary>
public sealed record OfficialCommandExecutionResult
{
    public required string CommandExecuted { get; init; }
    public required string TargetPath { get; init; }
    public required bool Succeeded { get; init; }
    public required int ExitCode { get; init; }
    public required long BytesBefore { get; init; }
    public required long BytesAfter { get; init; }
    public required TimeSpan Duration { get; init; }
    public required string StandardOutput { get; init; }
    public required string StandardError { get; init; }
    public required string SummaryMessage { get; init; }

    public long BytesFreed => Math.Max(0L, BytesBefore - BytesAfter);
    public string FormattedBytesBefore => ByteSizeFormatter.FormatBytes(BytesBefore);
    public string FormattedBytesAfter => ByteSizeFormatter.FormatBytes(BytesAfter);
    public string FormattedBytesFreed => ByteSizeFormatter.FormatBytes(BytesFreed);
}


