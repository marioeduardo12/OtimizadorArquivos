using DiskInspector.Analysis;
using DiskInspector.Core.Enums;
using DiskInspector.Core.Formatting;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Cleanup;

/// <summary>
/// Serviço de limpeza controlada com prévia obrigatória, revalidação de segurança em tempo de execução,
/// suporte prioritário à Lixeira do Windows e registro completo de auditoria (Seção 8).
///
/// Garantias desta versão:
/// - Com "Usar Lixeira" ligado, nada é excluído em definitivo: o envio é recusado quando o Windows não
///   puder reciclar o item, e o conjunto aprovado nunca ultrapassa o espaço livre da Lixeira.
/// - Uma pasta é removida por inteiro ou não é tocada: se houver um arquivo aberto dentro dela, a operação falha limpa.
/// - Cada limpeza gera um registro com todos os caminhos, tamanhos, métodos e resultados.
/// </summary>
public sealed class SafeCleanupService : ISafeCleanupService
{
    private readonly ICleanupSafetyValidator _validator;
    private readonly IOperationHistoryRepository _historyRepository;
    private readonly Action<string, bool, CleanupOperationMethod>? _customFileSystemExecutor;
    private readonly IRecycleBin? _recycleBin;

    public SafeCleanupService(
        ICleanupSafetyValidator validator,
        IOperationHistoryRepository historyRepository,
        Action<string, bool, CleanupOperationMethod>? customFileSystemExecutor = null,
        IRecycleBin? recycleBin = null)
    {
        _validator = validator;
        _historyRepository = historyRepository;
        _customFileSystemExecutor = customFileSystemExecutor;
        _recycleBin = recycleBin;
    }

    public CleanupPreviewReport BuildPreview(IEnumerable<StorageItem> selectedItems, bool preferRecycleBin)
    {
        ArgumentNullException.ThrowIfNull(selectedItems);

        // Uma pasta selecionada já cobre tudo o que está dentro dela
        List<StorageItem> distinctItems = PathNesting.SelectTopMost(selectedItems, onlyDirectoriesContain: true);
        List<CleanupPreviewItem> approved = [];
        List<CleanupPreviewItem> blocked = [];
        List<string> warnings = [];

        // Espaço que ainda cabe na Lixeira de cada volume sem que o Windows descarte itens mais antigos
        Dictionary<string, long?> recycleBudgetByVolume = new(StringComparer.OrdinalIgnoreCase);
        int blockedByRecycleBudget = 0;

        foreach (StorageItem item in distinctItems)
        {
            SafetyValidationDecision decision = _validator.ValidateForCleanup(item, preferRecycleBin, CleanupValidationStage.Preview);

            if (decision.IsAllowed &&
                decision.AllowedMethod == CleanupOperationMethod.MoveToRecycleBin &&
                !TryReserveRecycleSpace(item, recycleBudgetByVolume, out string budgetProblem))
            {
                blockedByRecycleBudget++;
                decision = new SafetyValidationDecision
                {
                    IsAllowed = false,
                    Reason = $"BLOQUEADO (Lixeira sem espaço): {budgetProblem}",
                    AllowedMethod = CleanupOperationMethod.NoneReadOnly,
                    IsRecycleBinSupported = true
                };
            }

            CleanupPreviewItem previewItem = new()
            {
                Item = item,
                IsApprovedForExecution = decision.IsAllowed,
                PlannedMethod = decision.AllowedMethod,
                ValidationMessage = decision.Reason,
                IsReversibleViaRecycleBin = decision.AllowedMethod == CleanupOperationMethod.MoveToRecycleBin
            };

            if (decision.IsAllowed)
            {
                approved.Add(previewItem);
            }
            else
            {
                blocked.Add(previewItem);
            }
        }

        if (approved.Any(a => !a.IsReversibleViaRecycleBin))
        {
            warnings.Add("ATENÇÃO: Um ou mais itens aprovados serão excluídos permanentemente sem passar pela Lixeira. Essa operação poderá ser irreversível.");
        }

        if (approved.Any(a => a.IsReversibleViaRecycleBin))
        {
            warnings.Add("Os itens vão para a Lixeira do Windows e podem ser restaurados por lá. O espaço em disco só é liberado de fato quando a Lixeira for esvaziada.");
        }

        if (approved.Any(a => a.Item.RiskClassification == RiskLevel.Yellow))
        {
            warnings.Add("NOTA: A seleção inclui itens de risco AMARELO (ex.: caches de desenvolvimento, downloads antigos ou logs). Remover caches de desenvolvimento pode exigir novos downloads ou recompilações.");
        }

        if (blockedByRecycleBudget > 0)
        {
            warnings.Add($"{blockedByRecycleBudget} item(ns) ficaram de fora porque não cabem no espaço livre da Lixeira. Esvazie a Lixeira e gere a prévia novamente, ou desmarque \"Usar Lixeira\" para exclusão definitiva.");
        }

        if (blocked.Count > 0)
        {
            warnings.Add($"{blocked.Count} item(ns) foram bloqueados automaticamente pelas regras de proteção ou por estarem em uso.");
        }

        long totalRecoverable = approved.Sum(a => a.Item.LogicalSizeBytes);

        CleanupPreviewReport report = new()
        {
            GeneratedAtUtc = DateTime.UtcNow,
            PreferRecycleBin = preferRecycleBin,
            ApprovedItems = approved,
            BlockedItems = blocked,
            TotalEstimatedBytesToRecover = totalRecoverable,
            SafetyWarnings = warnings
        };

        _historyRepository.RecordOperation(new OperationLogEntry
        {
            Id = Guid.NewGuid(),
            TimestampUtc = report.GeneratedAtUtc,
            OperationType = "Prévia de Limpeza",
            TargetPath = $"{approved.Count} aprovados / {blocked.Count} bloqueados",
            Summary = $"Prévia gerada: {report.FormattedEstimatedRecovery} estimados para recuperação ({(preferRecycleBin ? "Priorizando Lixeira" : "Exclusão Direta")}).",
            AffectedBytes = totalRecoverable,
            Succeeded = true,
            Details = string.Join(" | ", warnings)
        });

        return report;
    }

    public Task<CleanupExecutionResult> ExecuteCleanupAsync(
        CleanupPreviewReport approvedPreview,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(approvedPreview);

        return Task.Run(() =>
        {
            List<CleanupItemOutcome> outcomes = [];
            int succeededCount = 0;
            int skippedOrBlockedCount = approvedPreview.BlockedItems.Count;
            int failedOrLockedCount = 0;
            long bytesRecycled = 0L;
            long bytesPermanentlyDeleted = 0L;

            // Registra também os itens que já haviam sido bloqueados na prévia
            foreach (CleanupPreviewItem blockedItem in approvedPreview.BlockedItems)
            {
                outcomes.Add(CreateOutcome(blockedItem.Item, false, CleanupOperationMethod.NoneReadOnly, blockedItem.ValidationMessage));
            }

            int total = approvedPreview.ApprovedItems.Count;
            int position = 0;

            foreach (CleanupPreviewItem candidate in approvedPreview.ApprovedItems)
            {
                position++;
                StorageItem item = candidate.Item;

                if (cancellationToken.IsCancellationRequested)
                {
                    skippedOrBlockedCount++;
                    outcomes.Add(CreateOutcome(item, false, CleanupOperationMethod.NoneReadOnly,
                        "Operação cancelada pelo usuário antes do processamento deste item."));
                    continue;
                }

                progress?.Report($"Limpando {position} de {total}: {item.FullPath}");

                // Revalidação estrita imediatamente antes da execução (proteção contra condição de corrida TOCTOU)
                SafetyValidationDecision liveCheck = _validator.ValidateForCleanup(item, approvedPreview.PreferRecycleBin, CleanupValidationStage.Execution);
                if (!liveCheck.IsAllowed)
                {
                    skippedOrBlockedCount++;
                    outcomes.Add(CreateOutcome(item, false, CleanupOperationMethod.NoneReadOnly, liveCheck.Reason));
                    continue;
                }

                try
                {
                    ExecuteSingleItemCleanup(item.FullPath, item.IsDirectory, liveCheck.AllowedMethod);

                    succeededCount++;
                    item.IsRemovedByCleanup = true;

                    bool recycled = liveCheck.AllowedMethod == CleanupOperationMethod.MoveToRecycleBin;
                    if (recycled)
                    {
                        bytesRecycled += item.LogicalSizeBytes;
                    }
                    else
                    {
                        bytesPermanentlyDeleted += item.LogicalSizeBytes;
                    }

                    outcomes.Add(CreateOutcome(item, true, liveCheck.AllowedMethod, recycled
                        ? "Movido para a Lixeira do Windows (pode ser restaurado por lá)."
                        : "Excluído em definitivo."));
                }
                catch (Exception ex)
                {
                    failedOrLockedCount++;
                    outcomes.Add(CreateOutcome(item, false, liveCheck.AllowedMethod,
                        $"Não foi removido: {ex.Message}"));
                }
            }

            CleanupExecutionResult result = new()
            {
                ExecutionId = Guid.NewGuid(),
                TimestampUtc = DateTime.UtcNow,
                TotalRequested = approvedPreview.ApprovedItems.Count + approvedPreview.BlockedItems.Count,
                TotalSucceeded = succeededCount,
                TotalSkippedOrBlocked = skippedOrBlockedCount,
                TotalFailedOrLocked = failedOrLockedCount,
                TotalBytesRecovered = bytesRecycled + bytesPermanentlyDeleted,
                TotalBytesMovedToRecycleBin = bytesRecycled,
                TotalBytesPermanentlyDeleted = bytesPermanentlyDeleted,
                Outcomes = outcomes
            };

            result.ManifestFilePath = _historyRepository.SaveCleanupManifest(result);

            string manifestNote = result.ManifestFilePath is null
                ? "Registro detalhado não pôde ser gravado."
                : $"Registro completo: {result.ManifestFilePath}";

            _historyRepository.RecordOperation(new OperationLogEntry
            {
                Id = result.ExecutionId,
                TimestampUtc = result.TimestampUtc,
                OperationType = "Limpeza Controlada",
                TargetPath = $"{result.TotalSucceeded} de {result.TotalRequested} itens limpos",
                Summary = $"Na Lixeira: {ByteSizeFormatter.FormatBytes(bytesRecycled)} | Excluído em definitivo: {ByteSizeFormatter.FormatBytes(bytesPermanentlyDeleted)} ({result.TotalSucceeded} removidos, {result.TotalSkippedOrBlocked} bloqueados/ignorados, {result.TotalFailedOrLocked} com falha).",
                AffectedBytes = result.TotalBytesRecovered,
                Succeeded = result.TotalFailedOrLocked == 0,
                Details = manifestNote
            });

            return result;
        }, CancellationToken.None);
    }

    /// <summary>
    /// Desconta o item do espaço livre da Lixeira do seu volume. Sem esse controle, o Windows abriria espaço
    /// descartando em definitivo os itens mais antigos da Lixeira, inclusive os enviados nesta mesma limpeza.
    /// </summary>
    private bool TryReserveRecycleSpace(StorageItem item, Dictionary<string, long?> budgetByVolume, out string problem)
    {
        problem = string.Empty;
        if (_recycleBin is null)
        {
            return true;
        }

        string volume;
        try
        {
            volume = Path.GetPathRoot(Path.GetFullPath(item.FullPath)) ?? string.Empty;
        }
        catch
        {
            return true;
        }

        if (!budgetByVolume.TryGetValue(volume, out long? remaining))
        {
            RecycleBinStatus status = _recycleBin.GetStatus(item.FullPath);
            remaining = status.IsAvailable ? status.FreeBytes : null;
            budgetByVolume[volume] = remaining;
        }

        if (remaining is null)
        {
            return true; // Capacidade desconhecida: a guarda do envio continua impedindo exclusão definitiva
        }

        if (item.LogicalSizeBytes > remaining.Value)
        {
            problem = $"o item tem {ByteSizeFormatter.FormatBytes(item.LogicalSizeBytes)} e restam {ByteSizeFormatter.FormatBytes(remaining.Value)} livres na Lixeira deste volume. Para abrir espaço, o Windows descartaria em definitivo os itens mais antigos dela.";
            return false;
        }

        budgetByVolume[volume] = remaining.Value - item.LogicalSizeBytes;
        return true;
    }

    private static CleanupItemOutcome CreateOutcome(StorageItem item, bool succeeded, CleanupOperationMethod method, string message) => new()
    {
        FullPath = item.FullPath,
        Succeeded = succeeded,
        ExecutedMethod = method,
        BytesRecovered = succeeded ? item.LogicalSizeBytes : 0L,
        StatusMessage = message,
        IsDirectory = item.IsDirectory,
        RiskLabel = item.RiskDisplayName,
        Category = item.CategoryDisplayName,
        AssociatedApp = item.AssociatedAppOrComponent
    };

    private void ExecuteSingleItemCleanup(string fullPath, bool isDirectory, CleanupOperationMethod method)
    {
        if (_customFileSystemExecutor is not null)
        {
            _customFileSystemExecutor(fullPath, isDirectory, method);
            return;
        }

        if (method == CleanupOperationMethod.MoveToRecycleBin)
        {
            if (_recycleBin is null)
            {
                throw new InvalidOperationException("O serviço de Lixeira não está disponível; nada foi removido.");
            }

            RecycleAttemptResult attempt = _recycleBin.SendToRecycleBin(fullPath);
            if (!attempt.Succeeded)
            {
                throw new IOException(attempt.Message);
            }
        }
        else if (method == CleanupOperationMethod.DirectPermanentDelete)
        {
            if (isDirectory)
            {
                DeleteDirectoryAllOrNothing(fullPath);
            }
            else
            {
                DeleteFileEvenIfReadOnly(fullPath);
            }
        }
        else
        {
            throw new InvalidOperationException($"Método de operação '{method}' não permite exclusão de arquivos.");
        }
    }

    /// <summary>
    /// Exclusão definitiva de pasta sem estado parcial: primeiro a pasta inteira é renomeada (o Windows recusa
    /// se houver qualquer arquivo aberto dentro dela, e nesse caso nada mudou); só depois o conteúdo é apagado.
    /// </summary>
    internal static void DeleteDirectoryAllOrNothing(string fullPath)
    {
        string trimmed = fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string parent = Path.GetDirectoryName(trimmed)
            ?? throw new IOException("Não é possível remover a raiz de uma unidade.");
        string staging = Path.Combine(parent, $"{Path.GetFileName(trimmed)}.removendo-{Guid.NewGuid().ToString("N")[..8]}");

        try
        {
            Directory.Move(trimmed, staging);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new IOException("A pasta contém arquivos em uso por outro programa (ou sem permissão). Nada foi alterado.", ex);
        }

        try
        {
            DeleteTree(staging);
        }
        catch (Exception ex)
        {
            throw new IOException($"A remoção começou, mas parte do conteúdo não pôde ser apagada. O que restou está em '{staging}'.", ex);
        }
    }

    private static void DeleteTree(string directoryPath)
    {
        EnumerationOptions options = new()
        {
            IgnoreInaccessible = false,
            RecurseSubdirectories = false,
            AttributesToSkip = 0
        };

        foreach (FileSystemInfo entry in new DirectoryInfo(directoryPath).EnumerateFileSystemInfos("*", options))
        {
            if (entry is DirectoryInfo subdirectory)
            {
                if ((subdirectory.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    // Link ou junction: remove só o atalho, nunca o destino
                    Directory.Delete(subdirectory.FullName, recursive: false);
                }
                else
                {
                    DeleteTree(subdirectory.FullName);
                }
            }
            else
            {
                DeleteFileEvenIfReadOnly(entry.FullName);
            }
        }

        DirectoryInfo self = new(directoryPath);
        if ((self.Attributes & FileAttributes.ReadOnly) != 0)
        {
            self.Attributes &= ~FileAttributes.ReadOnly;
        }

        Directory.Delete(directoryPath, recursive: false);
    }

    private static void DeleteFileEvenIfReadOnly(string filePath)
    {
        FileAttributes attributes = File.GetAttributes(filePath);
        if ((attributes & FileAttributes.ReadOnly) != 0)
        {
            File.SetAttributes(filePath, attributes & ~FileAttributes.ReadOnly);
        }

        File.Delete(filePath);
    }
}
