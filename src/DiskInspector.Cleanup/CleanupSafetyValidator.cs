using DiskInspector.Core.Enums;
using DiskInspector.Core.Formatting;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Cleanup;

/// <summary>
/// Validador estrito e centralizado de segurança (Gatekeeper).
/// Garante que NENHUM item Vermelho (Alto Risco), Cinza (Protegido/Desconhecido), caminho crítico do Windows 11,
/// raiz de perfil, link simbólico/reparse point ou arquivo em uso seja autorizado para exclusão (Seções 5, 6, 8 e 12).
///
/// Com a opção "Usar Lixeira" ligada, a validação também garante que o item realmente pode ser desfeito:
/// se não houver Lixeira no volume ou o item não couber nela, ele é BLOQUEADO em vez de excluído em definitivo.
/// </summary>
public sealed class CleanupSafetyValidator : ICleanupSafetyValidator
{
    // Quantas entradas no máximo são inspecionadas para saber se uma pasta mudou depois da análise
    private const int MaxEntriesForChangeCheck = 20_000;

    // Tolerância entre o relógio da análise e o carimbo de data gravado pelo sistema de arquivos
    private static readonly TimeSpan ChangeTolerance = TimeSpan.FromSeconds(2);

    private readonly ISystemPathProtector _systemPathProtector;
    private readonly IFileLockDetector _fileLockDetector;
    private readonly IRecycleBin? _recycleBin;

    public CleanupSafetyValidator(
        ISystemPathProtector systemPathProtector,
        IFileLockDetector fileLockDetector,
        IRecycleBin? recycleBin = null)
    {
        _systemPathProtector = systemPathProtector;
        _fileLockDetector = fileLockDetector;
        _recycleBin = recycleBin;
    }

    public SafetyValidationDecision ValidateForCleanup(
        StorageItem item,
        bool preferRecycleBin,
        CleanupValidationStage stage = CleanupValidationStage.Preview)
    {
        ArgumentNullException.ThrowIfNull(item);

        string path = item.FullPath;

        // 1. Caminho vazio
        if (string.IsNullOrWhiteSpace(path))
        {
            return Block("Caminho vazio ou inválido.");
        }

        // 2. Proteção incondicional de caminhos críticos do Windows 11 (mesmo se o arquivo não existir no disco de teste)
        if (_systemPathProtector.IsProtectedSystemPath(path, out string sysReason, out string? officialGuidance))
        {
            string msg = string.IsNullOrWhiteSpace(officialGuidance)
                ? $"BLOQUEADO (Proteção do Windows 11): {sysReason}"
                : $"BLOQUEADO (Proteção do Windows 11): {sysReason} Use: {officialGuidance}";
            return new SafetyValidationDecision
            {
                IsAllowed = false,
                Reason = msg,
                AllowedMethod = officialGuidance is null
                    ? CleanupOperationMethod.NoneReadOnly
                    : CleanupOperationMethod.OfficialToolGuidanceOnly,
                IsRecycleBinSupported = false
            };
        }

        // 3. Proteção de pastas-raiz estruturais do perfil do usuário
        if (_systemPathProtector.IsCriticalRootOrProfileFolder(path, out string rootReason))
        {
            return Block($"BLOQUEADO (Raiz de Perfil/Unidade): {rootReason}");
        }

        // 4. Proteção contra Links Simbólicos, Junctions e Reparse Points
        if (item.IsReparsePoint || HasReparsePointAttributeOnDisk(path))
        {
            return Block("BLOQUEADO: Links simbólicos, junctions e reparse points nunca são removidos pelo mecanismo de limpeza.");
        }

        // 5. Verificar se o arquivo está marcado como em uso
        if (item.IsLockedInUse)
        {
            return Block("BLOQUEADO (Arquivo em Uso): O item está aberto por outro processo em execução. Feche o aplicativo correspondente antes de limpar.");
        }

        // 6. Bloqueio incondicional de categorias de risco CINZA e VERMELHO (Seção 6: "A aplicação nunca deve excluir automaticamente itens vermelhos ou cinzas")
        if (item.RiskClassification == RiskLevel.Gray)
        {
            return Block("BLOQUEADO (Risco CINZA — Protegido ou Desconhecido): A política de segurança proíbe a exclusão de itens desconhecidos ou protegidos.");
        }

        if (item.RiskClassification == RiskLevel.Red)
        {
            return Block("BLOQUEADO (Risco VERMELHO — Alto Risco): Dados persistentes, configurações, projetos, bancos locais e discos Docker/WSL2 não podem ser excluídos pelo otimizador.");
        }

        if (item.IsProtectedSystemItem)
        {
            return Block("BLOQUEADO: Item marcado com flag de proteção interna (ex.: cópia original de arquivo duplicado ou componente de sistema).");
        }

        // 6b. Só o item de primeiro nível de um achado pode ser limpo, e só pelas ações de limpeza direta
        if (item.Recommendation == RecommendedAction.CleanViaParentItem)
        {
            return Block("BLOQUEADO: Este item faz parte de um item maior. Selecione o item de primeiro nível, que é verificado por inteiro.");
        }

        if (item.Recommendation is not (RecommendedAction.SafeToMoveToRecycleBin
            or RecommendedAction.SafeToCleanWhenAppClosed
            or RecommendedAction.KeepOriginalRemoveDuplicateCopy))
        {
            return Block("BLOQUEADO: A ação recomendada para este item não é a exclusão direta (use a ferramenta ou o comando oficial indicado).");
        }

        // 7. Verificar existência física no disco
        bool existsOnDisk = item.IsDirectory ? Directory.Exists(path) : File.Exists(path);
        if (!existsOnDisk)
        {
            return Block("BLOQUEADO: O caminho especificado não existe mais no sistema de arquivos.");
        }

        // 7b. O item mudou depois da análise? A classificação (idade, tamanho) foi feita sobre o estado antigo.
        if (HasChangedSinceAnalysis(item, path, out string changeDescription))
        {
            return Block($"BLOQUEADO (Alterado após a análise): {changeDescription} Refaça a análise para reavaliar este item.");
        }

        // 8. Verificar no disco se o arquivo ou diretório possui arquivos bloqueados/em uso por processos ativos.
        // Para pastas esta é uma amostra informativa: a garantia vem da própria remoção, que é atômica
        // (a pasta inteira muda de lugar de uma vez, ou nada acontece se houver arquivo aberto dentro dela).
        bool isLocked = item.IsDirectory
            ? _fileLockDetector.ContainsLockedFiles(path, maxSampleCount: 30)
            : _fileLockDetector.IsFileLocked(path);

        if (isLocked)
        {
            IReadOnlyList<LockingProcessInfo> holders = _fileLockDetector.GetLockingProcesses(path, maxSampleFiles: 15);
            string whoText = holders.Count > 0
                ? $" por {string.Join(", ", holders.Take(3).Select(h => h.DisplaySummary))}"
                : string.Empty;
            return Block($"BLOQUEADO (Arquivo em Uso{whoText}): O item está aberto por outro processo em execução. Feche o aplicativo correspondente antes de limpar.");
        }

        // 9. Com "Usar Lixeira" ligado, o item precisa ser de fato reversível
        if (preferRecycleBin)
        {
            string? recycleProblem = DescribeRecycleProblem(item, path);
            if (recycleProblem is not null)
            {
                return Block($"BLOQUEADO (Sem possibilidade de desfazer): {recycleProblem} Para remover mesmo assim, desmarque \"Usar Lixeira\" — a exclusão será definitiva.");
            }

            return new SafetyValidationDecision
            {
                IsAllowed = true,
                Reason = $"Qualificado ({item.ShortRiskBadge}). Será movido para a Lixeira do Windows.",
                AllowedMethod = CleanupOperationMethod.MoveToRecycleBin,
                IsRecycleBinSupported = true
            };
        }

        return new SafetyValidationDecision
        {
            IsAllowed = true,
            Reason = $"Qualificado ({item.ShortRiskBadge}). ATENÇÃO: exclusão direta e definitiva (a opção \"Usar Lixeira\" está desmarcada).",
            AllowedMethod = CleanupOperationMethod.DirectPermanentDelete,
            IsRecycleBinSupported = false
        };
    }

    private string? DescribeRecycleProblem(StorageItem item, string path)
    {
        if (_recycleBin is null)
        {
            return IsRecycleBinSupportedForPath(path)
                ? null
                : "O volume ou caminho não oferece suporte à Lixeira do Windows.";
        }

        RecycleBinStatus status = _recycleBin.GetStatus(path);
        if (!status.IsAvailable)
        {
            return status.UnavailableReason ?? "A Lixeira não está disponível neste volume.";
        }

        if (status.CapacityBytes is long capacity && item.LogicalSizeBytes > capacity)
        {
            return $"O item ({ByteSizeFormatter.FormatBytes(item.LogicalSizeBytes)}) é maior que o tamanho máximo da Lixeira deste volume ({ByteSizeFormatter.FormatBytes(capacity)}); o Windows o excluiria em definitivo.";
        }

        return null;
    }

    /// <summary>
    /// Compara o estado atual com o que a análise registrou. Só se aplica a itens que trazem esse registro
    /// (os produzidos pelo motor de varredura ou pelo detector de duplicados).
    /// </summary>
    private static bool HasChangedSinceAnalysis(StorageItem item, string path, out string description)
    {
        description = string.Empty;
        if (item.LatestContentWriteUtc == DateTime.MinValue)
        {
            return false;
        }

        DateTime recorded = item.EffectiveLatestWriteUtc + ChangeTolerance;

        try
        {
            if (!item.IsDirectory)
            {
                FileInfo info = new(path);
                if (info.Length != item.LogicalSizeBytes)
                {
                    description = "O tamanho do arquivo mudou desde a análise.";
                    return true;
                }

                if (info.LastWriteTimeUtc > recorded)
                {
                    description = "O arquivo foi modificado depois da análise.";
                    return true;
                }

                return false;
            }

            if (Directory.GetLastWriteTimeUtc(path) > recorded)
            {
                description = "Itens foram criados ou removidos nesta pasta depois da análise.";
                return true;
            }

            EnumerationOptions options = new()
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            };

            int inspected = 0;
            foreach (FileSystemInfo entry in new DirectoryInfo(path).EnumerateFileSystemInfos("*", options))
            {
                if (entry.LastWriteTimeUtc > recorded)
                {
                    description = $"Há conteúdo gravado depois da análise ('{entry.Name}').";
                    return true;
                }

                if (++inspected >= MaxEntriesForChangeCheck)
                {
                    break;
                }
            }
        }
        catch
        {
            // Sem conseguir inspecionar, as demais verificações (uso e reversibilidade) continuam valendo
        }

        return false;
    }

    private static SafetyValidationDecision Block(string reason) => new()
    {
        IsAllowed = false,
        Reason = reason,
        AllowedMethod = CleanupOperationMethod.NoneReadOnly,
        IsRecycleBinSupported = false
    };

    private static bool HasReparsePointAttributeOnDisk(string path)
    {
        try
        {
            FileAttributes attr = File.GetAttributes(path);
            return (attr & FileAttributes.ReparsePoint) != 0;
        }
        catch
        {
            return false;
        }
    }

    public static bool IsRecycleBinSupportedForPath(string path)
    {
        try
        {
            if (path.StartsWith(@"\\", StringComparison.Ordinal))
            {
                return false; // Caminhos UNC / rede não suportam Lixeira local do Windows
            }

            string? root = Path.GetPathRoot(path);
            if (string.IsNullOrWhiteSpace(root))
            {
                return false;
            }

            DriveInfo drive = new(root);
            return drive.IsReady && drive.DriveType == DriveType.Fixed;
        }
        catch
        {
            return false;
        }
    }
}
