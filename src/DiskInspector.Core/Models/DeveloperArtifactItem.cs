using DiskInspector.Core.Enums;
using DiskInspector.Core.Formatting;

namespace DiskInspector.Core.Models;

/// <summary>
/// Representa caches de desenvolvimento, diretórios de build ou ambientes de containers/virtualização (Seção 7).
/// Diferencia dados recuperáveis de volumes persistentes (Docker/WSL2) e indica comandos oficiais.
/// </summary>
public sealed class DeveloperArtifactItem
{
    public required string Ecosystem { get; init; } // Ex.: Node.js, Python, .NET, Rust, Java/Gradle, Docker/WSL2, IDE
    public required string ArtifactKind { get; init; } // Ex.: Cache Global npm, node_modules, target, bin/obj, VHDX WSL2
    public required string Name { get; init; }
    public required string FullPath { get; init; }
    public required long LogicalSizeBytes { get; init; }
    public required long AllocatedSizeBytes { get; init; }
    public required long FileCount { get; init; }
    public required DateTime LastModifiedUtc { get; init; }
    public required bool IsGlobalCache { get; init; }
    public required bool IsProjectBuildOutput { get; init; }
    public required bool IsPersistentVolumeOrVirtualDisk { get; init; }
    public required RiskLevel RiskClassification { get; init; }
    public required string PurposeExplanation { get; init; }
    public required string RebuildOrRedownloadImpact { get; init; }
    public required string RecommendedActionText { get; init; }
    public string? OfficialCliCommand { get; init; }
    public StorageItem? UnderlyingItem { get; init; }

    public string FormattedSize => ByteSizeFormatter.FormatBytes(LogicalSizeBytes);
    public string FormattedAllocatedSize => ByteSizeFormatter.FormatBytes(AllocatedSizeBytes);
    public string RiskBadge => ByteSizeFormatter.GetShortRiskBadge(RiskClassification);
    public string PersistenceBadge => IsPersistentVolumeOrVirtualDisk
        ? "Volume / Disco Virtual Persistente (NÃO EXCLUIR)"
        : (IsGlobalCache ? "Cache Global Reconstruível" : "Artefato de Build / Dependência");
    public string FormattedLastModified => LastModifiedUtc == DateTime.MinValue
        ? "N/D"
        : LastModifiedUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm");
}

/// <summary>
/// Agrupa artefatos de build e dependências (node_modules, bin/obj, target, build, .venv) por projeto do usuário,
/// indicando a data da última atividade no código-fonte e se o projeto está parado há mais de 90 dias (Diferencial 5).
/// </summary>
public sealed class ProjectActivitySummary
{
    public required string ProjectName { get; init; }
    public required string ProjectRootPath { get; init; }
    public required string EcosystemsSummary { get; init; }
    public required DateTime LastSourceActivityUtc { get; init; }
    public required int InactiveDays { get; init; }
    public required bool IsDormantOver90Days { get; init; }
    public required long TotalArtifactBytes { get; init; }
    public required long ReclaimableArtifactBytes { get; init; }
    public required IReadOnlyList<DeveloperArtifactItem> Artifacts { get; init; }

    public string FormattedTotalSize => ByteSizeFormatter.FormatBytes(TotalArtifactBytes);
    public string FormattedReclaimableSize => ByteSizeFormatter.FormatBytes(ReclaimableArtifactBytes);
    public long CleanableBytes => ReclaimableArtifactBytes;
    public string FormattedCleanable => FormattedReclaimableSize;
    public string FormattedLastActivity => LastSourceActivityUtc == DateTime.MinValue
        ? "N/D"
        : LastSourceActivityUtc.ToLocalTime().ToString("dd/MM/yyyy");
    public string ActivityStatusBadge => IsDormantOver90Days
        ? $"PARADO ({InactiveDays} dias sem atividade)"
        : $"Ativo ({InactiveDays}d atrás)";
    public string ArtifactNamesSummary => string.Join(", ", Artifacts.Select(a => $"{a.Name} ({a.FormattedSize})"));
}

/// <summary>
/// Opção segura para liberar espaço sem apagar arquivos do usuário (Diferencial 6:
/// compactação de VHDX do WSL2/Docker, compressão NTFS transparente ou liberação de cache local do OneDrive).
/// </summary>
public sealed class NonDestructiveOption
{
    public required string OptionId { get; init; }
    public required string Title { get; init; }
    public required string CategoryLabel { get; init; } // "Compactação WSL2/Docker", "Compressão NTFS", "OneDrive Sob Demanda"
    public required string TargetPath { get; init; }
    public required long CurrentLogicalBytes { get; init; }
    public required long CurrentAllocatedBytes { get; init; }
    public required long EstimatedSavingsBytes { get; init; }
    public required string Explanation { get; init; }
    public required string SafetyGuarantee { get; init; }
    public required string CommandPreview { get; init; }
    public required bool CanExecuteDirectly { get; init; }
    public required bool RequiresElevation { get; init; }

    public string OfficialCommand => CommandPreview;
    public string ActionKind => OptionId.StartsWith("ntfs-compact:", StringComparison.OrdinalIgnoreCase)
        ? "CompactacaoNtfs"
        : OptionId.StartsWith("onedrive-dehydrate:", StringComparison.OrdinalIgnoreCase)
            ? "OneDriveFilesOnDemand"
            : OptionId.StartsWith("vhdx-compact:", StringComparison.OrdinalIgnoreCase)
                ? "CompactacaoVhdx"
                : OptionId;
    public string FormattedCurrentSize => ByteSizeFormatter.FormatBytes(CurrentAllocatedBytes > 0 ? CurrentAllocatedBytes : CurrentLogicalBytes);
    public string FormattedEstimatedSavings => ByteSizeFormatter.FormatBytes(EstimatedSavingsBytes);
    public string ActionBadge => CanExecuteDirectly
        ? (RequiresElevation ? "Requer Administrador" : "Executar com 1 Clique")
        : "Orientação / Comando Oficial";
}


