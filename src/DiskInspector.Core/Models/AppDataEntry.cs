using DiskInspector.Core.Enums;
using DiskInspector.Core.Formatting;

namespace DiskInspector.Core.Models;

/// <summary>
/// Entrada detalhada da análise especial do AppData (Local, Roaming, LocalLow) conforme Seção 4.
/// Separa claramente cache descartável de dados persistentes, sessões, autenticação e bancos locais.
/// </summary>
public sealed class AppDataEntry
{
    public required AppDataScope Scope { get; init; }
    public required string DirectoryName { get; init; }
    public required string FullPath { get; init; }
    public required string IdentifiedApplication { get; init; }
    public required string PublisherOrEcosystem { get; init; }
    public required AppDataContentKind PrimaryContentKind { get; init; }
    public required long TotalLogicalBytes { get; init; }
    public required long TotalAllocatedBytes { get; init; }
    public required long SafeDisposableCacheBytes { get; init; }
    public required long PersistentOrSensitiveBytes { get; init; }
    public required long FileCount { get; init; }
    public required DateTime LastModifiedUtc { get; init; }
    public required RiskLevel OverallRisk { get; init; }
    public required string ContentSummaryExplanation { get; init; }
    public required string DeletionWarning { get; init; }
    public required string GuidanceText { get; init; }
    public required bool LooksLikeUninstalledApp { get; init; }
    public IReadOnlyList<StorageItem> SafeCacheSubdirectories { get; init; } = [];
    public IReadOnlyList<StorageItem> SubItemBreakdown { get; init; } = [];
    public StorageItem? RootStorageItem { get; init; }

    public string ScopeDisplayName => Scope switch
    {
        AppDataScope.Local => @"AppData\Local",
        AppDataScope.Roaming => @"AppData\Roaming",
        AppDataScope.LocalLow => @"AppData\LocalLow",
        _ => "AppData"
    };

    public string ContentKindDisplayName => ByteSizeFormatter.GetAppDataContentKindDisplayName(PrimaryContentKind);

    /// <summary>
    /// Natureza dos dados para a tabela, destacando quando a pasta parece ser sobra de um programa removido.
    /// </summary>
    public string NatureDisplayName => LooksLikeUninstalledApp
        ? "Possível resíduo de programa desinstalado"
        : ContentKindDisplayName;

    /// <summary>
    /// Texto único para a tabela: o que a pasta contém, seguido da orientação.
    /// </summary>
    public string ExplanationAndGuidance => string.IsNullOrWhiteSpace(ContentSummaryExplanation)
        ? GuidanceText
        : $"{ContentSummaryExplanation} {GuidanceText}";
    public string FormattedTotalSize => ByteSizeFormatter.FormatBytes(TotalLogicalBytes);
    public string FormattedAllocatedSize => ByteSizeFormatter.FormatBytes(TotalAllocatedBytes);
    public string FormattedSafeCacheSize => ByteSizeFormatter.FormatBytes(SafeDisposableCacheBytes);
    public string FormattedPersistentSize => ByteSizeFormatter.FormatBytes(PersistentOrSensitiveBytes);
    public string RiskBadge => ByteSizeFormatter.GetShortRiskBadge(OverallRisk);
    public string FormattedLastModified => LastModifiedUtc == DateTime.MinValue
        ? "N/D"
        : LastModifiedUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm");
}

