using DiskInspector.Core.Enums;
using DiskInspector.Core.Formatting;

namespace DiskInspector.Core.Models;

/// <summary>
/// Relatório progressivo emitido durante a varredura assíncrona em segundo plano.
/// </summary>
public sealed record ScanProgressReport
{
    public required string CurrentDirectory { get; init; }
    public required string PhaseDescription { get; init; }
    public required long FilesScanned { get; init; }
    public required long DirectoriesScanned { get; init; }
    public required long LogicalBytesAccumulated { get; init; }
    public required long AllocatedBytesAccumulated { get; init; }
    public required int AccessDeniedCount { get; init; }
    public required int ReparsePointsSkipped { get; init; }
    public required TimeSpan Elapsed { get; init; }

    public string FormattedScannedSize => ByteSizeFormatter.FormatBytes(LogicalBytesAccumulated);
    public string FormattedAllocatedSize => ByteSizeFormatter.FormatBytes(AllocatedBytesAccumulated);
}

/// <summary>
/// Fatia de distribuição visual do armazenamento por categoria ou risco.
/// </summary>
public sealed record StorageDistributionSlice
{
    public required string Label { get; init; }
    public required string ColorHex { get; init; }
    public required long Bytes { get; init; }
    public required double PercentageOfScanned { get; init; }
    public required int ItemCount { get; init; }

    public string FormattedSize => ByteSizeFormatter.FormatBytes(Bytes);
    public string FormattedPercentage => $"{PercentageOfScanned:0.0}%";
}

/// <summary>
/// Grupo lógico de achados para revisão e seleção rápida por categoria semântica (Diferencial 1).
/// Resolve o excesso de linhas soltas agrupando itens por natureza ("Temporários antigos", "Caches de Navegadores", etc.).
/// </summary>
public sealed class FindingGroupSummary
{
    public required string GroupKey { get; init; }
    public required string Title { get; init; }
    public required string Explanation { get; init; }
    public required string DeletionImpact { get; init; }
    public required RiskLevel RiskClassification { get; init; }
    public required long TotalLogicalBytes { get; init; }
    public required int ItemCount { get; init; }
    public required bool CanSelectForCleanup { get; init; }
    public string? OfficialCommand { get; init; }
    public required IReadOnlyList<StorageItem> Items { get; init; }

    public string FormattedTotalSize => ByteSizeFormatter.FormatBytes(TotalLogicalBytes);
    public string ShortRiskBadge => ByteSizeFormatter.GetShortRiskBadge(RiskClassification);
    public string ItemCountLabel => $"{ItemCount:N0} item(ns)";
    public string GroupId => GroupKey;
    public string GroupTitle => Title;
    public bool CanSelectAll => CanSelectForCleanup;
}

/// <summary>
/// Bloco retangular proporcional do Mapa de Blocos colorido por risco ("Posso apagar?") (Diferencial 2).
/// </summary>
public sealed record TreemapBlockItem
{
    public required string Label { get; init; }
    public required string Subtitle { get; init; }
    public required string FullPath { get; init; }
    public required long Bytes { get; init; }
    public required double PercentageOfRoot { get; init; }
    public required RiskLevel RiskClassification { get; init; }
    public required string BackgroundHex { get; init; }
    public required string BorderHex { get; init; }
    public required string TextHex { get; init; }
    public required double X { get; init; }
    public required double Y { get; init; }
    public required double Width { get; init; }
    public required double Height { get; init; }
    public StorageItem? UnderlyingItem { get; init; }

    public string Title => Label;
    public string FormattedSize => ByteSizeFormatter.FormatBytes(Bytes);
    public string ShortRiskBadge => ByteSizeFormatter.GetShortRiskBadge(RiskClassification);
    public string RiskBadge => ShortRiskBadge;
    public bool ShowTitle => Width >= 48 && Height >= 22;
    public bool ShowSize => Width >= 64 && Height >= 40;
    public bool ShowBadge => Width >= 115 && Height >= 58;
    public string DisplaySubtitle => !string.IsNullOrWhiteSpace(Subtitle) && !string.Equals(Subtitle, "Desconhecido", StringComparison.OrdinalIgnoreCase)
        ? $"{ShortRiskBadge} • {Subtitle}"
        : ShortRiskBadge;
    public string TooltipText => $"{Label} — {FormattedSize} ({PercentageOfRoot:0.0}%)\n{ShortRiskBadge}\n{Subtitle}\nCaminho: {FullPath}";
}

/// <summary>
/// Diferença de consumo de uma pasta entre a análise anterior e a atual ("O que cresceu?") (Diferencial 3).
/// </summary>
public sealed record FolderGrowthDelta
{
    public required string Name { get; init; }
    public required string FullPath { get; init; }
    public required long PreviousBytes { get; init; }
    public required long CurrentBytes { get; init; }
    public required DateTime PreviousScanUtc { get; init; }
    public required DateTime CurrentScanUtc { get; init; }
    public StorageItem? UnderlyingItem { get; init; }

    public long DeltaBytes => CurrentBytes - PreviousBytes;
    public double DeltaPercentage => PreviousBytes > 0
        ? Math.Round((double)DeltaBytes / PreviousBytes * 100.0, 1)
        : 100.0;

    public string FormattedPreviousSize => ByteSizeFormatter.FormatBytes(PreviousBytes);
    public string FormattedCurrentSize => ByteSizeFormatter.FormatBytes(CurrentBytes);
    public string FormattedDelta => DeltaBytes >= 0
        ? $"+{ByteSizeFormatter.FormatBytes(DeltaBytes)}"
        : $"-{ByteSizeFormatter.FormatBytes(Math.Abs(DeltaBytes))}";
    public string FormattedTimeSpan
    {
        get
        {
            TimeSpan span = CurrentScanUtc - PreviousScanUtc;
            if (span.TotalDays >= 1) return $"em {span.TotalDays:0.0} dia(s)";
            if (span.TotalHours >= 1) return $"em {span.TotalHours:0.0} hora(s)";
            return $"há {Math.Max(1, (int)span.TotalMinutes)} min";
        }
    }
    public string SummaryBadge => $"{FormattedDelta} ({(DeltaBytes >= 0 ? "+" : "")}{DeltaPercentage:0.0}%) {FormattedTimeSpan}";
}

/// <summary>
/// Resultado completo e imutável de uma análise profunda de armazenamento.
/// </summary>
public sealed class ScanResult
{
    public required Guid ScanId { get; init; }
    public required DateTime StartedAtUtc { get; init; }
    public required DateTime CompletedAtUtc { get; init; }
    public required string TargetRootPath { get; init; }
    public required DriveMetadata DriveInfo { get; init; }
    public required bool RanWithAdminPrivileges { get; init; }
    public required StorageItem RootNode { get; init; }

    public required long TotalFilesScanned { get; init; }
    public required long TotalDirectoriesScanned { get; init; }
    public required long TotalLogicalBytes { get; init; }
    public required long TotalAllocatedBytes { get; init; }
    public required int TotalAccessDenied { get; init; }
    public required int TotalReparsePointsSkipped { get; init; }
    public required int TotalHardLinksDeduplicated { get; init; }
    public required int TotalSparseFilesDetected { get; init; }

    // Listagens principais da Fase 1 & 2
    public required IReadOnlyList<StorageItem> TopHeavyFolders { get; init; }
    public required IReadOnlyList<StorageItem> TopHeavyFiles { get; init; }
    public required IReadOnlyList<StorageItem> HighDensityFolders { get; init; } // Milhares de pequenos arquivos
    public required IReadOnlyList<StorageItem> ClassifiedFindings { get; init; }

    // Análises especializadas (Seções 4 e 7)
    public required IReadOnlyList<AppDataEntry> AppDataEntries { get; init; }
    public required long AppDataLocalBytes { get; init; }
    public required long AppDataRoamingBytes { get; init; }
    public required long AppDataLocalLowBytes { get; init; }

    public required IReadOnlyList<DeveloperArtifactItem> DeveloperArtifacts { get; init; }
    public IReadOnlyList<DuplicateGroup> DuplicateGroups { get; set; } = [];

    // Novos Diferenciais (1, 2, 3, 5, 6)
    public IReadOnlyList<FindingGroupSummary> FindingGroups { get; init; } = [];
    public IReadOnlyList<TreemapBlockItem> RiskTreemapBlocks { get; init; } = [];
    public IReadOnlyList<FolderGrowthDelta> GrowthDeltas { get; init; } = [];
    public IReadOnlyList<ProjectActivitySummary> DeveloperProjects { get; init; } = [];
    public IReadOnlyList<NonDestructiveOption> NonDestructiveOptions { get; init; } = [];
    public DateTime? PreviousSnapshotUtc { get; init; }
    public long? PreviousRootTotalBytes { get; init; }

    // Distribuição visual do armazenamento
    public required IReadOnlyList<StorageDistributionSlice> CategoryDistribution { get; init; }
    public required IReadOnlyList<StorageDistributionSlice> RiskDistribution { get; init; }

    // Estimativas de recuperação
    public required long EstimatedSafeGreenRecoverableBytes { get; init; }
    public required long EstimatedAttentionYellowRecoverableBytes { get; init; }

    public TimeSpan Duration => CompletedAtUtc - StartedAtUtc;
    public string FormattedTotalLogical => ByteSizeFormatter.FormatBytes(TotalLogicalBytes);
    public string FormattedTotalAllocated => ByteSizeFormatter.FormatBytes(TotalAllocatedBytes);
    public string FormattedGreenRecoverable => ByteSizeFormatter.FormatBytes(EstimatedSafeGreenRecoverableBytes);
    public string FormattedYellowRecoverable => ByteSizeFormatter.FormatBytes(EstimatedAttentionYellowRecoverableBytes);
    public string FormattedTotalRecoverable => ByteSizeFormatter.FormatBytes(EstimatedSafeGreenRecoverableBytes + EstimatedAttentionYellowRecoverableBytes);
}

