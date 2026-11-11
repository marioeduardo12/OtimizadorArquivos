using DiskInspector.Core.Formatting;

namespace DiskInspector.Core.Models;

/// <summary>
/// Metadados de uma unidade de disco detectada no sistema.
/// </summary>
public sealed record DriveMetadata
{
    public required string Name { get; init; }
    public required string RootDirectory { get; init; }
    public required string VolumeLabel { get; init; }
    public required string FileSystem { get; init; }
    public required string DriveTypeDescription { get; init; }
    public required long TotalBytes { get; init; }
    public required long AvailableFreeBytes { get; init; }
    public required bool IsSystemDrive { get; init; }
    public required bool IsReady { get; init; }

    public long UsedBytes => Math.Max(0, TotalBytes - AvailableFreeBytes);

    public double UsagePercentage => TotalBytes > 0
        ? Math.Round((double)UsedBytes / TotalBytes * 100.0, 1)
        : 0.0;

    public string FormattedTotal => ByteSizeFormatter.FormatBytes(TotalBytes);
    public string FormattedUsed => ByteSizeFormatter.FormatBytes(UsedBytes);
    public string FormattedFree => ByteSizeFormatter.FormatBytes(AvailableFreeBytes);

    public string DisplayTitle
    {
        get
        {
            string label = string.IsNullOrWhiteSpace(VolumeLabel) ? "Disco Local" : VolumeLabel;
            string sysTag = IsSystemDrive ? " [Sistema]" : string.Empty;
            return $"{Name} ({label}){sysTag} — {FormattedUsed} de {FormattedTotal} ({UsagePercentage:0.0}% usado)";
        }
    }
}

