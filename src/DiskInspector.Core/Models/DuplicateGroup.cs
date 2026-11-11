using DiskInspector.Core.Formatting;

namespace DiskInspector.Core.Models;

/// <summary>
/// Grupo de arquivos duplicados confirmados por tamanho exato, pré-hash e hash criptográfico SHA-256 completo.
/// Exclui hard links NTFS que apontam para o mesmo FileId físico.
/// </summary>
public sealed class DuplicateGroup
{
    public required string Sha256Hash { get; init; }
    public required long FileSizeBytes { get; init; }
    public required IReadOnlyList<DuplicateFileEntry> Entries { get; init; }

    public int CopyCount => Entries.Count;
    public long ReclaimableBytes => Entries.Count > 1 ? FileSizeBytes * (Entries.Count - 1) : 0;

    public string FormattedFileSize => ByteSizeFormatter.FormatBytes(FileSizeBytes);
    public string FormattedReclaimableSize => ByteSizeFormatter.FormatBytes(ReclaimableBytes);
    public string ShortHash => Sha256Hash.Length > 16 ? $"{Sha256Hash[..16]}…" : Sha256Hash;
    public string RepresentativeName => Entries.Count > 0 ? Entries[0].Name : "Arquivo";
}

public sealed class DuplicateFileEntry
{
    public required string Name { get; init; }
    public required string FullPath { get; init; }
    public required string DirectoryPath { get; init; }
    public required long FileSizeBytes { get; init; }
    public required DateTime LastModifiedUtc { get; init; }
    public required bool IsCanonicalOriginal { get; init; }
    public required StorageItem StorageItem { get; init; }

    public string RoleLabel => IsCanonicalOriginal
        ? "Original Sugerido (Protegido da seleção)"
        : "Cópia Duplicada (Revisável)";

    public string FormattedSize => ByteSizeFormatter.FormatBytes(FileSizeBytes);
    public string FormattedLastModified => LastModifiedUtc == DateTime.MinValue
        ? "N/D"
        : LastModifiedUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm");
}

