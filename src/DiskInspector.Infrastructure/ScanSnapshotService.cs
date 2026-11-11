using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Infrastructure;

/// <summary>
/// Persiste snapshots leves do tamanho das pastas a cada análise e calcula as maiores variações
/// ("O que cresceu desde a última análise?") (Diferencial 3).
/// </summary>
public sealed class ScanSnapshotService : IScanSnapshotService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _snapshotsDirectory;

    public ScanSnapshotService(IEnvironmentProvider environmentProvider, string? customSnapshotsDirectory = null)
    {
        if (!string.IsNullOrWhiteSpace(customSnapshotsDirectory))
        {
            _snapshotsDirectory = customSnapshotsDirectory;
        }
        else
        {
            EnvironmentPaths env = environmentProvider.GetEnvironmentPaths();
            _snapshotsDirectory = Path.Combine(env.LocalAppDataDir, "DiskInspector", "snapshots");
        }
    }

    public IReadOnlyList<FolderGrowthDelta> CompareAndSaveSnapshot(
        string targetRootPath,
        DateTime scanCompletedUtc,
        long rootLogicalBytes,
        IEnumerable<StorageItem> trackedFolders,
        out DateTime? previousScanUtc,
        out long? previousRootBytes)
    {
        previousScanUtc = null;
        previousRootBytes = null;

        if (string.IsNullOrWhiteSpace(targetRootPath))
        {
            return [];
        }

        string normalizedRoot = targetRootPath.TrimEnd('\\', '/');
        string snapshotFilePath = GetSnapshotFilePath(normalizedRoot);

        // Coleta o mapa atual de pastas significativas
        Dictionary<string, StorageItem> currentItemsByPath = new(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, long> currentSizes = new(StringComparer.OrdinalIgnoreCase);

        foreach (StorageItem folder in trackedFolders)
        {
            if (folder is null || !folder.IsDirectory || string.IsNullOrWhiteSpace(folder.FullPath) || folder.LogicalSizeBytes <= 0)
            {
                continue;
            }

            string key = folder.FullPath.TrimEnd('\\', '/');
            if (currentItemsByPath.TryAdd(key, folder))
            {
                currentSizes[key] = folder.LogicalSizeBytes;
            }
        }

        List<FolderGrowthDelta> deltas = [];

        // 1. Compara com o snapshot anterior do mesmo escopo, se existir
        PersistedScanSnapshot? previous = TryLoadSnapshot(snapshotFilePath);
        if (previous is not null && previous.FolderBytes is not null)
        {
            previousScanUtc = previous.ScanCompletedUtc;
            previousRootBytes = previous.RootLogicalBytes;

            foreach ((string path, StorageItem currentItem) in currentItemsByPath)
            {
                if (string.Equals(path, normalizedRoot, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (previous.FolderBytes.TryGetValue(path, out long oldBytes))
                {
                    long diff = currentItem.LogicalSizeBytes - oldBytes;
                    // Considera variações relevantes (>= 64 KB de crescimento)
                    if (diff >= 64 * 1024)
                    {
                        deltas.Add(new FolderGrowthDelta
                        {
                            Name = currentItem.Name,
                            FullPath = currentItem.FullPath,
                            PreviousBytes = oldBytes,
                            CurrentBytes = currentItem.LogicalSizeBytes,
                            PreviousScanUtc = previous.ScanCompletedUtc,
                            CurrentScanUtc = scanCompletedUtc,
                            UnderlyingItem = currentItem
                        });
                    }
                }
                else if (currentItem.LogicalSizeBytes >= 5 * 1024 * 1024)
                {
                    // Pasta nova de porte significativo (>= 5 MB) criada desde a última análise
                    deltas.Add(new FolderGrowthDelta
                    {
                        Name = $"{currentItem.Name} (nova pasta)",
                        FullPath = currentItem.FullPath,
                        PreviousBytes = 0L,
                        CurrentBytes = currentItem.LogicalSizeBytes,
                        PreviousScanUtc = previous.ScanCompletedUtc,
                        CurrentScanUtc = scanCompletedUtc,
                        UnderlyingItem = currentItem
                    });
                }
            }
        }

        // 2. Salva o snapshot atual para a próxima comparação
        TrySaveSnapshot(snapshotFilePath, new PersistedScanSnapshot
        {
            TargetRootPath = normalizedRoot,
            ScanCompletedUtc = scanCompletedUtc,
            RootLogicalBytes = rootLogicalBytes,
            FolderBytes = currentSizes
        });

        return deltas
            .OrderByDescending(d => d.DeltaBytes)
            .Take(60)
            .ToList();
    }

    private string GetSnapshotFilePath(string normalizedRoot)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalizedRoot.ToUpperInvariant()));
        string shortHash = Convert.ToHexString(hash)[..16].ToLowerInvariant();
        return Path.Combine(_snapshotsDirectory, $"snapshot_{shortHash}.json");
    }

    private static PersistedScanSnapshot? TryLoadSnapshot(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                return null;
            }

            string json = File.ReadAllText(filePath);
            PersistedScanSnapshot? loaded = JsonSerializer.Deserialize<PersistedScanSnapshot>(json, JsonOptions);
            if (loaded?.FolderBytes is not null)
            {
                // Reconstrói com comparador case-insensitive do Windows
                loaded.FolderBytes = new Dictionary<string, long>(loaded.FolderBytes, StringComparer.OrdinalIgnoreCase);
            }

            return loaded;
        }
        catch
        {
            return null;
        }
    }

    private void TrySaveSnapshot(string filePath, PersistedScanSnapshot snapshot)
    {
        try
        {
            Directory.CreateDirectory(_snapshotsDirectory);
            string json = JsonSerializer.Serialize(snapshot, JsonOptions);
            File.WriteAllText(filePath, json);
        }
        catch
        {
            // Falha ao gravar snapshot não deve interromper a análise
        }
    }

    private sealed class PersistedScanSnapshot
    {
        public string TargetRootPath { get; set; } = string.Empty;
        public DateTime ScanCompletedUtc { get; set; }
        public long RootLogicalBytes { get; set; }
        public Dictionary<string, long>? FolderBytes { get; set; }
    }
}
