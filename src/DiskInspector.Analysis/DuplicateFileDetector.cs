using System.IO.Enumeration;
using System.Security.Cryptography;
using DiskInspector.Core.Enums;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;
using DiskInspector.Infrastructure;

namespace DiskInspector.Analysis;

/// <summary>
/// Detector de arquivos duplicados em 3 estágios (Tamanho Exato -> Pré-Hash Rápido -> SHA-256 Completo).
/// Ignora links simbólicos, placeholders de nuvem, caminhos de sistema e deduplica hard links NTFS (Seções 3, 9 e 12).
/// </summary>
public sealed class DuplicateFileDetector : IDuplicateFileDetector
{
    private const int PreHashSliceSize = 16 * 1024; // 16 KB início + 16 KB fim

    private readonly ISystemPathProtector _systemPathProtector;
    private readonly IEnvironmentProvider? _environmentProvider;

    public DuplicateFileDetector(ISystemPathProtector systemPathProtector, IEnvironmentProvider? environmentProvider = null)
    {
        _systemPathProtector = systemPathProtector;
        _environmentProvider = environmentProvider;
    }

    /// <summary>
    /// Áreas onde arquivos idênticos são esperados e necessários: dois programas instalados trazem a mesma
    /// biblioteca, uma extensão repete arquivos de outra. Remover a "cópia" quebraria um deles, então essas
    /// áreas ficam fora da busca: AppData e as pastas de ferramentas iniciadas por ponto na raiz do perfil.
    /// </summary>
    private bool IsApplicationOwnedArea(string directoryPath)
    {
        if (_environmentProvider is null)
        {
            return false;
        }

        EnvironmentPaths env = _environmentProvider.GetEnvironmentPaths();
        if (SystemPathProtector.IsSameOrSubpath(directoryPath, env.LocalAppDataDir) ||
            SystemPathProtector.IsSameOrSubpath(directoryPath, env.RoamingAppDataDir) ||
            SystemPathProtector.IsSameOrSubpath(directoryPath, env.LocalLowAppDataDir))
        {
            return true;
        }

        string profile = env.UserProfileDir.TrimEnd('\\', '/');
        string? parent = Path.GetDirectoryName(directoryPath.TrimEnd('\\', '/'));
        return parent is not null &&
               string.Equals(parent.TrimEnd('\\', '/'), profile, StringComparison.OrdinalIgnoreCase) &&
               Path.GetFileName(directoryPath.TrimEnd('\\', '/')).StartsWith('.');
    }

    public Task<IReadOnlyList<DuplicateGroup>> FindDuplicatesAsync(
        string rootPath,
        long minimumFileSizeBytes,
        IProgress<string>? statusProgress,
        CancellationToken cancellationToken)
    {
        return Task.Run<IReadOnlyList<DuplicateGroup>>(() =>
        {
            if (string.IsNullOrWhiteSpace(rootPath) || !Directory.Exists(rootPath))
            {
                return [];
            }

            long minBytes = Math.Max(1L, minimumFileSizeBytes);
            Dictionary<long, List<CandidateFile>> bySize = [];
            HashSet<(uint Volume, ulong FileId)> seenHardLinks = [];

            statusProgress?.Report("Estágio 1/3: Agrupando arquivos elegíveis por tamanho exato...");
            CollectCandidatesIterative(rootPath, minBytes, bySize, seenHardLinks, cancellationToken);

            List<List<CandidateFile>> sizeGroups = bySize.Values
                .Where(g => g.Count >= 2)
                .OrderByDescending(g => g[0].SizeBytes * (g.Count - 1))
                .Take(500) // Limita aos 500 maiores grupos candidatos para uso eficiente de memória e I/O
                .ToList();

            statusProgress?.Report($"Estágio 2/3: Calculando pré-hash rápido em {sizeGroups.Count} grupos de mesmo tamanho...");
            List<List<CandidateFile>> preHashGroups = [];

            foreach (List<CandidateFile> group in sizeGroups)
            {
                cancellationToken.ThrowIfCancellationRequested();

                Dictionary<string, List<CandidateFile>> byPreHash = new(StringComparer.Ordinal);
                foreach (CandidateFile file in group)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    string? preHash = TryComputeEdgeHash(file.FullPath, file.SizeBytes);
                    if (preHash is null)
                    {
                        continue;
                    }

                    if (!byPreHash.TryGetValue(preHash, out List<CandidateFile>? bucket))
                    {
                        bucket = [];
                        byPreHash[preHash] = bucket;
                    }

                    bucket.Add(file);
                }

                foreach (List<CandidateFile> matchBucket in byPreHash.Values.Where(b => b.Count >= 2))
                {
                    preHashGroups.Add(matchBucket);
                }
            }

            statusProgress?.Report($"Estágio 3/3: Confirmando duplicados com hash criptográfico SHA-256 completo em {preHashGroups.Count} grupos...");
            List<DuplicateGroup> confirmedGroups = [];

            foreach (List<CandidateFile> preGroup in preHashGroups)
            {
                cancellationToken.ThrowIfCancellationRequested();

                Dictionary<string, List<CandidateFile>> byFullHash = new(StringComparer.OrdinalIgnoreCase);
                foreach (CandidateFile file in preGroup)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    string? fullHash = TryComputeFullSha256(file.FullPath, cancellationToken);
                    if (fullHash is null)
                    {
                        continue;
                    }

                    if (!byFullHash.TryGetValue(fullHash, out List<CandidateFile>? bucket))
                    {
                        bucket = [];
                        byFullHash[fullHash] = bucket;
                    }

                    bucket.Add(file);
                }

                foreach ((string sha256, List<CandidateFile> identicalFiles) in byFullHash)
                {
                    if (identicalFiles.Count < 2)
                    {
                        continue;
                    }

                    // Ordena para preservar o arquivo mais antigo (ou de caminho mais curto) como Original Protegido
                    List<CandidateFile> ordered = identicalFiles
                        .OrderBy(f => f.LastModifiedUtc)
                        .ThenBy(f => f.FullPath.Length)
                        .ThenBy(f => f.FullPath, StringComparer.OrdinalIgnoreCase)
                        .ToList();

                    List<DuplicateFileEntry> entries = new(ordered.Count);
                    for (int i = 0; i < ordered.Count; i++)
                    {
                        CandidateFile c = ordered[i];
                        bool isOriginal = i == 0;

                        StorageItem storageItem = new()
                        {
                            Name = c.Name,
                            FullPath = c.FullPath,
                            ParentPath = Path.GetDirectoryName(c.FullPath),
                            LogicalSizeBytes = c.SizeBytes,
                            AllocatedSizeBytes = c.SizeBytes,
                            LastModifiedUtc = c.LastModifiedUtc,
                            // Registro usado na limpeza: se o arquivo mudar depois da comparação, ele deixa de ser cópia
                            LatestContentWriteUtc = c.LastModifiedUtc,
                            IsDirectory = false,
                            Category = ItemCategory.DuplicateFile,
                            AssociatedAppOrComponent = "Detector de Duplicados (SHA-256)",
                            PurposeExplanation = isOriginal
                                ? $"Arquivo original de referência (SHA-256: {sha256[..16]}...). Possui {ordered.Count - 1} cópia(s) idêntica(s) em outros locais."
                                : $"Cópia 100% idêntica confirmada por hash SHA-256 ({sha256[..16]}...) de '{ordered[0].FullPath}'.",
                            DeletionConsequences = isOriginal
                                ? "Protegido como cópia original para evitar a exclusão acidental de todas as cópias do arquivo."
                                : "A cópia original permanecerá intacta; certifique-se apenas de que nenhum projeto específico depende deste caminho exato.",
                            RiskClassification = isOriginal ? RiskLevel.Red : RiskLevel.Yellow,
                            Recommendation = isOriginal
                                ? RecommendedAction.NoneProtected
                                : RecommendedAction.KeepOriginalRemoveDuplicateCopy,
                            RecommendationDetails = isOriginal
                                ? "Manter original intacto."
                                : "Pode ser enviado para a Lixeira caso esta cópia extra seja desnecessária.",
                            IsProtectedSystemItem = isOriginal
                        };

                        entries.Add(new DuplicateFileEntry
                        {
                            Name = c.Name,
                            FullPath = c.FullPath,
                            DirectoryPath = Path.GetDirectoryName(c.FullPath) ?? string.Empty,
                            FileSizeBytes = c.SizeBytes,
                            LastModifiedUtc = c.LastModifiedUtc,
                            IsCanonicalOriginal = isOriginal,
                            StorageItem = storageItem
                        });
                    }

                    confirmedGroups.Add(new DuplicateGroup
                    {
                        Sha256Hash = sha256,
                        FileSizeBytes = ordered[0].SizeBytes,
                        Entries = entries
                    });
                }
            }

            return confirmedGroups
                .OrderByDescending(g => g.ReclaimableBytes)
                .ToList();
        }, cancellationToken);
    }

    private void CollectCandidatesIterative(
        string rootPath,
        long minBytes,
        Dictionary<long, List<CandidateFile>> bySize,
        HashSet<(uint Volume, ulong FileId)> seenHardLinks,
        CancellationToken cancellationToken)
    {
        Stack<string> pendingDirs = new();
        pendingDirs.Push(rootPath);

        EnumerationOptions options = new()
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            ReturnSpecialDirectories = false,
            AttributesToSkip = 0
        };

        while (pendingDirs.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string currentDir = pendingDirs.Pop();

            if (_systemPathProtector.IsProtectedSystemPath(currentDir, out _, out _))
            {
                continue;
            }

            // A pasta escolhida para a busca é sempre percorrida; áreas de programas dentro dela são puladas
            if (!ReferenceEquals(currentDir, rootPath) && IsApplicationOwnedArea(currentDir))
            {
                continue;
            }

            string dirName = Path.GetFileName(currentDir);
            if (string.Equals(dirName, ".git", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(dirName, "node_modules", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            try
            {
                FileSystemEnumerable<CandidateEntry> enumerable = new(
                    currentDir,
                    (ref FileSystemEntry entry) => new CandidateEntry(
                        entry.ToFullPath(),
                        entry.FileName.ToString(),
                        entry.IsDirectory,
                        entry.Length,
                        entry.Attributes,
                        entry.LastWriteTimeUtc.UtcDateTime),
                    options);

                foreach (CandidateEntry entry in enumerable)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if ((entry.Attributes & FileAttributes.ReparsePoint) != 0 ||
                        NativeDiskInterop.IsCloudPlaceholder(entry.Attributes))
                    {
                        continue;
                    }

                    if (entry.IsDirectory)
                    {
                        pendingDirs.Push(entry.FullPath);
                    }
                    else if (entry.Length >= minBytes)
                    {
                        if (_systemPathProtector.IsProtectedSystemPath(entry.FullPath, out _, out _))
                        {
                            continue;
                        }

                        // Verifica se é um hard link NTFS apontando para o mesmo arquivo físico já contabilizado
                        if (NativeDiskInterop.TryGetHardLinkInfo(entry.FullPath, out uint links, out ulong fileId, out uint vol) &&
                            links > 1 && fileId != 0)
                        {
                            if (!seenHardLinks.Add((vol, fileId)))
                            {
                                continue;
                            }
                        }

                        if (!bySize.TryGetValue(entry.Length, out List<CandidateFile>? list))
                        {
                            list = [];
                            bySize[entry.Length] = list;
                        }

                        list.Add(new CandidateFile(entry.Name, entry.FullPath, entry.Length, entry.LastModifiedUtc));
                    }
                }
            }
            catch
            {
                // Ignora diretórios inacessíveis sem interromper a busca
            }
        }
    }

    private static string? TryComputeEdgeHash(string filePath, long fileSize)
    {
        try
        {
            if (fileSize <= PreHashSliceSize * 2)
            {
                return TryComputeFullSha256(filePath, CancellationToken.None);
            }

            using FileStream fs = new(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: PreHashSliceSize,
                FileOptions.SequentialScan);

            byte[] buffer = new byte[PreHashSliceSize * 2];
            int headRead = fs.Read(buffer, 0, PreHashSliceSize);
            fs.Seek(-PreHashSliceSize, SeekOrigin.End);
            int tailRead = fs.Read(buffer, headRead, PreHashSliceSize);

            byte[] hash = SHA256.HashData(buffer.AsSpan(0, headRead + tailRead));
            return Convert.ToHexString(hash);
        }
        catch
        {
            return null;
        }
    }

    private static string? TryComputeFullSha256(string filePath, CancellationToken cancellationToken)
    {
        try
        {
            using FileStream fs = new(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 65536,
                FileOptions.SequentialScan);

            using IncrementalHash sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] buffer = new byte[65536];
            int bytesRead;
            while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                sha.AppendData(buffer, 0, bytesRead);
            }

            return Convert.ToHexString(sha.GetHashAndReset());
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private readonly record struct CandidateEntry(
        string FullPath,
        string Name,
        bool IsDirectory,
        long Length,
        FileAttributes Attributes,
        DateTime LastModifiedUtc);

    private sealed record CandidateFile(
        string Name,
        string FullPath,
        long SizeBytes,
        DateTime LastModifiedUtc);
}

