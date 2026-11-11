using DiskInspector.Core.Models;

namespace DiskInspector.Analysis;

/// <summary>
/// Operações sobre conjuntos de caminhos em que um item pode estar dentro de outro
/// (ex.: uma pasta selecionada e uma subpasta dela também selecionada).
///
/// O custo é proporcional ao número de itens vezes a profundidade do caminho. A versão anterior comparava
/// cada item com todos os demais e travava a interface com algumas centenas de itens selecionados.
/// </summary>
public static class PathNesting
{
    private static readonly char[] Separators = [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar];

    /// <summary>
    /// Devolve apenas os itens de primeiro nível: os que não estão dentro de outro item da mesma coleção.
    /// Caminhos repetidos são considerados uma única vez.
    /// </summary>
    /// <param name="onlyDirectoriesContain">
    /// Quando true, apenas pastas contam como possíveis ancestrais (um arquivo nunca contém outro item).
    /// </param>
    public static List<StorageItem> SelectTopMost(IEnumerable<StorageItem> items, bool onlyDirectoriesContain = true)
    {
        ArgumentNullException.ThrowIfNull(items);

        List<(string Key, StorageItem Item)> entries = [];
        HashSet<string> seenKeys = new(StringComparer.OrdinalIgnoreCase);

        foreach (StorageItem item in items)
        {
            if (item is null || string.IsNullOrWhiteSpace(item.FullPath))
            {
                continue;
            }

            string key = SystemPathProtector.NormalizeForComparison(item.FullPath);
            if (seenKeys.Add(key))
            {
                entries.Add((key, item));
            }
        }

        // Um ancestral é sempre mais curto que seus descendentes: processando do menor para o maior,
        // todo ancestral aceito já está registrado quando o descendente chega.
        entries.Sort(static (a, b) =>
        {
            int byLength = a.Key.Length.CompareTo(b.Key.Length);
            return byLength != 0 ? byLength : string.CompareOrdinal(a.Key, b.Key);
        });

        HashSet<string> acceptedContainers = new(StringComparer.OrdinalIgnoreCase);
        List<StorageItem> topMost = new(entries.Count);

        foreach ((string key, StorageItem item) in entries)
        {
            if (HasAcceptedAncestor(key, acceptedContainers))
            {
                continue;
            }

            topMost.Add(item);
            if (!onlyDirectoriesContain || item.IsDirectory)
            {
                acceptedContainers.Add(key);
            }
        }

        return topMost;
    }

    /// <summary>
    /// Soma o tamanho lógico dos itens sem contar duas vezes o que está dentro de outro item da coleção.
    /// </summary>
    public static long ComputeNonOverlappingSize(IEnumerable<StorageItem> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        long total = 0L;
        foreach (StorageItem item in SelectTopMost(items.Where(i => i is not null && i.LogicalSizeBytes > 0), onlyDirectoriesContain: false))
        {
            total += item.LogicalSizeBytes;
        }

        return total;
    }

    private static bool HasAcceptedAncestor(string normalizedPath, HashSet<string> acceptedContainers)
    {
        if (acceptedContainers.Count == 0)
        {
            return false;
        }

        int end = normalizedPath.Length;
        while (end > 0)
        {
            int separatorIndex = normalizedPath.LastIndexOfAny(Separators, end - 1);
            if (separatorIndex <= 0)
            {
                return false;
            }

            if (acceptedContainers.Contains(normalizedPath[..separatorIndex]))
            {
                return true;
            }

            end = separatorIndex;
        }

        return false;
    }
}
