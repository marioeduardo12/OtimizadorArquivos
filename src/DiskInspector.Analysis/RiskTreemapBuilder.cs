using DiskInspector.Core.Enums;
using DiskInspector.Core.Models;

namespace DiskInspector.Analysis;

/// <summary>
/// Constrói o Mapa de Blocos proporcional colorido por risco ("Posso apagar?") (Diferencial 2).
/// Diferente do WizTree/WinDirStat (que pintam por extensão de arquivo), cada bloco mostra visualmente
/// a classificação de segurança: Verde (seguro remover), Amarelo (atenção), Vermelho (dados persistentes/VMs)
/// e Cinza (sistema Windows 11 ou desconhecido).
/// </summary>
public static class RiskTreemapBuilder
{
    public const double DefaultCanvasWidth = 1040.0;
    public const double DefaultCanvasHeight = 196.0;

    private sealed record WeightedBlockCandidate(
        StorageItem Item,
        string DisplayLabel,
        long EffectiveBytes);

    public static IReadOnlyList<TreemapBlockItem> BuildRiskTreemap(
        StorageItem rootNode,
        IReadOnlyList<StorageItem> classifiedFindings,
        IReadOnlyList<StorageItem> topHeavyFolders,
        double canvasWidth = DefaultCanvasWidth,
        double canvasHeight = DefaultCanvasHeight)
    {
        ArgumentNullException.ThrowIfNull(rootNode);

        long rootTotal = Math.Max(1L, rootNode.LogicalSizeBytes);

        List<StorageItem> rawCandidates = [];
        if (classifiedFindings is not null)
        {
            rawCandidates.AddRange(classifiedFindings.Where(f =>
                f.LogicalSizeBytes > 0 &&
                f.Recommendation != RecommendedAction.CleanViaParentItem));
        }

        foreach (StorageItem child in rootNode.Children)
        {
            if (child.LogicalSizeBytes > 0)
            {
                rawCandidates.Add(child);
            }
        }

        if (topHeavyFolders is not null)
        {
            rawCandidates.AddRange(topHeavyFolders.Take(35));
        }

        List<WeightedBlockCandidate> selected = SelectRepresentativeBlocks(rawCandidates, rootNode.FullPath)
            .OrderByDescending(i => i.EffectiveBytes)
            .Take(16)
            .ToList();

        if (selected.Count == 0 && rootNode.LogicalSizeBytes > 0)
        {
            selected.Add(new WeightedBlockCandidate(rootNode, rootNode.Name, rootNode.LogicalSizeBytes));
        }

        double totalWeight = selected.Sum(i => Math.Max(1.0, i.EffectiveBytes));
        if (totalWeight <= 0)
        {
            return [];
        }

        List<TreemapBlockItem> blocks = [];
        LayoutBalanced(
            selected,
            startIndex: 0,
            count: selected.Count,
            x: 0,
            y: 0,
            width: Math.Max(120, canvasWidth),
            height: Math.Max(80, canvasHeight),
            rootTotalBytes: rootTotal,
            output: blocks);

        return blocks;
    }

    private static List<WeightedBlockCandidate> SelectRepresentativeBlocks(List<StorageItem> candidates, string rootPath)
    {
        string normRoot = SystemPathProtector.NormalizeForComparison(rootPath);

        // Desduplica por caminho, priorizando a classificação mais específica
        List<StorageItem> uniqueByPath = candidates
            .Where(c => c is not null && c.LogicalSizeBytes > 0 &&
                        !string.Equals(SystemPathProtector.NormalizeForComparison(c.FullPath), normRoot, StringComparison.OrdinalIgnoreCase))
            .GroupBy(c => SystemPathProtector.NormalizeForComparison(c.FullPath), StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderBy(i => GetRiskPriority(i.RiskClassification)).First())
            .ToList();

        // 1º passe: garante que os maiores blocos Verdes e Amarelos não-sobrepostos entrem no mapa
        List<StorageItem> cleanablePool = uniqueByPath
            .Where(i => i.RiskClassification is RiskLevel.Green or RiskLevel.Yellow)
            .OrderByDescending(i => i.LogicalSizeBytes)
            .ToList();

        List<WeightedBlockCandidate> accepted = [];
        List<(string NormPath, long Bytes)> acceptedRegions = [];

        foreach (StorageItem cleanable in cleanablePool)
        {
            if (accepted.Count >= 7)
            {
                break;
            }

            string norm = SystemPathProtector.NormalizeForComparison(cleanable.FullPath);
            if (OverlapsAny(norm, acceptedRegions))
            {
                continue;
            }

            accepted.Add(new WeightedBlockCandidate(
                cleanable,
                BuildReadableBlockTitle(cleanable),
                cleanable.LogicalSizeBytes));
            acceptedRegions.Add((norm, cleanable.LogicalSizeBytes));
        }

        // 2º passe: adiciona as maiores pastas Vermelhas/Cinzas/restantes, descontando o tamanho de subpastas Verdes/Amarelas já destacadas
        foreach (StorageItem other in uniqueByPath
                     .OrderByDescending(i => i.LogicalSizeBytes))
        {
            if (accepted.Count >= 18)
            {
                break;
            }

            string norm = SystemPathProtector.NormalizeForComparison(other.FullPath);

            // Se já está contido dentro de um bloco aceito, pula
            if (acceptedRegions.Any(r => IsSameOrSubpath(norm, r.NormPath)))
            {
                continue;
            }

            // Se este diretório é pai de blocos Verdes/Amarelos já aceitos, subtrai o espaço já representado por eles
            long childBytesAlreadyShown = acceptedRegions
                .Where(r => IsSameOrSubpath(r.NormPath, norm))
                .Sum(r => r.Bytes);

            long remainingBytes = other.LogicalSizeBytes - childBytesAlreadyShown;
            if (remainingBytes <= 0 || (other.LogicalSizeBytes > 0 && (double)remainingBytes / other.LogicalSizeBytes < 0.15))
            {
                continue;
            }

            accepted.Add(new WeightedBlockCandidate(
                other,
                BuildReadableBlockTitle(other),
                remainingBytes));
            acceptedRegions.Add((norm, remainingBytes));
        }

        return accepted;
    }

    private static string BuildReadableBlockTitle(StorageItem item)
    {
        if (item.RiskClassification == RiskLevel.Green &&
            !string.IsNullOrWhiteSpace(item.AssociatedAppOrComponent) &&
            !string.Equals(item.AssociatedAppOrComponent, "Desconhecido", StringComparison.OrdinalIgnoreCase) &&
            (item.Name.Equals("Cache", StringComparison.OrdinalIgnoreCase) ||
             item.Name.Equals("Code Cache", StringComparison.OrdinalIgnoreCase) ||
             item.Name.Equals("GPUCache", StringComparison.OrdinalIgnoreCase)))
        {
            string shortApp = item.AssociatedAppOrComponent.Split('(')[0].Trim();
            return $"{shortApp} ({item.Name})";
        }

        return item.Name;
    }

    private static int GetRiskPriority(RiskLevel risk) => risk switch
    {
        RiskLevel.Green => 0,
        RiskLevel.Yellow => 1,
        RiskLevel.Red => 2,
        _ => 3
    };

    private static bool OverlapsAny(string normCandidate, List<(string NormPath, long Bytes)> acceptedRegions)
    {
        foreach ((string existing, _) in acceptedRegions)
        {
            if (IsSameOrSubpath(normCandidate, existing) || IsSameOrSubpath(existing, normCandidate))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsSameOrSubpath(string candidate, string parent)
    {
        if (candidate.Length < parent.Length)
        {
            return false;
        }

        return candidate.StartsWith(parent, StringComparison.OrdinalIgnoreCase) &&
               (candidate.Length == parent.Length || candidate[parent.Length] == '\\' || candidate[parent.Length] == '/');
    }

    /// <summary>
    /// Divide sempre ao longo da maior dimensão atual (largura vs altura) para manter os blocos próximos de quadrados/cartões legíveis,
    /// evitando tiras horizontais estreitas.
    /// </summary>
    private static void LayoutBalanced(
        List<WeightedBlockCandidate> items,
        int startIndex,
        int count,
        double x,
        double y,
        double width,
        double height,
        long rootTotalBytes,
        List<TreemapBlockItem> output)
    {
        if (count <= 0 || width <= 4 || height <= 4)
        {
            return;
        }

        if (count == 1)
        {
            WeightedBlockCandidate entry = items[startIndex];
            StorageItem item = entry.Item;
            (string bg, string border, string fg) = GetColorsForRisk(item.RiskClassification);
            double pct = Math.Min(100.0, Math.Round((double)entry.EffectiveBytes / rootTotalBytes * 100.0, 1));

            const double gap = 3.0;
            output.Add(new TreemapBlockItem
            {
                Label = entry.DisplayLabel,
                Subtitle = item.AssociatedAppOrComponent,
                FullPath = item.FullPath,
                Bytes = entry.EffectiveBytes,
                PercentageOfRoot = pct,
                RiskClassification = item.RiskClassification,
                BackgroundHex = bg,
                BorderHex = border,
                TextHex = fg,
                X = Math.Round(x, 1),
                Y = Math.Round(y, 1),
                Width = Math.Max(6, Math.Round(width - gap, 1)),
                Height = Math.Max(6, Math.Round(height - gap, 1)),
                UnderlyingItem = item
            });
            return;
        }

        double total = 0;
        for (int i = startIndex; i < startIndex + count; i++)
        {
            total += Math.Max(1.0, items[i].EffectiveBytes);
        }

        double half = total / 2.0;
        double running = 0;
        int splitCount = 1;

        for (int i = 0; i < count - 1; i++)
        {
            running += Math.Max(1.0, items[startIndex + i].EffectiveBytes);
            splitCount = i + 1;
            if (running >= half)
            {
                break;
            }
        }

        double ratio = total > 0 ? Math.Clamp(running / total, 0.18, 0.82) : 0.5;

        // Sempre corta o lado mais comprido para preservar proporção de cartão (evita tiras achatadas)
        bool splitHorizontally = width >= height * 1.15;

        if (splitHorizontally)
        {
            double leftWidth = width * ratio;
            LayoutBalanced(items, startIndex, splitCount, x, y, leftWidth, height, rootTotalBytes, output);
            LayoutBalanced(items, startIndex + splitCount, count - splitCount, x + leftWidth, y, width - leftWidth, height, rootTotalBytes, output);
        }
        else
        {
            double topHeight = height * ratio;
            LayoutBalanced(items, startIndex, splitCount, x, y, width, topHeight, rootTotalBytes, output);
            LayoutBalanced(items, startIndex + splitCount, count - splitCount, x, y + topHeight, width, height - topHeight, rootTotalBytes, output);
        }
    }

    private static (string BackgroundHex, string BorderHex, string TextHex) GetColorsForRisk(RiskLevel risk) => risk switch
    {
        RiskLevel.Green => ("#133624", "#22C55E", "#4ADE80"),
        RiskLevel.Yellow => ("#362910", "#EAB308", "#FACC15"),
        RiskLevel.Red => ("#36171C", "#EF4444", "#FCA5A5"),
        _ => ("#1E2230", "#475569", "#E2E8F0")
    };
}
