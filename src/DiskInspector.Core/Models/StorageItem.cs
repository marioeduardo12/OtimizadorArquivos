using System.ComponentModel;
using System.Runtime.CompilerServices;
using DiskInspector.Core.Enums;
using DiskInspector.Core.Formatting;

namespace DiskInspector.Core.Models;

/// <summary>
/// Representa um arquivo ou diretório analisado com os 10 atributos obrigatórios da Seção 3,
/// além de metadados estruturais (tamanho lógico vs alocado, reparse points, hard links, arquivos esparsos).
/// </summary>
public sealed class StorageItem : INotifyPropertyChanged
{
    private bool _isSelectedForCleanup;
    private bool _isRemovedByCleanup;

    // 1. Nome do arquivo ou pasta
    public required string Name { get; init; }

    // 2. Caminho completo
    public required string FullPath { get; init; }

    // 3. Tamanho (Lógico e Efetivamente Alocado em Disco)
    public long LogicalSizeBytes { get; set; }
    public long AllocatedSizeBytes { get; set; }

    // 4. Data da última modificação
    public DateTime LastModifiedUtc { get; init; }

    /// <summary>
    /// Escrita mais recente dentro do item. Para pastas é o arquivo mais novo de toda a subárvore,
    /// porque a data da própria pasta só muda quando um item direto é criado ou removido.
    /// </summary>
    public DateTime LatestContentWriteUtc { get; set; }

    /// <summary>
    /// Data usada pelas regras de idade: a mais recente entre a data do item e a do seu conteúdo.
    /// </summary>
    public DateTime EffectiveLatestWriteUtc =>
        LatestContentWriteUtc > LastModifiedUtc ? LatestContentWriteUtc : LastModifiedUtc;

    // 5. Categoria
    public ItemCategory Category { get; set; } = ItemCategory.Unknown;

    // 6. Aplicativo ou componente associado, quando identificável
    public string AssociatedAppOrComponent { get; set; } = "Desconhecido";

    // 7. Explicação sobre sua finalidade
    public string PurposeExplanation { get; set; } = "Finalidade não determinada com segurança.";

    // 8. Consequências potenciais da exclusão
    public string DeletionConsequences { get; set; } = "A exclusão sem conhecimento da finalidade pode causar perda de dados ou mau funcionamento de aplicativos.";

    // 9. Classificação de risco
    public RiskLevel RiskClassification { get; set; } = RiskLevel.Gray;

    // 10. Ação recomendada
    public RecommendedAction Recommendation { get; set; } = RecommendedAction.ManualReviewRequired;
    public string RecommendationDetails { get; set; } = "Manter até verificação manual.";
    public string? OfficialMaintenanceCommand { get; set; }

    // Metadados estruturais adicionais
    public bool IsDirectory { get; init; }
    public bool IsExpandedByDefault { get; set; }
    public string? ParentPath { get; init; }
    public long FileCount { get; set; }
    public long DirectoryCount { get; set; }
    public long SmallFileCount { get; set; } // Arquivos < 16 KB
    public bool IsReparsePoint { get; init; }
    public bool IsSparseFile { get; init; }
    public uint HardLinkCount { get; init; } = 1;
    public ulong? NtfsFileId { get; init; }
    public int AccessDeniedCount { get; set; }
    public bool IsProtectedSystemItem { get; set; }
    public bool IsLockedInUse { get; set; }
    public double PercentageOfParent { get; set; }
    public double PercentageOfDrive { get; set; }

    public List<StorageItem> Children { get; } = [];

    // Propriedades formatadas para exibição na UI
    public string FormattedLogicalSize => ByteSizeFormatter.FormatBytes(LogicalSizeBytes);
    public string FormattedAllocatedSize => ByteSizeFormatter.FormatBytes(AllocatedSizeBytes);
    public string FormattedLastModified => LastModifiedUtc == DateTime.MinValue
        ? "N/D"
        : LastModifiedUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm");

    public string CategoryDisplayName => ByteSizeFormatter.GetCategoryDisplayName(Category);
    public string RiskDisplayName => ByteSizeFormatter.GetRiskLabel(RiskClassification);
    public string ShortRiskBadge => ByteSizeFormatter.GetShortRiskBadge(RiskClassification);
    public string RecommendationDisplayName => ByteSizeFormatter.GetRecommendedActionDisplayName(Recommendation);
    public string ItemTypeLabel => IsDirectory ? "Pasta" : "Arquivo";

    /// <summary>
    /// Regra estrita de segurança (Seção 5, 6 e 8):
    /// Itens VERMELHOS (Alto Risco), CINZAS (Protegidos/Desconhecidos), caminhos de sistema,
    /// reparse points/links simbólicos ou arquivos em uso NUNCA podem ser selecionados para exclusão genérica.
    /// </summary>
    public bool CanSelectForCleanup =>
        !IsRemovedByCleanup &&
        !IsProtectedSystemItem &&
        !IsReparsePoint &&
        !IsLockedInUse &&
        (RiskClassification == RiskLevel.Green || RiskClassification == RiskLevel.Yellow) &&
        (Recommendation == RecommendedAction.SafeToMoveToRecycleBin ||
         Recommendation == RecommendedAction.SafeToCleanWhenAppClosed ||
         Recommendation == RecommendedAction.KeepOriginalRemoveDuplicateCopy);

    public bool IsSelectedForCleanup
    {
        get => _isSelectedForCleanup && CanSelectForCleanup;
        set
        {
            bool sanitized = value && CanSelectForCleanup;
            if (_isSelectedForCleanup != sanitized)
            {
                _isSelectedForCleanup = sanitized;
                OnPropertyChanged();
            }
        }
    }

    /// <summary>
    /// Marcado quando a limpeza removeu o item do disco. Um item removido nunca mais é selecionável.
    /// </summary>
    public bool IsRemovedByCleanup
    {
        get => _isRemovedByCleanup;
        set
        {
            if (_isRemovedByCleanup == value)
            {
                return;
            }

            _isRemovedByCleanup = value;
            if (value)
            {
                _isSelectedForCleanup = false;
            }

            OnPropertyChanged();
            OnPropertyChanged(nameof(CanSelectForCleanup));
            OnPropertyChanged(nameof(IsSelectedForCleanup));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

