using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using DiskInspector.Core.Models;
using DiskInspector.UI.ViewModels;

namespace DiskInspector.UI;

public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }

    private void DirectoryTree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (DataContext is MainViewModel vm && e.NewValue is StorageItem selectedNode)
        {
            vm.SelectedInspectorItem = selectedNode;
        }
    }

    private void TreemapHost_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            vm.UpdateTreemapDimensions(e.NewSize.Width, e.NewSize.Height);
        }
    }

    private void GridGrowthDeltas_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (DataContext is MainViewModel vm &&
            sender is DataGrid grid &&
            grid.SelectedItem is FolderGrowthDelta delta &&
            delta.UnderlyingItem is not null)
        {
            vm.SelectedInspectorItem = delta.UnderlyingItem;
        }
    }

    private void ChkHeaderSelectAllFindings_Checked(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            vm.SelectAllVisibleFilteredItems();
        }
    }

    private void ChkHeaderSelectAllFindings_Unchecked(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            vm.UnselectAllVisibleFilteredItems();
        }
    }

    private void BtnCheckHighlightedFindings_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            List<StorageItem> items = GridFindings.SelectedItems.OfType<StorageItem>().ToList();
            vm.SetHighlightedItemsSelection(items, selected: true);
        }
    }

    private void BtnCheckHighlighted_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            List<StorageItem> items = GetHighlightedFromTab2();
            vm.SetHighlightedItemsSelection(items, selected: true);
        }
    }

    private void BtnUncheckHighlighted_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            List<StorageItem> items = GetHighlightedFromTab2();
            vm.SetHighlightedItemsSelection(items, selected: false);
        }
    }

    private List<StorageItem> GetHighlightedFromTab2()
    {
        List<StorageItem> result = [];
        result.AddRange(GridHeavyFolders.SelectedItems.OfType<StorageItem>());
        result.AddRange(GridHeavyFiles.SelectedItems.OfType<StorageItem>());
        result.AddRange(GridDenseFolders.SelectedItems.OfType<StorageItem>());
        return result;
    }

    private void DataGrid_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Space && sender is DataGrid grid && DataContext is MainViewModel vm)
        {
            List<StorageItem> selectedItems = grid.SelectedItems.OfType<StorageItem>().ToList();
            if (selectedItems.Count > 0)
            {
                bool targetState = selectedItems.Any(i => i.CanSelectForCleanup && !i.IsSelectedForCleanup);
                vm.SetHighlightedItemsSelection(selectedItems, targetState);
                e.Handled = true;
            }
        }
    }
}
