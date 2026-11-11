using System.Windows;
using DiskInspector.Core.Models;

namespace DiskInspector.UI.Views;

public partial class CleanupPreviewWindow : Window
{
    private readonly CleanupPreviewReport _report;

    public CleanupPreviewWindow(CleanupPreviewReport report)
    {
        InitializeComponent();
        _report = report ?? throw new ArgumentNullException(nameof(report));

        TxtTotalRecoverable.Text = _report.FormattedEstimatedRecovery;
        GridApproved.ItemsSource = _report.ApprovedItems;
        GridBlocked.ItemsSource = _report.BlockedItems;

        List<string> warnings = _report.SafetyWarnings.ToList();
        if (warnings.Count == 0)
        {
            warnings.Add(_report.PreferRecycleBin
                ? "Operação configurada para priorizar a Lixeira do Windows nos volumes suportados."
                : "ATENÇÃO: Você optou por exclusão direta sem usar a Lixeira. Os arquivos removidos não poderão ser recuperados.");
        }
        WarningsList.ItemsSource = warnings;

        UpdateConfirmButtonState();
    }

    private void ChkExplicitConfirm_Changed(object sender, RoutedEventArgs e)
    {
        UpdateConfirmButtonState();
    }

    private void UpdateConfirmButtonState()
    {
        if (BtnConfirmCleanup is null || ChkExplicitConfirm is null)
        {
            return;
        }

        BtnConfirmCleanup.IsEnabled = _report.HasApprovedItems && ChkExplicitConfirm.IsChecked == true;
    }

    private void BtnCancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void BtnConfirm_Click(object sender, RoutedEventArgs e)
    {
        if (!_report.HasApprovedItems || ChkExplicitConfirm.IsChecked != true)
        {
            return;
        }

        DialogResult = true;
        Close();
    }
}

