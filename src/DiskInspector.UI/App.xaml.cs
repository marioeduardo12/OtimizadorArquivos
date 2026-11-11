using System.Windows;
using DiskInspector.Analysis;
using DiskInspector.Cleanup;
using DiskInspector.Core.Interfaces;
using DiskInspector.Infrastructure;
using DiskInspector.UI.ViewModels;

namespace DiskInspector.UI;

public partial class App : Application
{
    private bool _isShowingErrorDialog;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Composição modular explícita das camadas (Core -> Infrastructure -> Analysis -> Cleanup -> UI)
        IEnvironmentProvider environmentProvider = new WindowsEnvironmentProvider();
        IDriveDiscoveryService driveDiscoveryService = new DriveDiscoveryService(environmentProvider);
        ISystemPathProtector systemPathProtector = new SystemPathProtector(environmentProvider);
        IFileLockDetector fileLockDetector = new FileLockDetector();
        IRecycleBin recycleBin = new WindowsRecycleBin();
        IScanSnapshotService snapshotService = new ScanSnapshotService(environmentProvider);
        IStorageClassifier storageClassifier = new StorageClassifier(environmentProvider, systemPathProtector);
        IOperationHistoryRepository historyRepository = new OperationHistoryRepository(environmentProvider);
        IDiskScannerService diskScannerService = new DiskScannerService(
            environmentProvider,
            systemPathProtector,
            storageClassifier,
            historyRepository,
            snapshotService);
        IDuplicateFileDetector duplicateFileDetector = new DuplicateFileDetector(systemPathProtector, environmentProvider);
        ICleanupSafetyValidator cleanupSafetyValidator = new CleanupSafetyValidator(systemPathProtector, fileLockDetector, recycleBin);
        ISafeCleanupService safeCleanupService = new SafeCleanupService(cleanupSafetyValidator, historyRepository, recycleBin: recycleBin);
        IOfficialMaintenanceExecutor officialMaintenanceExecutor = new OfficialMaintenanceExecutor(historyRepository);

        MainViewModel mainViewModel = new(
            environmentProvider,
            driveDiscoveryService,
            diskScannerService,
            duplicateFileDetector,
            safeCleanupService,
            historyRepository,
            recycleBin,
            fileLockDetector,
            officialMaintenanceExecutor);

        DispatcherUnhandledException += (_, args) =>
        {
            args.Handled = true;
            mainViewModel.StatusHeadline = $"Aviso de interface: {args.Exception.Message}";

            if (_isShowingErrorDialog)
            {
                return;
            }

            try
            {
                _isShowingErrorDialog = true;
                MessageBox.Show(
                    $"Ocorreu um erro inesperado na interface:\n\n{args.Exception.Message}",
                    "DiskInspector — Aviso de Estabilidade",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            finally
            {
                _isShowingErrorDialog = false;
            }
        };

        MainWindow window = new(mainViewModel);
        MainWindow = window;
        window.Show();
    }
}
