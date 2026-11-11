using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;
using DiskInspector.Analysis;
using DiskInspector.Core.Enums;
using DiskInspector.Core.Formatting;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;
using DiskInspector.UI.MVVM;
using DiskInspector.UI.Views;
using Microsoft.Win32;

namespace DiskInspector.UI.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly IEnvironmentProvider _environmentProvider;
    private readonly IDriveDiscoveryService _driveDiscoveryService;
    private readonly IDiskScannerService _diskScannerService;
    private readonly IDuplicateFileDetector _duplicateFileDetector;
    private readonly ISafeCleanupService _safeCleanupService;
    private readonly IOperationHistoryRepository _historyRepository;
    private readonly IRecycleBin? _recycleBin;
    private readonly IFileLockDetector? _fileLockDetector;
    private readonly IOfficialMaintenanceExecutor? _officialMaintenanceExecutor;

    private CancellationTokenSource? _scanCts;
    private CancellationTokenSource? _duplicateCts;
    private CancellationTokenSource? _cleanupCts;

    // Enquanto uma operação marca ou desmarca muitos itens, o resumo da seleção é recalculado uma única vez no fim
    private int _bulkSelectionDepth;
    private string _recycleBinSummaryText = "Lixeira: consultando...";

    // Caminhos removidos pela limpeza desde a última análise (os itens saem das listas sem precisar reanalisar)
    private readonly HashSet<string> _removedPaths = new(StringComparer.OrdinalIgnoreCase);

    // Caminhos enviados para a Lixeira na última sessão de limpeza, para permitir "Desfazer Última Limpeza" (Diferencial 7B)
    private readonly List<string> _lastRecycledPaths = [];

    private DriveMetadata? _selectedDrive;
    private string _selectedScanScope = "Unidade Completa Selecionada";
    private bool _isScanning;
    private bool _isDuplicateScanning;
    private bool _isActionModalBusy;
    private string _busyOperationTitle = "Executando operação em segundo plano...";
    private string _busyStepDetail = "Aguarde enquanto a tarefa é processada...";
    private string _busyLiveOutputLog = string.Empty;
    private readonly Queue<string> _recentBusyLines = new();
    private readonly Stopwatch _busyStopwatch = new();
    private System.Windows.Threading.DispatcherTimer? _busyTimer;
    private bool _isCleanupUnlocked = true; // Habilitado para permitir seleção rápida com prévia obrigatória
    private bool _preferRecycleBin = true;

    private string _statusHeadline = "Pronto para analisar. Selecione a unidade ou escopo e clique em 'Analisar Armazenamento'.";
    private string _currentScanningPath = "Aguardando início da varredura...";
    private string _filesScannedText = "0";
    private string _dirsScannedText = "0";
    private string _scannedLogicalSizeText = "0 B";
    private string _scannedAllocatedSizeText = "0 B";
    private string _accessDeniedText = "0";
    private string _elapsedTimeText = "0,0s";

    private string _estimatedRecoverableTotalText = "0 B";
    private string _estimatedGreenRecoverableText = "0 B";
    private string _estimatedYellowRecoverableText = "0 B";
    private string _selectedForCleanupSummaryText = "0 itens selecionados (0 B)";
    private string _cleanActionButtonText = "🧹 Prévia e Limpar Selecionados (0)";

    private string _appDataLocalTotalText = "0 B";
    private string _appDataRoamingTotalText = "0 B";
    private string _appDataLocalLowTotalText = "0 B";
    private string _appDataSafeCacheTotalText = "0 B";

    private string _selectedRiskFilter = "Todos os Níveis de Risco";
    private string _findingsSearchQuery = string.Empty;
    private string? _activeFindingGroupId;
    private string _selectedAppDataScopeFilter = "Todos (Local + Roaming + LocalLow)";
    private string _selectedDuplicateMinSizeOption = "1 MB (Recomendado)";
    private string _duplicateStatusText = "A análise de duplicados calcula tamanho exato, pré-hash e SHA-256 completo sob demanda.";

    private string _growthComparisonBannerText = "Analise uma unidade para salvar o snapshot e comparar o que cresceu ao longo do tempo.";
    private bool _onlyDormantProjectsOver90Days;
    private string _lockingProcessesStatusText = "Clique em '🔍 Quem está usando?' para consultar o Restart Manager do Windows sem travar o arquivo.";

    private StorageItem? _selectedInspectorItem;
    private AppDataEntry? _selectedAppDataEntry;
    private DeveloperArtifactItem? _selectedDevArtifact;
    private ProjectActivitySummary? _selectedDeveloperProject;
    private DuplicateFileEntry? _selectedDuplicateEntry;
    private ScanResult? _lastScanResult;

    public MainViewModel(
        IEnvironmentProvider environmentProvider,
        IDriveDiscoveryService driveDiscoveryService,
        IDiskScannerService diskScannerService,
        IDuplicateFileDetector duplicateFileDetector,
        ISafeCleanupService safeCleanupService,
        IOperationHistoryRepository historyRepository,
        IRecycleBin? recycleBin = null,
        IFileLockDetector? fileLockDetector = null,
        IOfficialMaintenanceExecutor? officialMaintenanceExecutor = null)
    {
        _environmentProvider = environmentProvider;
        _driveDiscoveryService = driveDiscoveryService;
        _diskScannerService = diskScannerService;
        _duplicateFileDetector = duplicateFileDetector;
        _safeCleanupService = safeCleanupService;
        _historyRepository = historyRepository;
        _recycleBin = recycleBin;
        _fileLockDetector = fileLockDetector;
        _officialMaintenanceExecutor = officialMaintenanceExecutor;

        EnvironmentInfo = _environmentProvider.GetEnvironmentPaths();

        StartScanCommand = new AsyncRelayCommand(StartScanAsync, () => !IsScanning && SelectedDrive is not null);
        CancelScanCommand = new RelayCommand(CancelScan, () => IsScanning || IsDuplicateScanning);
        RefreshDrivesCommand = new RelayCommand(LoadDrives, () => !IsScanning);
        RunDuplicateScanCommand = new AsyncRelayCommand(RunDuplicateScanAsync, () => !IsScanning && !IsDuplicateScanning && SelectedDrive is not null);

        // Comandos de seleção em massa (um clique). Com a limpeza travada (modo somente leitura) ficam desabilitados:
        // a trava é uma decisão explícita do usuário e nenhum botão a desfaz por conta própria.
        SelectAllSafeGreenCommand = new RelayCommand(SelectAllSafeGreenItems, () => IsCleanupUnlocked && !IsScanning && _lastScanResult is not null);
        SelectAllYellowCommand = new RelayCommand(SelectAllYellowItems, () => IsCleanupUnlocked && !IsScanning && _lastScanResult is not null);
        SelectAllFilteredCommand = new RelayCommand(SelectAllVisibleFilteredItems, () => IsCleanupUnlocked && !IsScanning && FilteredFindings.Count > 0);
        UnselectAllFilteredCommand = new RelayCommand(UnselectAllVisibleFilteredItems, () => !IsScanning && FilteredFindings.Count > 0);
        SelectAllAppDataSafeCachesCommand = new RelayCommand(SelectAllAppDataSafeCaches, () => IsCleanupUnlocked && !IsScanning && _lastScanResult is not null);
        SelectAllDevCachesCommand = new RelayCommand(SelectAllDevCaches, () => IsCleanupUnlocked && !IsScanning && DeveloperArtifacts.Count > 0);
        SelectAllDuplicateCopiesCommand = new RelayCommand(SelectAllDuplicateCopies, () => IsCleanupUnlocked && !IsScanning && DuplicateGroups.Count > 0);
        ClearSelectionCommand = new RelayCommand(ClearAllCleanupSelections, () => !IsScanning);
        EmptyRecycleBinCommand = new RelayCommand(EmptyRecycleBin, () => !IsScanning && _recycleBin is not null && SelectedDrive is not null);

        // Diferencial 1: Achados por Grupo
        SelectFindingGroupCommand = new RelayCommand(SelectFindingGroup, p => IsCleanupUnlocked && !IsScanning && p is FindingGroupSummary g && g.CanSelectAll);
        FilterByFindingGroupCommand = new RelayCommand(FilterByFindingGroup, p => !IsScanning && p is FindingGroupSummary);

        // Diferencial 2: Mapa de Blocos Colorido por Risco
        SelectTreemapBlockCommand = new RelayCommand(SelectTreemapBlock, p => p is TreemapBlockItem);

        // Diferencial 4: Execução de Comando Oficial em 1 Clique (com medição antes e depois)
        ExecuteOfficialCommand = new AsyncRelayCommand(
            ExecuteOfficialCommandAsync,
            CanExecuteOfficialCommand);

        // Diferencial 5: Projetos Parados (> 90 dias)
        SelectAllDormantProjectsCommand = new RelayCommand(
            SelectAllDormantProjects,
            () => IsCleanupUnlocked && !IsScanning && FilteredDeveloperProjects.Any(p => p.IsDormantOver90Days && p.CleanableBytes > 0));
        SelectProjectArtifactsCommand = new RelayCommand(
            SelectProjectArtifacts,
            p => IsCleanupUnlocked && !IsScanning && p is ProjectActivitySummary proj && proj.CleanableBytes > 0);

        // Diferencial 6: Liberar Espaço Sem Apagar
        ExecuteNonDestructiveOptionCommand = new AsyncRelayCommand(
            ExecuteNonDestructiveOptionAsync,
            p => !IsScanning && _officialMaintenanceExecutor is not null && p is NonDestructiveOption);

        // Diferencial 7: Quem está usando (Restart Manager) + Desfazer última limpeza
        CheckWhoIsUsingCommand = new RelayCommand(
            CheckWhoIsUsingSelectedItem,
            () => _fileLockDetector is not null && SelectedInspectorItem is not null);
        UndoLastCleanupCommand = new RelayCommand(
            UndoLastCleanup,
            () => !IsScanning && _recycleBin is not null && _lastRecycledPaths.Count > 0);

        OpenCleanupPreviewCommand = new AsyncRelayCommand(OpenCleanupPreviewAndExecuteAsync, () => IsCleanupUnlocked && !IsScanning && _lastScanResult is not null);
        OpenInExplorerCommand = new RelayCommand(OpenSelectedInExplorer, () => SelectedInspectorItem is not null);
        CopyPathCommand = new RelayCommand(CopySelectedPath, () => SelectedInspectorItem is not null);
        CopyOfficialCommand = new RelayCommand(CopyOfficialCommandToClipboard, () => !string.IsNullOrWhiteSpace(SelectedInspectorItem?.OfficialMaintenanceCommand));
        ExportHistoryCommand = new RelayCommand(ExportHistoryToJson);

        LoadDrives();
        RefreshHistoryList();
    }

    public EnvironmentPaths EnvironmentInfo { get; }

    public string PrivilegeStatusBadge => EnvironmentInfo.IsElevatedAdmin
        ? "Modo Administrador Elevado"
        : "Modo Usuário Padrão (Seguro)";

    public string PrivilegeExplanation => EnvironmentInfo.IsElevatedAdmin
        ? "Executando com privilégios administrativos: leitura completa de diretórios de sistema habilitada."
        : "Funcionando com privilégios normais (recomendado). Pastas exclusivas do sistema (como System Volume Information) serão contabilizadas em 'Sem Permissão' sem interromper a análise.";

    public ObservableCollection<DriveMetadata> Drives { get; } = [];

    public IReadOnlyList<string> ScanScopeOptions { get; } =
    [
        "Unidade Completa Selecionada",
        "Apenas Perfil do Usuário Atual (%USERPROFILE%)",
        "Apenas AppData Completo (Local + Roaming + LocalLow)",
        "Apenas Pasta Downloads do Usuário"
    ];

    public IReadOnlyList<string> RiskFilterOptions { get; } =
    [
        "Todos os Níveis de Risco",
        "VERDE — Apenas Baixo Risco (Seguro)",
        "AMARELO — Apenas Requer Atenção",
        "VERMELHO — Apenas Alto Risco (Protegido)",
        "CINZA — Apenas Sistema / Desconhecido"
    ];

    public IReadOnlyList<string> AppDataScopeFilterOptions { get; } =
    [
        "Todos (Local + Roaming + LocalLow)",
        @"Apenas AppData\Local",
        @"Apenas AppData\Roaming",
        @"Apenas AppData\LocalLow",
        "Apenas Possíveis Resíduos de Programas Desinstalados"
    ];

    public IReadOnlyList<string> DuplicateMinSizeOptions { get; } =
    [
        "100 KB (Detalhado)",
        "1 MB (Recomendado)",
        "10 MB (Apenas Arquivos Grandes)",
        "50 MB (Apenas Mídia / Instaladores)"
    ];

    // Coleções vinculadas à interface
    public ObservableCollection<StorageItem> RootTreeNodes { get; } = [];
    public ObservableCollection<StorageDistributionSlice> CategorySlices { get; } = [];
    public ObservableCollection<StorageDistributionSlice> RiskSlices { get; } = [];
    public ObservableCollection<TreemapBlockItem> RiskTreemapBlocks { get; } = [];
    public ObservableCollection<FindingGroupSummary> FindingGroups { get; } = [];
    public ObservableCollection<FolderGrowthDelta> GrowthDeltas { get; } = [];
    public ObservableCollection<StorageItem> TopHeavyFolders { get; } = [];
    public ObservableCollection<StorageItem> TopHeavyFiles { get; } = [];
    public ObservableCollection<StorageItem> HighDensityFolders { get; } = [];
    public ObservableCollection<StorageItem> FilteredFindings { get; } = [];
    public ObservableCollection<AppDataEntry> FilteredAppDataEntries { get; } = [];
    public ObservableCollection<DeveloperArtifactItem> DeveloperArtifacts { get; } = [];
    public ObservableCollection<ProjectActivitySummary> FilteredDeveloperProjects { get; } = [];
    public ObservableCollection<NonDestructiveOption> NonDestructiveOptions { get; } = [];
    public ObservableCollection<DuplicateGroup> DuplicateGroups { get; } = [];
    public ObservableCollection<OperationLogEntry> OperationLogs { get; } = [];

    // Comandos MVVM
    public AsyncRelayCommand StartScanCommand { get; }
    public RelayCommand CancelScanCommand { get; }
    public RelayCommand RefreshDrivesCommand { get; }
    public AsyncRelayCommand RunDuplicateScanCommand { get; }

    public RelayCommand SelectAllSafeGreenCommand { get; }
    public RelayCommand SelectAllYellowCommand { get; }
    public RelayCommand SelectAllFilteredCommand { get; }
    public RelayCommand UnselectAllFilteredCommand { get; }
    public RelayCommand SelectAllAppDataSafeCachesCommand { get; }
    public RelayCommand SelectAllDevCachesCommand { get; }
    public RelayCommand SelectAllDuplicateCopiesCommand { get; }
    public RelayCommand ClearSelectionCommand { get; }
    public RelayCommand EmptyRecycleBinCommand { get; }

    public RelayCommand SelectFindingGroupCommand { get; }
    public RelayCommand FilterByFindingGroupCommand { get; }
    public RelayCommand SelectTreemapBlockCommand { get; }
    public AsyncRelayCommand ExecuteOfficialCommand { get; }
    public RelayCommand SelectAllDormantProjectsCommand { get; }
    public RelayCommand SelectProjectArtifactsCommand { get; }
    public AsyncRelayCommand ExecuteNonDestructiveOptionCommand { get; }
    public RelayCommand CheckWhoIsUsingCommand { get; }
    public RelayCommand UndoLastCleanupCommand { get; }

    public AsyncRelayCommand OpenCleanupPreviewCommand { get; }
    public RelayCommand OpenInExplorerCommand { get; }
    public RelayCommand CopyPathCommand { get; }
    public RelayCommand CopyOfficialCommand { get; }
    public RelayCommand ExportHistoryCommand { get; }

    public DriveMetadata? SelectedDrive
    {
        get => _selectedDrive;
        set
        {
            if (SetProperty(ref _selectedDrive, value))
            {
                OnPropertyChanged(nameof(DriveTotalCapacityText));
                OnPropertyChanged(nameof(DriveUsedSpaceText));
                OnPropertyChanged(nameof(DriveFreeSpaceText));
                OnPropertyChanged(nameof(DriveUsagePercentText));
                OnPropertyChanged(nameof(DriveUsagePercentValue));
                OnPropertyChanged(nameof(DriveFileSystemText));
                RefreshRecycleBinSummary();
            }
        }
    }

    public string RecycleBinSummaryText
    {
        get => _recycleBinSummaryText;
        private set => SetProperty(ref _recycleBinSummaryText, value);
    }

    public string SelectedScanScope
    {
        get => _selectedScanScope;
        set => SetProperty(ref _selectedScanScope, value);
    }

    public string DriveTotalCapacityText => SelectedDrive?.FormattedTotal ?? "0 B";
    public string DriveUsedSpaceText => SelectedDrive?.FormattedUsed ?? "0 B";
    public string DriveFreeSpaceText => SelectedDrive?.FormattedFree ?? "0 B";
    public string DriveUsagePercentText => SelectedDrive is not null ? $"{SelectedDrive.UsagePercentage:0.0}%" : "0%";
    public double DriveUsagePercentValue => SelectedDrive?.UsagePercentage ?? 0.0;
    public string DriveFileSystemText => SelectedDrive is not null
        ? $"{SelectedDrive.FileSystem} • {SelectedDrive.DriveTypeDescription}"
        : "N/D";

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (SetProperty(ref _isScanning, value))
            {
                OnPropertyChanged(nameof(IsBusy));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public bool IsDuplicateScanning
    {
        get => _isDuplicateScanning;
        private set
        {
            if (SetProperty(ref _isDuplicateScanning, value))
            {
                OnPropertyChanged(nameof(IsBusy));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public bool IsActionModalBusy
    {
        get => _isActionModalBusy;
        private set
        {
            if (SetProperty(ref _isActionModalBusy, value))
            {
                OnPropertyChanged(nameof(IsBusy));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public bool IsBusy => IsScanning || IsDuplicateScanning || IsActionModalBusy;

    public string BusyOperationTitle
    {
        get => _busyOperationTitle;
        set => SetProperty(ref _busyOperationTitle, value);
    }

    public string BusyStepDetail
    {
        get => _busyStepDetail;
        set => SetProperty(ref _busyStepDetail, value);
    }

    public string BusyLiveOutputLog
    {
        get => _busyLiveOutputLog;
        set => SetProperty(ref _busyLiveOutputLog, value);
    }

    private void BeginBusyOperation(string title, string initialStep, bool showModalOverlay)
    {
        BusyOperationTitle = title;
        BusyStepDetail = initialStep;
        _recentBusyLines.Clear();
        _recentBusyLines.Enqueue($"[0,0s] {initialStep}");
        BusyLiveOutputLog = $"[0,0s] {initialStep}";
        StatusHeadline = title;
        CurrentScanningPath = initialStep;

        _busyStopwatch.Restart();
        ElapsedTimeText = "0,0s";

        if (_busyTimer is null)
        {
            _busyTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(200)
            };
            _busyTimer.Tick += (_, _) =>
            {
                if (_busyStopwatch.IsRunning)
                {
                    ElapsedTimeText = $"{_busyStopwatch.Elapsed.TotalSeconds:0.0}s";
                }
            };
        }

        _busyTimer.Start();
        IsScanning = true;
        IsActionModalBusy = showModalOverlay;
    }

    private void ReportBusyProgress(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return;
        }

        BusyStepDetail = message;
        StatusHeadline = message;
        CurrentScanningPath = message;
        _recentBusyLines.Enqueue($"[{_busyStopwatch.Elapsed.TotalSeconds:0.0}s] {message}");
        while (_recentBusyLines.Count > 7)
        {
            _recentBusyLines.Dequeue();
        }

        BusyLiveOutputLog = string.Join(Environment.NewLine, _recentBusyLines);
    }

    private void EndBusyOperation()
    {
        _busyTimer?.Stop();
        _busyStopwatch.Stop();
        IsActionModalBusy = false;
        IsScanning = false;
    }

    public bool IsCleanupUnlocked
    {
        get => _isCleanupUnlocked;
        set
        {
            if (SetProperty(ref _isCleanupUnlocked, value))
            {
                if (!value)
                {
                    ClearAllCleanupSelections();
                }

                OnPropertyChanged(nameof(SecurityModeStatusText));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public string SecurityModeStatusText => IsCleanupUnlocked
        ? "Limpeza habilitada (sempre com prévia e confirmação)"
        : "Modo somente leitura (seleção e limpeza travadas)";

    public bool PreferRecycleBin
    {
        get => _preferRecycleBin;
        set => SetProperty(ref _preferRecycleBin, value);
    }

    public string StatusHeadline
    {
        get => _statusHeadline;
        set => SetProperty(ref _statusHeadline, value);
    }

    public string CurrentScanningPath
    {
        get => _currentScanningPath;
        set => SetProperty(ref _currentScanningPath, value);
    }

    public string FilesScannedText
    {
        get => _filesScannedText;
        set => SetProperty(ref _filesScannedText, value);
    }

    public string DirsScannedText
    {
        get => _dirsScannedText;
        set => SetProperty(ref _dirsScannedText, value);
    }

    public string ScannedLogicalSizeText
    {
        get => _scannedLogicalSizeText;
        set => SetProperty(ref _scannedLogicalSizeText, value);
    }

    public string ScannedAllocatedSizeText
    {
        get => _scannedAllocatedSizeText;
        set => SetProperty(ref _scannedAllocatedSizeText, value);
    }

    public string AccessDeniedText
    {
        get => _accessDeniedText;
        set => SetProperty(ref _accessDeniedText, value);
    }

    public string ElapsedTimeText
    {
        get => _elapsedTimeText;
        set => SetProperty(ref _elapsedTimeText, value);
    }

    public string EstimatedRecoverableTotalText
    {
        get => _estimatedRecoverableTotalText;
        set => SetProperty(ref _estimatedRecoverableTotalText, value);
    }

    public string EstimatedGreenRecoverableText
    {
        get => _estimatedGreenRecoverableText;
        set => SetProperty(ref _estimatedGreenRecoverableText, value);
    }

    public string EstimatedYellowRecoverableText
    {
        get => _estimatedYellowRecoverableText;
        set => SetProperty(ref _estimatedYellowRecoverableText, value);
    }

    public string SelectedForCleanupSummaryText
    {
        get => _selectedForCleanupSummaryText;
        set => SetProperty(ref _selectedForCleanupSummaryText, value);
    }

    public string CleanActionButtonText
    {
        get => _cleanActionButtonText;
        set => SetProperty(ref _cleanActionButtonText, value);
    }

    public string AppDataLocalTotalText
    {
        get => _appDataLocalTotalText;
        set => SetProperty(ref _appDataLocalTotalText, value);
    }

    public string AppDataRoamingTotalText
    {
        get => _appDataRoamingTotalText;
        set => SetProperty(ref _appDataRoamingTotalText, value);
    }

    public string AppDataLocalLowTotalText
    {
        get => _appDataLocalLowTotalText;
        set => SetProperty(ref _appDataLocalLowTotalText, value);
    }

    public string AppDataSafeCacheTotalText
    {
        get => _appDataSafeCacheTotalText;
        set => SetProperty(ref _appDataSafeCacheTotalText, value);
    }

    public string SelectedRiskFilter
    {
        get => _selectedRiskFilter;
        set
        {
            if (SetProperty(ref _selectedRiskFilter, value))
            {
                _activeFindingGroupId = null;
                ApplyFindingsFilter();
            }
        }
    }

    public string FindingsSearchQuery
    {
        get => _findingsSearchQuery;
        set
        {
            if (SetProperty(ref _findingsSearchQuery, value))
            {
                ApplyFindingsFilter();
            }
        }
    }

    public string SelectedAppDataScopeFilter
    {
        get => _selectedAppDataScopeFilter;
        set
        {
            if (SetProperty(ref _selectedAppDataScopeFilter, value))
            {
                ApplyAppDataFilter();
            }
        }
    }

    public string SelectedDuplicateMinSizeOption
    {
        get => _selectedDuplicateMinSizeOption;
        set => SetProperty(ref _selectedDuplicateMinSizeOption, value);
    }

    public string DuplicateStatusText
    {
        get => _duplicateStatusText;
        set => SetProperty(ref _duplicateStatusText, value);
    }

    public string GrowthComparisonBannerText
    {
        get => _growthComparisonBannerText;
        set => SetProperty(ref _growthComparisonBannerText, value);
    }

    public bool OnlyDormantProjectsOver90Days
    {
        get => _onlyDormantProjectsOver90Days;
        set
        {
            if (SetProperty(ref _onlyDormantProjectsOver90Days, value))
            {
                ApplyDeveloperProjectsFilter();
            }
        }
    }

    public string LockingProcessesStatusText
    {
        get => _lockingProcessesStatusText;
        set => SetProperty(ref _lockingProcessesStatusText, value);
    }

    public StorageItem? SelectedInspectorItem
    {
        get => _selectedInspectorItem;
        set
        {
            if (SetProperty(ref _selectedInspectorItem, value))
            {
                LockingProcessesStatusText = "Clique em '🔍 Quem está usando?' para consultar o Windows Restart Manager sem travar o arquivo.";
                OnPropertyChanged(nameof(CanExecuteOfficialCommandForSelected));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public bool CanExecuteOfficialCommandForSelected =>
        _officialMaintenanceExecutor is not null &&
        SelectedInspectorItem is not null &&
        _officialMaintenanceExecutor.CanExecuteCommand(SelectedInspectorItem.OfficialMaintenanceCommand, SelectedInspectorItem.FullPath, out _);

    public AppDataEntry? SelectedAppDataEntry
    {
        get => _selectedAppDataEntry;
        set
        {
            if (SetProperty(ref _selectedAppDataEntry, value) && value?.RootStorageItem is not null)
            {
                SelectedInspectorItem = value.RootStorageItem;
            }
        }
    }

    public DeveloperArtifactItem? SelectedDevArtifact
    {
        get => _selectedDevArtifact;
        set
        {
            if (SetProperty(ref _selectedDevArtifact, value) && value?.UnderlyingItem is not null)
            {
                SelectedInspectorItem = value.UnderlyingItem;
            }
        }
    }

    public ProjectActivitySummary? SelectedDeveloperProject
    {
        get => _selectedDeveloperProject;
        set
        {
            if (SetProperty(ref _selectedDeveloperProject, value))
            {
                StorageItem? firstItem = value?.Artifacts.FirstOrDefault()?.UnderlyingItem;
                if (firstItem is not null)
                {
                    SelectedInspectorItem = firstItem;
                }
            }
        }
    }

    public DuplicateFileEntry? SelectedDuplicateEntry
    {
        get => _selectedDuplicateEntry;
        set
        {
            if (SetProperty(ref _selectedDuplicateEntry, value) && value?.StorageItem is not null)
            {
                SelectedInspectorItem = value.StorageItem;
            }
        }
    }

    public void LoadDrives()
    {
        string? previousDriveName = SelectedDrive?.Name;
        IReadOnlyList<DriveMetadata> discovered = _driveDiscoveryService.GetAvailableDrives();

        Drives.Clear();
        foreach (DriveMetadata d in discovered)
        {
            Drives.Add(d);
        }

        SelectedDrive = Drives.FirstOrDefault(d => string.Equals(d.Name, previousDriveName, StringComparison.OrdinalIgnoreCase))
                        ?? Drives.FirstOrDefault();

        RefreshRecycleBinSummary();
    }

    private string ResolveTargetScanPath()
    {
        if (SelectedDrive is null)
        {
            return EnvironmentInfo.UserProfileDir;
        }

        if (SelectedScanScope.Contains("%USERPROFILE%", StringComparison.OrdinalIgnoreCase))
        {
            return EnvironmentInfo.UserProfileDir;
        }

        if (SelectedScanScope.Contains("AppData", StringComparison.OrdinalIgnoreCase))
        {
            string? appDataRoot = Directory.GetParent(EnvironmentInfo.LocalAppDataDir)?.FullName;
            if (!string.IsNullOrWhiteSpace(appDataRoot) && Directory.Exists(appDataRoot))
            {
                return appDataRoot;
            }
        }

        if (SelectedScanScope.Contains("Downloads", StringComparison.OrdinalIgnoreCase) &&
            Directory.Exists(EnvironmentInfo.DownloadsDir))
        {
            return EnvironmentInfo.DownloadsDir;
        }

        return SelectedDrive.RootDirectory;
    }

    private async Task StartScanAsync()
    {
        if (SelectedDrive is null || IsScanning)
        {
            return;
        }

        string targetPath = ResolveTargetScanPath();
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();

        IsScanning = true;
        StatusHeadline = $"Analisando armazenamento em '{targetPath}' (100% Somente Leitura)...";
        CurrentScanningPath = targetPath;

        Progress<ScanProgressReport> progress = new(report =>
        {
            CurrentScanningPath = report.CurrentDirectory;
            FilesScannedText = $"{report.FilesScanned:N0}";
            DirsScannedText = $"{report.DirectoriesScanned:N0}";
            ScannedLogicalSizeText = report.FormattedScannedSize;
            ScannedAllocatedSizeText = report.FormattedAllocatedSize;
            AccessDeniedText = $"{report.AccessDeniedCount:N0}";
            ElapsedTimeText = $"{report.Elapsed.TotalSeconds:0.0}s";
        });

        try
        {
            ScanResult result = await _diskScannerService.ScanAsync(
                SelectedDrive,
                targetPath,
                progress,
                _scanCts.Token);

            ApplyScanResult(result);
            StatusHeadline = $"Análise concluída em {result.Duration.TotalSeconds:0.0}s — {result.TotalFilesScanned:N0} arquivos ({result.FormattedTotalLogical} lógicos / {result.FormattedTotalAllocated} alocados).";
            CurrentScanningPath = $"Concluído: {targetPath}";
        }
        catch (OperationCanceledException)
        {
            StatusHeadline = "Análise cancelada pelo usuário.";
            CurrentScanningPath = "Operação interrompida com segurança.";
        }
        catch (Exception ex)
        {
            StatusHeadline = $"Erro durante a varredura: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
            RefreshHistoryList();
            LoadDrives();
        }
    }

    private void CancelScan()
    {
        _scanCts?.Cancel();
        _duplicateCts?.Cancel();
        _cleanupCts?.Cancel();
    }

    private void RefreshRecycleBinSummary()
    {
        if (_recycleBin is null || SelectedDrive is null)
        {
            RecycleBinSummaryText = "Lixeira: sem informação";
            return;
        }

        RecycleBinStatus status = _recycleBin.GetStatus(SelectedDrive.RootDirectory);
        RecycleBinSummaryText = status.IsAvailable
            ? $"Lixeira: {status.FormattedUsed} em {status.ItemCount:N0} item(ns) (limite {status.FormattedCapacity})"
            : $"Lixeira indisponível: {status.UnavailableReason}";
    }

    private void EmptyRecycleBin()
    {
        if (_recycleBin is null || SelectedDrive is null)
        {
            return;
        }

        IntPtr owner = Application.Current?.MainWindow is Window window
            ? new System.Windows.Interop.WindowInteropHelper(window).Handle
            : IntPtr.Zero;

        _recycleBin.Empty(SelectedDrive.RootDirectory, owner);
        LoadDrives();
        StatusHeadline = $"Lixeira de {SelectedDrive?.Name}: {RecycleBinSummaryText}";
    }

    private void RunBulkSelection(Action change)
    {
        _bulkSelectionDepth++;
        try
        {
            change();
        }
        finally
        {
            _bulkSelectionDepth--;
            if (_bulkSelectionDepth == 0)
            {
                UpdateCleanupSelectionSummary();
            }
        }
    }

    private double _treemapWidth = RiskTreemapBuilder.DefaultCanvasWidth;
    private double _treemapHeight = RiskTreemapBuilder.DefaultCanvasHeight;

    public void UpdateTreemapDimensions(double width, double height)
    {
        if (width < 220 || height < 90)
        {
            return;
        }

        if (Math.Abs(_treemapWidth - width) < 4.0 && Math.Abs(_treemapHeight - height) < 4.0)
        {
            return;
        }

        _treemapWidth = width;
        _treemapHeight = height;

        if (_lastScanResult is not null)
        {
            RebuildTreemapBlocks();
        }
    }

    private void RebuildTreemapBlocks()
    {
        RiskTreemapBlocks.Clear();
        if (_lastScanResult is null)
        {
            return;
        }

        IReadOnlyList<TreemapBlockItem> blocks = RiskTreemapBuilder.BuildRiskTreemap(
            _lastScanResult.RootNode,
            _lastScanResult.ClassifiedFindings,
            _lastScanResult.TopHeavyFolders,
            _treemapWidth,
            _treemapHeight);

        foreach (TreemapBlockItem block in blocks)
        {
            RiskTreemapBlocks.Add(block);
        }
    }

    private void ApplyScanResult(ScanResult result)
    {
        _lastScanResult = result;
        _removedPaths.Clear();
        _activeFindingGroupId = null;

        FilesScannedText = $"{result.TotalFilesScanned:N0}";
        DirsScannedText = $"{result.TotalDirectoriesScanned:N0}";
        ScannedLogicalSizeText = result.FormattedTotalLogical;
        ScannedAllocatedSizeText = result.FormattedTotalAllocated;
        AccessDeniedText = $"{result.TotalAccessDenied:N0}";
        ElapsedTimeText = $"{result.Duration.TotalSeconds:0.0}s";

        EstimatedGreenRecoverableText = result.FormattedGreenRecoverable;
        EstimatedYellowRecoverableText = result.FormattedYellowRecoverable;
        EstimatedRecoverableTotalText = result.FormattedTotalRecoverable;

        AppDataLocalTotalText = ByteSizeFormatter.FormatBytes(result.AppDataLocalBytes);
        AppDataRoamingTotalText = ByteSizeFormatter.FormatBytes(result.AppDataRoamingBytes);
        AppDataLocalLowTotalText = ByteSizeFormatter.FormatBytes(result.AppDataLocalLowBytes);
        long safeAppDataTotal = result.AppDataEntries.Sum(a => a.SafeDisposableCacheBytes);
        AppDataSafeCacheTotalText = ByteSizeFormatter.FormatBytes(safeAppDataTotal);

        result.RootNode.IsExpandedByDefault = true;
        RootTreeNodes.Clear();
        RootTreeNodes.Add(result.RootNode);

        CategorySlices.Clear();
        foreach (StorageDistributionSlice slice in result.CategoryDistribution)
        {
            CategorySlices.Add(slice);
        }

        RiskSlices.Clear();
        foreach (StorageDistributionSlice slice in result.RiskDistribution)
        {
            RiskSlices.Add(slice);
        }

        RebuildTreemapBlocks();

        FindingGroups.Clear();
        foreach (FindingGroupSummary group in result.FindingGroups)
        {
            FindingGroups.Add(group);
        }

        GrowthDeltas.Clear();
        foreach (FolderGrowthDelta delta in result.GrowthDeltas)
        {
            GrowthDeltas.Add(delta);
        }

        if (result.PreviousSnapshotUtc is DateTime prevUtc && result.PreviousRootTotalBytes is long prevRootBytes)
        {
            long rootDiff = result.RootNode.LogicalSizeBytes - prevRootBytes;
            string sign = rootDiff >= 0 ? "+" : "-";
            GrowthComparisonBannerText =
                $"Comparado com a análise anterior ({prevUtc.ToLocalTime():dd/MM/yyyy HH:mm}): variação total de {sign}{ByteSizeFormatter.FormatBytes(Math.Abs(rootDiff))} ({result.GrowthDeltas.Count} pastas com variação relevante).";
        }
        else
        {
            GrowthComparisonBannerText =
                "Snapshot inicial salvo! Nas próximas análises deste mesmo escopo, esta aba mostrará exatamente quais pastas cresceram ou encolheram.";
        }

        TopHeavyFolders.Clear();
        foreach (StorageItem folder in result.TopHeavyFolders)
        {
            AttachSelectionObserver(folder);
            TopHeavyFolders.Add(folder);
        }

        TopHeavyFiles.Clear();
        foreach (StorageItem file in result.TopHeavyFiles)
        {
            AttachSelectionObserver(file);
            TopHeavyFiles.Add(file);
        }

        HighDensityFolders.Clear();
        foreach (StorageItem hd in result.HighDensityFolders)
        {
            AttachSelectionObserver(hd);
            HighDensityFolders.Add(hd);
        }

        foreach (StorageItem finding in result.ClassifiedFindings)
        {
            AttachSelectionObserver(finding);
        }

        foreach (AppDataEntry appEntry in result.AppDataEntries)
        {
            foreach (StorageItem cacheSub in appEntry.SafeCacheSubdirectories)
            {
                AttachSelectionObserver(cacheSub);
            }
        }

        DeveloperArtifacts.Clear();
        foreach (DeveloperArtifactItem dev in result.DeveloperArtifacts)
        {
            if (dev.UnderlyingItem is not null)
            {
                AttachSelectionObserver(dev.UnderlyingItem);
            }
            DeveloperArtifacts.Add(dev);
        }

        NonDestructiveOptions.Clear();
        foreach (NonDestructiveOption opt in result.NonDestructiveOptions)
        {
            NonDestructiveOptions.Add(opt);
        }

        ApplyFindingsFilter();
        ApplyAppDataFilter();
        ApplyDeveloperProjectsFilter();

        SelectedInspectorItem = result.TopHeavyFolders.FirstOrDefault() ?? result.RootNode;
        UpdateCleanupSelectionSummary();
    }

    private void AttachSelectionObserver(StorageItem item)
    {
        item.PropertyChanged -= OnStorageItemPropertyChanged;
        item.PropertyChanged += OnStorageItemPropertyChanged;
    }

    private void OnStorageItemPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(StorageItem.IsSelectedForCleanup) && _bulkSelectionDepth == 0)
        {
            UpdateCleanupSelectionSummary();
        }
    }

    private void ApplyFindingsFilter()
    {
        FilteredFindings.Clear();
        if (_lastScanResult is null)
        {
            return;
        }

        IEnumerable<StorageItem> query;
        if (!string.IsNullOrWhiteSpace(_activeFindingGroupId))
        {
            FindingGroupSummary? activeGroup = FindingGroups.FirstOrDefault(g => g.GroupId == _activeFindingGroupId);
            query = activeGroup is not null
                ? activeGroup.Items.Where(i => !WasRemoved(i))
                : _lastScanResult.ClassifiedFindings.Where(i => !WasRemoved(i));
        }
        else
        {
            query = _lastScanResult.ClassifiedFindings.Where(i => !WasRemoved(i));
        }

        if (SelectedRiskFilter.StartsWith("VERDE", StringComparison.OrdinalIgnoreCase))
        {
            query = query.Where(i => i.RiskClassification == RiskLevel.Green);
        }
        else if (SelectedRiskFilter.StartsWith("AMARELO", StringComparison.OrdinalIgnoreCase))
        {
            query = query.Where(i => i.RiskClassification == RiskLevel.Yellow);
        }
        else if (SelectedRiskFilter.StartsWith("VERMELHO", StringComparison.OrdinalIgnoreCase))
        {
            query = query.Where(i => i.RiskClassification == RiskLevel.Red);
        }
        else if (SelectedRiskFilter.StartsWith("CINZA", StringComparison.OrdinalIgnoreCase))
        {
            query = query.Where(i => i.RiskClassification == RiskLevel.Gray);
        }

        if (!string.IsNullOrWhiteSpace(FindingsSearchQuery))
        {
            string term = FindingsSearchQuery.Trim();
            query = query.Where(i =>
                i.Name.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                i.FullPath.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                i.AssociatedAppOrComponent.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                i.CategoryDisplayName.Contains(term, StringComparison.OrdinalIgnoreCase));
        }

        foreach (StorageItem item in query)
        {
            FilteredFindings.Add(item);
        }

        CommandManager.InvalidateRequerySuggested();
    }

    private void ApplyAppDataFilter()
    {
        FilteredAppDataEntries.Clear();
        if (_lastScanResult is null)
        {
            return;
        }

        IEnumerable<AppDataEntry> query = _lastScanResult.AppDataEntries;

        if (SelectedAppDataScopeFilter.Contains("Desinstalados", StringComparison.OrdinalIgnoreCase))
        {
            query = query.Where(e => e.LooksLikeUninstalledApp);
        }
        else if (SelectedAppDataScopeFilter.Contains(@"AppData\LocalLow", StringComparison.OrdinalIgnoreCase))
        {
            query = query.Where(e => e.Scope == AppDataScope.LocalLow);
        }
        else if (SelectedAppDataScopeFilter.Contains(@"AppData\Local", StringComparison.OrdinalIgnoreCase))
        {
            query = query.Where(e => e.Scope == AppDataScope.Local);
        }
        else if (SelectedAppDataScopeFilter.Contains(@"AppData\Roaming", StringComparison.OrdinalIgnoreCase))
        {
            query = query.Where(e => e.Scope == AppDataScope.Roaming);
        }

        foreach (AppDataEntry entry in query)
        {
            FilteredAppDataEntries.Add(entry);
        }
    }

    private void ApplyDeveloperProjectsFilter()
    {
        FilteredDeveloperProjects.Clear();
        if (_lastScanResult is null)
        {
            return;
        }

        IEnumerable<ProjectActivitySummary> query = _lastScanResult.DeveloperProjects;
        if (OnlyDormantProjectsOver90Days)
        {
            query = query.Where(p => p.IsDormantOver90Days);
        }

        foreach (ProjectActivitySummary proj in query)
        {
            FilteredDeveloperProjects.Add(proj);
        }

        CommandManager.InvalidateRequerySuggested();
    }

    private void SelectFindingGroup(object? parameter)
    {
        if (!IsCleanupUnlocked || parameter is not FindingGroupSummary group)
        {
            return;
        }

        int count = 0;
        RunBulkSelection(() =>
        {
            foreach (StorageItem item in group.Items)
            {
                if (!WasRemoved(item) && item.CanSelectForCleanup)
                {
                    item.IsSelectedForCleanup = true;
                    count++;
                }
            }
        });

        StatusHeadline = $"Grupo '{group.GroupTitle}': {count} item(ns) marcado(s) ({group.FormattedTotalSize}).";
    }

    private void FilterByFindingGroup(object? parameter)
    {
        if (parameter is not FindingGroupSummary group)
        {
            return;
        }

        if (_activeFindingGroupId == group.GroupId)
        {
            _activeFindingGroupId = null;
            StatusHeadline = "Filtro por grupo removido: exibindo todos os achados.";
        }
        else
        {
            _activeFindingGroupId = group.GroupId;
            StatusHeadline = $"Exibindo apenas os {group.ItemCount} item(ns) do grupo '{group.GroupTitle}' ({group.FormattedTotalSize}). Clique novamente em 'Filtrar' para mostrar todos.";
        }

        ApplyFindingsFilter();
    }

    private void SelectTreemapBlock(object? parameter)
    {
        if (parameter is TreemapBlockItem block && block.UnderlyingItem is not null)
        {
            SelectedInspectorItem = block.UnderlyingItem;
            StatusHeadline = $"Bloco selecionado no mapa de risco: {block.Title} ({block.FormattedSize} • {block.RiskBadge}).";
        }
    }

    private bool CanExecuteOfficialCommand(object? parameter)
    {
        if (IsScanning || _officialMaintenanceExecutor is null)
        {
            return false;
        }

        if (parameter is DeveloperArtifactItem dev && !string.IsNullOrWhiteSpace(dev.OfficialCliCommand))
        {
            return _officialMaintenanceExecutor.CanExecuteCommand(dev.OfficialCliCommand, dev.FullPath, out _);
        }

        if (SelectedInspectorItem is not null && !string.IsNullOrWhiteSpace(SelectedInspectorItem.OfficialMaintenanceCommand))
        {
            return _officialMaintenanceExecutor.CanExecuteCommand(
                SelectedInspectorItem.OfficialMaintenanceCommand,
                SelectedInspectorItem.FullPath,
                out _);
        }

        return false;
    }

    private async Task ExecuteOfficialCommandAsync(object? parameter)
    {
        if (_officialMaintenanceExecutor is null || IsScanning)
        {
            return;
        }

        string? command = null;
        string? targetPath = null;

        if (parameter is DeveloperArtifactItem dev)
        {
            command = dev.OfficialCliCommand;
            targetPath = dev.FullPath;
        }
        else if (SelectedInspectorItem is not null)
        {
            command = SelectedInspectorItem.OfficialMaintenanceCommand;
            targetPath = SelectedInspectorItem.FullPath;
        }

        if (string.IsNullOrWhiteSpace(command) || string.IsNullOrWhiteSpace(targetPath))
        {
            return;
        }

        if (!_officialMaintenanceExecutor.CanExecuteCommand(command, targetPath, out string actionDescription))
        {
            MessageBox.Show(
                $"O comando '{command}' é apenas orientativo ou requer execução manual no Windows.",
                "Comando Manual",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        MessageBoxResult confirm = MessageBox.Show(
            $"Deseja executar agora o comando oficial abaixo com medição automática de espaço antes e depois?\n\n" +
            $"• Ação: {actionDescription}\n" +
            $"• Comando: {command}\n" +
            $"• Alvo: {targetPath}",
            "Executar Comando Oficial (1 Clique)",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        _cleanupCts?.Dispose();
        _cleanupCts = new CancellationTokenSource();
        BeginBusyOperation(
            $"⚡ Executando Comando Oficial: {command}",
            $"{actionDescription} em '{targetPath}'...",
            showModalOverlay: true);
        Progress<string> progress = new(ReportBusyProgress);

        try
        {
            OfficialCommandExecutionResult res = await _officialMaintenanceExecutor.ExecuteOfficialCommandAsync(
                command,
                targetPath,
                progress,
                _cleanupCts.Token);

            EndBusyOperation();
            StatusHeadline = res.SummaryMessage;
            CurrentScanningPath = $"Concluído: {res.CommandExecuted}";
            RefreshHistoryList();
            LoadDrives();

            MessageBox.Show(
                $"{res.SummaryMessage}\n\n" +
                $"• Comando: {res.CommandExecuted}\n" +
                $"• Tamanho Antes: {res.FormattedBytesBefore}\n" +
                $"• Tamanho Depois: {res.FormattedBytesAfter}\n" +
                $"• Espaço Liberado: {res.FormattedBytesFreed}\n" +
                $"• Código de Saída: {res.ExitCode}",
                "Resultado do Comando Oficial",
                MessageBoxButton.OK,
                res.Succeeded ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (OperationCanceledException)
        {
            EndBusyOperation();
            StatusHeadline = "Execução do comando oficial cancelada pelo usuário.";
            CurrentScanningPath = "Operação interrompida com segurança.";
        }
        finally
        {
            EndBusyOperation();
        }
    }

    public void SelectAllDormantProjects()
    {
        if (!IsCleanupUnlocked || _lastScanResult is null)
        {
            return;
        }

        int projectCount = 0;
        int artifactCount = 0;
        RunBulkSelection(() =>
        {
            foreach (ProjectActivitySummary proj in _lastScanResult.DeveloperProjects.Where(p => p.IsDormantOver90Days))
            {
                bool anyMarked = false;
                foreach (DeveloperArtifactItem art in proj.Artifacts)
                {
                    if (art.UnderlyingItem is not null && art.UnderlyingItem.CanSelectForCleanup)
                    {
                        art.UnderlyingItem.IsSelectedForCleanup = true;
                        artifactCount++;
                        anyMarked = true;
                    }
                }

                if (anyMarked)
                {
                    projectCount++;
                }
            }
        });

        StatusHeadline = $"Marcados {artifactCount} diretórios de dependências em {projectCount} projeto(s) parado(s) há mais de 90 dias.";
    }

    private void SelectProjectArtifacts(object? parameter)
    {
        if (!IsCleanupUnlocked || parameter is not ProjectActivitySummary proj)
        {
            return;
        }

        int count = 0;
        RunBulkSelection(() =>
        {
            foreach (DeveloperArtifactItem art in proj.Artifacts)
            {
                if (art.UnderlyingItem is not null && art.UnderlyingItem.CanSelectForCleanup)
                {
                    art.UnderlyingItem.IsSelectedForCleanup = true;
                    count++;
                }
            }
        });

        StatusHeadline = $"Projeto '{proj.ProjectName}': {count} artefato(s) elegível(is) marcado(s) ({proj.FormattedCleanable}).";
    }

    private async Task ExecuteNonDestructiveOptionAsync(object? parameter)
    {
        if (_officialMaintenanceExecutor is null || IsScanning || parameter is not NonDestructiveOption option)
        {
            return;
        }

        MessageBoxResult confirm = MessageBox.Show(
            $"Deseja executar esta otimização sem apagar nenhum arquivo pessoal?\n\n" +
            $"• Otimização: {option.Title}\n" +
            $"• Alvo: {option.TargetPath}\n" +
            $"• Economia estimada: {option.FormattedEstimatedSavings}\n" +
            $"• Comando oficial: {option.OfficialCommand}\n\n" +
            $"{option.Explanation}",
            "Liberar Espaço Sem Apagar",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (confirm != MessageBoxResult.Yes)
        {
            return;
        }

        _cleanupCts?.Dispose();
        _cleanupCts = new CancellationTokenSource();
        BeginBusyOperation(
            $"⚡ Otimizando Sem Apagar: {option.Title}",
            $"Preparando otimização não-destrutiva em '{option.TargetPath}'...",
            showModalOverlay: true);
        Progress<string> progress = new(ReportBusyProgress);

        try
        {
            OfficialCommandExecutionResult res = await _officialMaintenanceExecutor.ExecuteNonDestructiveOptionAsync(
                option,
                progress,
                _cleanupCts.Token);

            EndBusyOperation();
            StatusHeadline = res.SummaryMessage;
            CurrentScanningPath = $"Concluído: {option.Title}";
            RefreshHistoryList();
            LoadDrives();

            MessageBox.Show(
                $"{res.SummaryMessage}\n\n" +
                $"• Espaço Alocado Antes: {res.FormattedBytesBefore}\n" +
                $"• Espaço Alocado Depois: {res.FormattedBytesAfter}\n" +
                $"• Espaço Físico Economizado: {res.FormattedBytesFreed}",
                "Otimização Sem Apagar Concluída",
                MessageBoxButton.OK,
                res.Succeeded ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (OperationCanceledException)
        {
            EndBusyOperation();
            StatusHeadline = "Otimização interrompida pelo usuário.";
            CurrentScanningPath = "Operação cancelada com segurança.";
        }
        finally
        {
            EndBusyOperation();
        }
    }

    private void CheckWhoIsUsingSelectedItem()
    {
        if (_fileLockDetector is null || SelectedInspectorItem is null)
        {
            return;
        }

        IReadOnlyList<LockingProcessInfo> holders = _fileLockDetector.GetLockingProcesses(SelectedInspectorItem.FullPath);
        if (holders.Count == 0)
        {
            LockingProcessesStatusText = "✅ Nenhum processo aberto está segurando este item no momento (verificado via Restart Manager).";
            StatusHeadline = $"Restart Manager: '{SelectedInspectorItem.Name}' não está em uso por nenhum processo.";
        }
        else
        {
            string list = string.Join(", ", holders.Select(h => h.DisplaySummary));
            LockingProcessesStatusText = $"🔒 Em uso por {holders.Count} processo(s): {list}";
            StatusHeadline = $"Restart Manager identificou {holders.Count} processo(s) usando '{SelectedInspectorItem.Name}': {list}";
        }
    }

    private void UndoLastCleanup()
    {
        if (_recycleBin is null || _lastRecycledPaths.Count == 0)
        {
            return;
        }

        RecycleRestoreResult restoreResult = _recycleBin.RestoreItems(_lastRecycledPaths);
        foreach (string restored in restoreResult.RestoredPaths)
        {
            _removedPaths.Remove(restored.TrimEnd('\\', '/'));
        }

        if (restoreResult.TotalRestored > 0)
        {
            _lastRecycledPaths.RemoveAll(p => restoreResult.RestoredPaths.Contains(p, StringComparer.OrdinalIgnoreCase));
        }

        _historyRepository.RecordOperation(new OperationLogEntry
        {
            Id = Guid.NewGuid(),
            TimestampUtc = DateTime.UtcNow,
            OperationType = "Desfazer Limpeza (Restauração)",
            TargetPath = SelectedDrive?.RootDirectory ?? "Lixeira",
            Summary = $"Restaurados {restoreResult.TotalRestored} de {restoreResult.TotalRequested} item(ns) ({restoreResult.FormattedBytesRestored}) da Lixeira para seus locais originais.",
            AffectedBytes = restoreResult.BytesRestored,
            Succeeded = restoreResult.TotalRestored > 0,
            Details = string.Join("; ", restoreResult.RestoredPaths.Take(10))
        });

        RefreshHistoryList();
        LoadDrives();
        ApplyFindingsFilter();
        CommandManager.InvalidateRequerySuggested();

        StatusHeadline = $"Desfazer limpeza: {restoreResult.TotalRestored}/{restoreResult.TotalRequested} item(ns) restaurado(s) da Lixeira ({restoreResult.FormattedBytesRestored}).";

        MessageBox.Show(
            $"Restauração da Lixeira concluída:\n\n" +
            $"• Itens solicitados: {restoreResult.TotalRequested}\n" +
            $"• Itens restaurados ao local original: {restoreResult.TotalRestored} ({restoreResult.FormattedBytesRestored})\n" +
            (restoreResult.NotFoundOrFailedMessages.Count > 0
                ? $"\nAvisos:\n• {string.Join("\n• ", restoreResult.NotFoundOrFailedMessages.Take(6))}"
                : "\nTodos os itens foram restaurados com sucesso!"),
            "Desfazer Última Limpeza",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private async Task RunDuplicateScanAsync()
    {
        if (IsScanning || IsDuplicateScanning)
        {
            return;
        }

        string targetPath = _lastScanResult?.TargetRootPath ?? ResolveTargetScanPath();
        long minBytes = SelectedDuplicateMinSizeOption switch
        {
            var s when s.StartsWith("100 KB", StringComparison.OrdinalIgnoreCase) => 100 * 1024L,
            var s when s.StartsWith("10 MB", StringComparison.OrdinalIgnoreCase) => 10 * 1024 * 1024L,
            var s when s.StartsWith("50 MB", StringComparison.OrdinalIgnoreCase) => 50 * 1024 * 1024L,
            _ => 1024 * 1024L
        };

        _duplicateCts?.Dispose();
        _duplicateCts = new CancellationTokenSource();
        IsDuplicateScanning = true;

        Progress<string> statusProgress = new(msg => DuplicateStatusText = msg);

        try
        {
            IReadOnlyList<DuplicateGroup> groups = await _duplicateFileDetector.FindDuplicatesAsync(
                targetPath,
                minBytes,
                statusProgress,
                _duplicateCts.Token);

            DuplicateGroups.Clear();
            foreach (DuplicateGroup group in groups)
            {
                foreach (DuplicateFileEntry entry in group.Entries)
                {
                    AttachSelectionObserver(entry.StorageItem);
                }
                DuplicateGroups.Add(group);
            }

            long totalWaste = groups.Sum(g => g.ReclaimableBytes);
            DuplicateStatusText = groups.Count == 0
                ? $"Nenhum arquivo duplicado (>= {ByteSizeFormatter.FormatBytes(minBytes)}) encontrado em '{targetPath}'."
                : $"Encontrados {groups.Count} grupos de duplicados confirmados por SHA-256 ({ByteSizeFormatter.FormatBytes(totalWaste)} em cópias extras).";
        }
        catch (OperationCanceledException)
        {
            DuplicateStatusText = "Verificação de duplicados cancelada pelo usuário.";
        }
        catch (Exception ex)
        {
            DuplicateStatusText = $"Erro ao analisar duplicados: {ex.Message}";
        }
        finally
        {
            IsDuplicateScanning = false;
            CommandManager.InvalidateRequerySuggested();
        }
    }

    public void SelectAllSafeGreenItems()
    {
        if (_lastScanResult is null)
        {
            return;
        }

        int count = 0;
        RunBulkSelection(() =>
        {
            foreach (StorageItem item in GatherAllKnownItems())
            {
                if (item.RiskClassification == RiskLevel.Green && item.CanSelectForCleanup)
                {
                    item.IsSelectedForCleanup = true;
                    count++;
                }
            }
        });

        StatusHeadline = $"Foram selecionados todos os {count} itens VERDES (Baixo Risco). Clique em 'Prévia e Limpar Selecionados' para revisar.";
    }

    public void SelectAllYellowItems()
    {
        if (_lastScanResult is null)
        {
            return;
        }

        int count = 0;
        RunBulkSelection(() =>
        {
            foreach (StorageItem item in GatherAllKnownItems())
            {
                if (item.RiskClassification == RiskLevel.Yellow && item.CanSelectForCleanup)
                {
                    item.IsSelectedForCleanup = true;
                    count++;
                }
            }
        });

        StatusHeadline = $"Foram adicionados {count} itens AMARELOS (Requer Atenção) à seleção. Revise a lista na prévia antes de confirmar.";
    }

    public void SelectAllVisibleFilteredItems()
    {
        if (!IsCleanupUnlocked)
        {
            return;
        }

        int count = 0;
        RunBulkSelection(() =>
        {
            foreach (StorageItem item in FilteredFindings)
            {
                if (item.CanSelectForCleanup)
                {
                    item.IsSelectedForCleanup = true;
                    count++;
                }
            }
        });

        StatusHeadline = $"Foram marcados {count} itens elegíveis visíveis no filtro atual (Itens Vermelhos/Cinzas permanecem protegidos).";
    }

    public void UnselectAllVisibleFilteredItems()
    {
        RunBulkSelection(() =>
        {
            foreach (StorageItem item in FilteredFindings)
            {
                item.IsSelectedForCleanup = false;
            }
        });

        StatusHeadline = "Os itens visíveis no filtro atual foram desmarcados.";
    }

    public void SelectAllAppDataSafeCaches()
    {
        if (_lastScanResult is null)
        {
            return;
        }

        int count = 0;
        RunBulkSelection(() =>
        {
            foreach (AppDataEntry entry in FilteredAppDataEntries)
            {
                foreach (StorageItem cacheSub in entry.SafeCacheSubdirectories)
                {
                    if (cacheSub.CanSelectForCleanup)
                    {
                        cacheSub.IsSelectedForCleanup = true;
                        count++;
                    }
                }
            }
        });

        StatusHeadline = $"Selecionadas {count} subpastas de cache comprovadamente descartáveis do AppData.";
    }

    public void SelectAllDevCaches()
    {
        int count = 0;
        RunBulkSelection(() =>
        {
            foreach (DeveloperArtifactItem dev in DeveloperArtifacts)
            {
                if (dev.UnderlyingItem is not null && dev.UnderlyingItem.CanSelectForCleanup)
                {
                    dev.UnderlyingItem.IsSelectedForCleanup = true;
                    count++;
                }
            }
        });

        StatusHeadline = $"Selecionados {count} caches/diretórios de build de projetos seus (Discos .vhdx Docker/WSL2 permanecem protegidos).";
    }

    public void SelectAllDuplicateCopies()
    {
        int count = 0;
        RunBulkSelection(() =>
        {
            foreach (DuplicateGroup group in DuplicateGroups)
            {
                foreach (DuplicateFileEntry entry in group.Entries)
                {
                    if (!entry.IsCanonicalOriginal && entry.StorageItem.CanSelectForCleanup)
                    {
                        entry.StorageItem.IsSelectedForCleanup = true;
                        count++;
                    }
                }
            }
        });

        StatusHeadline = $"Selecionadas {count} cópias duplicadas extras (O arquivo original mais antigo de cada grupo permanece protegido).";
    }

    public void SetHighlightedItemsSelection(IEnumerable<StorageItem> items, bool selected)
    {
        if (selected && !IsCleanupUnlocked)
        {
            StatusHeadline = "Modo somente leitura ativo: marque \"Habilitar Limpeza Controlada\" para selecionar itens.";
            return;
        }

        int changed = 0;
        RunBulkSelection(() =>
        {
            foreach (StorageItem item in items)
            {
                if (selected && !item.CanSelectForCleanup)
                {
                    continue;
                }

                item.IsSelectedForCleanup = selected;
                changed++;
            }
        });

        StatusHeadline = selected
            ? $"{changed} item(ns) destacado(s) marcado(s) para limpeza."
            : $"{changed} item(ns) destacado(s) desmarcado(s).";
    }

    public void ClearAllCleanupSelections()
    {
        RunBulkSelection(() =>
        {
            foreach (StorageItem item in GatherAllKnownItems())
            {
                item.IsSelectedForCleanup = false;
            }
        });

        StatusHeadline = "Todas as seleções de limpeza foram desmarcadas.";
    }

    private IEnumerable<StorageItem> GatherAllKnownItems()
    {
        HashSet<StorageItem> all = [];
        if (_lastScanResult is not null)
        {
            foreach (StorageItem i in _lastScanResult.ClassifiedFindings) all.Add(i);
            foreach (StorageItem i in _lastScanResult.TopHeavyFolders) all.Add(i);
            foreach (StorageItem i in _lastScanResult.TopHeavyFiles) all.Add(i);
            foreach (StorageItem i in _lastScanResult.HighDensityFolders) all.Add(i);
            foreach (AppDataEntry a in _lastScanResult.AppDataEntries)
            {
                foreach (StorageItem s in a.SafeCacheSubdirectories) all.Add(s);
            }
        }

        foreach (DeveloperArtifactItem dev in DeveloperArtifacts)
        {
            if (dev.UnderlyingItem is not null)
            {
                all.Add(dev.UnderlyingItem);
            }
        }

        foreach (DuplicateGroup g in DuplicateGroups)
        {
            foreach (DuplicateFileEntry e in g.Entries)
            {
                all.Add(e.StorageItem);
            }
        }

        return all;
    }

    public void UpdateCleanupSelectionSummary()
    {
        List<StorageItem> selected = GatherAllKnownItems()
            .Where(i => i.IsSelectedForCleanup)
            .GroupBy(i => i.FullPath, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

        long nonOverlappingBytes = DiskScannerService.ComputeNonOverlappingSize(selected);
        string formatted = ByteSizeFormatter.FormatBytes(nonOverlappingBytes);

        SelectedForCleanupSummaryText = $"{selected.Count} item(ns) selecionado(s) ({formatted})";
        CleanActionButtonText = selected.Count > 0
            ? $"🧹 Prévia e Limpar ({selected.Count} itens • {formatted})"
            : "🧹 Prévia e Limpar Selecionados (0)";
    }

    private async Task OpenCleanupPreviewAndExecuteAsync()
    {
        if (!IsCleanupUnlocked)
        {
            MessageBox.Show(
                "O aplicativo está no Modo Somente Leitura. Ative a chave 'Habilitar Modo de Limpeza Controlada' na barra superior primeiro.",
                "Modo Somente Leitura Ativo",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        List<StorageItem> selected = GatherAllKnownItems()
            .Where(i => i.IsSelectedForCleanup)
            .GroupBy(i => i.FullPath, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

        if (selected.Count == 0)
        {
            MessageBox.Show(
                "Nenhum item foi selecionado para limpeza.\n\nDica: Use o botão '✅ Selecionar Todos os Verdes (Baixo Risco)' ou marque as caixas dos itens que deseja limpar.",
                "Seleção Vazia",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        CleanupPreviewReport preview;
        BeginBusyOperation(
            $"🔍 Verificando {selected.Count} item(ns) antes da prévia...",
            "Validando permissões, arquivos em uso e espaço disponível na Lixeira...",
            showModalOverlay: true);
        try
        {
            bool preferRecycleBin = PreferRecycleBin;
            preview = await Task.Run(() => _safeCleanupService.BuildPreview(selected, preferRecycleBin));
        }
        finally
        {
            EndBusyOperation();
        }

        RefreshHistoryList();

        CleanupPreviewWindow dialog = new(preview)
        {
            Owner = Application.Current.MainWindow
        };

        bool? confirmed = dialog.ShowDialog();
        if (confirmed != true)
        {
            StatusHeadline = "Limpeza cancelada na tela de prévia. Nenhum arquivo foi modificado.";
            return;
        }

        _cleanupCts?.Dispose();
        _cleanupCts = new CancellationTokenSource();
        BeginBusyOperation(
            $"🧹 Executando Limpeza Controlada ({preview.ApprovedItems.Count} item(ns))...",
            "Movendo itens aprovados com segurança...",
            showModalOverlay: true);
        Progress<string> cleanupProgress = new(ReportBusyProgress);

        _bulkSelectionDepth++;
        try
        {
            CleanupExecutionResult execResult = await _safeCleanupService.ExecuteCleanupAsync(
                preview,
                cleanupProgress,
                _cleanupCts.Token);

            _lastRecycledPaths.Clear();
            foreach (CleanupItemOutcome outcome in execResult.Outcomes)
            {
                if (outcome.Succeeded)
                {
                    _removedPaths.Add(outcome.FullPath.TrimEnd('\\', '/'));
                    if (outcome.ExecutedMethod == CleanupOperationMethod.MoveToRecycleBin)
                    {
                        _lastRecycledPaths.Add(outcome.FullPath);
                    }
                }
            }

            RemoveCleanedItemsFromLists();
            RefreshHistoryList();
            LoadDrives();
            EndBusyOperation();
            CommandManager.InvalidateRequerySuggested();

            bool wasCancelled = _cleanupCts.IsCancellationRequested;
            StatusHeadline = execResult.TotalBytesPermanentlyDeleted > 0
                ? $"Limpeza {(wasCancelled ? "interrompida" : "concluída")}: {execResult.TotalSucceeded} item(ns) removido(s) — {execResult.FormattedBytesMovedToRecycleBin} na Lixeira, {execResult.FormattedBytesPermanentlyDeleted} excluídos em definitivo."
                : $"Limpeza {(wasCancelled ? "interrompida" : "concluída")}: {execResult.TotalSucceeded} item(ns) movido(s) para a Lixeira ({execResult.FormattedBytesMovedToRecycleBin}). Use '↩️ Desfazer Última Limpeza' se quiser restaurar.";

            MessageBox.Show(
                $"Limpeza {(wasCancelled ? "interrompida pelo usuário" : "concluída")}.\n\n" +
                $"• Itens removidos: {execResult.TotalSucceeded}\n" +
                $"• Movido para a Lixeira: {execResult.FormattedBytesMovedToRecycleBin}\n" +
                $"   (pode ser restaurado em 1 clique pelo botão '↩️ Desfazer Última Limpeza'; continua ocupando o disco até a Lixeira ser esvaziada)\n" +
                $"• Excluído em definitivo: {execResult.FormattedBytesPermanentlyDeleted}\n" +
                $"• Bloqueados ou ignorados: {execResult.TotalSkippedOrBlocked}\n" +
                $"• Não removidos (em uso ou sem permissão): {execResult.TotalFailedOrLocked}\n\n" +
                (execResult.ManifestFilePath is null
                    ? "O resumo foi gravado na aba 'Histórico'.\n\n"
                    : $"Registro completo, com o caminho de cada item:\n{execResult.ManifestFilePath}\n\n") +
                "Os tamanhos da árvore são os da análise anterior. Refaça a análise para atualizá-los.",
                "Relatório da Limpeza",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        finally
        {
            _bulkSelectionDepth--;
            EndBusyOperation();
            UpdateCleanupSelectionSummary();
        }
    }

    private bool WasRemoved(StorageItem item)
    {
        if (item.IsRemovedByCleanup)
        {
            return true;
        }

        if (_removedPaths.Count == 0)
        {
            return false;
        }

        string path = item.FullPath.TrimEnd('\\', '/');
        while (!string.IsNullOrEmpty(path))
        {
            if (_removedPaths.Contains(path))
            {
                return true;
            }

            int separator = path.LastIndexOf('\\');
            if (separator <= 0)
            {
                break;
            }

            path = path[..separator];
        }

        return false;
    }

    private void RemoveCleanedItemsFromLists()
    {
        RemoveWhere(TopHeavyFolders, WasRemoved);
        RemoveWhere(TopHeavyFiles, WasRemoved);
        RemoveWhere(HighDensityFolders, WasRemoved);
        RemoveWhere(DeveloperArtifacts, dev => dev.UnderlyingItem is not null && WasRemoved(dev.UnderlyingItem));

        List<DuplicateGroup> remainingGroups = [];
        foreach (DuplicateGroup group in DuplicateGroups)
        {
            List<DuplicateFileEntry> remainingEntries = group.Entries.Where(e => !WasRemoved(e.StorageItem)).ToList();
            if (remainingEntries.Count == group.Entries.Count)
            {
                remainingGroups.Add(group);
            }
            else if (remainingEntries.Count >= 2)
            {
                remainingGroups.Add(new DuplicateGroup
                {
                    Sha256Hash = group.Sha256Hash,
                    FileSizeBytes = group.FileSizeBytes,
                    Entries = remainingEntries
                });
            }
        }

        DuplicateGroups.Clear();
        foreach (DuplicateGroup group in remainingGroups)
        {
            DuplicateGroups.Add(group);
        }

        ApplyFindingsFilter();

        if (_lastScanResult is not null)
        {
            List<StorageItem> remainingAll = _lastScanResult.ClassifiedFindings.Where(i => !WasRemoved(i)).ToList();
            FindingGroups.Clear();
            foreach (FindingGroupSummary grp in FindingGrouper.BuildGroups(remainingAll))
            {
                FindingGroups.Add(grp);
            }

            List<StorageItem> remainingCleanable = remainingAll.Where(i => i.CanSelectForCleanup).ToList();
            long green = PathNesting.ComputeNonOverlappingSize(remainingCleanable.Where(i => i.RiskClassification == RiskLevel.Green));
            long yellow = PathNesting.ComputeNonOverlappingSize(remainingCleanable.Where(i => i.RiskClassification == RiskLevel.Yellow));
            EstimatedGreenRecoverableText = ByteSizeFormatter.FormatBytes(green);
            EstimatedYellowRecoverableText = ByteSizeFormatter.FormatBytes(yellow);
            EstimatedRecoverableTotalText = ByteSizeFormatter.FormatBytes(green + yellow);
        }
    }

    private static void RemoveWhere<T>(ObservableCollection<T> collection, Func<T, bool> shouldRemove)
    {
        for (int i = collection.Count - 1; i >= 0; i--)
        {
            if (shouldRemove(collection[i]))
            {
                collection.RemoveAt(i);
            }
        }
    }

    private void OpenSelectedInExplorer()
    {
        if (SelectedInspectorItem is null)
        {
            return;
        }

        string path = SelectedInspectorItem.FullPath;
        try
        {
            if (Directory.Exists(path))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"\"{path}\"",
                    UseShellExecute = true
                });
            }
            else if (File.Exists(path))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{path}\"",
                    UseShellExecute = true
                });
            }
        }
        catch (Exception ex)
        {
            StatusHeadline = $"Não foi possível abrir o Explorer: {ex.Message}";
        }
    }

    private void CopySelectedPath()
    {
        if (SelectedInspectorItem is null)
        {
            return;
        }

        try
        {
            Clipboard.SetText(SelectedInspectorItem.FullPath);
            StatusHeadline = $"Caminho copiado para a área de transferência: {SelectedInspectorItem.FullPath}";
        }
        catch
        {
            // Ignora falha de área de transferência
        }
    }

    private void CopyOfficialCommandToClipboard()
    {
        string? cmd = SelectedInspectorItem?.OfficialMaintenanceCommand;
        if (string.IsNullOrWhiteSpace(cmd))
        {
            return;
        }

        try
        {
            Clipboard.SetText(cmd);
            StatusHeadline = $"Comando oficial copiado: {cmd}";
        }
        catch
        {
            // Ignora falha de área de transferência
        }
    }

    private void ExportHistoryToJson()
    {
        SaveFileDialog dialog = new()
        {
            Title = "Exportar Histórico de Operações do DiskInspector",
            Filter = "Arquivo JSON (*.json)|*.json",
            FileName = $"DiskInspector_Historico_{DateTime.Now:yyyyMMdd_HHmm}.json"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                _historyRepository.ExportHistoryToJson(dialog.FileName);
                StatusHeadline = $"Histórico exportado com sucesso para '{dialog.FileName}'.";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Falha ao exportar histórico: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void RefreshHistoryList()
    {
        OperationLogs.Clear();
        foreach (OperationLogEntry entry in _historyRepository.GetHistory())
        {
            OperationLogs.Add(entry);
        }
    }
}
