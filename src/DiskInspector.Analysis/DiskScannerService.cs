using System.Diagnostics;
using System.IO.Enumeration;
using DiskInspector.Core.Enums;
using DiskInspector.Core.Formatting;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;
using DiskInspector.Infrastructure;

namespace DiskInspector.Analysis;

/// <summary>
/// Motor de varredura profunda de unidades e diretórios com alta performance, baixo consumo de memória,
/// tratamento de links simbólicos/junctions, separação entre tamanho lógico e alocado e atualização progressiva (Seções 3 e 9).
/// </summary>
public sealed class DiskScannerService : IDiskScannerService
{
    private const int MaxTopFolders = 150;
    private const int MaxTopFiles = 150;
    private const int MaxHighDensityFolders = 100;
    private const int MaxTreeChildrenPerNode = 35;
    private const long SmallFileThresholdBytes = 16 * 1024; // 16 KB

    // Limites de segurança de memória. Como só itens de primeiro nível de cada regra viram achados
    // (nunca o conteúdo interno), na prática esses limites não são atingidos em um disco comum.
    private const int MaxActionableCandidates = 20_000;
    private const int MaxDiscoveredDevNodes = 5_000;

    private readonly IEnvironmentProvider _environmentProvider;
    private readonly ISystemPathProtector _systemPathProtector;
    private readonly IStorageClassifier _classifier;
    private readonly IOperationHistoryRepository _historyRepository;
    private readonly IScanSnapshotService? _snapshotService;
    private readonly AppDataAnalyzer _appDataAnalyzer;
    private readonly DeveloperEnvironmentAnalyzer _devAnalyzer;
    private readonly NonDestructiveSpaceAdvisor _nonDestructiveAdvisor;

    public DiskScannerService(
        IEnvironmentProvider environmentProvider,
        ISystemPathProtector systemPathProtector,
        IStorageClassifier classifier,
        IOperationHistoryRepository historyRepository,
        IScanSnapshotService? snapshotService = null)
    {
        _environmentProvider = environmentProvider;
        _systemPathProtector = systemPathProtector;
        _classifier = classifier;
        _historyRepository = historyRepository;
        _snapshotService = snapshotService;
        _appDataAnalyzer = new AppDataAnalyzer(environmentProvider, classifier);
        _devAnalyzer = new DeveloperEnvironmentAnalyzer(environmentProvider, classifier);
        _nonDestructiveAdvisor = new NonDestructiveSpaceAdvisor(environmentProvider, systemPathProtector);
    }

    public Task<ScanResult> ScanAsync(
        DriveMetadata drive,
        string? customRootPath,
        IProgress<ScanProgressReport>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(drive);

        return Task.Run(() =>
        {
            string rootPath = string.IsNullOrWhiteSpace(customRootPath)
                ? drive.RootDirectory
                : customRootPath;

            if (!Directory.Exists(rootPath))
            {
                throw new DirectoryNotFoundException($"O caminho selecionado não existe: {rootPath}");
            }

            DateTime startedAtUtc = DateTime.UtcNow;
            Stopwatch sw = Stopwatch.StartNew();
            EnvironmentPaths env = _environmentProvider.GetEnvironmentPaths();

            ScanContext context = new(sw, progress, env);

            // Dicas de estrutura de pastas de uma varredura anterior podem estar desatualizadas
            _classifier.ResetObservations();

            StorageItem rootNode = new()
            {
                Name = string.IsNullOrWhiteSpace(Path.GetFileName(rootPath.TrimEnd('\\', '/')))
                    ? rootPath
                    : Path.GetFileName(rootPath.TrimEnd('\\', '/')),
                FullPath = Path.GetFullPath(rootPath),
                LastModifiedUtc = SafeGetDirectoryLastWriteUtc(rootPath),
                IsDirectory = true
            };

            // Travessia pós-ordem iterativa usando pilha explícita (evita StackOverflowException em caminhos muito profundos)
            TraverseDirectoryIterative(rootNode, context, cancellationToken);

            // Calcula porcentagens relativas na árvore
            long rootTotal = Math.Max(1L, rootNode.LogicalSizeBytes);
            ComputeTreePercentagesRecursive(rootNode, rootTotal, rootTotal);

            // Classifica os principais itens coletados
            List<StorageItem> topFolders = DequeueSortedDescending(context.TopFoldersHeap);
            foreach (StorageItem folder in topFolders)
            {
                _classifier.ClassifyItem(folder);
            }

            List<StorageItem> topFiles = DequeueSortedDescending(context.TopFilesHeap);
            foreach (StorageItem file in topFiles)
            {
                _classifier.ClassifyItem(file);
            }

            List<StorageItem> highDensityFolders = DequeueSortedBySmallFilesDescending(context.HighDensityHeap);
            foreach (StorageItem hd in highDensityFolders)
            {
                _classifier.ClassifyItem(hd);
                if (hd.Category == ItemCategory.Unknown)
                {
                    hd.Category = ItemCategory.HighDensityDirectory;
                }
            }

            // Análise profunda do AppData (Seção 4)
            IReadOnlyList<AppDataEntry> appDataEntries = _appDataAnalyzer.AnalyzeFromTree(
                rootNode,
                out long appDataLocalBytes,
                out long appDataRoamingBytes,
                out long appDataLocalLowBytes,
                out List<StorageItem> safeAppDataCaches);

            // Análise de ambientes de desenvolvimento e containers (Seção 7)
            IReadOnlyList<DeveloperArtifactItem> devArtifacts = _devAnalyzer.Analyze(
                rootNode,
                context.DiscoveredDevNodes);

            // Consolida achados classificáveis (Temporários, Caches, Dev, Downloads, Sistema, Logs)
            Dictionary<string, StorageItem> findingsByPath = new(StringComparer.OrdinalIgnoreCase);

            foreach (StorageItem candidate in context.ActionableCandidates
                         .Concat(safeAppDataCaches)
                         .Concat(devArtifacts.Where(d => d.UnderlyingItem is not null).Select(d => d.UnderlyingItem!))
                         .Concat(topFolders.Take(40))
                         .Concat(topFiles.Take(40)))
            {
                if (candidate.LogicalSizeBytes <= 0)
                {
                    continue;
                }

                // Pastas já foram classificadas ao final da sua travessia (com tamanho e data consolidados);
                // arquivos só são classificados aqui. Itens virtuais (ex.: relatório do Docker) mantêm a própria descrição.
                if (!candidate.IsDirectory)
                {
                    _classifier.ClassifyItem(candidate);
                }

                // O conteúdo interno de um achado nunca é listado como achado independente
                if (candidate.Recommendation == RecommendedAction.CleanViaParentItem)
                {
                    continue;
                }

                findingsByPath.TryAdd(candidate.FullPath, candidate);
            }

            _classifier.ResetObservations();

            List<StorageItem> classifiedFindings = findingsByPath.Values
                .OrderBy(i => i.RiskClassification)
                .ThenByDescending(i => i.LogicalSizeBytes)
                .ToList();

            // Calcula estimativa de espaço recuperável (apenas itens não sobrepostos)
            long greenRecoverable = ComputeNonOverlappingSize(
                classifiedFindings.Where(i => i.RiskClassification == RiskLevel.Green && i.CanSelectForCleanup));

            long yellowRecoverable = ComputeNonOverlappingSize(
                classifiedFindings.Where(i => i.RiskClassification == RiskLevel.Yellow && i.CanSelectForCleanup));

            // Distribuição visual por Categoria e Risco
            IReadOnlyList<StorageDistributionSlice> categoryDist = BuildCategoryDistribution(rootNode, classifiedFindings);
            IReadOnlyList<StorageDistributionSlice> riskDist = BuildRiskDistribution(rootNode, classifiedFindings, greenRecoverable, yellowRecoverable);

            // Diferencial 1: Achados agrupados por natureza semântica
            IReadOnlyList<FindingGroupSummary> findingGroups = FindingGrouper.BuildGroups(classifiedFindings);

            // Diferencial 2: Mapa de blocos proporcional colorido por risco ("Posso apagar?")
            IReadOnlyList<TreemapBlockItem> treemapBlocks = RiskTreemapBuilder.BuildRiskTreemap(rootNode, classifiedFindings, topFolders);

            // Diferencial 5: Agrupamento de projetos de desenvolvimento e detecção de projetos parados (> 90 dias)
            IReadOnlyList<ProjectActivitySummary> developerProjects = DeveloperEnvironmentAnalyzer.AggregateProjects(devArtifacts);

            // Diferencial 6: Oportunidades de recuperar espaço sem apagar arquivos (VHDX, OneDrive, NTFS Compact)
            IReadOnlyList<NonDestructiveOption> nonDestructiveOptions = _nonDestructiveAdvisor.AnalyzeOptions(
                rootNode,
                devArtifacts,
                highDensityFolders);

            DateTime completedAtUtc = DateTime.UtcNow;

            // Diferencial 3: "O que cresceu?" comparando com o snapshot anterior do mesmo escopo
            DateTime? previousScanUtc = null;
            long? previousRootBytes = null;
            IReadOnlyList<FolderGrowthDelta> growthDeltas = [];
            if (_snapshotService is not null)
            {
                IEnumerable<StorageItem> trackedFolders = rootNode.Children
                    .Where(c => c.IsDirectory)
                    .Concat(topFolders)
                    .Concat(appDataEntries.Where(a => a.RootStorageItem is not null).Select(a => a.RootStorageItem!))
                    .Concat(classifiedFindings.Where(f => f.IsDirectory));

                growthDeltas = _snapshotService.CompareAndSaveSnapshot(
                    rootPath,
                    completedAtUtc,
                    rootNode.LogicalSizeBytes,
                    trackedFolders,
                    out previousScanUtc,
                    out previousRootBytes);
            }

            ScanResult result = new()
            {
                ScanId = Guid.NewGuid(),
                StartedAtUtc = startedAtUtc,
                CompletedAtUtc = completedAtUtc,
                TargetRootPath = rootPath,
                DriveInfo = drive,
                RanWithAdminPrivileges = env.IsElevatedAdmin,
                RootNode = rootNode,
                TotalFilesScanned = context.FilesScanned,
                TotalDirectoriesScanned = context.DirectoriesScanned,
                TotalLogicalBytes = rootNode.LogicalSizeBytes,
                TotalAllocatedBytes = rootNode.AllocatedSizeBytes,
                TotalAccessDenied = context.AccessDeniedCount,
                TotalReparsePointsSkipped = context.ReparsePointsSkipped,
                TotalHardLinksDeduplicated = context.HardLinksDeduplicated,
                TotalSparseFilesDetected = context.SparseFilesDetected,
                TopHeavyFolders = topFolders,
                TopHeavyFiles = topFiles,
                HighDensityFolders = highDensityFolders,
                ClassifiedFindings = classifiedFindings,
                AppDataEntries = appDataEntries,
                AppDataLocalBytes = appDataLocalBytes,
                AppDataRoamingBytes = appDataRoamingBytes,
                AppDataLocalLowBytes = appDataLocalLowBytes,
                DeveloperArtifacts = devArtifacts,
                FindingGroups = findingGroups,
                RiskTreemapBlocks = treemapBlocks,
                GrowthDeltas = growthDeltas,
                DeveloperProjects = developerProjects,
                NonDestructiveOptions = nonDestructiveOptions,
                PreviousSnapshotUtc = previousScanUtc,
                PreviousRootTotalBytes = previousRootBytes,
                CategoryDistribution = categoryDist,
                RiskDistribution = riskDist,
                EstimatedSafeGreenRecoverableBytes = greenRecoverable,
                EstimatedAttentionYellowRecoverableBytes = yellowRecoverable
            };

            _historyRepository.RecordOperation(new OperationLogEntry
            {
                Id = result.ScanId,
                TimestampUtc = completedAtUtc,
                OperationType = "Análise de Armazenamento (Somente Leitura)",
                TargetPath = rootPath,
                Summary = $"Varredura concluída: {result.TotalFilesScanned:N0} arquivos e {result.TotalDirectoriesScanned:N0} pastas ({result.FormattedTotalLogical}).",
                AffectedBytes = result.TotalLogicalBytes,
                Succeeded = true,
                Details = $"Tempo: {result.Duration.TotalSeconds:0.0}s | Recuperável (Baixo Risco): {result.FormattedGreenRecoverable} | Atenção: {result.FormattedYellowRecoverable} | Sem permissão: {result.TotalAccessDenied}"
            });

            return result;
        }, cancellationToken);
    }

    private void TraverseDirectoryIterative(
        StorageItem rootNode,
        ScanContext context,
        CancellationToken cancellationToken)
    {
        Stack<TraversalFrame> stack = new();
        stack.Push(new TraversalFrame(rootNode, depth: 0));

        EnumerationOptions enumOptions = new()
        {
            IgnoreInaccessible = false,
            RecurseSubdirectories = false,
            ReturnSpecialDirectories = false,
            AttributesToSkip = 0
        };

        while (stack.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            TraversalFrame frame = stack.Peek();

            if (!frame.HasEnumeratedChildren)
            {
                frame.HasEnumeratedChildren = true;
                context.DirectoriesScanned++;
                context.MaybeReportProgress(frame.Node.FullPath, "Analisando estrutura de diretórios e alocação NTFS...");

                List<StorageItem> subDirectories = [];

                // Calculado uma vez por pasta (e não por arquivo)
                string currentDirPath = frame.Node.FullPath.TrimEnd('\\', '/');
                bool isDirectUserTempDir = string.Equals(currentDirPath, context.UserTempDir, StringComparison.OrdinalIgnoreCase);
                bool isDirectDownloadsDir = string.Equals(currentDirPath, context.DownloadsDir, StringComparison.OrdinalIgnoreCase);

                try
                {
                    FileSystemEnumerable<RawFileSystemEntry> enumerable = new(
                        frame.Node.FullPath,
                        (ref FileSystemEntry entry) => new RawFileSystemEntry(
                            entry.ToFullPath(),
                            entry.FileName.ToString(),
                            entry.IsDirectory,
                            entry.IsDirectory ? 0L : entry.Length,
                            entry.Attributes,
                            entry.LastWriteTimeUtc.UtcDateTime),
                        enumOptions);

                    foreach (RawFileSystemEntry raw in enumerable)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        bool isReparse = (raw.Attributes & FileAttributes.ReparsePoint) != 0;
                        bool isSparse = (raw.Attributes & FileAttributes.SparseFile) != 0;

                        if (isSparse)
                        {
                            context.SparseFilesDetected++;
                        }

                        if (raw.IsDirectory)
                        {
                            if (isReparse)
                            {
                                // NUNCA segue links simbólicos, junctions ou reparse points para evitar ciclos infinitos (Seção 9)
                                context.ReparsePointsSkipped++;
                                StorageItem reparseNode = new()
                                {
                                    Name = raw.Name,
                                    FullPath = raw.FullPath,
                                    ParentPath = frame.Node.FullPath,
                                    LastModifiedUtc = raw.LastModifiedUtc,
                                    IsDirectory = true,
                                    IsReparsePoint = true
                                };
                                _classifier.ClassifyItem(reparseNode);
                                frame.DirectSubfolders.Add(reparseNode);
                                continue;
                            }

                            StorageItem childDir = new()
                            {
                                Name = raw.Name,
                                FullPath = raw.FullPath,
                                ParentPath = frame.Node.FullPath,
                                LastModifiedUtc = raw.LastModifiedUtc,
                                IsDirectory = true,
                                IsReparsePoint = false
                            };

                            frame.DirectSubfolders.Add(childDir);
                            subDirectories.Add(childDir);
                        }
                        else
                        {
                            context.FilesScanned++;
                            long logicalSize = Math.Max(0L, raw.Length);
                            long allocatedSize = NativeDiskInterop.GetAllocatedDiskSize(raw.FullPath, logicalSize, raw.Attributes);
                            uint linkCount = 1;
                            ulong? fileId = null;

                            // Deduplicação de hard links NTFS em arquivos grandes (>= 4 MB) para precisão de espaço físico
                            if (logicalSize >= 4 * 1024 * 1024 &&
                                NativeDiskInterop.TryGetHardLinkInfo(raw.FullPath, out uint links, out ulong fid, out uint vol))
                            {
                                linkCount = links;
                                fileId = fid;
                                if (links > 1 && fid != 0 && !context.SeenHardLinks.Add((vol, fid)))
                                {
                                    allocatedSize = 0L; // Já contabilizado fisicamente em outro link do mesmo volume
                                    context.HardLinksDeduplicated++;
                                }
                            }

                            frame.Node.LogicalSizeBytes += logicalSize;
                            frame.Node.AllocatedSizeBytes += allocatedSize;
                            frame.Node.FileCount++;
                            if (logicalSize > 0 && logicalSize < SmallFileThresholdBytes)
                            {
                                frame.Node.SmallFileCount++;
                            }

                            // A data da pasta não reflete alterações em arquivos internos: guarda a escrita mais recente
                            if (raw.LastModifiedUtc > frame.Node.LatestContentWriteUtc)
                            {
                                frame.Node.LatestContentWriteUtc = raw.LastModifiedUtc;
                            }

                            context.LogicalBytesAccumulated += logicalSize;
                            context.AllocatedBytesAccumulated += allocatedSize;

                            // Registra se for um arquivo pesado, de desenvolvimento (.vhdx), download/instalador ou temporário direto
                            bool isVhdx = raw.Name.EndsWith(".vhdx", StringComparison.OrdinalIgnoreCase);
                            bool isDirectUserTempFile = isDirectUserTempDir;
                            bool isDirectDownloadsFile = isDirectDownloadsDir;

                            if (logicalSize >= 1024 * 1024 || isVhdx || isDirectUserTempFile || isDirectDownloadsFile || frame.Depth <= 2)
                            {
                                StorageItem fileItem = new()
                                {
                                    Name = raw.Name,
                                    FullPath = raw.FullPath,
                                    ParentPath = frame.Node.FullPath,
                                    LogicalSizeBytes = logicalSize,
                                    AllocatedSizeBytes = allocatedSize,
                                    LastModifiedUtc = raw.LastModifiedUtc,
                                    LatestContentWriteUtc = raw.LastModifiedUtc,
                                    IsDirectory = false,
                                    IsReparsePoint = isReparse,
                                    IsSparseFile = isSparse,
                                    HardLinkCount = linkCount,
                                    NtfsFileId = fileId
                                };

                                EnqueueBounded(context.TopFilesHeap, fileItem, fileItem.LogicalSizeBytes, MaxTopFiles);

                                if (isVhdx)
                                {
                                    context.DiscoveredDevNodes.Add(fileItem);
                                }

                                if ((isDirectUserTempFile || isDirectDownloadsFile) &&
                                    context.ActionableCandidates.Count < MaxActionableCandidates)
                                {
                                    context.ActionableCandidates.Add(fileItem);
                                }
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    frame.Node.AccessDeniedCount++;
                    context.AccessDeniedCount++;
                }
                catch (IOException)
                {
                    frame.Node.AccessDeniedCount++;
                    context.AccessDeniedCount++;
                }
                catch
                {
                    frame.Node.AccessDeniedCount++;
                    context.AccessDeniedCount++;
                }

                // Dentro do AppData, informa ao classificador os nomes das subpastas já listadas: ele reconhece
                // a estrutura de aplicativos Electron/Chromium sem precisar consultar o disco outra vez
                if (context.IsInsideAppData(currentDirPath))
                {
                    string[] subdirectoryNames = new string[subDirectories.Count];
                    for (int i = 0; i < subDirectories.Count; i++)
                    {
                        subdirectoryNames[i] = subDirectories[i].Name;
                    }

                    _classifier.ObserveDirectoryStructure(currentDirPath, subdirectoryNames);
                }

                // Empilha subdiretórios na ordem inversa para processar em profundidade
                for (int i = subDirectories.Count - 1; i >= 0; i--)
                {
                    stack.Push(new TraversalFrame(subDirectories[i], frame.Depth + 1));
                }
            }
            else
            {
                // Todos os subdiretórios de 'frame.Node' já foram processados: consolida métricas de baixo para cima!
                stack.Pop();
                StorageItem dir = frame.Node;

                foreach (StorageItem childDir in frame.DirectSubfolders)
                {
                    dir.LogicalSizeBytes += childDir.LogicalSizeBytes;
                    dir.AllocatedSizeBytes += childDir.AllocatedSizeBytes;
                    dir.FileCount += childDir.FileCount;
                    dir.DirectoryCount += 1 + childDir.DirectoryCount;
                    dir.SmallFileCount += childDir.SmallFileCount;
                    dir.AccessDeniedCount += childDir.AccessDeniedCount;

                    DateTime childLatest = childDir.EffectiveLatestWriteUtc;
                    if (childLatest > dir.LatestContentWriteUtc)
                    {
                        dir.LatestContentWriteUtc = childLatest;
                    }
                }

                // Preserva filhos importantes na árvore (todas as pastas do AppData ou os maiores subdiretórios para não estourar RAM)
                string consolidatedPath = dir.FullPath.TrimEnd('\\', '/');
                bool isInsideAppDataTopLevels =
                    context.IsInsideAppData(consolidatedPath) ||
                    SystemPathProtector.IsSameOrSubpath(context.Env.LocalAppDataDir, dir.FullPath);

                // Temp e Downloads mantêm todos os itens diretos: cada um deles é um achado avaliado individualmente
                bool keepAllChildren =
                    string.Equals(consolidatedPath, context.UserTempDir, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(consolidatedPath, context.DownloadsDir, StringComparison.OrdinalIgnoreCase);

                int maxKeep = keepAllChildren
                    ? int.MaxValue
                    : ((frame.Depth <= 3 || isInsideAppDataTopLevels) ? 100 : MaxTreeChildrenPerNode);

                foreach (StorageItem child in frame.DirectSubfolders
                             .OrderByDescending(c => c.LogicalSizeBytes)
                             .Take(maxKeep))
                {
                    dir.Children.Add(child);
                }

                _classifier.ClassifyItem(dir);

                if (frame.Depth > 0 && dir.LogicalSizeBytes > 0)
                {
                    EnqueueBounded(context.TopFoldersHeap, dir, dir.LogicalSizeBytes, MaxTopFolders);
                }

                // Diretórios com milhares de pequenos arquivos (ou >= 100 em diretórios menores)
                if (dir.SmallFileCount >= 100 && frame.Depth >= 1)
                {
                    EnqueueBounded(context.HighDensityHeap, dir, dir.SmallFileCount, MaxHighDensityFolders);
                }

                // Só o item de primeiro nível de cada regra é um achado. O conteúdo interno (uma subpasta dentro
                // de um item temporário, de um cache ou de uma node_modules) aponta para o item pai e fica de fora:
                // antes ele lotava as listas e escondia os achados reais.
                bool isFindingRoot = dir.Recommendation != RecommendedAction.CleanViaParentItem;

                // Captura artefatos de desenvolvimento descobertos na árvore
                if (isFindingRoot &&
                    (dir.Category == ItemCategory.DeveloperBuildArtifact ||
                     dir.Category == ItemCategory.DeveloperCache ||
                     dir.Category == ItemCategory.ContainerOrVirtualization))
                {
                    if (context.DiscoveredDevNodes.Count < MaxDiscoveredDevNodes)
                    {
                        context.DiscoveredDevNodes.Add(dir);
                    }
                }

                // Captura candidatos acionáveis (Temp, Caches, Downloads, Sistema Protegido de topo)
                if (isFindingRoot &&
                    (dir.RiskClassification == RiskLevel.Green ||
                     dir.RiskClassification == RiskLevel.Yellow ||
                     (dir.Category == ItemCategory.SystemCritical && frame.Depth <= 2)))
                {
                    if (context.ActionableCandidates.Count < MaxActionableCandidates)
                    {
                        context.ActionableCandidates.Add(dir);
                    }
                }
            }
        }
    }

    private static void ComputeTreePercentagesRecursive(StorageItem node, long parentBytes, long driveTotalBytes)
    {
        node.PercentageOfParent = parentBytes > 0
            ? Math.Round((double)node.LogicalSizeBytes / parentBytes * 100.0, 1)
            : 0.0;

        node.PercentageOfDrive = driveTotalBytes > 0
            ? Math.Round((double)node.LogicalSizeBytes / driveTotalBytes * 100.0, 1)
            : 0.0;

        long childBase = Math.Max(1L, node.LogicalSizeBytes);
        foreach (StorageItem child in node.Children)
        {
            ComputeTreePercentagesRecursive(child, childBase, driveTotalBytes);
        }
    }

    public static long ComputeNonOverlappingSize(IEnumerable<StorageItem> items) =>
        PathNesting.ComputeNonOverlappingSize(items);

    private static IReadOnlyList<StorageDistributionSlice> BuildCategoryDistribution(
        StorageItem rootNode,
        IReadOnlyList<StorageItem> findings)
    {
        long totalScanned = Math.Max(1L, rootNode.LogicalSizeBytes);

        // Agrupa pelo primeiro nível da raiz ou pelas categorias identificadas
        Dictionary<ItemCategory, (long Bytes, int Count)> byCat = [];
        foreach (StorageItem child in rootNode.Children)
        {
            var current = byCat.GetValueOrDefault(child.Category);
            byCat[child.Category] = (current.Bytes + child.LogicalSizeBytes, current.Count + 1);
        }

        if (byCat.Count <= 1)
        {
            byCat.Clear();
            foreach (StorageItem item in findings)
            {
                var current = byCat.GetValueOrDefault(item.Category);
                byCat[item.Category] = (current.Bytes + item.LogicalSizeBytes, current.Count + 1);
            }
        }

        string[] palette = ["#38BDF8", "#818CF8", "#34D399", "#FBBF24", "#F87171", "#A78BFA", "#FB923C", "#94A3B8"];
        int colorIdx = 0;

        return byCat
            .Where(kv => kv.Value.Bytes > 0)
            .OrderByDescending(kv => kv.Value.Bytes)
            .Select(kv => new StorageDistributionSlice
            {
                Label = ByteSizeFormatter.GetCategoryDisplayName(kv.Key),
                ColorHex = palette[colorIdx++ % palette.Length],
                Bytes = kv.Value.Bytes,
                PercentageOfScanned = Math.Min(100.0, Math.Round((double)kv.Value.Bytes / totalScanned * 100.0, 1)),
                ItemCount = kv.Value.Count
            })
            .ToList();
    }

    private static IReadOnlyList<StorageDistributionSlice> BuildRiskDistribution(
        StorageItem rootNode,
        IReadOnlyList<StorageItem> findings,
        long greenBytes,
        long yellowBytes)
    {
        long total = Math.Max(1L, rootNode.LogicalSizeBytes);
        long redBytes = ComputeNonOverlappingSize(findings.Where(f => f.RiskClassification == RiskLevel.Red));
        long grayBytes = Math.Max(0L, total - greenBytes - yellowBytes - redBytes);

        return
        [
            new StorageDistributionSlice
            {
                Label = "VERDE — Baixo Risco (Temporários / Caches Seguros)",
                ColorHex = "#22C55E",
                Bytes = greenBytes,
                PercentageOfScanned = Math.Round((double)greenBytes / total * 100.0, 1),
                ItemCount = findings.Count(f => f.RiskClassification == RiskLevel.Green)
            },
            new StorageDistributionSlice
            {
                Label = "AMARELO — Requer Atenção (Caches Dev / Downloads / Logs)",
                ColorHex = "#EAB308",
                Bytes = yellowBytes,
                PercentageOfScanned = Math.Round((double)yellowBytes / total * 100.0, 1),
                ItemCount = findings.Count(f => f.RiskClassification == RiskLevel.Yellow)
            },
            new StorageDistributionSlice
            {
                Label = "VERMELHO — Alto Risco (Dados Persistentes / Perfis / VMs)",
                ColorHex = "#EF4444",
                Bytes = redBytes,
                PercentageOfScanned = Math.Round((double)redBytes / total * 100.0, 1),
                ItemCount = findings.Count(f => f.RiskClassification == RiskLevel.Red)
            },
            new StorageDistributionSlice
            {
                Label = "CINZA — Protegido pelo Windows 11 ou Desconhecido",
                ColorHex = "#64748B",
                Bytes = grayBytes,
                PercentageOfScanned = Math.Round((double)grayBytes / total * 100.0, 1),
                ItemCount = findings.Count(f => f.RiskClassification == RiskLevel.Gray)
            }
        ];
    }

    private static void EnqueueBounded(PriorityQueue<StorageItem, long> heap, StorageItem item, long priorityValue, int maxCount)
    {
        if (heap.Count < maxCount)
        {
            heap.Enqueue(item, priorityValue);
        }
        else if (heap.TryPeek(out _, out long smallest) && priorityValue > smallest)
        {
            heap.DequeueEnqueue(item, priorityValue);
        }
    }

    private static List<StorageItem> DequeueSortedDescending(PriorityQueue<StorageItem, long> heap)
    {
        List<StorageItem> list = new(heap.Count);
        while (heap.Count > 0)
        {
            list.Add(heap.Dequeue());
        }

        list.Reverse();
        return list;
    }

    private static List<StorageItem> DequeueSortedBySmallFilesDescending(PriorityQueue<StorageItem, long> heap)
    {
        List<StorageItem> list = DequeueSortedDescending(heap);
        return list.OrderByDescending(i => i.SmallFileCount).ThenByDescending(i => i.FileCount).ToList();
    }

    private static DateTime SafeGetDirectoryLastWriteUtc(string path)
    {
        try
        {
            return Directory.GetLastWriteTimeUtc(path);
        }
        catch
        {
            return DateTime.UtcNow;
        }
    }

    private sealed class TraversalFrame
    {
        public TraversalFrame(StorageItem node, int depth)
        {
            Node = node;
            Depth = depth;
        }

        public StorageItem Node { get; }
        public int Depth { get; }
        public bool HasEnumeratedChildren { get; set; }
        public List<StorageItem> DirectSubfolders { get; } = [];
    }

    private readonly record struct RawFileSystemEntry(
        string FullPath,
        string Name,
        bool IsDirectory,
        long Length,
        FileAttributes Attributes,
        DateTime LastModifiedUtc);

    private sealed class ScanContext
    {
        private readonly Stopwatch _stopwatch;
        private readonly IProgress<ScanProgressReport>? _progress;
        private long _lastProgressElapsedMs;

        private readonly string[] _appDataRoots;

        public ScanContext(Stopwatch stopwatch, IProgress<ScanProgressReport>? progress, EnvironmentPaths env)
        {
            _stopwatch = stopwatch;
            _progress = progress;
            Env = env;
            UserTempDir = (env.UserTempDir ?? string.Empty).TrimEnd('\\', '/');
            DownloadsDir = (env.DownloadsDir ?? string.Empty).TrimEnd('\\', '/');
            _appDataRoots = new[] { env.LocalAppDataDir, env.RoamingAppDataDir, env.LocalLowAppDataDir }
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Select(p => p.TrimEnd('\\', '/'))
                .ToArray();
        }

        public EnvironmentPaths Env { get; }
        public string UserTempDir { get; }
        public string DownloadsDir { get; }

        /// <summary>
        /// Verdadeiro quando o caminho (sem barra final) é uma das raízes do AppData ou está dentro delas.
        /// </summary>
        public bool IsInsideAppData(string trimmedPath)
        {
            foreach (string root in _appDataRoots)
            {
                if (trimmedPath.Length >= root.Length &&
                    trimmedPath.StartsWith(root, StringComparison.OrdinalIgnoreCase) &&
                    (trimmedPath.Length == root.Length || trimmedPath[root.Length] == '\\' || trimmedPath[root.Length] == '/'))
                {
                    return true;
                }
            }

            return false;
        }
        public long FilesScanned { get; set; }
        public long DirectoriesScanned { get; set; }
        public long LogicalBytesAccumulated { get; set; }
        public long AllocatedBytesAccumulated { get; set; }
        public int AccessDeniedCount { get; set; }
        public int ReparsePointsSkipped { get; set; }
        public int HardLinksDeduplicated { get; set; }
        public int SparseFilesDetected { get; set; }

        public PriorityQueue<StorageItem, long> TopFoldersHeap { get; } = new();
        public PriorityQueue<StorageItem, long> TopFilesHeap { get; } = new();
        public PriorityQueue<StorageItem, long> HighDensityHeap { get; } = new();
        public List<StorageItem> DiscoveredDevNodes { get; } = [];
        public List<StorageItem> ActionableCandidates { get; } = [];
        public HashSet<(uint Volume, ulong FileId)> SeenHardLinks { get; } = [];

        public void MaybeReportProgress(string currentDirectory, string phase)
        {
            if (_progress is null)
            {
                return;
            }

            long nowMs = _stopwatch.ElapsedMilliseconds;
            if (nowMs - _lastProgressElapsedMs < 120)
            {
                return;
            }

            _lastProgressElapsedMs = nowMs;
            _progress.Report(new ScanProgressReport
            {
                CurrentDirectory = currentDirectory,
                PhaseDescription = phase,
                FilesScanned = FilesScanned,
                DirectoriesScanned = DirectoriesScanned,
                LogicalBytesAccumulated = LogicalBytesAccumulated,
                AllocatedBytesAccumulated = AllocatedBytesAccumulated,
                AccessDeniedCount = AccessDeniedCount,
                ReparsePointsSkipped = ReparsePointsSkipped,
                Elapsed = _stopwatch.Elapsed
            });
        }
    }
}

