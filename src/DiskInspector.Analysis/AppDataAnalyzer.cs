using DiskInspector.Core.Enums;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;
using DiskInspector.Infrastructure;

namespace DiskInspector.Analysis;

/// <summary>
/// Analisador profundo dedicado ao diretório AppData (Local, Roaming e LocalLow) conforme Seção 4.
/// Explica por que o AppData acumula dezenas de gigabytes e separa caches seguros de sessões/bancos persistentes.
/// </summary>
public sealed class AppDataAnalyzer
{
    private readonly IEnvironmentProvider _environmentProvider;
    private readonly IStorageClassifier _classifier;

    public AppDataAnalyzer(IEnvironmentProvider environmentProvider, IStorageClassifier classifier)
    {
        _environmentProvider = environmentProvider;
        _classifier = classifier;
    }

    public IReadOnlyList<AppDataEntry> AnalyzeFromTree(
        StorageItem rootNode,
        out long localBytes,
        out long roamingBytes,
        out long localLowBytes,
        out List<StorageItem> safeCacheFindings)
    {
        localBytes = 0;
        roamingBytes = 0;
        localLowBytes = 0;
        safeCacheFindings = [];

        EnvironmentPaths env = _environmentProvider.GetEnvironmentPaths();
        HashSet<string> installedTokens = InstalledAppsRegistryReader.GetInstalledAppKeywords();

        List<AppDataEntry> entries = [];

        StorageItem? localNode = FindNodeByPath(rootNode, env.LocalAppDataDir);
        if (localNode is not null)
        {
            localBytes = localNode.LogicalSizeBytes;
            ProcessScopeNode(localNode, AppDataScope.Local, installedTokens, entries, safeCacheFindings);
        }

        StorageItem? roamingNode = FindNodeByPath(rootNode, env.RoamingAppDataDir);
        if (roamingNode is not null)
        {
            roamingBytes = roamingNode.LogicalSizeBytes;
            ProcessScopeNode(roamingNode, AppDataScope.Roaming, installedTokens, entries, safeCacheFindings);
        }

        StorageItem? localLowNode = FindNodeByPath(rootNode, env.LocalLowAppDataDir);
        if (localLowNode is not null)
        {
            localLowBytes = localLowNode.LogicalSizeBytes;
            ProcessScopeNode(localLowNode, AppDataScope.LocalLow, installedTokens, entries, safeCacheFindings);
        }

        return entries
            .OrderByDescending(e => e.TotalLogicalBytes)
            .ToList();
    }

    private void ProcessScopeNode(
        StorageItem scopeNode,
        AppDataScope scope,
        HashSet<string> installedTokens,
        List<AppDataEntry> entries,
        List<StorageItem> safeCacheFindings)
    {
        foreach (StorageItem child in scopeNode.Children.Where(c => c.IsDirectory))
        {
            // Ignora a pasta Temp na listagem de aplicativos do AppData\Local (já tratada em Temporários),
            // ou inclui com rótulo explícito de Temporários do Sistema
            string appName = StorageClassifier.IdentifyAppDataOwner(child.FullPath, out string publisher);

            // Se for uma pasta de fabricante que agrupa subaplicativos (ex.: Google\Chrome, Microsoft\Edge, BraveSoftware\Brave-Browser),
            // inspecionamos também os subdiretórios de segundo nível para precisão cirúrgica
            if (IsVendorContainerFolder(child.Name) && child.Children.Any(c => c.IsDirectory))
            {
                foreach (StorageItem subVendorChild in child.Children.Where(c => c.IsDirectory))
                {
                    AppDataEntry subEntry = BuildEntryForAppDirectory(subVendorChild, scope, installedTokens, safeCacheFindings);
                    if (subEntry.TotalLogicalBytes > 0)
                    {
                        entries.Add(subEntry);
                    }
                }
                continue;
            }

            AppDataEntry entry = BuildEntryForAppDirectory(child, scope, installedTokens, safeCacheFindings);
            if (entry.TotalLogicalBytes > 0)
            {
                entries.Add(entry);
            }
        }
    }

    private AppDataEntry BuildEntryForAppDirectory(
        StorageItem appDirNode,
        AppDataScope scope,
        HashSet<string> installedTokens,
        List<StorageItem> safeCacheFindings)
    {
        string identifiedApp = StorageClassifier.IdentifyAppDataOwner(appDirNode.FullPath, out string publisher);
        bool isKnownApp = !string.Equals(identifiedApp, "Desconhecido", StringComparison.OrdinalIgnoreCase);
        string parentFolderName = Path.GetFileName(Path.GetDirectoryName(appDirNode.FullPath.TrimEnd('\\', '/')) ?? string.Empty);
        bool isUserTempDir = string.Equals(appDirNode.Name, "Temp", StringComparison.OrdinalIgnoreCase) && scope == AppDataScope.Local;

        if (isUserTempDir)
        {
            identifiedApp = "Arquivos Temporários do Usuário (%TEMP%)";
            publisher = "Microsoft Windows";
            isKnownApp = true;
        }
        else if (string.Equals(appDirNode.Name, "Packages", StringComparison.OrdinalIgnoreCase) && scope == AppDataScope.Local)
        {
            identifiedApp = "Pacotes UWP / MSIX (Microsoft Store & Windows 11 Apps)";
            publisher = "Microsoft Windows";
            isKnownApp = true;
        }
        else if (scope == AppDataScope.Local && string.Equals(parentFolderName, "Packages", StringComparison.OrdinalIgnoreCase))
        {
            // Cada aplicativo da Microsoft Store tem a própria pasta: "Nome.Do.Pacote_sufixoDoEditor"
            if (!isKnownApp)
            {
                int suffixIndex = appDirNode.Name.LastIndexOf('_');
                identifiedApp = suffixIndex > 0 ? appDirNode.Name[..suffixIndex] : appDirNode.Name;
                publisher = "Aplicativo da Microsoft Store (MSIX)";
                isKnownApp = true;
            }
        }
        else if (scope == AppDataScope.Local && string.Equals(parentFolderName, "Programs", StringComparison.OrdinalIgnoreCase))
        {
            // AppData\Local\Programs guarda os binários de programas instalados só para este usuário
            identifiedApp = $"{appDirNode.Name} (programa instalado para este usuário)";
            publisher = "Instalação no perfil do usuário";
            isKnownApp = true;
        }

        List<StorageItem> safeCaches = [];
        if (isUserTempDir)
        {
            // No Temp, cada item direto já é um achado avaliado por idade e sessão: só os VERDES contam aqui
            safeCaches.AddRange(appDirNode.Children.Where(c =>
                c.RiskClassification == RiskLevel.Green && c.CanSelectForCleanup));
        }
        else
        {
            CollectVerifiedSafeCachesRecursive(appDirNode, identifiedApp, safeCaches, maxDepth: 8);

            foreach (StorageItem cacheItem in safeCaches)
            {
                _classifier.ClassifyItem(cacheItem);
            }

            // Proteções aplicadas pelo classificador (ex.: pasta do próprio DiskInspector) prevalecem
            safeCaches.RemoveAll(c => !c.CanSelectForCleanup);
        }

        foreach (StorageItem cacheItem in safeCaches)
        {
            if (cacheItem.RiskClassification == RiskLevel.Green || cacheItem.RiskClassification == RiskLevel.Yellow)
            {
                safeCacheFindings.Add(cacheItem);
            }
        }

        long safeCacheBytes = safeCaches.Sum(c => c.LogicalSizeBytes);
        long persistentBytes = Math.Max(0, appDirNode.LogicalSizeBytes - safeCacheBytes);

        AppDataContentKind contentKind = DeterminePrimaryContentKind(appDirNode, identifiedApp, scope, safeCacheBytes, persistentBytes);

        bool looksUninstalled = !isKnownApp &&
                                installedTokens.Count > 0 &&
                                !installedTokens.Contains(appDirNode.Name) &&
                                appDirNode.LastModifiedUtc < DateTime.UtcNow.AddDays(-90);

        RiskLevel overallRisk;
        string explanation;
        string warning;
        string guidance;

        if (isUserTempDir)
        {
            overallRisk = RiskLevel.Green;
            explanation = "Diretório oficial de arquivos temporários do usuário (%LOCALAPPDATA%\\Temp). Contém arquivos transitórios de instaladores e sessões passadas.";
            warning = "Itens alterados durante a sessão atual do Windows ficam em AMARELO: podem pertencer a um programa aberto.";
            guidance = "Os itens VERDES (sem alteração desde antes da sessão atual) podem ser enviados com segurança para a Lixeira.";
        }
        else if (contentKind == AppDataContentKind.DisposableCache || contentKind == AppDataContentKind.ShaderOrGpuCache)
        {
            overallRisk = isKnownApp ? RiskLevel.Green : RiskLevel.Yellow;
            explanation = $"Diretório dedicado a cache técnico ({identifiedApp}). Armazena shaders compilados ou pacotes baixados reconstruíveis.";
            warning = "Limpar este cache pode causar uma leve lentidão inicial na próxima abertura do aplicativo enquanto o cache é recriado.";
            guidance = "Seguro limpar apenas quando o aplicativo correspondente estiver fechado.";
        }
        else if (isKnownApp)
        {
            overallRisk = RiskLevel.Red;
            explanation = $"Contém configurações, dados persistentes, sessões/autenticação, bancos locais (IndexedDB/SQLite) e caches internos do {identifiedApp}.";
            warning = $"NÃO apague a pasta '{appDirNode.Name}' inteira! Isso causará perda de login, perfis, configurações e bancos locais.";
            guidance = safeCacheBytes > 0
                ? $"Existem {DiskInspector.Core.Formatting.ByteSizeFormatter.FormatBytes(safeCacheBytes)} em subpastas de cache descartáveis dentro deste aplicativo que podem ser limpas isoladamente."
                : "Mantenha esta pasta protegida. Não foram detectados caches descartáveis volumosos separados.";
        }
        else
        {
            overallRisk = RiskLevel.Gray;
            explanation = looksUninstalled
                ? $"Diretório sem correspondência óbvia nos programas instalados atuais e sem modificação recente (possível resíduo de aplicativo desinstalado ou utilitário portátil)."
                : "Finalidade específica desconhecida. Pode conter configurações, licenças ou bancos de dados locais de um software instalado.";
            warning = "Excluir pastas desconhecidas no AppData pode apagar configurações, chaves ou dados salvos.";
            guidance = "Classificado conservadoramente como CINZA (Desconhecido). Exige decisão manual informada fora da limpeza automática.";
        }

        return new AppDataEntry
        {
            Scope = scope,
            DirectoryName = appDirNode.Name,
            FullPath = appDirNode.FullPath,
            IdentifiedApplication = isKnownApp ? identifiedApp : $"Desconhecido ({appDirNode.Name})",
            PublisherOrEcosystem = string.IsNullOrWhiteSpace(publisher) ? "Não identificado" : publisher,
            PrimaryContentKind = contentKind,
            TotalLogicalBytes = appDirNode.LogicalSizeBytes,
            TotalAllocatedBytes = appDirNode.AllocatedSizeBytes,
            SafeDisposableCacheBytes = safeCacheBytes,
            PersistentOrSensitiveBytes = persistentBytes,
            FileCount = appDirNode.FileCount,
            LastModifiedUtc = appDirNode.LastModifiedUtc,
            OverallRisk = overallRisk,
            ContentSummaryExplanation = explanation,
            DeletionWarning = warning,
            GuidanceText = guidance,
            LooksLikeUninstalledApp = looksUninstalled,
            SafeCacheSubdirectories = safeCaches,
            SubItemBreakdown = appDirNode.Children.OrderByDescending(c => c.LogicalSizeBytes).Take(15).ToList(),
            RootStorageItem = appDirNode
        };
    }

    private static void CollectVerifiedSafeCachesRecursive(
        StorageItem current,
        string identifiedApp,
        List<StorageItem> accumulator,
        int maxDepth)
    {
        if (maxDepth < 0 || !current.IsDirectory)
        {
            return;
        }

        if (StorageClassifier.IsVerifiedDisposableAppDataCache(current.FullPath, current.Name, identifiedApp))
        {
            if (current.LogicalSizeBytes > 0)
            {
                accumulator.Add(current);
            }
            return; // Não desce dentro de uma pasta já inteiramente marcada como cache descartável
        }

        foreach (StorageItem child in current.Children)
        {
            if (child.IsDirectory)
            {
                CollectVerifiedSafeCachesRecursive(child, identifiedApp, accumulator, maxDepth - 1);
            }
        }
    }

    private static AppDataContentKind DeterminePrimaryContentKind(
        StorageItem node,
        string identifiedApp,
        AppDataScope scope,
        long safeCacheBytes,
        long persistentBytes)
    {
        string path = node.FullPath;

        if (path.Contains("D3DSCache", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("DXCache", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("GLCache", StringComparison.OrdinalIgnoreCase))
        {
            return AppDataContentKind.ShaderOrGpuCache;
        }

        if (path.Contains("CrashDumps", StringComparison.OrdinalIgnoreCase))
        {
            return AppDataContentKind.CrashDumpsOrLogs;
        }

        if (path.Contains("npm-cache", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\pip", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\NuGet", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\pnpm", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\Yarn", StringComparison.OrdinalIgnoreCase))
        {
            return AppDataContentKind.DisposableCache;
        }

        if (string.Equals(identifiedApp, "Desconhecido", StringComparison.OrdinalIgnoreCase))
        {
            return AppDataContentKind.Unknown;
        }

        if (safeCacheBytes > 0 && persistentBytes == 0)
        {
            return AppDataContentKind.DisposableCache;
        }

        if (scope == AppDataScope.Roaming)
        {
            return AppDataContentKind.SessionOrAuthentication;
        }

        return AppDataContentKind.PersistentDatabaseOrStorage;
    }

    /// <summary>
    /// Pastas que apenas agrupam vários aplicativos (um fabricante, os pacotes da Microsoft Store, os programas
    /// instalados no perfil). Uma linha única para elas esconderia quem de fato ocupa o espaço.
    /// </summary>
    private static bool IsVendorContainerFolder(string folderName)
    {
        return folderName.Equals("Google", StringComparison.OrdinalIgnoreCase) ||
               folderName.Equals("BraveSoftware", StringComparison.OrdinalIgnoreCase) ||
               folderName.Equals("Mozilla", StringComparison.OrdinalIgnoreCase) ||
               folderName.Equals("Microsoft", StringComparison.OrdinalIgnoreCase) ||
               folderName.Equals("JetBrains", StringComparison.OrdinalIgnoreCase) ||
               folderName.Equals("Packages", StringComparison.OrdinalIgnoreCase) ||
               folderName.Equals("Programs", StringComparison.OrdinalIgnoreCase);
    }

    public static StorageItem? FindNodeByPath(StorageItem current, string targetPath)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            return null;
        }

        string normCurrent = current.FullPath.TrimEnd('\\', '/');
        string normTarget = targetPath.TrimEnd('\\', '/');

        if (string.Equals(normCurrent, normTarget, StringComparison.OrdinalIgnoreCase))
        {
            return current;
        }

        if (!normTarget.StartsWith(normCurrent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        foreach (StorageItem child in current.Children)
        {
            if (child.IsDirectory)
            {
                StorageItem? found = FindNodeByPath(child, normTarget);
                if (found is not null)
                {
                    return found;
                }
            }
        }

        return null;
    }
}

