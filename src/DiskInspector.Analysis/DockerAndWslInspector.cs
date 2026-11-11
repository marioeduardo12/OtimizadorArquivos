using System.Diagnostics;
using System.Text;
using System.Text.Json;
using DiskInspector.Core.Enums;
using DiskInspector.Core.Formatting;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Analysis;

/// <summary>
/// Inspetor estritamente somente-leitura para Docker Desktop (Images, Containers, Local Volumes, Build Cache)
/// e distribuições WSL2 via comandos oficiais de consulta ('docker system df' e 'wsl --list --verbose').
/// Nunca executa prune, stop ou comandos destrutivos automaticamente (Seção 7).
/// </summary>
public sealed class DockerAndWslInspector
{
    private readonly IEnvironmentProvider _environmentProvider;

    public DockerAndWslInspector(IEnvironmentProvider environmentProvider)
    {
        _environmentProvider = environmentProvider;
    }

    public IReadOnlyList<DeveloperArtifactItem> InspectDockerAndWsl(IReadOnlyList<StorageItem> discoveredVhdxNodes)
    {
        List<DeveloperArtifactItem> results = [];
        EnvironmentPaths env = _environmentProvider.GetEnvironmentPaths();

        // 1. Consulta não-destrutiva ao 'docker system df' se o binário docker estiver disponível e o daemon responder rápido
        TryQueryDockerSystemDf(results);

        // 2. Inspeciona discos virtuais .vhdx do Docker Desktop e das distros WSL2 encontrados na máquina
        HashSet<string> seenPaths = new(StringComparer.OrdinalIgnoreCase);

        foreach (StorageItem vhdx in discoveredVhdxNodes.Where(n => n.FullPath.EndsWith(".vhdx", StringComparison.OrdinalIgnoreCase)))
        {
            if (seenPaths.Add(vhdx.FullPath))
            {
                results.Add(CreateVhdxArtifactItem(vhdx));
            }
        }

        // Procura também nos caminhos padrão do perfil atual caso a varredura tenha sido feita em outro escopo
        foreach (string candidateVhdx in DiscoverDefaultWslAndDockerVhdxFiles(env))
        {
            if (!seenPaths.Add(candidateVhdx))
            {
                continue;
            }

            try
            {
                FileInfo fi = new(candidateVhdx);
                if (!fi.Exists)
                {
                    continue;
                }

                long allocated = Infrastructure.NativeDiskInterop.GetAllocatedDiskSize(fi.FullName, fi.Length, fi.Attributes);
                StorageItem item = new()
                {
                    Name = fi.Name,
                    FullPath = fi.FullName,
                    LogicalSizeBytes = fi.Length,
                    AllocatedSizeBytes = allocated,
                    LastModifiedUtc = fi.LastWriteTimeUtc,
                    IsDirectory = false,
                    Category = ItemCategory.ContainerOrVirtualization,
                    RiskClassification = RiskLevel.Red,
                    Recommendation = RecommendedAction.UseOfficialDeveloperCommand,
                    IsProtectedSystemItem = true
                };

                results.Add(CreateVhdxArtifactItem(item));
            }
            catch
            {
                // Ignora arquivos inacessíveis
            }
        }

        return results;
    }

    private static DeveloperArtifactItem CreateVhdxArtifactItem(StorageItem vhdx)
    {
        string path = vhdx.FullPath;
        bool isDocker = path.Contains(@"\Docker\", StringComparison.OrdinalIgnoreCase) ||
                        path.Contains("docker_data.vhdx", StringComparison.OrdinalIgnoreCase);

        string distroName = ExtractWslDistroOrPackageName(path);

        return new DeveloperArtifactItem
        {
            Ecosystem = isDocker ? "Docker Desktop (WSL2 Engine)" : $"WSL2 Linux ({distroName})",
            ArtifactKind = isDocker
                ? "Disco Virtual de Containers/Volumes Docker (.vhdx)"
                : "Disco Virtual de Distribuição Linux WSL2 (.vhdx)",
            Name = $"{vhdx.Name} ({distroName})",
            FullPath = path,
            LogicalSizeBytes = vhdx.LogicalSizeBytes,
            AllocatedSizeBytes = vhdx.AllocatedSizeBytes,
            FileCount = 1,
            LastModifiedUtc = vhdx.LastModifiedUtc,
            IsGlobalCache = false,
            IsProjectBuildOutput = false,
            IsPersistentVolumeOrVirtualDisk = true,
            RiskClassification = RiskLevel.Red,
            PurposeExplanation = isDocker
                ? $"Disco virtual ext4 ({vhdx.FormattedLogicalSize} lógicos / {vhdx.FormattedAllocatedSize} alocados fisicamente) que armazena imagens, containers, build cache e VOLUMES PERSISTENTES do Docker Desktop."
                : $"Disco virtual ext4 ({vhdx.FormattedLogicalSize} lógicos / {vhdx.FormattedAllocatedSize} alocados fisicamente) contendo todo o sistema de arquivos Linux e projetos internos da distro '{distroName}'.",
            RebuildOrRedownloadImpact = "ALTO RISCO (PROTEGIDO): Excluir este arquivo .vhdx apaga permanentemente todos os volumes de bancos de dados, containers ou arquivos Linux!",
            RecommendedActionText = isDocker
                ? "Diferencie cache de volumes: use 'docker system df' para inspecionar e 'docker builder prune' para limpar apenas o cache de build sem tocar nos volumes."
                : "Nunca exclua o arquivo .vhdx se desejar manter seus dados no Linux. Para liberar blocos vazios, execute 'fstrim /' dentro do WSL e 'wsl --shutdown'.",
            OfficialCliCommand = isDocker
                ? "docker system df -v  |  docker builder prune"
                : "wsl --list --verbose  |  wsl --shutdown",
            UnderlyingItem = vhdx
        };
    }

    private static void TryQueryDockerSystemDf(List<DeveloperArtifactItem> results)
    {
        try
        {
            ProcessStartInfo psi = new()
            {
                FileName = "docker",
                Arguments = "system df --format \"{{json .}}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };

            using Process? proc = Process.Start(psi);
            if (proc is null)
            {
                return;
            }

            // As saídas são lidas de forma assíncrona. Uma leitura síncrona antes do limite de tempo travaria
            // a análise inteira, sem possibilidade de cancelar, sempre que o daemon do Docker não respondesse.
            Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = proc.StandardError.ReadToEndAsync();

            if (!proc.WaitForExit(3500))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return;
            }

            _ = stderrTask.Wait(500);
            if (proc.ExitCode != 0 || !stdoutTask.Wait(1000))
            {
                return;
            }

            string output = stdoutTask.Result;
            if (string.IsNullOrWhiteSpace(output))
            {
                return;
            }

            foreach (string line in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                using JsonDocument doc = JsonDocument.Parse(line);
                JsonElement root = doc.RootElement;

                string type = root.TryGetProperty("Type", out JsonElement t) ? t.GetString() ?? "" : "";
                string totalCount = root.TryGetProperty("TotalCount", out JsonElement tc) ? tc.GetString() ?? "0" : "0";
                string active = root.TryGetProperty("Active", out JsonElement ac) ? ac.GetString() ?? "0" : "0";
                string sizeStr = root.TryGetProperty("Size", out JsonElement sz) ? sz.GetString() ?? "0B" : "0B";
                string reclaimStr = root.TryGetProperty("Reclaimable", out JsonElement rc) ? rc.GetString() ?? "0B" : "0B";

                long parsedBytes = ParseDockerHumanSize(sizeStr);
                if (parsedBytes <= 0 && totalCount == "0")
                {
                    continue;
                }

                bool isVolumes = type.Contains("Volumes", StringComparison.OrdinalIgnoreCase);
                bool isBuildCache = type.Contains("Build Cache", StringComparison.OrdinalIgnoreCase);

                RiskLevel risk = isVolumes ? RiskLevel.Red : RiskLevel.Yellow;
                string kindLabel = type switch
                {
                    "Images" => $"Imagens Docker ({totalCount} total, {active} ativas)",
                    "Containers" => $"Containers Docker ({totalCount} total, {active} ativos)",
                    "Local Volumes" => $"Volumes Persistentes Docker ({totalCount} total, {active} em uso)",
                    "Build Cache" => $"Build Cache do Docker BuildKit ({totalCount} entradas)",
                    _ => $"Docker {type}"
                };

                string cliCommand = type switch
                {
                    "Images" => "docker image prune",
                    "Containers" => "docker container prune",
                    "Local Volumes" => "docker volume ls  (NÃO execute prune sem backup!)",
                    "Build Cache" => "docker builder prune",
                    _ => "docker system df"
                };

                string explanation = isVolumes
                    ? $"Armazenamento persistente de volumes Docker (Bancos de Dados, arquivos de estado). Total: {sizeStr} (Recuperável relatado: {reclaimStr})."
                    : $"Componente '{type}' reportado pelo daemon Docker ativo. Tamanho total: {sizeStr} | Recuperável estimado pelo Docker: {reclaimStr}.";

                string impact = isVolumes
                    ? "ALTO RISCO: Volumes contêm dados persistentes de bancos de dados e aplicações containerizadas. O DiskInspector jamais remove volumes."
                    : (isBuildCache
                        ? "Limpar o Build Cache com 'docker builder prune' é seguro e apenas fará com que próximos 'docker build' recompilem camadas não cacheadas."
                        : "Remover imagens não utilizadas exigirá novo 'docker pull' ou 'docker build' caso volte a utilizá-las.");

                StorageItem virtualItem = new()
                {
                    Name = kindLabel,
                    FullPath = $"docker://{type.ToLowerInvariant().Replace(' ', '-')}",
                    LogicalSizeBytes = parsedBytes,
                    AllocatedSizeBytes = parsedBytes,
                    LastModifiedUtc = DateTime.UtcNow,
                    IsDirectory = true,
                    IsProtectedSystemItem = true,
                    Category = ItemCategory.ContainerOrVirtualization,
                    AssociatedAppOrComponent = "Docker Engine (API Oficial)",
                    PurposeExplanation = explanation,
                    DeletionConsequences = impact,
                    RiskClassification = risk,
                    Recommendation = RecommendedAction.UseOfficialDeveloperCommand,
                    RecommendationDetails = $"Gerencie exclusivamente via CLI oficial: {cliCommand}",
                    OfficialMaintenanceCommand = cliCommand
                };

                results.Add(new DeveloperArtifactItem
                {
                    Ecosystem = "Docker Engine (Daemon Ativo)",
                    ArtifactKind = kindLabel,
                    Name = $"{kindLabel} — Recuperável: {reclaimStr}",
                    FullPath = $"[Docker CLI] Total: {sizeStr} | Recuperável: {reclaimStr}",
                    LogicalSizeBytes = parsedBytes,
                    AllocatedSizeBytes = parsedBytes,
                    FileCount = int.TryParse(totalCount, out int c) ? c : 0,
                    LastModifiedUtc = DateTime.UtcNow,
                    IsGlobalCache = isBuildCache,
                    IsProjectBuildOutput = !isVolumes && !isBuildCache,
                    IsPersistentVolumeOrVirtualDisk = isVolumes,
                    RiskClassification = risk,
                    PurposeExplanation = explanation,
                    RebuildOrRedownloadImpact = impact,
                    RecommendedActionText = $"Execute no terminal: {cliCommand}",
                    OfficialCliCommand = cliCommand,
                    UnderlyingItem = virtualItem
                });
            }
        }
        catch
        {
            // Docker não instalado ou daemon desligado — falha silenciosa e segura
        }
    }

    private static IEnumerable<string> DiscoverDefaultWslAndDockerVhdxFiles(EnvironmentPaths env)
    {
        List<string> found = [];

        string dockerWslDir = Path.Combine(env.LocalAppDataDir, "Docker", "wsl");
        if (Directory.Exists(dockerWslDir))
        {
            try
            {
                found.AddRange(Directory.EnumerateFiles(dockerWslDir, "*.vhdx", SearchOption.AllDirectories));
            }
            catch { }
        }

        string packagesDir = Path.Combine(env.LocalAppDataDir, "Packages");
        if (Directory.Exists(packagesDir))
        {
            try
            {
                foreach (string pkgDir in Directory.EnumerateDirectories(packagesDir))
                {
                    string localState = Path.Combine(pkgDir, "LocalState");
                    if (Directory.Exists(localState))
                    {
                        try
                        {
                            found.AddRange(Directory.EnumerateFiles(localState, "*.vhdx", SearchOption.TopDirectoryOnly));
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        return found;
    }

    private static string ExtractWslDistroOrPackageName(string path)
    {
        string[] parts = path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < parts.Length - 1; i++)
        {
            if (parts[i].Equals("Packages", StringComparison.OrdinalIgnoreCase) && i + 1 < parts.Length)
            {
                string pkg = parts[i + 1];
                int underscore = pkg.IndexOf('_');
                return underscore > 0 ? pkg[..underscore] : pkg;
            }

            if (parts[i].Equals("wsl", StringComparison.OrdinalIgnoreCase) && i + 1 < parts.Length)
            {
                return $"Docker/{parts[i + 1]}";
            }
        }

        return Path.GetFileName(Path.GetDirectoryName(path) ?? "WSL2");
    }

    public static long ParseDockerHumanSize(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return 0L;
        }

        // Exemplo: "4.25GB" ou "812.3MB (45%)"
        string clean = raw.Split(' ')[0].Trim();
        int idx = 0;
        while (idx < clean.Length && (char.IsDigit(clean[idx]) || clean[idx] == '.' || clean[idx] == ','))
        {
            idx++;
        }

        if (idx == 0)
        {
            return 0L;
        }

        string numPart = clean[..idx].Replace(',', '.');
        string unitPart = clean[idx..].Trim().ToUpperInvariant();

        if (!double.TryParse(numPart, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double value))
        {
            return 0L;
        }

        double multiplier = unitPart switch
        {
            "TB" or "TIB" => 1024d * 1024d * 1024d * 1024d,
            "GB" or "GIB" => 1024d * 1024d * 1024d,
            "MB" or "MIB" => 1024d * 1024d,
            "KB" or "KIB" => 1024d,
            _ => 1d
        };

        return (long)(value * multiplier);
    }
}

