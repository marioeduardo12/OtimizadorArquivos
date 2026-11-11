using DiskInspector.Core.Enums;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Analysis;

/// <summary>
/// Identifica oportunidades de recuperar espaço em disco SEM apagar nenhum arquivo do usuário (Diferencial 6):
/// 1. Compactação de discos virtuais .vhdx do WSL2 / Docker Desktop (libera blocos vazios após uso).
/// 2. Compressão NTFS transparente (compact.exe) em pastas densas e pouco alteradas fora do sistema.
/// 3. Desidratação de arquivos locais do OneDrive ("Liberar espaço" mantendo os arquivos seguros na nuvem).
/// </summary>
public sealed class NonDestructiveSpaceAdvisor
{
    private readonly IEnvironmentProvider _environmentProvider;
    private readonly ISystemPathProtector _systemPathProtector;

    public NonDestructiveSpaceAdvisor(IEnvironmentProvider environmentProvider, ISystemPathProtector systemPathProtector)
    {
        _environmentProvider = environmentProvider;
        _systemPathProtector = systemPathProtector;
    }

    public IReadOnlyList<NonDestructiveOption> AnalyzeOptions(
        StorageItem rootNode,
        IReadOnlyList<DeveloperArtifactItem> devArtifacts,
        IReadOnlyList<StorageItem> highDensityFolders)
    {
        EnvironmentPaths env = _environmentProvider.GetEnvironmentPaths();
        List<NonDestructiveOption> options = [];
        HashSet<string> seenPaths = new(StringComparer.OrdinalIgnoreCase);

        // 1. Discos virtuais .vhdx do WSL2 / Docker Desktop
        foreach (DeveloperArtifactItem vhdx in devArtifacts.Where(d =>
                     d.IsPersistentVolumeOrVirtualDisk &&
                     d.FullPath.EndsWith(".vhdx", StringComparison.OrdinalIgnoreCase) &&
                     d.LogicalSizeBytes >= 64 * 1024 * 1024))
        {
            if (!seenPaths.Add(vhdx.FullPath))
            {
                continue;
            }

            long currentBytes = vhdx.AllocatedSizeBytes > 0 ? vhdx.AllocatedSizeBytes : vhdx.LogicalSizeBytes;
            // Estimativa conservadora: discos dinâmicos VHDX costumam reter 15% a 30% de blocos ext4 já liberados
            long estimatedSavings = Math.Max(32L * 1024 * 1024, (long)(currentBytes * 0.20));

            options.Add(new NonDestructiveOption
            {
                OptionId = $"vhdx-compact:{vhdx.FullPath}",
                Title = $"Compactar Disco Virtual: {vhdx.Name}",
                CategoryLabel = "Compactação VHDX (WSL2 / Docker)",
                TargetPath = vhdx.FullPath,
                CurrentLogicalBytes = vhdx.LogicalSizeBytes,
                CurrentAllocatedBytes = currentBytes,
                EstimatedSavingsBytes = estimatedSavings,
                Explanation = "O disco virtual (.vhdx) do WSL2/Docker cresce automaticamente mas não devolve espaço sozinho ao Windows quando arquivos ou imagens são apagados dentro do Linux.",
                SafetyGuarantee = "NENHUM container, volume ou arquivo Linux é apagado. O comando encerra o WSL com segurança e compacta apenas os blocos vazios do arquivo .vhdx.",
                CommandPreview = $"wsl --shutdown  &&  diskpart (select vdisk file=\"{vhdx.FullPath}\" / compact vdisk)",
                CanExecuteDirectly = true,
                RequiresElevation = true
            });
        }

        // 2. Pasta do OneDrive (quando presente e com arquivos hidratados localmente)
        string? oneDriveDir = Environment.GetEnvironmentVariable("OneDrive")
                              ?? Environment.GetEnvironmentVariable("OneDriveConsumer");
        if (string.IsNullOrWhiteSpace(oneDriveDir))
        {
            string candidate = Path.Combine(env.UserProfileDir, "OneDrive");
            if (Directory.Exists(candidate))
            {
                oneDriveDir = candidate;
            }
        }

        if (!string.IsNullOrWhiteSpace(oneDriveDir))
        {
            StorageItem? oneDriveNode = AppDataAnalyzer.FindNodeByPath(rootNode, oneDriveDir);
            if (oneDriveNode is not null && oneDriveNode.AllocatedSizeBytes >= 50 * 1024 * 1024 && seenPaths.Add(oneDriveNode.FullPath))
            {
                options.Add(new NonDestructiveOption
                {
                    OptionId = $"onedrive-dehydrate:{oneDriveNode.FullPath}",
                    Title = "Liberar Espaço Local do OneDrive (Arquivos Sob Demanda)",
                    CategoryLabel = "OneDrive Sob Demanda",
                    TargetPath = oneDriveNode.FullPath,
                    CurrentLogicalBytes = oneDriveNode.LogicalSizeBytes,
                    CurrentAllocatedBytes = oneDriveNode.AllocatedSizeBytes,
                    EstimatedSavingsBytes = (long)(oneDriveNode.AllocatedSizeBytes * 0.85),
                    Explanation = "Converte arquivos sincronizados do OneDrive para o modo 'Somente Online' (placeholder NTFS). Eles continuam aparecendo normalmente no Explorer e são baixados ao abrir.",
                    SafetyGuarantee = "NENHUM arquivo é excluído da sua conta OneDrive nem das pastas locais; apenas a cópia física em cache local é liberada.",
                    CommandPreview = $"attrib +U -P \"{oneDriveNode.FullPath}\\*\" /S /D",
                    CanExecuteDirectly = true,
                    RequiresElevation = false
                });
            }
        }

        // 3. Compressão transparente NTFS (compact.exe) em diretórios densos e frios fora de caminhos protegidos
        foreach (StorageItem dense in highDensityFolders
                     .Where(d =>
                         d.LogicalSizeBytes >= 20 * 1024 * 1024 &&
                         d.SmallFileCount >= 100 &&
                         !d.IsProtectedSystemItem &&
                         !_systemPathProtector.IsProtectedSystemPath(d.FullPath, out _, out _) &&
                         !_systemPathProtector.IsCriticalRootOrProfileFolder(d.FullPath, out _) &&
                         d.EffectiveLatestWriteUtc < DateTime.UtcNow.AddDays(-14))
                     .Take(8))
        {
            if (!seenPaths.Add(dense.FullPath))
            {
                continue;
            }

            long currentBytes = dense.AllocatedSizeBytes > 0 ? dense.AllocatedSizeBytes : dense.LogicalSizeBytes;
            long estimatedSavings = (long)(currentBytes * 0.35);

            options.Add(new NonDestructiveOption
            {
                OptionId = $"ntfs-compact:{dense.FullPath}",
                Title = $"Compressão NTFS Transparente: {dense.Name}",
                CategoryLabel = "Compressão Nativa NTFS",
                TargetPath = dense.FullPath,
                CurrentLogicalBytes = dense.LogicalSizeBytes,
                CurrentAllocatedBytes = currentBytes,
                EstimatedSavingsBytes = estimatedSavings,
                Explanation = $"Pasta com {dense.FileCount:N0} arquivos ({dense.SmallFileCount:N0} pequenos) sem alteração recente. A compressão nativa do NTFS reduz o espaço em disco sem alterar o caminho nem o conteúdo.",
                SafetyGuarantee = "100% transparente para todos os programas: os arquivos continuam no mesmo lugar e podem ser lidos e editados normalmente.",
                CommandPreview = $"compact.exe /C /S:\"{dense.FullPath}\" /I /Q",
                CanExecuteDirectly = true,
                RequiresElevation = false
            });
        }

        return options
            .OrderByDescending(o => o.EstimatedSavingsBytes)
            .ToList();
    }
}
