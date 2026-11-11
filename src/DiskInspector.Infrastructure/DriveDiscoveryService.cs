using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Infrastructure;

/// <summary>
/// Serviço para descoberta dinâmica das unidades de disco disponíveis na máquina (Seções 2 e 10).
/// </summary>
public sealed class DriveDiscoveryService : IDriveDiscoveryService
{
    private readonly IEnvironmentProvider _environmentProvider;

    public DriveDiscoveryService(IEnvironmentProvider environmentProvider)
    {
        _environmentProvider = environmentProvider;
    }

    public IReadOnlyList<DriveMetadata> GetAvailableDrives()
    {
        EnvironmentPaths env = _environmentProvider.GetEnvironmentPaths();
        string systemRoot = Path.GetPathRoot(env.WindowsDir) ?? @"C:\";

        List<DriveMetadata> result = [];

        DriveInfo[] drives;
        try
        {
            drives = DriveInfo.GetDrives();
        }
        catch
        {
            return result;
        }

        foreach (DriveInfo drive in drives)
        {
            try
            {
                if (!drive.IsReady)
                {
                    continue;
                }

                string root = drive.RootDirectory.FullName;
                bool isSystemDrive = string.Equals(
                    root.TrimEnd('\\'),
                    systemRoot.TrimEnd('\\'),
                    StringComparison.OrdinalIgnoreCase);

                string driveTypeDesc = drive.DriveType switch
                {
                    DriveType.Fixed => "Disco Fixo Local",
                    DriveType.Removable => "Unidade Removível",
                    DriveType.Network => "Unidade de Rede",
                    DriveType.Ram => "Disco RAM",
                    DriveType.CDRom => "Unidade Óptica",
                    _ => "Unidade de Armazenamento"
                };

                result.Add(new DriveMetadata
                {
                    Name = drive.Name.TrimEnd('\\'),
                    RootDirectory = root,
                    VolumeLabel = SafeGet(() => drive.VolumeLabel, "Disco Local"),
                    FileSystem = SafeGet(() => drive.DriveFormat, "NTFS"),
                    DriveTypeDescription = driveTypeDesc,
                    TotalBytes = SafeGet(() => drive.TotalSize, 0L),
                    AvailableFreeBytes = SafeGet(() => drive.AvailableFreeSpace, 0L),
                    IsSystemDrive = isSystemDrive,
                    IsReady = true
                });
            }
            catch
            {
                // Ignora unidades inacessíveis ou desconectadas durante a consulta
            }
        }

        return result
            .OrderByDescending(d => d.IsSystemDrive)
            .ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static T SafeGet<T>(Func<T> getter, T fallback)
    {
        try
        {
            return getter();
        }
        catch
        {
            return fallback;
        }
    }
}

