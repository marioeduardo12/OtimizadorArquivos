using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Analysis;

/// <summary>
/// Guardião centralizado de proteção de caminhos críticos do Windows 11 (Seção 5).
/// Garante que diretórios do sistema, inicialização, drivers, Windows Update, Program Files e ProgramData
/// apareçam na análise de consumo, mas JAMAIS possam ser excluídos pelo mecanismo genérico de limpeza.
/// </summary>
public sealed class SystemPathProtector : ISystemPathProtector
{
    private readonly IEnvironmentProvider _environmentProvider;

    private static readonly HashSet<string> ProtectedRootSystemFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "pagefile.sys",
        "hiberfil.sys",
        "swapfile.sys",
        "bootmgr",
        "bootnxt",
        "bcd",
        "dumpstack.log",
        "dumpstack.log.tmp"
    };

    private static readonly HashSet<string> ProtectedDriveRootFolderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Windows",
        "Windows.old",
        "$Windows.~BT",
        "$Windows.~WS",
        "$SysReset",
        "$Recycle.Bin",
        "System Volume Information",
        "Recovery",
        "Boot",
        "EFI",
        "PerfLogs",
        "Config.Msi",
        "MSOCache",
        "Program Files",
        "Program Files (x86)",
        "ProgramData"
    };

    public SystemPathProtector(IEnvironmentProvider environmentProvider)
    {
        _environmentProvider = environmentProvider;
    }

    public bool IsProtectedSystemPath(string fullPath, out string protectionReason, out string? officialToolGuidance)
    {
        protectionReason = string.Empty;
        officialToolGuidance = null;

        if (string.IsNullOrWhiteSpace(fullPath))
        {
            protectionReason = "Caminho vazio ou inválido.";
            return true;
        }

        string normalized = NormalizePath(fullPath);
        EnvironmentPaths env = _environmentProvider.GetEnvironmentPaths();

        // 1. Raiz de unidade (C:\, D:\, etc.)
        string? root = Path.GetPathRoot(normalized)?.TrimEnd('\\', '/');
        if (!string.IsNullOrWhiteSpace(root) && string.Equals(normalized, root, StringComparison.OrdinalIgnoreCase))
        {
            protectionReason = "Raiz de unidade de disco do sistema operacional.";
            return true;
        }

        string fileName = Path.GetFileName(normalized);

        // 2. Arquivos de paginação, hibernação e boot na raiz do disco
        if (ProtectedRootSystemFiles.Contains(fileName))
        {
            protectionReason = $"Arquivo crítico de memória virtual, hibernação ou boot do Windows ({fileName}).";
            officialToolGuidance = "Gerenciado automaticamente pelo kernel do Windows (Configurações Avançadas do Sistema / powercfg /h).";
            return true;
        }

        // 3. WinSxS (Component Store)
        if (IsSameOrSubpath(normalized, env.WinSxSDir))
        {
            protectionReason = "Repositório de componentes do Windows (WinSxS). Essencial para integridade, atualizações e recuperação do Windows 11.";
            officialToolGuidance = "DISM.exe /Online /Cleanup-Image /StartComponentCleanup";
            return true;
        }

        // 4. Windows Update (SoftwareDistribution / DeliveryOptimization)
        string softwareDist = Path.Combine(env.WindowsDir, "SoftwareDistribution");
        if (IsSameOrSubpath(normalized, softwareDist))
        {
            protectionReason = "Diretório de componentes e pacotes do Windows Update (SoftwareDistribution).";
            officialToolGuidance = "Utilize Configurações do Windows > Sistema > Armazenamento > Arquivos Temporários (Sensor de Armazenamento / cleanmgr.exe).";
            return true;
        }

        // 5. Diretórios de Drivers (DriverStore / INF / System32\drivers)
        string driverStore = Path.Combine(env.System32Dir, "DriverStore");
        string driversDir = Path.Combine(env.System32Dir, "drivers");
        string infDir = Path.Combine(env.WindowsDir, "INF");
        if (IsSameOrSubpath(normalized, driverStore) ||
            IsSameOrSubpath(normalized, driversDir) ||
            IsSameOrSubpath(normalized, infDir))
        {
            protectionReason = "Repositório crítico de drivers de hardware do Windows 11.";
            officialToolGuidance = "Gerencie pacotes de drivers antigos exclusivamente via 'pnputil /enum-drivers' ou Limpeza de Disco do Sistema.";
            return true;
        }

        // 6. System32 e SysWOW64
        if (IsSameOrSubpath(normalized, env.System32Dir) || IsSameOrSubpath(normalized, env.SysWow64Dir))
        {
            protectionReason = "Diretório de bibliotecas nativas, subsistemas e executáveis de núcleo do Windows (System32 / SysWOW64).";
            officialToolGuidance = "Verificação de integridade oficial: 'sfc /scannow'.";
            return true;
        }

        // 7. Qualquer caminho dentro de C:\Windows
        if (IsSameOrSubpath(normalized, env.WindowsDir))
        {
            protectionReason = "Diretório principal do sistema operacional Windows 11.";
            officialToolGuidance = "Utilize o Sensor de Armazenamento do Windows 11 (ms-settings:storagesense) ou 'cleanmgr.exe'.";
            return true;
        }

        // 8. Program Files e Program Files (x86)
        if (IsSameOrSubpath(normalized, env.ProgramFilesDir) || IsSameOrSubpath(normalized, env.ProgramFilesX86Dir))
        {
            protectionReason = "Diretório protegido de binários de aplicativos instalados (Program Files).";
            officialToolGuidance = "Para remover programas, utilize Configurações do Windows > Aplicativos > Aplicativos Instalados (ou winget uninstall).";
            return true;
        }

        // 9. ProgramData
        if (IsSameOrSubpath(normalized, env.ProgramDataDir))
        {
            protectionReason = "Diretório global de dados de sistema, serviços, licenças e políticas compartilhadas (ProgramData).";
            officialToolGuidance = "Gerenciado pelos instaladores oficiais e serviços do Windows (MSI / Windows Defender / Windows Update).";
            return true;
        }

        // 10. Pastas de recuperação, inicialização, VSS e instalações anteriores na raiz de qualquer disco
        if (!string.IsNullOrWhiteSpace(root))
        {
            string relativeToRoot = normalized.Length > root.Length
                ? normalized[(root.Length + 1)..]
                : string.Empty;

            if (!string.IsNullOrWhiteSpace(relativeToRoot))
            {
                string firstSegment = relativeToRoot.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
                if (ProtectedDriveRootFolderNames.Contains(firstSegment))
                {
                    protectionReason = $"Diretório estrutural protegido de sistema, boot ou recuperação ({firstSegment}).";
                    officialToolGuidance = firstSegment.Equals("Windows.old", StringComparison.OrdinalIgnoreCase)
                        ? "Para remover instalações anteriores do Windows com segurança, use Configurações > Sistema > Armazenamento > Arquivos Temporários."
                        : "Gerenciado diretamente pelo sistema operacional Windows 11.";
                    return true;
                }
            }
        }

        return false;
    }

    public bool IsCriticalRootOrProfileFolder(string fullPath, out string reason)
    {
        reason = string.Empty;
        if (string.IsNullOrWhiteSpace(fullPath))
        {
            reason = "Caminho inválido.";
            return true;
        }

        string normalized = NormalizePath(fullPath);
        EnvironmentPaths env = _environmentProvider.GetEnvironmentPaths();

        string? root = Path.GetPathRoot(normalized)?.TrimEnd('\\', '/');
        if (!string.IsNullOrWhiteSpace(root) && string.Equals(normalized, root, StringComparison.OrdinalIgnoreCase))
        {
            reason = "Raiz da unidade de armazenamento.";
            return true;
        }

        string usersParent = Directory.GetParent(env.UserProfileDir)?.FullName.TrimEnd('\\', '/') ?? @"C:\Users";
        string appDataRoot = Directory.GetParent(env.LocalAppDataDir)?.FullName.TrimEnd('\\', '/') ?? Path.Combine(env.UserProfileDir, "AppData");

        string[] criticalFolders =
        [
            usersParent,
            env.UserProfileDir,
            appDataRoot,
            env.LocalAppDataDir,
            env.RoamingAppDataDir,
            env.LocalLowAppDataDir,
            env.DesktopDir,
            env.DocumentsDir,
            env.DownloadsDir,
            env.UserTempDir
        ];

        foreach (string critical in criticalFolders)
        {
            if (string.Equals(normalized, NormalizePath(critical), StringComparison.OrdinalIgnoreCase))
            {
                reason = $"Diretório-raiz estrutural do perfil do usuário ({Path.GetFileName(normalized)}). Apenas subitens qualificados podem ser limpos, nunca a pasta-raiz.";
                return true;
            }
        }

        return false;
    }

    public static bool IsSameOrSubpath(string candidatePath, string basePath)
    {
        if (string.IsNullOrWhiteSpace(candidatePath) || string.IsNullOrWhiteSpace(basePath))
        {
            return false;
        }

        string normCandidate = NormalizePath(candidatePath);
        string normBase = NormalizePath(basePath);

        if (string.Equals(normCandidate, normBase, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return normCandidate.StartsWith(normBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Forma canônica usada em todas as comparações de caminho: absoluta, sem prefixo \\?\ e sem barra final.
    /// </summary>
    public static string NormalizeForComparison(string path) => NormalizePath(path);

    private static string NormalizePath(string path)
    {
        try
        {
            string clean = path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
            return Path.GetFullPath(clean).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch
        {
            return path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
    }
}

