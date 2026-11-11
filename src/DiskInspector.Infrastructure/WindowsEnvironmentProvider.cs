using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Infrastructure;

/// <summary>
/// Descoberta dinâmica de caminhos do Windows 11 e privilégios de execução (Seção 10).
/// Nunca utiliza caminhos fixos com nomes de usuários.
/// </summary>
public sealed class WindowsEnvironmentProvider : IEnvironmentProvider
{
    private static readonly Guid KnownFolderDownloads = new("374DE290-123F-4565-9164-39C4925E467B");
    private static readonly Guid KnownFolderLocalLow = new("A520A1A4-1780-4FF6-BD18-167343C5AF16");

    private readonly EnvironmentPaths? _customOverride;

    // A descoberta custa ~75 µs (várias chamadas ao Shell e ao token do processo) e o classificador a consulta
    // para cada pasta varrida. Os caminhos não mudam durante a execução, então são calculados uma única vez.
    private readonly Lazy<EnvironmentPaths> _discovered;

    public WindowsEnvironmentProvider(EnvironmentPaths? customOverride = null)
    {
        _customOverride = customOverride;
        _discovered = new Lazy<EnvironmentPaths>(DiscoverEnvironmentPaths);
    }

    public EnvironmentPaths GetEnvironmentPaths() => _customOverride ?? _discovered.Value;

    private static EnvironmentPaths DiscoverEnvironmentPaths()
    {
        string windowsDir = NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"C:\Windows");
        string system32Dir = NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.System), Path.Combine(windowsDir, "System32"));
        string sysWow64Dir = NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), Path.Combine(windowsDir, "SysWOW64"));
        string winSxSDir = Path.Combine(windowsDir, "WinSxS");
        string programFilesDir = NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"C:\Program Files");
        string programFilesX86Dir = NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"C:\Program Files (x86)");
        string programDataDir = NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"C:\ProgramData");

        string userProfileDir = NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Environment.CurrentDirectory);
        string localAppDataDir = NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Path.Combine(userProfileDir, "AppData", "Local"));
        string roamingAppDataDir = NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Path.Combine(userProfileDir, "AppData", "Roaming"));
        string localLowAppDataDir = TryGetKnownFolderPath(KnownFolderLocalLow)
            ?? NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) is { Length: > 0 } local
                ? Path.Combine(Directory.GetParent(local)?.FullName ?? Path.Combine(userProfileDir, "AppData"), "LocalLow")
                : string.Empty, Path.Combine(userProfileDir, "AppData", "LocalLow"));

        string downloadsDir = TryGetKnownFolderPath(KnownFolderDownloads)
            ?? Path.Combine(userProfileDir, "Downloads");

        string documentsDir = NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), Path.Combine(userProfileDir, "Documents"));
        string desktopDir = NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Path.Combine(userProfileDir, "Desktop"));
        string userTempDir = NormalizePath(Path.GetTempPath(), Path.Combine(localAppDataDir, "Temp"));
        string systemTempDir = Path.Combine(windowsDir, "Temp");

        return new EnvironmentPaths
        {
            WindowsDir = windowsDir,
            System32Dir = system32Dir,
            SysWow64Dir = sysWow64Dir,
            WinSxSDir = winSxSDir,
            ProgramFilesDir = programFilesDir,
            ProgramFilesX86Dir = programFilesX86Dir,
            ProgramDataDir = programDataDir,
            UserProfileDir = userProfileDir,
            LocalAppDataDir = localAppDataDir,
            RoamingAppDataDir = roamingAppDataDir,
            LocalLowAppDataDir = localLowAppDataDir,
            UserTempDir = userTempDir,
            SystemTempDir = systemTempDir,
            DownloadsDir = downloadsDir,
            DocumentsDir = documentsDir,
            DesktopDir = desktopDir,
            IsElevatedAdmin = CheckIsAdministrator(),
            MachineName = Environment.MachineName,
            CurrentUserName = Environment.UserName,
            OsVersionDescription = RuntimeInformation.OSDescription,
            UserSessionStartUtc = DetectUserSessionStartUtc()
        };
    }

    /// <summary>
    /// Estima o início da sessão atual do usuário pelo processo mais antigo da própria sessão
    /// (explorer, sihost etc.). Todo programa aberto agora começou depois desse instante.
    /// </summary>
    private static DateTime? DetectUserSessionStartUtc()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            int sessionId;
            using (Process current = Process.GetCurrentProcess())
            {
                sessionId = current.SessionId;
            }

            DateTime? earliest = null;
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    if (process.SessionId != sessionId)
                    {
                        continue;
                    }

                    DateTime started = process.StartTime.ToUniversalTime();
                    if (earliest is null || started < earliest)
                    {
                        earliest = started;
                    }
                }
                catch
                {
                    // Processo protegido ou encerrado durante a consulta
                }
                finally
                {
                    process.Dispose();
                }
            }

            return earliest;
        }
        catch
        {
            return null;
        }
    }

    private static bool CheckIsAdministrator()
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static string? TryGetKnownFolderPath(Guid rfid)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        IntPtr pPath = IntPtr.Zero;
        try
        {
            int hr = SHGetKnownFolderPath(rfid, 0, IntPtr.Zero, out pPath);
            if (hr == 0 && pPath != IntPtr.Zero)
            {
                string? path = Marshal.PtrToStringUni(pPath);
                if (!string.IsNullOrWhiteSpace(path))
                {
                    return path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                }
            }
        }
        catch
        {
            // Fallback silencioso caso a API Shell falhe
        }
        finally
        {
            if (pPath != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(pPath);
            }
        }

        return null;
    }

    private static string NormalizePath(string? candidate, string fallback)
    {
        string raw = string.IsNullOrWhiteSpace(candidate) ? fallback : candidate;
        return raw.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    [DllImport("shell32.dll", ExactSpelling = true)]
    private static extern int SHGetKnownFolderPath(
        [MarshalAs(UnmanagedType.LPStruct)] Guid rfid,
        uint dwFlags,
        IntPtr hToken,
        out IntPtr ppszPath);
}
