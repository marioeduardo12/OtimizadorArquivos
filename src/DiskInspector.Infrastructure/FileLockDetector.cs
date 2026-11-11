using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Infrastructure;

/// <summary>
/// Verifica de forma não-destrutiva se um arquivo ou diretório contém arquivos bloqueados/em uso por processos
/// e identifica qual programa detém o arquivo via Windows Restart Manager (rstrtmgr.dll).
/// </summary>
public sealed class FileLockDetector : IFileLockDetector
{
    private const int ErrorSharingViolation = 32;
    private const int ErrorLockViolation = 33;
    private const int ErrorMoreData = 234;
    private const int RmInvalidSession = -1;
    private const int CchRmMaxAppName = 255;
    private const int CchRmMaxSvcName = 63;

    public bool IsFileLocked(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return false;
        }

        try
        {
            using FileStream stream = new(
                filePath,
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.None);
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            // Se o arquivo for somente-leitura ou protegido por ACL, verificamos abertura de leitura exclusiva
            try
            {
                using FileStream readStream = new(
                    filePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.None);
                return false;
            }
            catch (IOException ioEx) when (IsLockErrorCode(ioEx))
            {
                return true;
            }
            catch
            {
                return false;
            }
        }
        catch (IOException ioEx) when (IsLockErrorCode(ioEx))
        {
            return true;
        }
        catch
        {
            return false;
        }
    }

    public bool ContainsLockedFiles(string directoryPath, int maxSampleCount = 50)
    {
        if (string.IsNullOrWhiteSpace(directoryPath) || !Directory.Exists(directoryPath))
        {
            return false;
        }

        try
        {
            int checkedCount = 0;
            EnumerationOptions options = new()
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            };

            foreach (string file in Directory.EnumerateFiles(directoryPath, "*", options))
            {
                if (IsFileLocked(file))
                {
                    return true;
                }

                checkedCount++;
                if (checkedCount >= maxSampleCount)
                {
                    break;
                }
            }
        }
        catch
        {
            // Se não for possível enumerar, não bloqueia a checagem preliminar
        }

        return false;
    }

    /// <summary>
    /// Consulta o Windows Restart Manager (rstrtmgr.dll) para descobrir quais processos estão com o arquivo
    /// (ou arquivos dentro da pasta) abertos, sem abrir nem travar nenhum arquivo no disco.
    /// </summary>
    public IReadOnlyList<LockingProcessInfo> GetLockingProcesses(string fileOrDirectoryPath, int maxSampleFiles = 25)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(fileOrDirectoryPath))
        {
            return [];
        }

        List<string> candidateFiles = [];
        try
        {
            if (File.Exists(fileOrDirectoryPath))
            {
                candidateFiles.Add(fileOrDirectoryPath);
            }
            else if (Directory.Exists(fileOrDirectoryPath))
            {
                EnumerationOptions options = new()
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = true,
                    AttributesToSkip = FileAttributes.ReparsePoint
                };

                // Prioriza arquivos que realmente acusarem trava ou amostra os primeiros N arquivos da pasta
                List<string> allSampled = [];
                foreach (string file in Directory.EnumerateFiles(fileOrDirectoryPath, "*", options))
                {
                    allSampled.Add(file);
                    if (IsFileLocked(file))
                    {
                        candidateFiles.Add(file);
                        if (candidateFiles.Count >= 10)
                        {
                            break;
                        }
                    }

                    if (allSampled.Count >= Math.Max(1, maxSampleFiles))
                    {
                        break;
                    }
                }

                if (candidateFiles.Count == 0 && allSampled.Count > 0)
                {
                    candidateFiles.AddRange(allSampled.Take(Math.Min(10, maxSampleFiles)));
                }
            }
        }
        catch
        {
            // Ignora falha ao coletar amostra
        }

        if (candidateFiles.Count == 0)
        {
            return [];
        }

        return QueryRestartManager(candidateFiles.ToArray(), fileOrDirectoryPath);
    }

    private static IReadOnlyList<LockingProcessInfo> QueryRestartManager(string[] resourcePaths, string referencePath)
    {
        int handle = RmInvalidSession;
        string sessionKey = Guid.NewGuid().ToString("N");
        List<LockingProcessInfo> results = [];
        HashSet<int> seenPids = [];

        try
        {
            int res = RmStartSession(out handle, 0, sessionKey);
            if (res != 0)
            {
                return [];
            }

            res = RmRegisterResources(handle, (uint)resourcePaths.Length, resourcePaths, 0, null, 0, null);
            if (res != 0)
            {
                return [];
            }

            uint pnProcInfoNeeded = 0;
            uint pnProcInfo = 0;
            uint lpdwRebootReasons = 0;

            res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);
            if (res == ErrorMoreData && pnProcInfoNeeded > 0)
            {
                RmProcessInfo[] processInfo = new RmProcessInfo[pnProcInfoNeeded];
                pnProcInfo = pnProcInfoNeeded;

                res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                if (res == 0)
                {
                    for (int i = 0; i < pnProcInfo; i++)
                    {
                        int pid = processInfo[i].Process.dwProcessId;
                        if (pid <= 0 || !seenPids.Add(pid))
                        {
                            continue;
                        }

                        string appTitle = processInfo[i].strAppName ?? string.Empty;
                        string procName = TryGetProcessNameById(pid) ?? appTitle;
                        if (string.IsNullOrWhiteSpace(procName))
                        {
                            procName = $"Processo {pid}";
                        }

                        results.Add(new LockingProcessInfo
                        {
                            ProcessId = pid,
                            ProcessName = procName,
                            ApplicationTitle = appTitle,
                            LockedFilePath = resourcePaths.Length == 1 ? resourcePaths[0] : referencePath
                        });
                    }
                }
            }
        }
        catch
        {
            // Se o Restart Manager não puder consultar, retorna lista vazia sem interromper o fluxo
        }
        finally
        {
            if (handle != RmInvalidSession)
            {
                _ = RmEndSession(handle);
            }
        }

        return results;
    }

    private static string? TryGetProcessNameById(int pid)
    {
        try
        {
            using Process proc = Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsLockErrorCode(IOException ex)
    {
        int code = ex.HResult & 0xFFFF;
        return code == ErrorSharingViolation || code == ErrorLockViolation;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RmUniqueProcess
    {
        public int dwProcessId;
        public FILETIME ProcessStartTime;
    }

    private enum RmAppType
    {
        RmUnknownApp = 0,
        RmMainWindow = 1,
        RmOtherWindow = 2,
        RmService = 3,
        RmExplorer = 4,
        RmConsole = 5,
        RmCritical = 1000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RmProcessInfo
    {
        public RmUniqueProcess Process;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CchRmMaxAppName + 1)]
        public string strAppName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CchRmMaxSvcName + 1)]
        public string strServiceShortName;

        public RmAppType ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;

        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out int pSessionHandle, int dwSessionFlags, string strSessionKey);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(int pSessionHandle);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(
        int pSessionHandle,
        uint nFiles,
        string[]? rgsFilenames,
        uint nApplications,
        [In] RmUniqueProcess[]? rgApplications,
        uint nServices,
        string[]? rgsServiceNames);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmGetList(
        int dwSessionHandle,
        out uint pnProcInfoNeeded,
        ref uint pnProcInfo,
        [In, Out] RmProcessInfo[]? rgAffectedApps,
        ref uint lpdwRebootReasons);
}

