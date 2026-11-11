using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DiskInspector.Infrastructure;

/// <summary>
/// Interoperabilidade nativa Win32 para cálculo preciso de espaço alocado em disco,
/// detecção de arquivos esparsos, compressão NTFS, placeholders de nuvem, reparse points e hard links (Seção 9).
/// </summary>
public static class NativeDiskInterop
{
    private const uint InvalidFileSize = 0xFFFFFFFF;
    private const int NoError = 0;
    private const uint FileShareAll = 0x00000001 | 0x00000002 | 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;

    // Atributos de arquivos sob demanda (OneDrive / Cloud Filter API)
    private const int FileAttributeOffline = 0x00001000;
    private const int FileAttributeRecallOnOpen = 0x00040000;
    private const int FileAttributePinned = 0x00080000;
    private const int FileAttributeUnpinned = 0x00100000;
    private const int FileAttributeRecallOnDataAccess = 0x00400000;

    private const long DefaultClusterSize = 4096L;

    /// <summary>
    /// Normaliza um caminho para suportar caminhos longos (>260 caracteres) no Windows via prefixo \\?\.
    /// </summary>
    public static string ToLongPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return path;
        }

        if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            return path;
        }

        string full = Path.GetFullPath(path);
        if (full.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return @"\\?\UNC\" + full.TrimStart('\\');
        }

        return @"\\?\" + full;
    }

    /// <summary>
    /// Verifica se os atributos indicam um placeholder de nuvem não hidratado (ex.: OneDrive online-only).
    /// </summary>
    public static bool IsCloudPlaceholder(FileAttributes attributes)
    {
        int raw = (int)attributes;
        return (raw & FileAttributeRecallOnDataAccess) != 0 ||
               (raw & FileAttributeRecallOnOpen) != 0 ||
               (raw & FileAttributeOffline) != 0 ||
               ((raw & FileAttributeUnpinned) != 0 && (raw & FileAttributePinned) == 0);
    }

    /// <summary>
    /// Calcula o espaço efetivamente alocado em disco (AllocatedSizeBytes) vs tamanho lógico.
    /// Trata arquivos esparsos, comprimidos pelo NTFS, placeholders de nuvem e arredondamento de cluster.
    /// </summary>
    public static long GetAllocatedDiskSize(string fullPath, long logicalSize, FileAttributes attributes)
    {
        if (logicalSize <= 0)
        {
            return 0L;
        }

        bool hasSpecialAllocation =
            (attributes & FileAttributes.SparseFile) != 0 ||
            (attributes & FileAttributes.Compressed) != 0 ||
            (attributes & FileAttributes.ReparsePoint) != 0 ||
            IsCloudPlaceholder(attributes);

        if (OperatingSystem.IsWindows() && (hasSpecialAllocation || logicalSize >= 65536))
        {
            long? nativeAllocated = TryGetCompressedFileSizeNative(fullPath);
            if (nativeAllocated.HasValue)
            {
                return nativeAllocated.Value;
            }
        }

        if (IsCloudPlaceholder(attributes))
        {
            return 0L;
        }

        // Em NTFS, arquivos muito pequenos (<= 512 bytes) frequentemente residem direto na MFT (0 clusters extras),
        // enquanto os demais ocupam múltiplos do tamanho do cluster (4 KB padrão).
        if (logicalSize <= 512)
        {
            return logicalSize;
        }

        long remainder = logicalSize % DefaultClusterSize;
        return remainder == 0
            ? logicalSize
            : logicalSize + (DefaultClusterSize - remainder);
    }

    /// <summary>
    /// Consulta diretamente a API Win32 GetCompressedFileSizeW com suporte a caminhos longos.
    /// </summary>
    public static long? TryGetCompressedFileSizeNative(string fullPath)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            string longPath = ToLongPath(fullPath);
            uint low = GetCompressedFileSizeW(longPath, out uint high);
            if (low == InvalidFileSize)
            {
                int err = Marshal.GetLastWin32Error();
                if (err != NoError)
                {
                    return null;
                }
            }

            return ((long)high << 32) | low;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Obtém a contagem de hard links NTFS e o identificador único de arquivo (64-bit FileId)
    /// sem abrir acesso de leitura/escrita de dados (dwDesiredAccess = 0), evitando bloqueios
    /// e evitando hidratar arquivos em nuvem.
    /// </summary>
    public static bool TryGetHardLinkInfo(string fullPath, out uint linkCount, out ulong fileId, out uint volumeSerialNumber)
    {
        linkCount = 1;
        fileId = 0;
        volumeSerialNumber = 0;

        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            string longPath = ToLongPath(fullPath);
            using SafeFileHandle handle = CreateFileW(
                longPath,
                0, // Zero access = consulta apenas metadados sem abrir conteúdo
                FileShareAll,
                IntPtr.Zero,
                OpenExisting,
                FileFlagOpenReparsePoint | FileFlagBackupSemantics,
                IntPtr.Zero);

            if (handle.IsInvalid)
            {
                return false;
            }

            if (!GetFileInformationByHandle(handle, out BY_HANDLE_FILE_INFORMATION info))
            {
                return false;
            }

            linkCount = info.nNumberOfLinks;
            fileId = ((ulong)info.nFileIndexHigh << 32) | info.nFileIndexLow;
            volumeSerialNumber = info.dwVolumeSerialNumber;
            return true;
        }
        catch
        {
            return false;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint dwFileAttributes;
        public FILETIME ftCreationTime;
        public FILETIME ftLastAccessTime;
        public FILETIME ftLastWriteTime;
        public uint dwVolumeSerialNumber;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint nNumberOfLinks;
        public uint nFileIndexHigh;
        public uint nFileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern uint GetCompressedFileSizeW(string lpFileName, out uint lpFileSizeHigh);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile,
        out BY_HANDLE_FILE_INFORMATION lpFileInformation);
}

