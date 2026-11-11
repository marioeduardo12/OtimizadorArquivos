using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;
using Microsoft.Win32;

namespace DiskInspector.Infrastructure;

/// <summary>
/// Lixeira do Windows com garantia de reversibilidade.
///
/// A API clássica (SHFileOperation com "sem confirmação") exclui em definitivo, sem avisar, todo item que
/// não cabe na Lixeira. Aqui o envio usa IFileOperation com um observador que é consultado pelo Windows
/// antes de cada exclusão: se o item não for para a Lixeira, a operação é abortada e o item permanece intacto.
/// </summary>
public sealed class WindowsRecycleBin : IRecycleBin
{
    private const uint FofSilent = 0x0004;
    private const uint FofNoConfirmation = 0x0010;
    private const uint FofAllowUndo = 0x0040;
    private const uint FofNoConfirmMkDir = 0x0200;
    private const uint FofNoErrorUi = 0x0400;
    private const uint FofxRecycleOnDelete = 0x00080000;
    private const uint FofxAddUndoRecord = 0x20000000;

    private const uint FlagsNoUi = FofSilent | FofNoConfirmation | FofNoErrorUi | FofNoConfirmMkDir;

    // _TRANSFER_SOURCE_FLAGS: presente quando o Windows vai reciclar o item em vez de excluí-lo de vez
    private const uint TsfDeleteRecycleIfPossible = 0x00000080;

    private const int SOk = 0;
    private const int EAbort = unchecked((int)0x80004004);
    private const int EUnexpected = unchecked((int)0x8000FFFF);

    public RecycleBinStatus GetStatus(string anyPathOnVolume)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Unavailable("A Lixeira do Windows não existe neste sistema operacional.");
        }

        try
        {
            string full = Path.GetFullPath(anyPathOnVolume);
            if (full.StartsWith(@"\\", StringComparison.Ordinal) && !full.StartsWith(@"\\?\", StringComparison.Ordinal))
            {
                return Unavailable("Caminhos de rede não usam a Lixeira do Windows.");
            }

            string? root = Path.GetPathRoot(full);
            if (string.IsNullOrWhiteSpace(root))
            {
                return Unavailable("Não foi possível identificar o volume do caminho.");
            }

            DriveInfo drive = new(root);
            if (!drive.IsReady)
            {
                return Unavailable("A unidade não está pronta.");
            }

            if (drive.DriveType != DriveType.Fixed)
            {
                return Unavailable("Unidades removíveis ou de rede não usam a Lixeira do Windows.");
            }

            if (IsRecyclingDisabledByPolicy())
            {
                return Unavailable("A Lixeira está desativada por política do Windows.");
            }

            (long? capacityBytes, bool deleteImmediately) = ReadVolumeSettings(root, drive.TotalSize);
            if (deleteImmediately)
            {
                return Unavailable("A Lixeira deste volume está configurada para excluir os arquivos imediatamente.");
            }

            long usedBytes = 0;
            long itemCount = 0;
            if (Environment.Is64BitProcess)
            {
                ShQueryRbInfo info = new() { cbSize = (uint)Marshal.SizeOf<ShQueryRbInfo>() };
                if (SHQueryRecycleBinW(root, ref info) >= 0)
                {
                    usedBytes = Math.Max(0L, info.i64Size);
                    itemCount = Math.Max(0L, info.i64NumItems);
                }
            }

            return new RecycleBinStatus
            {
                IsAvailable = true,
                CapacityBytes = capacityBytes,
                UsedBytes = usedBytes,
                ItemCount = itemCount
            };
        }
        catch (Exception ex)
        {
            return Unavailable($"Não foi possível consultar a Lixeira: {ex.Message}");
        }
    }

    public RecycleAttemptResult SendToRecycleBin(string fullPath) =>
        RunOnStaThread(() => DeleteWithShell(fullPath, recycle: true));

    /// <summary>
    /// Somente para testes da guarda: pede ao Windows uma exclusão SEM Lixeira, mantendo a guarda ligada.
    /// O resultado esperado é a recusa da operação, com o arquivo intacto.
    /// </summary>
    internal RecycleAttemptResult AttemptDeleteWithoutRecycleFlagsForGuardTest(string fullPath) =>
        RunOnStaThread(() => DeleteWithShell(fullPath, recycle: false));

    public bool Empty(string? driveRoot, IntPtr ownerWindow)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            // Sem flags: o próprio Windows mostra a confirmação e o progresso ao usuário
            int hr = SHEmptyRecycleBinW(ownerWindow, string.IsNullOrWhiteSpace(driveRoot) ? null : driveRoot, 0);
            return hr >= 0 || hr == EUnexpected; // E_UNEXPECTED = a Lixeira já estava vazia
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Restaura itens da Lixeira do Windows ("Desfazer última limpeza") localizando os pares $I/$R
    /// em $Recycle.Bin\&lt;SID&gt; do volume correspondente e movendo cada item de volta ao caminho original.
    /// </summary>
    public RecycleRestoreResult RestoreItems(IEnumerable<string> originalFullPaths)
    {
        ArgumentNullException.ThrowIfNull(originalFullPaths);

        List<string> requested = originalFullPaths
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => Path.GetFullPath(p).TrimEnd('\\', '/'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (requested.Count == 0)
        {
            return new RecycleRestoreResult
            {
                TotalRequested = 0,
                TotalRestored = 0,
                BytesRestored = 0,
                RestoredPaths = [],
                NotFoundOrFailedMessages = []
            };
        }

        string? sid = TryGetCurrentUserSid();
        if (string.IsNullOrWhiteSpace(sid))
        {
            return new RecycleRestoreResult
            {
                TotalRequested = requested.Count,
                TotalRestored = 0,
                BytesRestored = 0,
                RestoredPaths = [],
                NotFoundOrFailedMessages = ["Não foi possível identificar o SID do usuário atual para inspecionar a Lixeira."]
            };
        }

        // Agrupa os caminhos solicitados por raiz de volume (C:\, D:\ etc.)
        List<string> restored = [];
        List<string> errors = [];
        long totalBytes = 0L;

        foreach (IGrouping<string, string> byVolume in requested.GroupBy(
                     p => Path.GetPathRoot(p) ?? string.Empty,
                     StringComparer.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(byVolume.Key))
            {
                continue;
            }

            string sidFolder = Path.Combine(byVolume.Key, "$Recycle.Bin", sid);
            RecycleRestoreResult partial = RestoreFromRecycleBinDirectory(sidFolder, byVolume);
            restored.AddRange(partial.RestoredPaths);
            errors.AddRange(partial.NotFoundOrFailedMessages);
            totalBytes += partial.BytesRestored;
        }

        return new RecycleRestoreResult
        {
            TotalRequested = requested.Count,
            TotalRestored = restored.Count,
            BytesRestored = totalBytes,
            RestoredPaths = restored,
            NotFoundOrFailedMessages = errors
        };
    }

    /// <summary>
    /// Restaura itens a partir de uma pasta de Lixeira no formato NTFS ($Ixxxxxx + $Rxxxxxx).
    /// Exposto internamente para permitir testes determinísticos em pastas temporárias isoladas.
    /// </summary>
    public static RecycleRestoreResult RestoreFromRecycleBinDirectory(
        string recycleBinSidDirectory,
        IEnumerable<string> originalFullPaths)
    {
        List<string> targets = originalFullPaths
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => p.TrimEnd('\\', '/'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        List<string> restored = [];
        List<string> failures = [];
        long bytesRestored = 0L;

        if (!Directory.Exists(recycleBinSidDirectory))
        {
            foreach (string target in targets)
            {
                failures.Add($"Pasta da Lixeira não encontrada para '{target}'.");
            }

            return new RecycleRestoreResult
            {
                TotalRequested = targets.Count,
                TotalRestored = 0,
                BytesRestored = 0,
                RestoredPaths = [],
                NotFoundOrFailedMessages = failures
            };
        }

        // Indexa todos os metadados $I* presentes na Lixeira (do mais recente para o mais antigo)
        Dictionary<string, List<RecycleBinEntryMetadata>> indexByOriginalPath = new(StringComparer.OrdinalIgnoreCase);
        try
        {
            EnumerationOptions enumOpts = new()
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = false,
                AttributesToSkip = 0
            };

            foreach (string iFile in Directory.EnumerateFiles(recycleBinSidDirectory, "$I*", enumOpts))
            {
                if (!TryParseRecycleBinMetadataFile(iFile, out RecycleBinEntryMetadata? meta) || meta is null)
                {
                    continue;
                }

                string normalizedOrig = meta.OriginalFullPath.TrimEnd('\\', '/');
                if (!indexByOriginalPath.TryGetValue(normalizedOrig, out List<RecycleBinEntryMetadata>? list))
                {
                    list = [];
                    indexByOriginalPath[normalizedOrig] = list;
                }

                list.Add(meta);
            }
        }
        catch (Exception ex)
        {
            failures.Add($"Erro ao ler índice da Lixeira: {ex.Message}");
        }

        foreach (string target in targets)
        {
            if (!indexByOriginalPath.TryGetValue(target, out List<RecycleBinEntryMetadata>? candidates) || candidates.Count == 0)
            {
                failures.Add($"Item não encontrado na Lixeira: '{target}' (pode já ter sido restaurado ou esvaziado).");
                continue;
            }

            // Escolhe a entrada excluída mais recentemente que ainda possua o correspondente $R no disco
            RecycleBinEntryMetadata? chosen = candidates
                .OrderByDescending(c => c.DeletedFileTime)
                .FirstOrDefault(c => File.Exists(c.DataPathR) || Directory.Exists(c.DataPathR));

            if (chosen is null)
            {
                failures.Add($"O conteúdo reciclado ($R) de '{target}' não está mais presente na Lixeira.");
                continue;
            }

            try
            {
                if (File.Exists(target) || Directory.Exists(target))
                {
                    failures.Add($"Já existe um item no destino original '{target}'; restauração ignorada para não sobrescrever.");
                    continue;
                }

                string? parentDir = Path.GetDirectoryName(target);
                if (!string.IsNullOrWhiteSpace(parentDir))
                {
                    Directory.CreateDirectory(parentDir);
                }

                if (Directory.Exists(chosen.DataPathR))
                {
                    Directory.Move(chosen.DataPathR, target);
                }
                else
                {
                    File.Move(chosen.DataPathR, target);
                }

                try
                {
                    File.Delete(chosen.MetadataPathI);
                }
                catch
                {
                    // Se o arquivo de metadados $I não puder ser apagado, o dado principal já foi restaurado com segurança
                }

                restored.Add(target);
                bytesRestored += Math.Max(0L, chosen.OriginalSizeBytes);
            }
            catch (Exception ex)
            {
                failures.Add($"Falha ao restaurar '{target}': {ex.Message}");
            }
        }

        return new RecycleRestoreResult
        {
            TotalRequested = targets.Count,
            TotalRestored = restored.Count,
            BytesRestored = bytesRestored,
            RestoredPaths = restored,
            NotFoundOrFailedMessages = failures
        };
    }

    /// <summary>
    /// Interpreta o cabeçalho binário de um arquivo $Ixxxxxx do Windows Vista/7/8/10/11.
    /// </summary>
    public static bool TryParseRecycleBinMetadataFile(string metadataFilePath, out RecycleBinEntryMetadata? metadata)
    {
        metadata = null;
        try
        {
            byte[] bytes = File.ReadAllBytes(metadataFilePath);
            if (bytes.Length < 28)
            {
                return false;
            }

            long version = BitConverter.ToInt64(bytes, 0);
            long originalSize = BitConverter.ToInt64(bytes, 8);
            long deletedFileTime = BitConverter.ToInt64(bytes, 16);
            string originalPath;

            if (version == 2)
            {
                int charCount = BitConverter.ToInt32(bytes, 24);
                if (charCount <= 0 || charCount > 32768 || 28 + (charCount * 2) > bytes.Length)
                {
                    return false;
                }

                originalPath = Encoding.Unicode.GetString(bytes, 28, charCount * 2).TrimEnd('\0');
            }
            else if (version == 1 && bytes.Length >= 24 + 520)
            {
                originalPath = Encoding.Unicode.GetString(bytes, 24, 520).Split('\0')[0];
            }
            else
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(originalPath))
            {
                return false;
            }

            string dir = Path.GetDirectoryName(metadataFilePath) ?? string.Empty;
            string iName = Path.GetFileName(metadataFilePath);
            if (!iName.StartsWith("$I", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string rPath = Path.Combine(dir, "$R" + iName[2..]);
            metadata = new RecycleBinEntryMetadata(metadataFilePath, rPath, originalPath, originalSize, deletedFileTime);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string? TryGetCurrentUserSid()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return identity.User?.Value;
        }
        catch
        {
            return null;
        }
    }

    public sealed record RecycleBinEntryMetadata(
        string MetadataPathI,
        string DataPathR,
        string OriginalFullPath,
        long OriginalSizeBytes,
        long DeletedFileTime);

    private static RecycleBinStatus Unavailable(string reason) => new()
    {
        IsAvailable = false,
        UnavailableReason = reason
    };

    private static RecycleAttemptResult RunOnStaThread(Func<RecycleAttemptResult> work)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Failure("A Lixeira do Windows não existe neste sistema operacional.", 0);
        }

        RecycleAttemptResult? result = null;
        Exception? failure = null;

        // IFileOperation só pode ser usado em apartamento de thread única (STA)
        Thread worker = new(() =>
        {
            try
            {
                result = work();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        })
        {
            IsBackground = true,
            Name = "DiskInspector.RecycleBin"
        };

        worker.SetApartmentState(ApartmentState.STA);
        worker.Start();
        worker.Join();

        if (failure is not null)
        {
            return Failure($"Falha ao acionar a Lixeira do Windows: {failure.Message}", failure.HResult);
        }

        return result ?? Failure("A operação de Lixeira não retornou resultado.", 0);
    }

    private static RecycleAttemptResult DeleteWithShell(string fullPath, bool recycle)
    {
        bool isDirectory = Directory.Exists(fullPath);
        if (!isDirectory && !File.Exists(fullPath))
        {
            return Failure("O item não existe mais no disco.", 0);
        }

        IFileOperation? operation = null;
        IShellItem? shellItem = null;
        try
        {
            operation = (IFileOperation)new FileOperationComObject();

            uint flags = FlagsNoUi;
            if (recycle)
            {
                flags |= FofAllowUndo | FofxRecycleOnDelete | FofxAddUndoRecord;
            }

            int hr = operation.SetOperationFlags(flags);
            if (hr < 0)
            {
                return Failure($"O Windows recusou a configuração da operação (0x{hr:X8}).", hr);
            }

            Guid shellItemId = typeof(IShellItem).GUID;
            hr = SHCreateItemFromParsingName(fullPath, IntPtr.Zero, ref shellItemId, out shellItem);
            if (hr < 0 || shellItem is null)
            {
                return Failure($"O Windows não conseguiu localizar o item para a Lixeira (0x{hr:X8}).", hr);
            }

            RecycleGuardSink guard = new();
            hr = operation.Advise(guard, out uint cookie);
            if (hr < 0)
            {
                return Failure($"Não foi possível acompanhar a operação de Lixeira (0x{hr:X8}); nada foi removido.", hr);
            }

            try
            {
                hr = operation.DeleteItem(shellItem, IntPtr.Zero);
                if (hr < 0)
                {
                    return Failure($"O Windows recusou o item (0x{hr:X8}).", hr);
                }

                int performHr = operation.PerformOperations();
                operation.GetAnyOperationsAborted(out bool anyAborted);

                if (guard.RefusedPermanentDelete)
                {
                    return new RecycleAttemptResult
                    {
                        Succeeded = false,
                        ConfirmedRecycled = false,
                        Message = "O Windows excluiria este item em definitivo (ele não cabe ou não pode ir para a Lixeira). A operação foi recusada e o item permanece no lugar.",
                        HResult = EAbort
                    };
                }

                bool stillExists = isDirectory ? Directory.Exists(fullPath) : File.Exists(fullPath);
                bool deleteSucceeded = performHr >= 0 && !anyAborted && guard.DeleteHResult >= 0 && !stillExists;

                if (!deleteSucceeded)
                {
                    int reported = guard.DeleteHResult < 0 ? guard.DeleteHResult : performHr;
                    return Failure(DescribeFailure(reported, stillExists), reported);
                }

                return new RecycleAttemptResult
                {
                    Succeeded = true,
                    ConfirmedRecycled = guard.SawRecycleFlag || guard.RecycledItemCreated,
                    Message = "Movido para a Lixeira do Windows.",
                    HResult = SOk
                };
            }
            finally
            {
                operation.Unadvise(cookie);
            }
        }
        finally
        {
            if (shellItem is not null)
            {
                Marshal.FinalReleaseComObject(shellItem);
            }

            if (operation is not null)
            {
                Marshal.FinalReleaseComObject(operation);
            }
        }
    }

    private static string DescribeFailure(int hr, bool stillExists)
    {
        string detail = (uint)hr switch
        {
            0x80070020 or 0x80270021 => "há arquivos em uso por outro programa",
            0x80070005 or 0x80270022 => "acesso negado",
            0x80270000 => "a operação foi cancelada",
            _ => $"código 0x{hr:X8}"
        };

        return stillExists
            ? $"Não foi possível mover para a Lixeira ({detail}). O item permanece intacto."
            : $"O Windows relatou um problema ao mover para a Lixeira ({detail}).";
    }

    private static RecycleAttemptResult Failure(string message, int hr) => new()
    {
        Succeeded = false,
        ConfirmedRecycled = false,
        Message = message,
        HResult = hr
    };

    private static bool IsRecyclingDisabledByPolicy()
    {
        const string policyPath = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
        return ReadDword(Registry.CurrentUser, policyPath, "NoRecycleFiles") == 1 ||
               ReadDword(Registry.LocalMachine, policyPath, "NoRecycleFiles") == 1;
    }

    /// <summary>
    /// Lê o tamanho máximo e a opção "não mover para a Lixeira" configurados para o volume.
    /// Sem configuração gravada, usa o padrão do Windows: 10% dos primeiros 40 GB e 5% do restante.
    /// </summary>
    private static (long? CapacityBytes, bool DeleteImmediately) ReadVolumeSettings(string driveRoot, long volumeTotalBytes)
    {
        string? volumeGuid = TryGetVolumeGuid(driveRoot);
        if (volumeGuid is not null)
        {
            string keyPath = $@"Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{volumeGuid}";
            int? nuke = ReadDword(Registry.CurrentUser, keyPath, "NukeOnDelete");
            int? maxCapacityMb = ReadDword(Registry.CurrentUser, keyPath, "MaxCapacity");

            if (nuke == 1)
            {
                return (null, true);
            }

            if (maxCapacityMb is > 0)
            {
                return (maxCapacityMb.Value * 1024L * 1024L, false);
            }
        }

        if (volumeTotalBytes <= 0)
        {
            return (null, false);
        }

        const long fortyGb = 40L * 1024 * 1024 * 1024;
        long defaultCapacity = volumeTotalBytes <= fortyGb
            ? volumeTotalBytes / 10
            : (fortyGb / 10) + ((volumeTotalBytes - fortyGb) / 20);

        return (defaultCapacity, false);
    }

    private static string? TryGetVolumeGuid(string driveRoot)
    {
        try
        {
            string mountPoint = driveRoot.EndsWith('\\') ? driveRoot : driveRoot + "\\";
            StringBuilder buffer = new(64);
            if (!GetVolumeNameForVolumeMountPointW(mountPoint, buffer, (uint)buffer.Capacity))
            {
                return null;
            }

            // Formato: \\?\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\
            string name = buffer.ToString();
            int open = name.IndexOf('{');
            int close = name.IndexOf('}');
            return open >= 0 && close > open ? name[open..(close + 1)] : null;
        }
        catch
        {
            return null;
        }
    }

    private static int? ReadDword(RegistryKey hive, string keyPath, string valueName)
    {
        try
        {
            using RegistryKey? key = hive.OpenSubKey(keyPath, writable: false);
            return key?.GetValue(valueName) is int value ? value : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Observador consultado pelo Windows antes e depois de cada exclusão.
    /// </summary>
    [ComVisible(true)]
    private sealed class RecycleGuardSink : IFileOperationProgressSink
    {
        public bool SawRecycleFlag { get; private set; }
        public bool RecycledItemCreated { get; private set; }
        public bool RefusedPermanentDelete { get; private set; }
        public int DeleteHResult { get; private set; } = SOk;

        public int StartOperations() => SOk;

        public int FinishOperations(int hrResult) => SOk;

        public int PreRenameItem(uint dwFlags, IntPtr psiItem, IntPtr pszNewName) => SOk;

        public int PostRenameItem(uint dwFlags, IntPtr psiItem, IntPtr pszNewName, int hrRename, IntPtr psiNewlyCreated) => SOk;

        public int PreMoveItem(uint dwFlags, IntPtr psiItem, IntPtr psiDestinationFolder, IntPtr pszNewName) => SOk;

        public int PostMoveItem(uint dwFlags, IntPtr psiItem, IntPtr psiDestinationFolder, IntPtr pszNewName, int hrMove, IntPtr psiNewlyCreated) => SOk;

        public int PreCopyItem(uint dwFlags, IntPtr psiItem, IntPtr psiDestinationFolder, IntPtr pszNewName) => SOk;

        public int PostCopyItem(uint dwFlags, IntPtr psiItem, IntPtr psiDestinationFolder, IntPtr pszNewName, int hrCopy, IntPtr psiNewlyCreated) => SOk;

        public int PreDeleteItem(uint dwFlags, IntPtr psiItem)
        {
            if ((dwFlags & TsfDeleteRecycleIfPossible) != 0)
            {
                SawRecycleFlag = true;
                return SOk;
            }

            // O Windows está prestes a excluir em definitivo: aborta antes que algo seja removido
            RefusedPermanentDelete = true;
            return EAbort;
        }

        public int PostDeleteItem(uint dwFlags, IntPtr psiItem, int hrDelete, IntPtr psiNewlyCreated)
        {
            if (hrDelete < 0)
            {
                DeleteHResult = hrDelete;
            }

            if (psiNewlyCreated != IntPtr.Zero)
            {
                // O Windows devolve o item recém-criado dentro da Lixeira: confirmação positiva
                RecycledItemCreated = true;
            }

            return SOk;
        }

        public int PreNewItem(uint dwFlags, IntPtr psiDestinationFolder, IntPtr pszNewName) => SOk;

        public int PostNewItem(uint dwFlags, IntPtr psiDestinationFolder, IntPtr pszNewName, IntPtr pszTemplateName, uint dwFileAttributes, int hrNew, IntPtr psiNewItem) => SOk;

        public int UpdateProgress(uint iWorkTotal, uint iWorkSoFar) => SOk;

        public int ResetTimer() => SOk;

        public int PauseTimer() => SOk;

        public int ResumeTimer() => SOk;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ShQueryRbInfo
    {
        public uint cbSize;
        public long i64Size;
        public long i64NumItems;
    }

    [ComImport]
    [Guid("3ad05575-8857-4850-9277-11b85bdb8e09")]
    private class FileOperationComObject
    {
    }

    [ComImport]
    [Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItem
    {
        [PreserveSig]
        int BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);

        [PreserveSig]
        int GetParent(out IntPtr ppsi);

        [PreserveSig]
        int GetDisplayName(uint sigdnName, out IntPtr ppszName);

        [PreserveSig]
        int GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);

        [PreserveSig]
        int Compare(IntPtr psi, uint hint, out int piOrder);
    }

    // A ordem dos métodos reproduz exatamente a tabela virtual de IFileOperation (shobjidl_core.h)
    [ComImport]
    [Guid("947aab5f-0a5c-4c13-b4d6-4bf7836fc9f8")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IFileOperation
    {
        [PreserveSig]
        int Advise(IFileOperationProgressSink pfops, out uint pdwCookie);

        [PreserveSig]
        int Unadvise(uint dwCookie);

        [PreserveSig]
        int SetOperationFlags(uint dwOperationFlags);

        [PreserveSig]
        int SetProgressMessage(IntPtr pszMessage);

        [PreserveSig]
        int SetProgressDialog(IntPtr popd);

        [PreserveSig]
        int SetProperties(IntPtr pproparray);

        [PreserveSig]
        int SetOwnerWindow(IntPtr hwndOwner);

        [PreserveSig]
        int ApplyPropertiesToItem(IntPtr psiItem);

        [PreserveSig]
        int ApplyPropertiesToItems(IntPtr punkItems);

        [PreserveSig]
        int RenameItem(IntPtr psiItem, IntPtr pszNewName, IntPtr pfopsItem);

        [PreserveSig]
        int RenameItems(IntPtr pUnkItems, IntPtr pszNewName);

        [PreserveSig]
        int MoveItem(IntPtr psiItem, IntPtr psiDestinationFolder, IntPtr pszNewName, IntPtr pfopsItem);

        [PreserveSig]
        int MoveItems(IntPtr punkItems, IntPtr psiDestinationFolder);

        [PreserveSig]
        int CopyItem(IntPtr psiItem, IntPtr psiDestinationFolder, IntPtr pszCopyName, IntPtr pfopsItem);

        [PreserveSig]
        int CopyItems(IntPtr punkItems, IntPtr psiDestinationFolder);

        [PreserveSig]
        int DeleteItem(IShellItem psiItem, IntPtr pfopsItem);

        [PreserveSig]
        int DeleteItems(IntPtr punkItems);

        [PreserveSig]
        int NewItem(IntPtr psiDestinationFolder, uint dwFileAttributes, IntPtr pszName, IntPtr pszTemplateName, IntPtr pfopsItem);

        [PreserveSig]
        int PerformOperations();

        [PreserveSig]
        int GetAnyOperationsAborted([MarshalAs(UnmanagedType.Bool)] out bool pfAnyOperationsAborted);
    }

    // A ordem dos métodos reproduz exatamente a tabela virtual de IFileOperationProgressSink
    [ComImport]
    [Guid("04b0f1a7-9490-44bc-96e1-4296a31252e2")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IFileOperationProgressSink
    {
        [PreserveSig]
        int StartOperations();

        [PreserveSig]
        int FinishOperations(int hrResult);

        [PreserveSig]
        int PreRenameItem(uint dwFlags, IntPtr psiItem, IntPtr pszNewName);

        [PreserveSig]
        int PostRenameItem(uint dwFlags, IntPtr psiItem, IntPtr pszNewName, int hrRename, IntPtr psiNewlyCreated);

        [PreserveSig]
        int PreMoveItem(uint dwFlags, IntPtr psiItem, IntPtr psiDestinationFolder, IntPtr pszNewName);

        [PreserveSig]
        int PostMoveItem(uint dwFlags, IntPtr psiItem, IntPtr psiDestinationFolder, IntPtr pszNewName, int hrMove, IntPtr psiNewlyCreated);

        [PreserveSig]
        int PreCopyItem(uint dwFlags, IntPtr psiItem, IntPtr psiDestinationFolder, IntPtr pszNewName);

        [PreserveSig]
        int PostCopyItem(uint dwFlags, IntPtr psiItem, IntPtr psiDestinationFolder, IntPtr pszNewName, int hrCopy, IntPtr psiNewlyCreated);

        [PreserveSig]
        int PreDeleteItem(uint dwFlags, IntPtr psiItem);

        [PreserveSig]
        int PostDeleteItem(uint dwFlags, IntPtr psiItem, int hrDelete, IntPtr psiNewlyCreated);

        [PreserveSig]
        int PreNewItem(uint dwFlags, IntPtr psiDestinationFolder, IntPtr pszNewName);

        [PreserveSig]
        int PostNewItem(uint dwFlags, IntPtr psiDestinationFolder, IntPtr pszNewName, IntPtr pszTemplateName, uint dwFileAttributes, int hrNew, IntPtr psiNewItem);

        [PreserveSig]
        int UpdateProgress(uint iWorkTotal, uint iWorkSoFar);

        [PreserveSig]
        int ResetTimer();

        [PreserveSig]
        int PauseTimer();

        [PreserveSig]
        int ResumeTimer();
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SHCreateItemFromParsingName(
        [MarshalAs(UnmanagedType.LPWStr)] string pszPath,
        IntPtr pbc,
        ref Guid riid,
        [MarshalAs(UnmanagedType.Interface)] out IShellItem? ppv);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SHQueryRecycleBinW(string? pszRootPath, ref ShQueryRbInfo pSHQueryRBInfo);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SHEmptyRecycleBinW(IntPtr hwnd, string? pszRootPath, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPointW(
        string lpszVolumeMountPoint,
        StringBuilder lpszVolumeName,
        uint cchBufferLength);
}
