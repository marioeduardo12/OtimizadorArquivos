using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using DiskInspector.Core.Formatting;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Cleanup;

/// <summary>
/// Executor controlado de comandos oficiais de limpeza de ferramentas de desenvolvimento (Diferencial 4)
/// e de otimizações não-destrutivas sem apagar arquivos (Diferencial 6), com medição de espaço antes e depois
/// e transmissão de progresso em tempo real para a interface.
/// </summary>
public sealed class OfficialMaintenanceExecutor : IOfficialMaintenanceExecutor
{
    public delegate Task<(int ExitCode, string StdOut, string StdErr)> ProcessRunnerDelegate(
        string fileName,
        string arguments,
        string workingDirectory,
        CancellationToken cancellationToken);

    private readonly IOperationHistoryRepository _historyRepository;
    private readonly ProcessRunnerDelegate? _customProcessRunner;

    public OfficialMaintenanceExecutor(
        IOperationHistoryRepository historyRepository,
        ProcessRunnerDelegate? customProcessRunner = null)
    {
        _historyRepository = historyRepository;
        _customProcessRunner = customProcessRunner;
    }

    public bool CanExecuteCommand(string? officialCommand, string? targetPath, out string executableActionDescription)
    {
        executableActionDescription = string.Empty;
        if (string.IsNullOrWhiteSpace(officialCommand))
        {
            return false;
        }

        return TryResolveWhitelistedCommand(officialCommand, targetPath, out _, out _, out _, out executableActionDescription);
    }

    public async Task<OfficialCommandExecutionResult> ExecuteOfficialCommandAsync(
        string officialCommand,
        string targetPath,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        if (!TryResolveWhitelistedCommand(
                officialCommand,
                targetPath,
                out string fileName,
                out string arguments,
                out string workingDir,
                out string description))
        {
            return new OfficialCommandExecutionResult
            {
                CommandExecuted = officialCommand,
                TargetPath = targetPath,
                Succeeded = false,
                ExitCode = -1,
                BytesBefore = 0,
                BytesAfter = 0,
                Duration = TimeSpan.Zero,
                StandardOutput = string.Empty,
                StandardError = "Este comando é apenas orientativo ou exige execução manual pelo painel do Windows.",
                SummaryMessage = "Comando não habilitado para execução automática em 1 clique."
            };
        }

        Stopwatch sw = Stopwatch.StartNew();
        progress?.Report($"Etapa 1/3: Medindo tamanho atual de '{Path.GetFileName(targetPath.TrimEnd('\\', '/'))}' antes da execução...");
        long bytesBefore = await Task.Run(() => MeasurePathBytes(targetPath, useAllocatedSize: false), cancellationToken);

        progress?.Report($"Etapa 2/3: Executando '{officialCommand}' ({description})...");
        (int exitCode, string stdOut, string stdErr) = await RunCommandAsync(
            fileName,
            arguments,
            workingDir,
            allowElevationFallback: false,
            progress,
            cancellationToken);

        progress?.Report($"Etapa 3/3: Medindo espaço ocupado após '{officialCommand}'...");
        long bytesAfter = await Task.Run(() => MeasurePathBytes(targetPath, useAllocatedSize: false), cancellationToken);
        sw.Stop();

        long freed = Math.Max(0L, bytesBefore - bytesAfter);
        bool succeeded = exitCode == 0;
        string summary = succeeded
            ? $"{description}: concluído em {sw.Elapsed.TotalSeconds:0.0}s — liberado {ByteSizeFormatter.FormatBytes(freed)} (antes: {ByteSizeFormatter.FormatBytes(bytesBefore)} → depois: {ByteSizeFormatter.FormatBytes(bytesAfter)})."
            : $"{description}: código de saída {exitCode}. {(string.IsNullOrWhiteSpace(stdErr) ? stdOut : stdErr)}";

        _historyRepository.RecordOperation(new OperationLogEntry
        {
            Id = Guid.NewGuid(),
            TimestampUtc = DateTime.UtcNow,
            OperationType = "Comando Oficial (1 Clique)",
            TargetPath = string.IsNullOrWhiteSpace(targetPath) ? workingDir : targetPath,
            Summary = summary,
            AffectedBytes = freed,
            Succeeded = succeeded,
            Details = $"Comando: {officialCommand} | Antes: {ByteSizeFormatter.FormatBytes(bytesBefore)} | Depois: {ByteSizeFormatter.FormatBytes(bytesAfter)} | Saída: {TruncateOutput(stdOut, 240)}"
        });

        return new OfficialCommandExecutionResult
        {
            CommandExecuted = officialCommand,
            TargetPath = targetPath,
            Succeeded = succeeded,
            ExitCode = exitCode,
            BytesBefore = bytesBefore,
            BytesAfter = bytesAfter,
            Duration = sw.Elapsed,
            StandardOutput = stdOut,
            StandardError = stdErr,
            SummaryMessage = summary
        };
    }

    public async Task<OfficialCommandExecutionResult> ExecuteNonDestructiveOptionAsync(
        NonDestructiveOption option,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(option);

        Stopwatch sw = Stopwatch.StartNew();
        string targetPath = option.TargetPath;
        progress?.Report($"Etapa 1/3: Medindo espaço físico alocado em '{Path.GetFileName(targetPath.TrimEnd('\\', '/'))}' antes da otimização...");
        long bytesBefore = await Task.Run(() => MeasurePathBytes(targetPath, useAllocatedSize: true), cancellationToken);

        int exitCode;
        string stdOut;
        string stdErr;

        if (string.Equals(option.ActionKind, "CompactacaoNtfs", StringComparison.OrdinalIgnoreCase))
        {
            progress?.Report($"Etapa 2/3: Aplicando compressão transparente NTFS (compact.exe) em '{option.Title}'...");
            string workingDir = Directory.Exists(targetPath) ? targetPath : (Path.GetDirectoryName(targetPath) ?? Environment.CurrentDirectory);
            (exitCode, stdOut, stdErr) = await RunCommandAsync(
                "compact.exe",
                $"/C /S:\"{targetPath}\" /I /Q",
                workingDir,
                allowElevationFallback: false,
                progress,
                cancellationToken);
        }
        else if (string.Equals(option.ActionKind, "OneDriveFilesOnDemand", StringComparison.OrdinalIgnoreCase))
        {
            progress?.Report($"Etapa 2/3: Liberando cache físico local do OneDrive (Arquivos Sob Demanda: attrib +U -P)...");
            string workingDir = Directory.Exists(targetPath) ? targetPath : Environment.CurrentDirectory;
            (exitCode, stdOut, stdErr) = await RunCommandAsync(
                "attrib.exe",
                $"+U -P \"{targetPath.TrimEnd('\\')}\\*\" /S /D",
                workingDir,
                allowElevationFallback: false,
                progress,
                cancellationToken);
        }
        else if (string.Equals(option.ActionKind, "CompactacaoVhdx", StringComparison.OrdinalIgnoreCase))
        {
            progress?.Report("Etapa 2/4: Encerrando instâncias ativas do WSL2 (wsl --shutdown) para liberar o disco virtual...");
            string workingDir = Path.GetDirectoryName(targetPath) ?? Environment.CurrentDirectory;
            await RunCommandAsync("wsl.exe", "--shutdown", workingDir, allowElevationFallback: false, progress, cancellationToken);

            string tempScript = Path.Combine(Path.GetTempPath(), $"diskinspector_vhdx_{Guid.NewGuid():N}.txt");
            try
            {
                // Sem "exit" explícito ao final para que o diskpart propague código de erro caso attach/compact falhe
                await File.WriteAllLinesAsync(
                    tempScript,
                    [
                        $"select vdisk file=\"{targetPath}\"",
                        "attach vdisk readonly",
                        "compact vdisk",
                        "detach vdisk"
                    ],
                    cancellationToken);

                progress?.Report($"Etapa 3/4: Compactando blocos vazios de '{Path.GetFileName(targetPath)}' via diskpart (confirme o UAC se solicitado)...");
                (exitCode, stdOut, stdErr) = await RunCommandAsync(
                    "diskpart.exe",
                    $"/s \"{tempScript}\"",
                    workingDir,
                    allowElevationFallback: true,
                    progress,
                    cancellationToken);
            }
            finally
            {
                try
                {
                    if (File.Exists(tempScript))
                    {
                        File.Delete(tempScript);
                    }
                }
                catch
                {
                    // Ignora falha ao apagar script temporário
                }
            }
        }
        else
        {
            return new OfficialCommandExecutionResult
            {
                CommandExecuted = option.OfficialCommand,
                TargetPath = targetPath,
                Succeeded = false,
                ExitCode = -1,
                BytesBefore = bytesBefore,
                BytesAfter = bytesBefore,
                Duration = TimeSpan.Zero,
                StandardOutput = string.Empty,
                StandardError = $"Tipo de otimização desconhecido: {option.ActionKind}",
                SummaryMessage = "Otimização não suportada."
            };
        }

        progress?.Report($"Etapa final: Medindo espaço físico alocado em '{Path.GetFileName(targetPath.TrimEnd('\\', '/'))}' após a otimização...");
        long bytesAfter = await Task.Run(() => MeasurePathBytes(targetPath, useAllocatedSize: true), cancellationToken);
        sw.Stop();

        long freed = Math.Max(0L, bytesBefore - bytesAfter);
        bool succeeded = exitCode == 0;
        string summary;
        if (!succeeded)
        {
            summary = $"{option.Title}: não concluído (código {exitCode}). {(string.IsNullOrWhiteSpace(stdErr) ? stdOut : stdErr)}";
        }
        else if (freed == 0 && string.Equals(option.ActionKind, "CompactacaoVhdx", StringComparison.OrdinalIgnoreCase))
        {
            summary = $"{option.Title}: concluído em {sw.Elapsed.TotalSeconds:0.0}s — o arquivo .vhdx já estava sem blocos vazios livres ({ByteSizeFormatter.FormatBytes(bytesAfter)}). Dica: se o Docker Desktop estiver aberto, feche-o no ícone da bandeja ou rode 'docker system prune' antes de compactar.";
        }
        else
        {
            summary = $"{option.Title}: concluído em {sw.Elapsed.TotalSeconds:0.0}s — liberado {ByteSizeFormatter.FormatBytes(freed)} sem apagar nenhum arquivo (antes: {ByteSizeFormatter.FormatBytes(bytesBefore)} → depois: {ByteSizeFormatter.FormatBytes(bytesAfter)}).";
        }

        _historyRepository.RecordOperation(new OperationLogEntry
        {
            Id = Guid.NewGuid(),
            TimestampUtc = DateTime.UtcNow,
            OperationType = "Otimização Sem Apagar",
            TargetPath = targetPath,
            Summary = summary,
            AffectedBytes = freed,
            Succeeded = succeeded,
            Details = $"Ação: {option.ActionKind} | Comando: {option.OfficialCommand} | Antes: {ByteSizeFormatter.FormatBytes(bytesBefore)} | Depois: {ByteSizeFormatter.FormatBytes(bytesAfter)} | Saída: {TruncateOutput(stdOut, 200)}"
        });

        return new OfficialCommandExecutionResult
        {
            CommandExecuted = option.OfficialCommand,
            TargetPath = targetPath,
            Succeeded = succeeded,
            ExitCode = exitCode,
            BytesBefore = bytesBefore,
            BytesAfter = bytesAfter,
            Duration = sw.Elapsed,
            StandardOutput = stdOut,
            StandardError = stdErr,
            SummaryMessage = summary
        };
    }

    private Task<(int ExitCode, string StdOut, string StdErr)> RunCommandAsync(
        string fileName,
        string arguments,
        string workingDirectory,
        bool allowElevationFallback,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        if (_customProcessRunner is not null)
        {
            return _customProcessRunner(fileName, arguments, workingDirectory, cancellationToken);
        }

        return Task.Run(
            () => RunProcessWithLiveProgressAsync(fileName, arguments, workingDirectory, allowElevationFallback, progress, cancellationToken),
            cancellationToken);
    }

    private static bool TryResolveWhitelistedCommand(
        string officialCommand,
        string? targetPath,
        out string fileName,
        out string arguments,
        out string workingDirectory,
        out string description)
    {
        fileName = string.Empty;
        arguments = string.Empty;
        workingDirectory = ResolveSafeWorkingDirectory(targetPath);
        description = string.Empty;

        string normalized = officialCommand.Trim();

        if (normalized.Equals("npm cache clean --force", StringComparison.OrdinalIgnoreCase))
        {
            fileName = "cmd.exe";
            arguments = "/c npm cache clean --force";
            description = "Limpar cache global do npm";
            return true;
        }

        if (normalized.Equals("pnpm store prune", StringComparison.OrdinalIgnoreCase))
        {
            fileName = "cmd.exe";
            arguments = "/c pnpm store prune";
            description = "Podar pacotes órfãos do pnpm store";
            return true;
        }

        if (normalized.Equals("yarn cache clean", StringComparison.OrdinalIgnoreCase))
        {
            fileName = "cmd.exe";
            arguments = "/c yarn cache clean";
            description = "Limpar cache global do Yarn";
            return true;
        }

        if (normalized.Equals("pip cache purge", StringComparison.OrdinalIgnoreCase))
        {
            fileName = "cmd.exe";
            arguments = "/c pip cache purge";
            description = "Limpar cache de pacotes Python (pip)";
            return true;
        }

        if (normalized.Equals("composer clear-cache", StringComparison.OrdinalIgnoreCase))
        {
            fileName = "cmd.exe";
            arguments = "/c composer clear-cache";
            description = "Limpar cache global do Composer (PHP)";
            return true;
        }

        if (normalized.Equals("dotnet nuget locals all --clear", StringComparison.OrdinalIgnoreCase))
        {
            fileName = "dotnet";
            arguments = "nuget locals all --clear";
            description = "Limpar todos os caches locais do NuGet (.NET)";
            return true;
        }

        if (normalized.Equals("dotnet nuget locals http-cache --clear", StringComparison.OrdinalIgnoreCase))
        {
            fileName = "dotnet";
            arguments = "nuget locals http-cache --clear";
            description = "Limpar cache HTTP do NuGet (.NET)";
            return true;
        }

        if (normalized.StartsWith("docker builder prune", StringComparison.OrdinalIgnoreCase))
        {
            fileName = "docker";
            arguments = "builder prune -f";
            description = "Limpar cache de camadas de build do Docker (BuildKit)";
            return true;
        }

        if (normalized.Equals("dotnet clean", StringComparison.OrdinalIgnoreCase))
        {
            fileName = "dotnet";
            arguments = "clean";
            workingDirectory = ResolveProjectParentDirectory(targetPath, ["bin", "obj"]);
            description = "Limpar artefatos de compilação .NET (dotnet clean)";
            return true;
        }

        if (normalized.Equals("cargo clean", StringComparison.OrdinalIgnoreCase))
        {
            fileName = "cargo";
            arguments = "clean";
            workingDirectory = ResolveProjectParentDirectory(targetPath, ["target"]);
            description = "Limpar diretório target/ do projeto Rust (cargo clean)";
            return true;
        }

        if (normalized.Equals("gradle clean", StringComparison.OrdinalIgnoreCase))
        {
            fileName = "cmd.exe";
            arguments = "/c if exist gradlew.bat (gradlew.bat clean) else (gradle clean)";
            workingDirectory = ResolveProjectParentDirectory(targetPath, [".gradle", "build"]);
            description = "Limpar artefatos de build do Gradle";
            return true;
        }

        return false;
    }

    private static string ResolveSafeWorkingDirectory(string? targetPath)
    {
        if (!string.IsNullOrWhiteSpace(targetPath))
        {
            if (Directory.Exists(targetPath))
            {
                return targetPath;
            }

            string? parent = Path.GetDirectoryName(targetPath);
            if (!string.IsNullOrWhiteSpace(parent) && Directory.Exists(parent))
            {
                return parent;
            }
        }

        return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    }

    private static string ResolveProjectParentDirectory(string? targetPath, string[] artifactFolderNames)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        }

        string trimmed = targetPath.TrimEnd('\\', '/');
        string folderName = Path.GetFileName(trimmed);
        foreach (string candidate in artifactFolderNames)
        {
            if (string.Equals(folderName, candidate, StringComparison.OrdinalIgnoreCase))
            {
                string? parent = Path.GetDirectoryName(trimmed);
                if (!string.IsNullOrWhiteSpace(parent) && Directory.Exists(parent))
                {
                    return parent;
                }
            }
        }

        return ResolveSafeWorkingDirectory(targetPath);
    }

    internal static long MeasurePathBytes(string? targetPath, bool useAllocatedSize)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            return 0L;
        }

        try
        {
            if (File.Exists(targetPath))
            {
                long len = new FileInfo(targetPath).Length;
                return useAllocatedSize
                    ? GetActualFileSizeOnDisk(targetPath, len)
                    : len;
            }

            if (!Directory.Exists(targetPath))
            {
                return 0L;
            }

            long total = 0L;
            EnumerationOptions opts = new()
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            };

            foreach (string file in Directory.EnumerateFiles(targetPath, "*", opts))
            {
                try
                {
                    long len = new FileInfo(file).Length;
                    total += useAllocatedSize ? GetActualFileSizeOnDisk(file, len) : len;
                }
                catch
                {
                    // Ignora arquivo individual inacessível
                }
            }

            return total;
        }
        catch
        {
            return 0L;
        }
    }

    private static long GetActualFileSizeOnDisk(string fullPath, long fallbackLogicalLength)
    {
        try
        {
            uint low = GetCompressedFileSizeW(fullPath, out uint high);
            if (low == 0xFFFFFFFF && Marshal.GetLastWin32Error() != 0)
            {
                return fallbackLogicalLength;
            }

            return ((long)high << 32) | low;
        }
        catch
        {
            return fallbackLogicalLength;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetCompressedFileSizeW(string lpFileName, out uint lpFileSizeHigh);

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunProcessWithLiveProgressAsync(
        string fileName,
        string arguments,
        string workingDirectory,
        bool allowElevationFallback,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        string safeWorkingDir = Directory.Exists(workingDirectory)
            ? workingDirectory
            : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        try
        {
            using Process process = new()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    WorkingDirectory = safeWorkingDir,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            StringBuilder stdOutBuilder = new();
            StringBuilder stdErrBuilder = new();

            process.OutputDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                {
                    lock (stdOutBuilder)
                    {
                        stdOutBuilder.AppendLine(e.Data);
                    }
                    progress?.Report($"[{fileName}] {e.Data.Trim()}");
                }
            };

            process.ErrorDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                {
                    lock (stdErrBuilder)
                    {
                        stdErrBuilder.AppendLine(e.Data);
                    }
                    progress?.Report($"[{fileName}] {e.Data.Trim()}");
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromMinutes(4));

            try
            {
                await process.WaitForExitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                }
                throw;
            }

            string outText;
            string errText;
            lock (stdOutBuilder) outText = stdOutBuilder.ToString().Trim();
            lock (stdErrBuilder) errText = stdErrBuilder.ToString().Trim();

            return (process.ExitCode, outText, errText);
        }
        catch (Win32Exception ex) when (allowElevationFallback && ex.NativeErrorCode == 740) // ERROR_ELEVATION_REQUIRED
        {
            progress?.Report($"Solicitando permissão de Administrador (UAC) para executar '{fileName}'...");
            return await RunElevatedProcessAsync(fileName, arguments, safeWorkingDir, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunElevatedProcessAsync(
        string fileName,
        string arguments,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        try
        {
            using Process process = new()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    WorkingDirectory = workingDirectory,
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden
                }
            };

            process.Start();
            await process.WaitForExitAsync(cancellationToken);
            return (process.ExitCode, "Executado com privilégios de Administrador (UAC).", string.Empty);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) // ERROR_CANCELLED (usuário recusou o UAC)
        {
            return (-1, string.Empty, "A elevação para Administrador (UAC) foi cancelada pelo usuário.");
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }

    private static string TruncateOutput(string text, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "(vazio)";
        }

        string singleLine = text.Replace("\r\n", " ").Replace('\n', ' ').Trim();
        return singleLine.Length <= maxLength ? singleLine : singleLine[..maxLength] + "...";
    }
}
