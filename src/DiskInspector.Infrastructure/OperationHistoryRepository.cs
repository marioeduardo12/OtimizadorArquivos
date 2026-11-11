using System.Text.Json;
using DiskInspector.Core.Interfaces;
using DiskInspector.Core.Models;

namespace DiskInspector.Infrastructure;

/// <summary>
/// Repositório local de histórico de operações (análises, prévias e limpezas).
/// Armazena dados exclusivamente na máquina local (Seção 10).
/// </summary>
public sealed class OperationHistoryRepository : IOperationHistoryRepository
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly object _sync = new();
    private readonly string _storageFilePath;
    private readonly List<OperationLogEntry> _entries = [];

    public OperationHistoryRepository(IEnvironmentProvider environmentProvider, string? customStorageFilePath = null)
    {
        if (!string.IsNullOrWhiteSpace(customStorageFilePath))
        {
            _storageFilePath = customStorageFilePath;
        }
        else
        {
            EnvironmentPaths env = environmentProvider.GetEnvironmentPaths();
            string appFolder = Path.Combine(env.LocalAppDataDir, "DiskInspector");
            _storageFilePath = Path.Combine(appFolder, "operation_history.json");
        }

        LoadExisting();
    }

    public IReadOnlyList<OperationLogEntry> GetHistory()
    {
        lock (_sync)
        {
            return _entries
                .OrderByDescending(e => e.TimestampUtc)
                .ToList();
        }
    }

    public void RecordOperation(OperationLogEntry entry)
    {
        lock (_sync)
        {
            _entries.Insert(0, entry);
            if (_entries.Count > 500)
            {
                _entries.RemoveRange(500, _entries.Count - 500);
            }

            Persist();
        }
    }

    public void ExportHistoryToJson(string outputFilePath)
    {
        List<OperationLogEntry> snapshot;
        lock (_sync)
        {
            snapshot = _entries.OrderByDescending(e => e.TimestampUtc).ToList();
        }

        string? dir = Path.GetDirectoryName(outputFilePath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        string json = JsonSerializer.Serialize(snapshot, JsonOptions);
        File.WriteAllText(outputFilePath, json);
    }

    public string? SaveCleanupManifest(CleanupExecutionResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        try
        {
            string baseDir = Path.GetDirectoryName(_storageFilePath) ?? Path.GetTempPath();
            string manifestDir = Path.Combine(baseDir, "limpezas");
            Directory.CreateDirectory(manifestDir);

            string fileName = $"limpeza_{result.TimestampUtc.ToLocalTime():yyyyMMdd_HHmmss}_{result.ExecutionId.ToString("N")[..8]}.json";
            string manifestPath = Path.Combine(manifestDir, fileName);

            var manifest = new
            {
                result.ExecutionId,
                result.TimestampUtc,
                result.TotalRequested,
                result.TotalSucceeded,
                result.TotalSkippedOrBlocked,
                result.TotalFailedOrLocked,
                result.TotalBytesMovedToRecycleBin,
                result.TotalBytesPermanentlyDeleted,
                Itens = result.Outcomes.Select(o => new
                {
                    Caminho = o.FullPath,
                    Tipo = o.IsDirectory ? "Pasta" : "Arquivo",
                    Removido = o.Succeeded,
                    Metodo = o.ExecutedMethod.ToString(),
                    Bytes = o.BytesRecovered,
                    Risco = o.RiskLabel,
                    Categoria = o.Category,
                    Aplicativo = o.AssociatedApp,
                    Mensagem = o.StatusMessage
                })
            };

            File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, JsonOptions));
            return manifestPath;
        }
        catch
        {
            // Falha ao gravar o registro detalhado não deve interromper a limpeza já concluída
            return null;
        }
    }

    private void LoadExisting()
    {
        try
        {
            if (!File.Exists(_storageFilePath))
            {
                return;
            }

            string json = File.ReadAllText(_storageFilePath);
            List<OperationLogEntry>? loaded = JsonSerializer.Deserialize<List<OperationLogEntry>>(json, JsonOptions);
            if (loaded is not null)
            {
                _entries.Clear();
                _entries.AddRange(loaded);
            }
        }
        catch
        {
            // Se o arquivo estiver corrompido ou inacessível, inicia com lista limpa em memória
        }
    }

    private void Persist()
    {
        try
        {
            string? dir = Path.GetDirectoryName(_storageFilePath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            string json = JsonSerializer.Serialize(_entries, JsonOptions);
            File.WriteAllText(_storageFilePath, json);
        }
        catch
        {
            // Falha de escrita de log não deve derrubar a aplicação
        }
    }
}

