using System.Reflection;
using System.Text.Json;

namespace DiskInspector.Analysis;

/// <summary>
/// Catálogo extensível de regras de identificação de aplicativos no AppData (Diferencial 8).
/// Carrega regras do arquivo JSON embutido (Rules/appdata-rules.json) ou de um arquivo externo ao lado do executável,
/// permitindo expandir o reconhecimento de aplicativos sem recompilar o código.
/// </summary>
public static class AppDataRulesCatalog
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private static readonly Lazy<IReadOnlyList<AppDataRuleDefinition>> LoadedRules = new(LoadDefaultRules);

    public static IReadOnlyList<AppDataRuleDefinition> GetRules() => LoadedRules.Value;

    public static IReadOnlyList<AppDataRuleDefinition> LoadRulesFromJson(string jsonContent)
    {
        if (string.IsNullOrWhiteSpace(jsonContent))
        {
            return [];
        }

        try
        {
            List<AppDataRuleDefinition>? parsed = JsonSerializer.Deserialize<List<AppDataRuleDefinition>>(jsonContent, JsonOptions);
            return parsed?.Where(r => !string.IsNullOrWhiteSpace(r.Pattern) && !string.IsNullOrWhiteSpace(r.AppName)).ToList()
                   ?? [];
        }
        catch
        {
            return [];
        }
    }

    private static IReadOnlyList<AppDataRuleDefinition> LoadDefaultRules()
    {
        try
        {
            // 1. Tenta carregar do arquivo externo ao lado do executável (permite customização pelo usuário)
            string externalPath = Path.Combine(AppContext.BaseDirectory, "Rules", "appdata-rules.json");
            if (File.Exists(externalPath))
            {
                IReadOnlyList<AppDataRuleDefinition> fromDisk = LoadRulesFromJson(File.ReadAllText(externalPath));
                if (fromDisk.Count > 0)
                {
                    return fromDisk;
                }
            }

            // 2. Carrega do recurso embutido na DLL DiskInspector.Analysis
            Assembly asm = typeof(AppDataRulesCatalog).Assembly;
            string? resourceName = asm.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith("appdata-rules.json", StringComparison.OrdinalIgnoreCase));

            if (resourceName is not null)
            {
                using Stream? stream = asm.GetManifestResourceStream(resourceName);
                if (stream is not null)
                {
                    using StreamReader reader = new(stream);
                    return LoadRulesFromJson(reader.ReadToEnd());
                }
            }
        }
        catch
        {
            // Fallback seguro caso o JSON não esteja disponível
        }

        return [];
    }
}

public sealed record AppDataRuleDefinition
{
    public string Pattern { get; init; } = string.Empty;
    public string AppName { get; init; } = string.Empty;
    public string Publisher { get; init; } = string.Empty;
    public bool TrustCacheFolderNames { get; init; }
    public bool PrefixOfSegment { get; init; }
}
