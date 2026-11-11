using Microsoft.Win32;

namespace DiskInspector.Infrastructure;

/// <summary>
/// Leitor exclusivamente de leitura do Registro do Windows para consultar aplicativos instalados,
/// auxiliando na identificação de dados associados ou resíduos de softwares desinstalados.
/// </summary>
public static class InstalledAppsRegistryReader
{
    private static readonly string[] UninstallRegistryPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ];

    public static HashSet<string> GetInstalledAppKeywords()
    {
        HashSet<string> tokens = new(StringComparer.OrdinalIgnoreCase);

        if (!OperatingSystem.IsWindows())
        {
            return tokens;
        }

        ReadHive(Registry.LocalMachine, tokens);
        ReadHive(Registry.CurrentUser, tokens);

        return tokens;
    }

    private static void ReadHive(RegistryKey rootHive, HashSet<string> tokens)
    {
        foreach (string subPath in UninstallRegistryPaths)
        {
            try
            {
                using RegistryKey? uninstallKey = rootHive.OpenSubKey(subPath, writable: false);
                if (uninstallKey is null)
                {
                    continue;
                }

                foreach (string subKeyName in uninstallKey.GetSubKeyNames())
                {
                    try
                    {
                        using RegistryKey? appKey = uninstallKey.OpenSubKey(subKeyName, writable: false);
                        if (appKey is null)
                        {
                            continue;
                        }

                        AddToken(appKey.GetValue("DisplayName") as string, tokens);
                        AddToken(appKey.GetValue("Publisher") as string, tokens);
                        AddToken(appKey.GetValue("InstallLocation") as string, tokens);
                    }
                    catch
                    {
                        // Ignora chaves individuais sem permissão
                    }
                }
            }
            catch
            {
                // Ignora hives inacessíveis
            }
        }
    }

    private static void AddToken(string? value, HashSet<string> tokens)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        tokens.Add(value.Trim());
        foreach (string part in value.Split([' ', '\\', '/', '-', '_', '.', '(', ')'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (part.Length >= 3)
            {
                tokens.Add(part);
            }
        }
    }
}

