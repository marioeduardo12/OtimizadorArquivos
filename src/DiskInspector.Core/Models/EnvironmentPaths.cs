namespace DiskInspector.Core.Models;

/// <summary>
/// Caminhos descobertos dinamicamente no sistema operacional (Seção 10 — Compatibilidade Universal).
/// Nunca utiliza nomes de usuários fixos em código.
/// </summary>
public sealed record EnvironmentPaths
{
    public required string WindowsDir { get; init; }
    public required string System32Dir { get; init; }
    public required string SysWow64Dir { get; init; }
    public required string WinSxSDir { get; init; }
    public required string ProgramFilesDir { get; init; }
    public required string ProgramFilesX86Dir { get; init; }
    public required string ProgramDataDir { get; init; }
    public required string UserProfileDir { get; init; }
    public required string LocalAppDataDir { get; init; }
    public required string RoamingAppDataDir { get; init; }
    public required string LocalLowAppDataDir { get; init; }
    public required string UserTempDir { get; init; }
    public required string SystemTempDir { get; init; }
    public required string DownloadsDir { get; init; }
    public required string DocumentsDir { get; init; }
    public required string DesktopDir { get; init; }
    public required bool IsElevatedAdmin { get; init; }
    public required string MachineName { get; init; }
    public required string CurrentUserName { get; init; }
    public required string OsVersionDescription { get; init; }

    /// <summary>
    /// Início da sessão atual do usuário no Windows (quando conhecido). Arquivos temporários gravados
    /// depois desse instante podem pertencer a um programa ainda aberto.
    /// </summary>
    public DateTime? UserSessionStartUtc { get; init; }
}

