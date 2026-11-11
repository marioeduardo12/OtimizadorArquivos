using DiskInspector.Core.Enums;

namespace DiskInspector.Core.Formatting;

/// <summary>
/// Formatador de tamanhos de armazenamento e descrições semânticas em português.
/// </summary>
public static class ByteSizeFormatter
{
    private static readonly string[] Units = ["B", "KB", "MB", "GB", "TB", "PB"];

    public static string FormatBytes(long bytes)
    {
        if (bytes < 0)
        {
            return "0 B";
        }

        if (bytes == 0)
        {
            return "0 B";
        }

        double value = bytes;
        int unitIndex = 0;

        while (value >= 1024.0 && unitIndex < Units.Length - 1)
        {
            value /= 1024.0;
            unitIndex++;
        }

        return unitIndex == 0
            ? $"{bytes:N0} B"
            : $"{value:N2} {Units[unitIndex]}";
    }

    public static string GetRiskLabel(RiskLevel risk) => risk switch
    {
        RiskLevel.Green => "VERDE — Baixo Risco",
        RiskLevel.Yellow => "AMARELO — Requer Atenção",
        RiskLevel.Red => "VERMELHO — Alto Risco",
        RiskLevel.Gray => "CINZA — Protegido / Desconhecido",
        _ => "CINZA — Desconhecido"
    };

    public static string GetShortRiskBadge(RiskLevel risk) => risk switch
    {
        RiskLevel.Green => "VERDE (Baixo Risco)",
        RiskLevel.Yellow => "AMARELO (Atenção)",
        RiskLevel.Red => "VERMELHO (Alto Risco)",
        RiskLevel.Gray => "CINZA (Protegido/Desc.)",
        _ => "CINZA"
    };

    public static string GetCategoryDisplayName(ItemCategory category) => category switch
    {
        ItemCategory.SystemCritical => "Sistema Crítico do Windows",
        ItemCategory.TemporaryFiles => "Arquivos Temporários",
        ItemCategory.ApplicationCache => "Cache de Aplicativo",
        ItemCategory.AppDataPersistent => "Dados Persistentes / Configuração (AppData)",
        ItemCategory.AppDataSessionOrProfile => "Sessão, Perfil ou Banco Local (AppData)",
        ItemCategory.InstallerResidue => "Instalador / Resíduo de Instalação",
        ItemCategory.LargeLogs => "Logs Grandes / Relatórios de Falha",
        ItemCategory.OldDownloads => "Downloads Antigos",
        ItemCategory.UninstalledAppData => "Possível Resíduo de App Desinstalado",
        ItemCategory.DeveloperCache => "Cache de Ambiente de Desenvolvimento",
        ItemCategory.DeveloperBuildArtifact => "Artefatos de Build / Dependências (Dev)",
        ItemCategory.ContainerOrVirtualization => "Containers, WSL2 ou Máquinas Virtuais",
        ItemCategory.DuplicateFile => "Arquivo Duplicado",
        ItemCategory.HighDensityDirectory => "Diretório com Milhares de Pequenos Arquivos",
        ItemCategory.LargeUserFile => "Arquivo Individual de Grande Porte",
        ItemCategory.StandardDirectory => "Diretório de Armazenamento",
        ItemCategory.Unknown => "Desconhecido (Não Classificado)",
        _ => "Desconhecido"
    };

    public static string GetRecommendedActionDisplayName(RecommendedAction action) => action switch
    {
        RecommendedAction.NoneProtected => "Manter Intacto (Protegido pelo Sistema)",
        RecommendedAction.ManualReviewRequired => "Revisão Manual Obrigatória",
        RecommendedAction.SafeToMoveToRecycleBin => "Limpeza Segura via Lixeira do Windows",
        RecommendedAction.SafeToCleanWhenAppClosed => "Limpar com o Aplicativo Fechado (via Lixeira)",
        RecommendedAction.UseOfficialWindowsTool => "Usar Ferramenta Oficial do Windows (DISM / Sensor de Armazenamento)",
        RecommendedAction.UseOfficialDeveloperCommand => "Usar Comando Oficial da Ferramenta de Desenvolvimento",
        RecommendedAction.KeepOriginalRemoveDuplicateCopy => "Manter Arquivo Original e Revisar Cópia Duplicada",
        RecommendedAction.CleanViaParentItem => "Faz Parte de um Item Maior (limpe pelo item de primeiro nível)",
        _ => "Revisão Manual"
    };

    public static string GetAppDataContentKindDisplayName(AppDataContentKind kind) => kind switch
    {
        AppDataContentKind.DisposableCache => "Cache Descartável",
        AppDataContentKind.ShaderOrGpuCache => "Cache de GPU / Shaders / Código Compilado",
        AppDataContentKind.CrashDumpsOrLogs => "Logs e Relatórios de Crash",
        AppDataContentKind.Configuration => "Configurações e Preferências",
        AppDataContentKind.PersistentDatabaseOrStorage => "Dados Persistentes / Bancos Locais",
        AppDataContentKind.SessionOrAuthentication => "Sessões, Autenticação, Perfis e Cookies",
        AppDataContentKind.LibrariesOrRuntime => "Bibliotecas, Extensões ou Runtimes",
        AppDataContentKind.Unknown => "Finalidade Desconhecida",
        _ => "Desconhecido"
    };

    public static string GetCleanupMethodDisplayName(CleanupOperationMethod method) => method switch
    {
        CleanupOperationMethod.NoneReadOnly => "Somente Leitura (Nenhuma Exclusão)",
        CleanupOperationMethod.MoveToRecycleBin => "Mover para a Lixeira do Windows (Recuperável se suportado)",
        CleanupOperationMethod.DirectPermanentDelete => "Exclusão Direta Permanente (IRREVERSÍVEL)",
        CleanupOperationMethod.OfficialToolGuidanceOnly => "Orientação via API / Ferramenta Oficial",
        _ => "Somente Leitura"
    };
}

