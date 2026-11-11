namespace DiskInspector.Core.Enums;

/// <summary>
/// Classificação inteligente de risco conforme Seção 6 da especificação.
/// </summary>
public enum RiskLevel
{
    /// <summary>
    /// VERDE — Baixo risco: Arquivos temporários e caches reconhecidos como descartáveis,
    /// respeitando regras específicas e verificando se não estão em uso.
    /// </summary>
    Green = 0,

    /// <summary>
    /// AMARELO — Requer atenção: Arquivos antigos, instaladores, downloads, artefatos de build
    /// e caches que possam afetar o desempenho inicial ou exigir recompilação/novo download.
    /// </summary>
    Yellow = 1,

    /// <summary>
    /// VERMELHO — Alto risco: Dados persistentes, configurações, bancos locais, arquivos de projetos,
    /// máquinas virtuais, ambientes Docker/WSL2 e dados que podem provocar perdas importantes.
    /// </summary>
    Red = 2,

    /// <summary>
    /// CINZA — Protegido ou desconhecido: Componentes críticos do Windows, arquivos cuja finalidade
    /// não foi identificada com segurança e diretórios sem permissão de acesso.
    /// </summary>
    Gray = 3
}

/// <summary>
/// Categorias semânticas de arquivos e diretórios analisados.
/// </summary>
public enum ItemCategory
{
    SystemCritical,
    TemporaryFiles,
    ApplicationCache,
    AppDataPersistent,
    AppDataSessionOrProfile,
    InstallerResidue,
    LargeLogs,
    OldDownloads,
    UninstalledAppData,
    DeveloperCache,
    DeveloperBuildArtifact,
    ContainerOrVirtualization,
    DuplicateFile,
    HighDensityDirectory,
    LargeUserFile,
    StandardDirectory,
    Unknown
}

/// <summary>
/// Ação recomendada para cada item analisado.
/// </summary>
public enum RecommendedAction
{
    NoneProtected,
    ManualReviewRequired,
    SafeToMoveToRecycleBin,
    SafeToCleanWhenAppClosed,
    UseOfficialWindowsTool,
    UseOfficialDeveloperCommand,
    KeepOriginalRemoveDuplicateCopy,

    /// <summary>
    /// O item faz parte de um achado maior (ex.: subpasta dentro de um item temporário ou de um cache).
    /// Nunca é selecionável sozinho: a limpeza acontece pelo item de primeiro nível.
    /// </summary>
    CleanViaParentItem
}

/// <summary>
/// Momento em que a validação de segurança é feita. Na prévia a checagem não pode alterar nada no disco;
/// na execução ela é refeita imediatamente antes de cada item.
/// </summary>
public enum CleanupValidationStage
{
    Preview,
    Execution
}

/// <summary>
/// Escopo dentro do diretório AppData do usuário.
/// </summary>
public enum AppDataScope
{
    Local,
    Roaming,
    LocalLow
}

/// <summary>
/// Natureza dos dados armazenados em uma subpasta do AppData.
/// </summary>
public enum AppDataContentKind
{
    DisposableCache,
    ShaderOrGpuCache,
    CrashDumpsOrLogs,
    Configuration,
    PersistentDatabaseOrStorage,
    SessionOrAuthentication,
    LibrariesOrRuntime,
    Unknown
}

/// <summary>
/// Tipo de operação de limpeza diferenciando claramente Lixeira, exclusão direta e ferramentas oficiais.
/// </summary>
public enum CleanupOperationMethod
{
    NoneReadOnly,
    MoveToRecycleBin,
    DirectPermanentDelete,
    OfficialToolGuidanceOnly
}

