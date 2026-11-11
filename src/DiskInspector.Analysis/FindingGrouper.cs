using DiskInspector.Core.Enums;
using DiskInspector.Core.Models;

namespace DiskInspector.Analysis;

/// <summary>
/// Agrupa os achados classificados em conjuntos lógicos compreensíveis ("Temporários de sessões anteriores",
/// "Caches de Navegadores e Electron", "Dependências de Projetos", etc.), evitando que centenas de linhas
/// soltas dificultem a revisão e permitindo seleção ou filtro com um único clique (Diferencial 1).
/// </summary>
public static class FindingGrouper
{
    public static IReadOnlyList<FindingGroupSummary> BuildGroups(IReadOnlyList<StorageItem> classifiedFindings)
    {
        ArgumentNullException.ThrowIfNull(classifiedFindings);

        Dictionary<string, GroupBucket> buckets = new(StringComparer.OrdinalIgnoreCase);

        foreach (StorageItem item in classifiedFindings)
        {
            if (item is null || item.LogicalSizeBytes <= 0 || item.Recommendation == RecommendedAction.CleanViaParentItem)
            {
                continue;
            }

            GroupTemplate template = ResolveTemplate(item);
            if (!buckets.TryGetValue(template.Key, out GroupBucket? bucket))
            {
                bucket = new GroupBucket(template);
                buckets[template.Key] = bucket;
            }

            bucket.Items.Add(item);
        }

        List<FindingGroupSummary> summaries = [];
        foreach (GroupBucket bucket in buckets.Values)
        {
            long nonOverlappingBytes = PathNesting.ComputeNonOverlappingSize(bucket.Items);
            if (nonOverlappingBytes <= 0)
            {
                continue;
            }

            bool anySelectable = bucket.Items.Any(i => i.CanSelectForCleanup);
            string? officialCmd = bucket.Items
                .Select(i => i.OfficialMaintenanceCommand)
                .FirstOrDefault(c => !string.IsNullOrWhiteSpace(c));

            summaries.Add(new FindingGroupSummary
            {
                GroupKey = bucket.Template.Key,
                Title = bucket.Template.Title,
                Explanation = bucket.Template.Explanation,
                DeletionImpact = bucket.Template.DeletionImpact,
                RiskClassification = bucket.Template.Risk,
                TotalLogicalBytes = nonOverlappingBytes,
                ItemCount = bucket.Items.Count,
                CanSelectForCleanup = anySelectable,
                OfficialCommand = officialCmd,
                Items = bucket.Items
                    .OrderByDescending(i => i.LogicalSizeBytes)
                    .ToList()
            });
        }

        return summaries
            .OrderBy(g => g.RiskClassification)
            .ThenByDescending(g => g.TotalLogicalBytes)
            .ToList();
    }

    private static GroupTemplate ResolveTemplate(StorageItem item)
    {
        if (item.Category == ItemCategory.TemporaryFiles)
        {
            if (item.RiskClassification == RiskLevel.Green)
            {
                return new GroupTemplate(
                    "temp-safe-green",
                    "Temporários de Sessões Anteriores (%TEMP%)",
                    "Arquivos e pastas temporárias sem modificação desde antes do início da sessão atual do Windows.",
                    "Nenhum impacto em dados pessoais ou programas abertos; envia para a Lixeira com segurança.",
                    RiskLevel.Green);
            }

            return new GroupTemplate(
                "temp-session-yellow",
                "Temporários da Sessão Atual (%TEMP%)",
                "Itens temporários criados ou alterados durante a sessão atual do Windows (podem pertencer a programas abertos).",
                "Feche os aplicativos abertos ou reinicie o Windows antes de limpar para evitar falhas em instaladores/editores.",
                RiskLevel.Yellow);
        }

        if (item.Category == ItemCategory.ApplicationCache && item.RiskClassification == RiskLevel.Green)
        {
            bool isBrowser = item.AssociatedAppOrComponent.Contains("Chrome", StringComparison.OrdinalIgnoreCase) ||
                             item.AssociatedAppOrComponent.Contains("Edge", StringComparison.OrdinalIgnoreCase) ||
                             item.AssociatedAppOrComponent.Contains("Brave", StringComparison.OrdinalIgnoreCase) ||
                             item.AssociatedAppOrComponent.Contains("Firefox", StringComparison.OrdinalIgnoreCase) ||
                             item.AssociatedAppOrComponent.Contains("Opera", StringComparison.OrdinalIgnoreCase) ||
                             item.AssociatedAppOrComponent.Contains("Vivaldi", StringComparison.OrdinalIgnoreCase);

            if (isBrowser)
            {
                return new GroupTemplate(
                    "browser-caches-green",
                    "Caches de Navegadores Web",
                    "Caches técnicos HTTP, Code Cache e GPUCache de navegadores instalados (não inclui senhas, histórico ou sessões).",
                    "Nenhuma perda de login ou favoritos. Os navegadores recriarão o cache automaticamente durante a navegação.",
                    RiskLevel.Green);
            }

            return new GroupTemplate(
                "app-electron-caches-green",
                "Caches Descartáveis de IDEs, Apps Electron e GPU",
                "Subpastas de cache técnico (Code Cache, GPUCache, CachedData, D3DSCache, TempState) em AppData.",
                "Nenhuma perda de configurações ou contas. Recomenda-se fechar o aplicativo correspondente antes da limpeza.",
                RiskLevel.Green);
        }

        if (item.Category == ItemCategory.LargeLogs)
        {
            return new GroupTemplate(
                item.RiskClassification == RiskLevel.Green ? "logs-crash-green" : "logs-large-yellow",
                item.RiskClassification == RiskLevel.Green
                    ? "Relatórios de Falha (CrashDumps) e Logs de Apps"
                    : "Arquivos de Log e Diagnóstico Volumosos",
                "Despejos de memória (CrashDumps) e arquivos .log/.dmp gerados para diagnóstico de erros passados.",
                "Apenas remove registros antigos de falhas; não altera configurações nem dados do usuário.",
                item.RiskClassification);
        }

        if (item.Category == ItemCategory.DeveloperBuildArtifact)
        {
            if (item.RiskClassification == RiskLevel.Yellow)
            {
                return new GroupTemplate(
                    "dev-project-artifacts-yellow",
                    "Dependências e Builds de Projetos (node_modules, bin/obj, target)",
                    "Pastas de dependências instaladas e artefatos de compilação de projetos seus (com lockfile/.git/.csproj).",
                    "Código-fonte permanece 100% intacto; voltar a compilar o projeto exigirá 'npm install', 'dotnet build' ou 'cargo build'.",
                    RiskLevel.Yellow);
            }

            return new GroupTemplate(
                "dev-venv-red",
                "Ambientes Virtuais Python (.venv / venv)",
                "Ambientes virtuais Python isolados contendo interpretador e bibliotecas instaladas.",
                "Protegido contra exclusão automática para evitar perda de pacotes sem requirements.txt atualizado.",
                RiskLevel.Red);
        }

        if (item.Category == ItemCategory.DeveloperCache)
        {
            return new GroupTemplate(
                "dev-global-caches-yellow",
                "Caches Globais de Gerenciadores de Pacotes (npm, NuGet, pip, Maven, Gradle, Cargo)",
                "Repositórios e caches globais de pacotes baixados por ferramentas de desenvolvimento.",
                "Pode ser limpo via comando oficial (1 clique) ou Lixeira; próximos builds baixarão os pacotes novamente.",
                RiskLevel.Yellow);
        }

        if (item.Category is ItemCategory.OldDownloads or ItemCategory.InstallerResidue)
        {
            return new GroupTemplate(
                "downloads-installers-yellow",
                "Downloads Antigos (> 30 dias) e Instaladores (.msi / .iso)",
                "Instaladores já baixados ou arquivos/pastas volumosas sem alteração há mais de 30 dias na pasta Downloads.",
                "Revise os nomes antes de enviar para a Lixeira, pois a pasta Downloads pode conter documentos que você ainda deseja guardar.",
                RiskLevel.Yellow);
        }

        if (item.Category == ItemCategory.ContainerOrVirtualization)
        {
            return new GroupTemplate(
                "containers-wsl-red",
                "Containers Docker Desktop e Discos Virtuais WSL2 (.vhdx)",
                "Discos virtuais ext4.vhdx e estruturas de armazenamento do Docker Desktop e distribuições Linux WSL2.",
                "PROTEGIDO: Excluir .vhdx apaga bancos de dados e sistemas Linux inteiros. Use a aba 'Liberar Sem Apagar' ou 'docker builder prune'.",
                item.RiskClassification);
        }

        if (item.RiskClassification == RiskLevel.Red)
        {
            return new GroupTemplate(
                "persistent-user-data-red",
                "Dados Persistentes, Perfis e Arquivos Pessoais (Protegidos)",
                "Pastas de aplicativos com sessões/bancos locais no AppData ou arquivos em Documentos/Área de Trabalho/Downloads recentes.",
                "Bloqueado contra limpeza automática para proteger logins, bancos de dados locais e arquivos pessoais.",
                RiskLevel.Red);
        }

        return new GroupTemplate(
            "system-or-unknown-gray",
            "Sistema Windows 11 Protegido ou Finalidade Desconhecida",
            "Diretórios críticos do Windows 11 (System32, WinSxS, Program Files) ou pastas sem assinatura verificada.",
            "Bloqueado incondicionalmente pelo guardião de segurança do DiskInspector.",
            RiskLevel.Gray);
    }

    private sealed record GroupTemplate(
        string Key,
        string Title,
        string Explanation,
        string DeletionImpact,
        RiskLevel Risk);

    private sealed class GroupBucket(GroupTemplate template)
    {
        public GroupTemplate Template { get; } = template;
        public List<StorageItem> Items { get; } = [];
    }
}
