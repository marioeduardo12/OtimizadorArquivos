# DiskInspector — Analisador e Otimizador Seguro de Armazenamento para Windows 11

O **DiskInspector** é uma aplicação desktop nativa em **C# / .NET 10 / WPF (MVVM)** voltada para inspeção profunda de armazenamento (no estilo WizTree / TreeSize), diagnóstico detalhado do `AppData`, identificação de caches de ambientes de desenvolvimento (Node.js, Python, .NET, Rust, Java, Docker/WSL2), detecção de duplicados por hash SHA-256 e limpeza controlada com foco em segurança para **Windows 11 (x64)**.

---

## 🚀 Execução Rápida (Sem precisar compilar)

O executável portátil independente (`win-x64` self-contained) **já está compilado e pronto para uso** na pasta `publish\win-x64`. Para abrir o aplicativo diretamente no PowerShell ou Prompt de Comando, execute qualquer uma das opções abaixo:

```powershell
# Opção 1: Abrir o executável pronto diretamente
.\publish\win-x64\DiskInspector.exe

# Opção 2: Usar o atalho em lote (também funciona dando duplo-clique no Windows Explorer)
.\Iniciar-DiskInspector.bat

# Opção 3: Usar o script PowerShell
powershell -ExecutionPolicy Bypass -File .\executar.ps1
```

---

## 🛠️ Como Compilar, Testar e Publicar no Seu Terminal

> **Por que o comando `dotnet build` puro deu erro `"No .NET SDKs were found"`?**
> Nesta máquina, a pasta global `C:\Program Files\dotnet` (que está no `PATH` de sistema do Windows) possui apenas o **Runtime 8.0** instalado (sem nenhum SDK). O **SDK do .NET 10 (`10.0.404`)** foi instalado na pasta do seu usuário em `$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe`.

Para compilar ou rodar os testes no seu terminal PowerShell, basta apontar para o `.NET 10 SDK` local ou rodar o script `.\publish-portable.ps1`:

### Opção A — Script Automatizado (Faz Teste + Build + Publicação Portátil)
```powershell
powershell -ExecutionPolicy Bypass -File .\publish-portable.ps1
```

### Opção B — Comandos Diretos no PowerShell
```powershell
# 1. Ativa o SDK do .NET 10 na sessão atual do PowerShell
$env:DOTNET_ROOT = "$env:LOCALAPPDATA\Microsoft\dotnet"
$env:PATH = "$env:LOCALAPPDATA\Microsoft\dotnet;$env:PATH"

# 2. Compilar a solução
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" build DiskInspector.sln -c Release

# 3. Executar os 27 testes automatizados de segurança
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" test DiskInspector.sln -c Release

# 4. Rodar direto pelo código-fonte
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" run --project src/DiskInspector.UI/DiskInspector.UI.csproj -c Release

# 5. Publicar o executável único portátil (Self-Contained Windows x64)
& "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" publish src/DiskInspector.UI/DiskInspector.UI.csproj `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:IncludeAllContentForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -p:DebugType=embedded `
    -o publish/win-x64
```

---

## 1. Arquitetura do Software

A solução (`DiskInspector.sln`) está dividida em 6 projetos desacoplados seguindo princípios de Clean Architecture e MVVM:

- **`src/DiskInspector.Core`**: Camada de domínio puro (sem dependências externas). Contém modelos imutáveis e reativos (`StorageItem`, `DriveMetadata`, `EnvironmentPaths`, `AppDataEntry`, `DeveloperArtifactItem`, `DuplicateGroup`, `ScanResult`, `CleanupPreviewReport`), enumerações (`RiskLevel`, `ItemCategory`, `RecommendedAction`) e interfaces de serviço.
- **`src/DiskInspector.Infrastructure`**: Descoberta dinâmica de caminhos do Windows (`WindowsEnvironmentProvider` via APIs `Environment.SpecialFolder` e `SHGetKnownFolderPath`), enumeração de unidades (`DriveDiscoveryService`), interoperabilidade nativa Win32 (`NativeDiskInterop` usando `GetCompressedFileSizeW` e `GetFileInformationByHandle` para diferenciar tamanho lógico vs. espaço alocado em disco, arquivos esparsos, placeholders OneDrive e hard links NTFS), detecção não-destrutiva de arquivos bloqueados (`FileLockDetector`) e persistência local de auditoria (`OperationHistoryRepository`).
- **`src/DiskInspector.Analysis`**:
  - `SystemPathProtector`: Guardião centralizado de proteção de caminhos críticos do Windows 11 (`C:\Windows`, `System32`, `WinSxS`, `DriverStore`, `SoftwareDistribution`, `Program Files`, `ProgramData`, `Recovery`, `$Recycle.Bin`, `System Volume Information`, `EFI`, `pagefile.sys`, `hiberfil.sys`) e pastas-raiz do perfil.
  - `StorageClassifier`: Classificador conservador baseado em múltiplos fatores (contexto completo do caminho, assinatura de aplicativo verificado, extensão, idade e status de bloqueio). **Nunca autoriza a exclusão de uma pasta apenas porque seu nome contém `"cache"`**.
  - `AppDataAnalyzer`: Raio-X individual de `AppData\Local`, `AppData\Roaming` e `AppData\LocalLow`, separando subpastas de cache comprovadamente descartáveis de dados persistentes, sessões, autenticação e bancos locais.
  - `DeveloperEnvironmentAnalyzer` & `DockerAndWslInspector`: Identificação de caches globais (`npm`, `pnpm`, `Yarn`, `pip`, `Composer`, `NuGet`, `Gradle`, `Maven`, `Cargo`), artefatos de projeto (`node_modules`, `target`, `bin/obj`) e discos virtuais `.vhdx` do Docker Desktop / WSL2.
  - `DuplicateFileDetector`: Pipeline em 3 estágios (tamanho exato -> pré-hash das bordas -> SHA-256 completo), ignorando links simbólicos e deduplicando hard links NTFS.
  - `DiskScannerService`: Motor assíncrono de varredura iterativa com `FileSystemEnumerable<T>`, filas de prioridade limitadas (`PriorityQueue`) para baixo consumo de memória e suporte a cancelamento (`CancellationToken`).
- **`src/DiskInspector.Cleanup`**:
  - `CleanupSafetyValidator`: Gatekeeper que bloqueia qualquer tentativa de remoção de itens `Vermelhos` (Alto Risco), `Cinzas` (Protegidos/Desconhecidos), caminhos do sistema, links simbólicos ou arquivos em uso.
  - `SafeCleanupService`: Gera prévia obrigatória (`CleanupPreviewReport`), revalida cada item imediatamente antes da execução (prevenção TOCTOU) e prioriza o envio para a **Lixeira do Windows**.
- **`src/DiskInspector.UI`**: Interface WPF com tema escuro inspirado no Windows 11, iniciando por padrão no **Modo Somente Leitura (Fase 1)** e permitindo desbloquear o **Modo de Limpeza Controlada (Fase 3)** mediante confirmação explícita.
- **`tests/DiskInspector.Tests`**: Suíte com 27 testes automatizados xUnit cobrindo todos os cenários de segurança em diretórios temporários isolados.

---

## 2. Guia de Utilização

1. **Início em Modo Somente Leitura (Fase 1 — MVP)**:
   - Ao abrir o `DiskInspector.exe`, o aplicativo inicia com a trava de segurança em **Fase 1 (Modo Somente Leitura)**. Nenhuma operação de exclusão pode ocorrer acidentalmente.
2. **Seleção de Unidade e Escopo**:
   - Escolha a unidade (`C:`, `D:`, etc.) e o escopo (`Unidade Completa Selecionada`, `Apenas Perfil do Usuário Atual`, `Apenas AppData Completo` ou `Apenas Pasta Downloads`).
   - Clique em **▶ Analisar Armazenamento**.
3. **Inspeção dos 10 Atributos Obrigatórios**:
   - Clique em qualquer pasta ou arquivo em qualquer uma das 6 abas de análise para visualizar, no painel lateral direito, os **10 atributos detalhados** (Nome, Caminho, Tamanho Lógico vs. Alocado, Data de Modificação, Categoria, Aplicativo Associado, Explicação da Finalidade, Consequências da Exclusão, Classificação de Risco e Ação Recomendada).
4. **Raio-X do AppData (Aba 4)**:
   - Veja quanto `AppData\Local`, `AppData\Roaming` e `AppData\LocalLow` consomem por aplicativo. Ao selecionar um aplicativo (ex.: Chrome, Edge, Discord, VS Code), a tabela inferior exibe **apenas as subpastas de cache comprovadamente descartáveis**, mantendo sessões, cookies e bancos locais protegidos.
5. **Limpeza Segura Controlada (Fase 3)**:
   - Ative a chave **"Habilitar Modo de Limpeza Controlada (Fase 3)"** no topo direito.
   - Selecione manualmente os itens `Verdes` (ou `Amarelos` após revisão) e clique em **🧹 Prévia e Limpar Selecionados**.
   - Revise a janela de **Prévia Detalhada**, marque a confirmação explícita e execute o envio para a Lixeira do Windows.

---

## 3. Limitações Conhecidas e Avisos de Segurança

- **Nenhuma garantia absoluta sem revisão humana**: Nenhuma ferramenta de análise de disco pode conhecer 100% dos softwares proprietários ou customizados existentes. Por isso, o DiskInspector classifica qualquer diretório sem assinatura verificada como **CINZA (Desconhecido)** e bloqueia sua exclusão.
- **Execução sem privilégios de Administrador**: Por segurança, o aplicativo executa como usuário padrão (`asInvoker`). Diretórios protegidos por ACLs exclusivas do `SYSTEM` (como `System Volume Information`) terão seu acesso negado contabilizado no indicador *"Sem Permissão"* sem travar a análise.
- **Limites da Lixeira do Windows**: Quando a opção *"Usar Lixeira do Windows"* está ativa, arquivos que excedam a cota máxima configurada na Lixeira do volume NTFS ou localizados em unidades que não suportam Lixeira não têm recuperação garantida pelo Windows.
