# Script de Compilação, Testes e Publicação Portátil Self-Contained (Windows x64) — DiskInspector
$ErrorActionPreference = "Stop"

# Prioriza o SDK do .NET 10 instalado em %LOCALAPPDATA%\Microsoft\dotnet
# (Pois C:\Program Files\dotnet nesta máquina possui apenas o Runtime 8.0 sem SDK)
$localDotnetDir = Join-Path $env:LOCALAPPDATA "Microsoft\dotnet"
$localDotnetExe = Join-Path $localDotnetDir "dotnet.exe"

if (Test-Path $localDotnetExe) {
    $env:DOTNET_ROOT = $localDotnetDir
    $env:PATH = "$localDotnetDir;$env:PATH"
    $dotnetCmd = $localDotnetExe
} else {
    $dotnetCmd = "dotnet"
}

Write-Host "Usando SDK em: $dotnetCmd" -ForegroundColor Yellow
& $dotnetCmd --version

Write-Host "`n==> 1/3: Executando suíte de testes automatizados de segurança e análise (DiskInspector.Tests)..." -ForegroundColor Cyan
& $dotnetCmd test DiskInspector.sln -c Release

# "$ErrorActionPreference = Stop" não interrompe o script quando um programa externo falha:
# sem esta checagem, o executável seria publicado mesmo com testes de segurança falhando.
if ($LASTEXITCODE -ne 0) {
    throw "Os testes falharam (código $LASTEXITCODE). A publicação foi cancelada."
}

Write-Host "`n==> 2/3: Gerando executável único portátil self-contained para Windows x64..." -ForegroundColor Cyan
$targetExe = "publish/win-x64/DiskInspector.exe"
$oldExe = "publish/win-x64/DiskInspector.old.exe"
if (Test-Path $oldExe) {
    Remove-Item $oldExe -Force -ErrorAction SilentlyContinue
}
if (Test-Path $targetExe) {
    try {
        Remove-Item $targetExe -Force -ErrorAction Stop
    } catch {
        Write-Host "Nota: DiskInspector.exe está aberto; movendo executável em uso para DiskInspector.old.exe para permitir atualização..." -ForegroundColor Yellow
        Move-Item $targetExe $oldExe -Force -ErrorAction SilentlyContinue
    }
}

& $dotnetCmd publish src/DiskInspector.UI/DiskInspector.UI.csproj `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:IncludeAllContentForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -p:DebugType=embedded `
    -o publish/win-x64

if ($LASTEXITCODE -ne 0) {
    throw "A publicação falhou (código $LASTEXITCODE)."
}

Write-Host "`n==> 3/3: Publicação concluída com sucesso em: publish\win-x64\DiskInspector.exe" -ForegroundColor Green
Get-ChildItem publish/win-x64
