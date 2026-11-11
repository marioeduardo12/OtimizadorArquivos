# Inicia o DiskInspector (compilando automaticamente se o executável ainda não existir)
$ErrorActionPreference = "Stop"

$exePath = Join-Path $PSScriptRoot "publish\win-x64\DiskInspector.exe"

if (-not (Test-Path $exePath)) {
    Write-Host "Executável ainda não encontrado em publish\win-x64. Compilando agora..." -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "publish-portable.ps1")
}

Write-Host "Iniciando DiskInspector..." -ForegroundColor Green
Start-Process -FilePath $exePath

