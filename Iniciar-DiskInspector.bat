@echo off
chcp 65001 >nul
set "EXE_PATH=%~dp0publish\win-x64\DiskInspector.exe"

if exist "%EXE_PATH%" (
    echo Iniciando DiskInspector...
    start "" "%EXE_PATH%"
    exit /b 0
)

echo Compilando o DiskInspector pela primeira vez...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0publish-portable.ps1"
if exist "%EXE_PATH%" (
    start "" "%EXE_PATH%"
) else (
    echo Falha ao localizar o executavel compilado.
    pause
)

