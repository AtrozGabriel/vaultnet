@echo off
setlocal DisableDelayedExpansion
title VaultNet - Desenvolvimento local

pushd "%~dp0"
if errorlevel 1 goto pasta_invalida
if not exist "iniciar_windows.py" goto pacote_incompleto
if not exist "iniciar_local_windows.py" goto pacote_incompleto

echo VaultNet - verificando o sistema...
echo.

call :detectar_python
if defined VAULTNET_PYTHON goto preparar
goto python_ausente

:preparar
"%VAULTNET_PYTHON%" %VAULTNET_SELETOR% -I "iniciar_windows.py" --preparar
if "%ERRORLEVEL%"=="4" goto cancelado
if "%ERRORLEVEL%"=="3" goto ja_aberto
if errorlevel 1 goto erro
".venv\Scripts\python.exe" -I "iniciar_local_windows.py"
if "%ERRORLEVEL%"=="3" goto ja_aberto
if errorlevel 1 goto erro
popd
endlocal
exit /b 0

:detectar_python
set "VAULTNET_PYTHON="
set "VAULTNET_SELETOR="
for %%P in (".venv\Scripts\python.exe" "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" "%ProgramFiles%\Python314\python.exe" "%ProgramFiles%\Python312\python.exe") do (
    if exist "%%~P" (
        "%%~P" -I -c "import struct,sys,sysconfig; sys.exit(0 if sys.version_info[:2] in ((3,12),(3,14)) and struct.calcsize('P') == 8 and sysconfig.get_platform() == 'win-amd64' else 1)" >nul 2>&1
        if not errorlevel 1 (
            set "VAULTNET_PYTHON=%%~P"
            exit /b 0
        )
    )
)
py -3.14 -I -c "import struct,sys,sysconfig; sys.exit(0 if struct.calcsize('P') == 8 and sysconfig.get_platform() == 'win-amd64' else 1)" >nul 2>&1
if not errorlevel 1 (
    set "VAULTNET_PYTHON=py"
    set "VAULTNET_SELETOR=-3.14"
    exit /b 0
)
py -3.12 -I -c "import struct,sys,sysconfig; sys.exit(0 if struct.calcsize('P') == 8 and sysconfig.get_platform() == 'win-amd64' else 1)" >nul 2>&1
if not errorlevel 1 (
    set "VAULTNET_PYTHON=py"
    set "VAULTNET_SELETOR=-3.12"
    exit /b 0
)
for /f "delims=" %%P in ('where.exe python.exe python3.exe 2^>nul') do (
    if /i not "%%~dpP"=="%LOCALAPPDATA%\Microsoft\WindowsApps\" (
        "%%~P" -I -c "import struct,sys,sysconfig; sys.exit(0 if sys.version_info[:2] in ((3,12),(3,14)) and struct.calcsize('P') == 8 and sysconfig.get_platform() == 'win-amd64' else 1)" >nul 2>&1
        if not errorlevel 1 (
            set "VAULTNET_PYTHON=%%~P"
            exit /b 0
        )
    )
)
exit /b 1

:python_ausente
echo Nao foi encontrado Python 3.14 ou 3.12 x64.
echo Instale Python 3.12 ou 3.14 x64 pelo site oficial.
echo Depois, abra este arquivo novamente. Consulte LEIA-ME.txt.
goto erro

:pacote_incompleto
echo Coloque os arquivos deste ZIP na pasta que contem app.py e iniciar_windows.py.
goto erro

:pasta_invalida
echo Nao foi possivel acessar a pasta do sistema.
pause
endlocal
exit /b 1

:ja_aberto
:cancelado
popd
endlocal
exit /b 0

:erro
echo.
echo O sistema nao iniciou. Confira a mensagem acima e LEIA-ME.txt.
pause
popd
endlocal
exit /b 1
