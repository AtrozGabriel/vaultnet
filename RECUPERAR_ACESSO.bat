@echo off
setlocal
pushd "%~dp0"
if not exist ".venv\Scripts\python.exe" goto erro
".venv\Scripts\python.exe" -I "acesso_rede.py" --recuperar
if errorlevel 1 goto erro
start "" "http://127.0.0.1:8081/login"
pause
popd
exit /b 0
:erro
echo Nao foi possivel recuperar. Confira se esta na pasta original do projeto.
pause
popd
exit /b 1
