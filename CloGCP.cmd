@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    powershell -NoProfile -File "%~dp0setup-windows.ps1"
    if errorlevel 1 exit /b 1
)
"%~dp0.venv\Scripts\python.exe" "%~dp0verify.py"
if errorlevel 1 exit /b 1
set "PYTHONPATH=%~dp0src"
"%~dp0.venv\Scripts\python.exe" -m offline_analyzer.clogcp --environment assessment --port 0 %*
exit /b %errorlevel%
