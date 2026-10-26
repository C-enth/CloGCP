@echo off
rem Double-click on Windows x64 to start CloSec; close this window to stop it. The same file
rem works in three places: next to a bundled release\ ZIP it extracts that once and starts it;
rem in an extracted release it performs the offline setup on first use; in a developer
rem checkout it uses the existing .venv. Plain batch, so the PowerShell execution policy is
rem neither needed nor changed.
setlocal
set "ROOT=%~dp0"
set "RELEASE="
for %%F in ("%ROOT%release\CloSec-*-portable-source.zip") do set "RELEASE=%%~fF"
for %%F in ("%RELEASE%") do set "APPNAME=%%~nF"
if defined RELEASE goto :release
set "PYTHON=%ROOT%.venv\Scripts\python.exe"
if not exist "%PYTHON%" call :setup || goto :failed
if exist "%ROOT%verify.py" "%PYTHON%" "%ROOT%verify.py" || goto :failed
set "PYTHONPATH=%ROOT%src"
rem Workspace: a folder given as the first argument, else CLOSEC_WORKSPACE (read by the
rem launcher), else the location remembered in CloSec, else the default. Quoted, so spaces
rem and non-ASCII characters in paths are passed through unchanged.
set "DEFAULT_WORKSPACE=%LOCALAPPDATA%\OfflineAWSAnalyzer\workspace"
if not "%~1"=="" (
    "%PYTHON%" -m offline_analyzer.launcher --workspace "%~1" --default-workspace "%DEFAULT_WORKSPACE%" --environment assessment --port 0 || goto :failed
    exit /b 0
)
"%PYTHON%" -m offline_analyzer.launcher --default-workspace "%DEFAULT_WORKSPACE%" --environment assessment --port 0 || goto :failed
exit /b 0

:release
rem One folder per release ZIP, so a newer release is extracted and set up afresh.
set "APP=%ROOT%release\%APPNAME%-app"
if exist "%APP%\CloSec.cmd" goto :run_release
echo First start: extracting the bundled CloSec release...
if exist "%APP%.partial" rmdir /s /q "%APP%.partial"
mkdir "%APP%.partial" || goto :failed
rem tar.exe ships with Windows 10 1803 and later and reads ZIP files.
tar -xf "%RELEASE%" -C "%APP%.partial" || goto :failed
move "%APP%.partial" "%APP%" >nul || goto :failed
:run_release
call "%APP%\CloSec.cmd" %*
exit /b

:setup
if not exist "%ROOT%wheelhouse\windows-x64" (
    echo This checkout has no bundled release and no .venv; see README.md to set it up.
    exit /b 1
)
where py >nul 2>nul || (echo Python 3.12 is required. Install Windows x64 Python 3.12 from python.org with the py launcher, then double-click CloSec.cmd again. & exit /b 1)
py -3.12 -c "import sys,platform; assert sys.platform == 'win32' and sys.version_info[:2] == (3,12) and platform.machine().upper() in ('AMD64','X86_64')" || (echo Windows x64 Python 3.12 is required; install it from python.org with the py launcher. & exit /b 1)
echo First start: installing CloSec offline from the bundled packages...
py -3.12 "%ROOT%verify.py" || exit /b 1
py -3.12 -m venv "%ROOT%.venv" || goto :setup_failed
"%PYTHON%" -m pip install --no-index --only-binary=:all: --find-links "%ROOT%wheelhouse\windows-x64" --require-hashes -r "%ROOT%locks\windows-x64.txt" || goto :setup_failed
"%PYTHON%" -m pip check || goto :setup_failed
exit /b 0

:setup_failed
rem A partial environment must not skip setup next time.
if exist "%ROOT%.venv" rmdir /s /q "%ROOT%.venv"
exit /b 1

:failed
echo.
echo CloSec stopped or did not start. Review the messages above.
pause
exit /b 1
