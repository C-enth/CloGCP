param(
    # Empty: CLOSEC_WORKSPACE, else the location remembered in CloSec, else the default.
    [string]$Workspace = '',
    [ValidateSet('assessment','synthetic')][string]$Environment = 'assessment'
)
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Python = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) { throw 'Run setup-windows.ps1 first.' }
& $Python -c 'import sys,platform; assert sys.platform == "win32" and sys.version_info[:2] == (3,12) and platform.machine().upper() in ("AMD64","X86_64"), "Windows x64 Python 3.12 is required"'
if ($LASTEXITCODE -ne 0) { throw 'Windows x64 Python 3.12 is required.' }
& $Python (Join-Path $Root 'verify.py')
if ($LASTEXITCODE -ne 0) { throw 'Portable source integrity check failed.' }
$env:PYTHONPATH = Join-Path $Root 'src'
$DefaultWorkspace = Join-Path $env:LOCALAPPDATA 'OfflineAWSAnalyzer\workspace'
if ($Workspace) {
    & $Python -m offline_analyzer.launcher --workspace $Workspace --default-workspace $DefaultWorkspace --environment $Environment --port 0
} else {
    & $Python -m offline_analyzer.launcher --default-workspace $DefaultWorkspace --environment $Environment --port 0
}
if ($LASTEXITCODE -ne 0) { throw 'CloSec startup failed; review the displayed startup stage.' }
