# Offline setup: installs only hash-locked Windows x64 wheels (locks\windows-x64.txt). Never
# downloads. Release ZIP: wheels are bundled. Source clone: set CLOGCP_WHEELHOUSE to a folder
# holding windows-x64\ wheels, e.g. the wheelhouse folder of the matching release ZIP.
# Run with the execution policy your organization approves; this script does not change it.
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw 'Install Windows x64 Python 3.12 with its Python launcher first.' }
& py -3.12 (Join-Path $Root 'check-windows.py')
if ($LASTEXITCODE -ne 0) { throw 'Windows x64 Python 3.12 is required.' }
& py -3.12 (Join-Path $Root 'verify.py')
if ($LASTEXITCODE -ne 0) { throw 'Portable source integrity check failed.' }
$Wheels = Join-Path $Root 'wheelhouse\windows-x64'
if (-not (Test-Path -LiteralPath $Wheels) -and $env:CLOGCP_WHEELHOUSE) {
    $Wheels = Join-Path $env:CLOGCP_WHEELHOUSE 'windows-x64'
}
$Lock = Join-Path $Root 'locks\windows-x64.txt'
if (-not (Test-Path -LiteralPath $Wheels) -or -not (Test-Path -LiteralPath $Lock)) { throw 'Wheels for windows-x64 not found. Use the release ZIP, or set CLOGCP_WHEELHOUSE to its wheelhouse folder.' }
& py -3.12 -m venv (Join-Path $Root '.venv')
if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
$Python = Join-Path $Root '.venv\Scripts\python.exe'
& $Python -m pip install --no-index --only-binary=:all: --find-links $Wheels --require-hashes -r $Lock
if ($LASTEXITCODE -ne 0) { throw 'Offline dependency installation failed. Preserve the error output.' }
& $Python -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Dependency verification failed.' }
Write-Output 'CloGCP setup complete. Run: .\CloGCP.cmd'
