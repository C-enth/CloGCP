# Windows startup correction — release candidate 0.8.4-clogcp.2

The reported traceback occurs in the platform preflight before dependency installation.
Windows PowerShell's native argument handling removes the embedded double quotation
marks from the Python `-c` argument, turning the intended string literal into the
undefined identifier `win32`. The subsequent Python-required message is therefore not
proof of an incorrect installed Python version.

`setup-windows.ps1` now invokes `check-windows.py` as a separate file. The check still
requires Windows x64 CPython 3.12 and now explicitly checks the interpreter word size.
No PowerShell execution policy is changed. Offline dependency locks, assessment code,
client workspaces and original CloSec packages are unchanged. The release builder
uses the corrected local Windows installer and includes the preflight file, preventing
it from silently restoring the old baseline installer.

Do not edit the original release script in isolation: its integrity manifest hashes it.
The corrected portable archive has matching file hashes and version metadata.

For an immediate workaround with the unchanged original .1 package, open **Command
Prompt** in the extracted folder containing `CloGCP.cmd` and run each line only if the
previous command succeeds:

```bat
py -3.12 verify.py
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install --no-index --only-binary=:all: --find-links wheelhouse\windows-x64 --require-hashes -r locks\windows-x64.txt
.venv\Scripts\python.exe -m pip check
CloGCP.cmd
```

This prepares the same offline environment without invoking the faulty PowerShell
preflight. It does not change the release files or bypass source/dependency integrity.
It does not open or reset any assessment workspace during installation.

Regression checks exercise platform/version/word-size rejection, clean error exits and
the file-based invocation. A native Windows PowerShell test, including paths containing
spaces, is provided and must pass on Windows before native acceptance can be claimed.
No Windows runner is available in this macOS development session. Local test and archive
results are recorded alongside the hotfix archive. The verified archive is distributed
as `CloGCP.zip` in the repository and in release candidate `v0.8.4-clogcp.2`.
The original `.1` release is retained.

Primary reference:
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parsing?view=powershell-5.1


## Git clone integrity error — 2026-10-24

The reported second startup failure was reproduced directly in the Git clone.
The source checkout does not contain `portable-manifest.json` or the offline wheels.
Its launcher incorrectly tried to validate the source checkout as a portable package,
producing the misleading instruction to re-extract the distribution.

The checkout's `CloGCP.cmd` now invokes `run-portable.py` before source verification
when no portable manifest is present. This standard-library helper pins the exact
SHA-256 of the existing `.2` ZIP, validates bounded archive paths, extracts to a fresh
ignored `.portable/` application folder, verifies all packaged manifest entries and
launches the extracted `CloGCP.cmd`. It verifies cached application files before reuse
and refuses changed files. It does not bypass integrity, overwrite existing installs,
open a workspace during preparation, reset configuration or change the release ZIP.
Running `setup-windows.ps1` in the source root now gives the correct launcher instruction.

Recovery from the clone folder: `git pull --ff-only`, then `.\CloGCP.cmd`.
An already running assessment does not need to be stopped to update Git; start the
updated launcher after closing the old application normally to release its workspace lock.

Synthetic launcher/isolation regressions: **22 passed, 2 skipped**. Skips require native
Windows PowerShell/cmd.exe. The actual 310-file ZIP manifest and extracted verifier pass,
including cache reuse. Ruff and source hash checks pass. Native Windows launch remains
pending; the development host is macOS. The first local preparation probe used the
host's Python 3.9 and failed; rerunning with the required Python 3.12 passed. The helper
now reports an explicit Python-version error rather than a traceback for that case.
