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
