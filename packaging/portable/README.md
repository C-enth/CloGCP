# CloSec 0.8.4 portable application

Targets: macOS (arm64, x86_64) and Windows x64, Python 3.12 64-bit. React is compiled and
included. Dependencies install **offline** from the bundled `wheelhouse/<platform>` with
hash-locked `locks/<platform>.txt`; setup never downloads packages, Python, Node or Docker.
The running application binds to loopback and makes no AWS/GCP API calls.

macOS, from the extracted directory:

```sh
bash setup-macos.sh
bash start-macos.sh            # optional: bash start-macos.sh /path/to/workspace
```

Or double-click `CloSec.command` in Finder: the first run performs the same offline setup,
then every run starts CloSec and opens the browser. The release is unsigned, so the first
time macOS may require right-click > Open. Close the Terminal window to stop CloSec.

Windows x64 PowerShell, from the extracted directory, under your approved execution policy:

```powershell
.\setup-windows.ps1
.\start-windows.ps1            # optional: -Workspace D:\CloSec\workspace
```

Or double-click `CloSec.cmd` in Explorer: the first run performs the same offline setup,
then every run starts CloSec in the default workspace and opens the browser. It is a plain
batch file, so it neither needs nor changes the PowerShell execution policy. SmartScreen may
warn the first time (More info > Run anyway). Close the console window to stop CloSec.

`verify.py` checks every file (source, wheels, locks, collectors, docs) against
`portable-manifest.json` before setup and start. Assessment data lives in your per-user
OfflineAWSAnalyzer/workspace directory, or the workspace you pass; a SYNTHETIC workspace
cannot accept customer evidence (`CLOSEC_ENVIRONMENT=synthetic` / `-Environment synthetic`).
No assessment evidence is bundled.

Workflow: **Evidence import** → choose an AWS/GCP ZIP or folder → **Validate evidence** →
**Import and analyze** → **Open assessment results** → review, approve, export. See
`docs/OPERATOR_GUIDE.md`. The corrected collectors are in `collectors/` with their contract.

Native Windows operation, the corrected collectors against real cloud APIs, and original
customer-evidence compatibility require acceptance in an authorized environment
(`docs/RELEASE_0.7.0.md`, field-acceptance checklist).
