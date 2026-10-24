# CloGCP operations

This independent correction build reuses CloSec's GUI and reporting. The window still
uses CloSec branding. Keep this folder and its workspace separate from the installed
CloSec application. Do not overwrite CloSec, its ZIP, settings, database or reports.

Requires Python 3.12 for bundled offline wheels. On macOS run `sh CloGCP.command`.
On Windows extract to a new folder and run `CloGCP.cmd`. Windows execution is pending
native acceptance; do not treat a macOS build as a Windows validation. Setup uses
only bundled hash-locked wheels. No cloud collection or network access is required.

Defaults: macOS `~/Library/Application Support/CloGCP/workspace`; Windows
`%LOCALAPPDATA%\CloGCP\workspace`. Configuration uses CloGCP-specific directories.
`CLOGCP_WORKSPACE` and `CLOGCP_CONFIG_DIR` override these locations. Inherited
`CLOSEC_WORKSPACE` and `CLOSEC_CONFIG_DIR` do not select the old CloSec workspace.
Existing nonempty unmarked workspaces are refused before database writes.

## Analyze existing collector evidence locally

Use an untouched copy of the already collected GCP packages. No further collection
is needed for supported datasets. Import through the existing GCP GUI, run assessment,
inspect evidence and review findings as before. For all additional assurance reports,
use the command below (macOS; Windows uses `.venv\Scripts\python.exe`):

```sh
PYTHONPATH=src .venv/bin/python -m offline_analyzer.clogcp analyze \
  --packages /path/to/project-one /path/to/project-two \
  --workspace /path/to/NEW-CloGCP-workspace \
  --output /path/to/NEW-CloGCP-reports
```

The output directory must not exist. Workspace and output must be outside the input
package. The source packages are copied into the independent workspace without
modification. Do not pass `--synthetic` for real locally authorized collector evidence.
Inspect collection coverage and evidence limitations before accepting any finding.
Configuration observations are not proof of effective access or exploitation.

Outputs include the existing assessment workbook and report ZIP, plus
`CloGCP_Analysis_Assurance.xlsx`, its full companion JSON and a run summary. Use
GCP_Observation_Register → GCP_Evidence_Index → GCP_Evidence_Details for provenance.
The assurance workbook includes dataset coverage, unassessed families, historical
comparison, domain distribution, insufficient evidence, high/critical review and
existing root-cause grouping. Criteria with no approved requirement remain review
observations. Missing evidence never means PASS.

## Optional historical comparison

Close CloSec completely first. Export from a copy of the original closed workspace
if desired. The adapter refuses an active WAL and opens DuckDB read-only, with no
migration or repair. It supports the current persisted schema; incompatible schemas
must be handled separately, never by migrating the original database here.

```sh
PYTHONPATH=src .venv/bin/python -m offline_analyzer.clogcp export-history \
  --workspace /path/to/closed-CloSec-workspace --run EXISTING_RUN_ID \
  --output /path/outside-workspace/NEW-history.json
```

Add `--history /path/to/history.json` to `analyze`. JSON contains confidential review
and evidence metadata: keep it locally protected. IDs, decisions, SRE validations,
report revisions and exclusions are retained as history. Results without a local
current decision stay PENDING. Explicit current-workspace decisions are reported from
local records, with their fingerprints checked; the adapter never creates a decision. Exact matches merely offer analyst consideration of carry-forward; changed
rule semantics, severity, interpretation or evidence require revalidation. Nothing
writes back to CloSec. The analyzer works without historical data.

## Verify download

macOS: `shasum -a 256 CloGCP.zip`.
Windows PowerShell: `Get-FileHash .\CloGCP.zip -Algorithm SHA256`.
Compare against `CloGCP.zip.sha256`. After extraction run `python3.12 verify.py`
(Windows: `py -3.12 verify.py`) before setup. Store new reports outside the application
folder; updates use a fresh folder and the existing **CloGCP** workspace.

No customer assessment has been validated in development. Run the final assessment
locally in the authorized client environment and review differences before approving
findings. Never copy historical approvals onto changed evidence automatically.
