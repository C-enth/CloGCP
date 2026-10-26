# Upgrade and rollback — 0.8.5-clogcp.1

Prerequisites: CPython 3.12 (Windows x64 or macOS arm64/x86_64); a closed, healthy CloGCP
workspace. Do not run two application versions against the same workspace. No Node or
internet is needed after the complete assets have been downloaded. Additional gcloud
reads require separately approved permissions and a reconciled plan.

1. Sign into GitHub, open `https://github.com/C-enth/CloGCP/releases/tag/v0.8.5-clogcp.1`
   and download `CloGCP.zip`, the two standalone ZIPs and `SHA256SUMS.txt`. Verify
   `Get-FileHash .\CloGCP.zip -Algorithm SHA256` (macOS: `shasum -a 256 CloGCP.zip`)
   against the published checksum. Verify each other ZIP before use.
2. Close the old application normally. Back up the **whole workspace**, including
   `assessment.duckdb`, raw artifacts, reviews, frozen editions, job metadata and sidecars.
   Keep the old installation and workspace. If shutdown recovery is pending, recover with
   the previous compatible version first; the new release refuses automatic recovery.
3. Extract the application beside the old installation, for example `CloGCP-0.8.5/`.
   In its `CloGCP/` folder, run `powershell -NoProfile -File .\setup-windows.ps1`
   (macOS: `CLOSEC_PYTHON=python3.12 sh setup-macos.sh`). Use your organization's
   approved PowerShell execution policy. Setup installs bundled wheels offline and
   verifies dependencies; it does not open or analyze assessment data.
4. Make a verified **new workspace copy**, with explicit additive upgrade if needed.
   From Windows Command Prompt in the extracted `CloGCP/` folder:

   ```bat
   set "PYTHONPATH=%CD%\src"
   .venv\Scripts\python.exe -m offline_analyzer.storage.side_by_side --source "D:\Assessments\CloGCP-workspace" --target "D:\Assessments\CloGCP-workspace-v085" --upgrade-additive
   ```

   macOS:

   ```sh
   PYTHONPATH=src .venv/bin/python -m offline_analyzer.storage.side_by_side --source "/path/to/CloGCP-workspace" --target "/path/to/CloGCP-workspace-v085" --upgrade-additive
   ```

   Replace example paths with actual locations. Target must not exist. Only the two known
   missing consolidation tables may be added, empty, in the new copy. Original rows/files
   are checked unchanged; `side-by-side-recovery.json` records every original file/table hash.
   Unknown schemas, unsafe links or pending journals stop the operation. No evidence is
   reimported and no assessment is recalculated. Preserve any refused copy for diagnosis.
5. Launch `CloGCP.cmd --workspace "D:\Assessments\CloGCP-workspace-v085"` (macOS:
   `sh CloGCP.command --workspace "/path/to/CloGCP-workspace-v085"`). Select existing B1/B2
   assessments. Confirm the expected finding IDs, counts, frozen edition and analyst/SRE
   decisions against the backup/export and recovery manifest. Opening does not migrate,
   recalculate, rewrite findings, finalize reports or inherit new path approvals.
6. In the existing GCP/consolidated attack-path view, choose **Recalculate Attack Paths**.
   It reads stored normalized evidence/relationships, saves a separate engine-2.0.1 version
   and old/new comparison. Do not rebuild Bulk Enterprise Assessment or reimport evidence.
   New paths remain unreviewed and execution-unverified.
7. Continue B2 validation in the copied workspace. Keep the original B1 frozen edition and
   decision history; qualify changed evidence and review status explicitly.
8. Later, after missing IAM permissions and exact scopes are approved, export stored
   inventory and run the separate collector planner/dry-run described in
   `GCP_FINAL_WORKFLOW.md`. Execute only the reconciled approved plan. No API enablement
   or IAM mutation is performed. Import the native delta folder, create a supplementary
   analysis version, inspect finding reconciliation, then independently recalculate paths.
   Shared IAM dependencies currently use broader security evaluation **in the new run**;
   fine-grained rule-result caching is not implemented. The finalized baseline is unchanged.
9. Download the assessment Excel/report export. Extract the standalone finalizer, verify it,
   and set `CLOGCP_PYTHON` to the compatible application Python (Windows:
   `set "CLOGCP_PYTHON=D:\Apps\CloGCP-0.8.5\CloGCP\.venv\Scripts\python.exe"`). Run
   `start-windows.cmd --input "D:\Exports\assessment.xlsx" --output "D:\Exports\review-copy"`
   (macOS: `CLOGCP_PYTHON=/path/to/python sh start-macos.sh --input /path/to/assessment.xlsx --output /path/to/review-copy`).
   Optional evidence/guidance/path/history exports must be selected explicitly; see tool help.
   Review `CloGCP-client-report.xlsx`, `Assessor-QA-Exceptions.json` and `qa-summary.json`.
   Missing evidence remains a QA exception. The tool preserves the source, ratings and reviews;
   it never reruns the analyzer. `--final` additionally requires explicit human acceptance
   and matching verification inputs; installation does not provide either.

Rollback: close the new application, retain its workspace for audit, and launch the previous
installation with the **untouched original workspace** or its verified backup. Never open
an upgraded copy with older software. Decisions made after upgrading remain in the new
copy; do not silently merge them into the baseline. Previous release tags/assets are retained.

Known gates: native Windows build/run, native Excel/Tk, actual approved cloud collection and
client B1/B2 acceptance. The assets are portable Python source applications, not native EXEs.
