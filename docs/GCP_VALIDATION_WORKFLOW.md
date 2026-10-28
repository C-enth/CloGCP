# CloGCP validation workflow (one page)

For the assessor finalizing B1/B2. CloGCP 0.8.5-clogcp.3, finalizer 1.0.0rc2.

## 0. Work on a copy, never on the live workspace or a backup

1. Close CloGCP. Copy a backup folder (made with **Workspace → Back up now**) to a **new**
   folder, for example with Explorer/Finder. Alternatively, use the verified copy, which
   compares every file hash and table row:
   `python -m offline_analyzer.storage.side_by_side --source BACKUP --target NEW_COPY`.
2. Start CloGCP, then go to **Workspace → Open existing workspace (recovery)**. Choose the
   copy, then click **Check location**. The check is read-only and applies the same checks
   as the launcher. A folder CloGCP would refuse shows its reason and cannot be opened:
   not a CloGCP workspace, leftover journal, older or newer schema, or in use. Tick the
   confirmation, click **Open this workspace**, then **Restart CloSec now**. The live
   workspace and the backup are never opened. If a remembered folder is refused at a later
   start, CloGCP shows this location screen with the reason instead of failing.
   - Leftover journal (`assessment.duckdb.wal`, after a crash): with CloGCP closed, make a
     recovered copy and open the copy. The source stays byte-identical:
     `python -m offline_analyzer.storage.side_by_side --source CRASHED --target NEW_COPY
     --recover-journal`. It prints the counts before and after; they must match.
   - Older schema: the same command with `--upgrade-additive` instead.
   - Start directly on a folder (launch argument, then environment variable, then remembered
     location; a refusal prints `Refused: CODE` and its reason):
     Windows `CloGCP.cmd --workspace "D:\CloGCP\copy"` or `set CLOGCP_WORKSPACE=D:\CloGCP\copy`
     then `CloGCP.cmd`; macOS `sh CloGCP.command --workspace "/path/copy"` or
     `CLOGCP_WORKSPACE="/path/copy" sh CloGCP.command`.
3. Optional count snapshot (CloGCP closed): `python tools/workspace_counts.py NEW_COPY`. It
   prints counts only: findings by run, status, stage, severity and rule; attack paths by
   class; collector versions. It refuses to run while the database is open.

## 1. Validate findings in the tool

- Open **Findings workbench**, then each finding's **Finding details**. Read **What the evidence
  shows** (only the cited bindings or fields), **Expected state**, **What the evidence does
  not establish** and **Evidence limits**.
- Record a decision with **Confirm**, **Reject**, **Mark for validation** or **Record
  exception** (needs a note). For findings that should not appear in the client report, use
  **Exclude from report** with a reason.
- **NEEDS_REVALIDATION** means the evidence changed since your decision (for example, a new
  analysis version). Re-review it; decisions are never carried over silently.
- **MANUAL_VALIDATION_REQUIRED** results (for example Cloud Run with internal-only ingress)
  are neither a gap nor a Pass. Confirm them with the owner.
- Attack paths: **GCP → Attack Paths → Recalculate Attack Paths**. SUPPORTED means
  configuration-supported, not exploited. Review CONDITIONAL and INSUFFICIENT_EVIDENCE
  prerequisites.

## 2. Group and export

- **Group** / **Consolidated findings** show the same issue across resources. In the register,
  column 29 shows the group title with its record count, and column 33 shows the count.
- Go to **Report center → Generate an assessment export** and keep **Only findings marked
  valid (confirmed) — default**. The Excel file contains `GCP_Observation_Register` (40
  columns), `GCP_Evidence_Index`, `GCP_Evidence_Details`, and `GCP_Review_Audit` (your recorded
  analyst/SRE decisions). Register columns 35, 36, 38 and 39 (SPOC assessment, SPOC
  justification, Reviewed by, Review date) and 34 (Applicability) are intentionally blank.
  Frozen editions keep their stored text; new wording appears only in new exports.

## 3. Run the finalizer (never on the original export)

```
python -m clogcp_report_finalizer --input EXPORT.xlsx --output NEW_FOLDER
```

The output is `NEW_FOLDER/CloGCP-client-report.xlsx` plus `Assessor-QA-Exceptions.json`. The
input file is hash-checked before and after the run and is never modified. Work through
every QA entry. **MANUAL_VALIDATION_ITEM**, **OBSERVATION_EVIDENCE_CONTRADICTION**,
**MISSING_FOCUSED_EVIDENCE**, **DUPLICATE_REPORTABLE_OBSERVATIONS** and
**PREFILLED_REVIEW_FIELDS** (older exports) need an assessor decision. Make technical
corrections in CloGCP and re-export; the finalizer only changes presentation.

## 4. Check in desktop Excel (not yet verified natively)

The workbook opens without a repair prompt. Sheet order is Assessment_Summary,
Consolidated_Issues, Client_Observation_Register, … Headers are the 40 approved ones, with
frozen panes and filters working. Evidence and index hyperlinks jump to the right rows.
There are no formulas or external links (the Data → Edit Links box is empty). Long evidence
cells wrap and stay readable. Fill in Reviewed by, Review date and the SPOC columns
yourself.

## 5. Targeted-collector delta, once permissions arrive

1. From the copy: `python -m offline_analyzer.evidence.inventory --workspace NEW_COPY --run
   RUN --output inventory.json`. Then `python -m clogcp_delta.planner --help` to build
   `approved-plan.json` from the missing-access matrix, the inventory and the approved
   buckets, folders and Discovery Engine parents.
2. Dry run (no token): `python -m clogcp_delta --plan approved-plan.json --output DRY`.
   Execute with the approved gcloud login: `python -m clogcp_delta --plan approved-plan.json
   --matrix matrix.json --execute --output DELTA`. The collector is read-only, paced and
   bounded.
3. In CloGCP: **Evidence import** the `DELTA` package. Then go to the base assessment, open
   **Attack Paths → Apply supplementary evidence**, select the import and choose **Create
   affected analysis version**. B1/B2, their decisions and frozen editions are untouched.
4. Select the new version and **Recalculate Attack Paths**. Re-review NEEDS_REVALIDATION and
   new findings, then export and finalize again (steps 2–3).
