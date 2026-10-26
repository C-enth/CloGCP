# CloSec — operational local GUI

Current 0.4.2 report-ready findings, independent approvals, copy/Word-compatible export,
additional investigations and service/domain coverage: see
[report findings usage](REPORT_FINDINGS_USAGE.md).

Current end-to-end workflow, including collector downloads: see
[the operator guide](OPERATOR_GUIDE.md).

Sprint 3 adds multi-import enterprise assessments and a ninth cross-account screen.
Use [ENTERPRISE_USAGE.md](ENTERPRISE_USAGE.md) for the implemented combined workflow,
account groups, filtered graph, shared review, limits and new Excel sheets. The original
import → assess → review → export workflow below remains available for individual runs.

From the repository root on macOS, using this session's installed virtual environment:
```sh
.venv/bin/python -m offline_analyzer.launcher
```
One command initializes `artifacts/gui-workspace`, binds to 127.0.0.1:8765, serves the
compiled React interface and opens the default browser with a protected local session.
No Node development server, internet, AWS credentials or remote AI is required at runtime.
Leave the terminal running. Stop with the GUI **Stop app** action or Ctrl+C; running
transactional work finishes safely. Use `--port 8766` if the default port is occupied.

A different local workspace can be chosen at launch:
```sh
.venv/bin/python -m offline_analyzer.launcher --workspace artifacts/my-assessment --port 8766
```
No API accepts arbitrary server filesystem paths. Do not run another CLI/GUI writer
against the same workspace concurrently. The GUI uses an OS ownership lock and one
serialized database executor; the existing DuckDB transaction/process lock remains in
place. Startup failures are reported generically without customer paths or exception
contents. A failed launch must be resolved, not treated as a running assessment.

## First workflow

1. Choose **Evidence import** → **Select package folder**, then select
   a synthetic package generated under tools/fixtures for the demonstration. Keep origin **Synthetic / test
   evidence**. The folder contains manifest.json and its JSON artifacts. Alternatively,
   select all those JSON files together with **Select JSON files**.
2. Click **Validate evidence**. Review parser acceptance, required fields, collection
   completeness/errors and manifest account/Region metadata. Acceptance is a structural
   gate, not proof of authorization correctness or complete account coverage.
3. Click **Import validated evidence**. The job reports QUEUED/RUNNING/SUCCEEDED or a
   fixed error code. The active evidence run is selected automatically.
4. Click **Run assessment**. Existing normalization, correlation, security rules and
   candidate generation are reused; no frontend security evaluator exists.
5. Open **Findings workbench** → **View**. Inspect source references/times, methodology
   criteria, classification, severity, confidence, contradictions, missing validation
   and remediation. Linked normalized observations have integrity and redaction views.
6. Enter analyst identity/remarks and explicitly Confirm, Reject or Mark for validation.
   **Record exception** adds an exception remark and keeps NEEDS_VALIDATION; it is not
   an approved risk-acceptance state. Decisions persist across reimport/reassessment and
   restart. Changed evidence/rules can show NEEDS_REVALIDATION.
7. Open **Report center** → **Generate Excel** → **Download**. Other actions export JSON
   findings, account-scoped control results, coverage and normalized evidence registers.
   Previously GUI-generated reports remain downloadable after restart. No report action
   merges into a maintained customer tracker or overwrites it.

The synthetic package currently produces 5 represented accounts, 48 evidence files,
78 normalized observations, 72 evaluations, 4 candidate findings and 52 IAM investigation
records. These are demo results, not customer assessment results or 143-account readiness.
No production page inserts synthetic metrics or findings into the database.

## Screens

- Dashboard: persisted account/evidence/evaluation/finding/review metrics and existing
  IAM conclusion counts. Accounts represented does not mean every control was assessed.
- Evidence import: browser file/folder selection, streamed upload progress, server-owned
  format detection where unambiguous, validation diagnostics, import and assessment jobs.
- Account explorer: searched account list, distinct resource inventory, source coverage,
  evaluations, findings and existing IAM relationships; no Organizations access needed.
- Findings workbench: "Root-cause groups" with group-level Mark valid / Send to SRE / Exclude.
- Report center: report scope defaults to confirmed findings (warning shown otherwise);
  "Group findings by root cause" (default on);
  "Custom scope limitations" text per run.
- Findings workbench: source-backed investigation and persistent independent decisions;
  "Mark as false positive" (single or bulk, reason required) with an FP tag and a
  show/hide filter (false positives hidden by default).
- IAM intelligence: roles, resolved/unresolved policy metadata, trust/PassRole
  investigations, observed/evaluated relationships, organization context and evidence gaps.
  Relationship detail visualizes only its existing source/target; no graph traversal or
  invented edges. IAM records are projections of existing IamAnalysis, not live AWS answers.
  For GCP, "Principal roles" lists every observed binding of a service account, user or group
  across the imported projects with its resolution status; a finding's "View roles" link
  opens the same view.
- Evidence explorer: searchable normalized evidence metadata, linked results/findings,
  hash/locator integrity checks and bounded redacted normalized inspection. Raw original
  files, policy documents, conditions, tags and credential-capable fields are not served.
- Network analysis: collected EC2/SG/ENI/route/RDS configuration and existing network/RDS
  candidate findings. It does not establish NACL/host/service or end-to-end reachability.
- Report center: existing openpyxl workbook plus streaming JSON register exports and
  persistent generated report downloads under opaque IDs.

## Input and privacy limits

Customer evidence stays local in the workspace's ignored `uploads`, content-addressed
`raw`, database and report directories. Protect the workspace with customer OS
permissions/disk protection; use artifacts/ or data/private/ in this repository. Selecting
files creates local copies and does not modify originals. Imports preserve manifest
hashes and existing bounded parser/credential rejection behavior. Paths must be relative
and inside the selected package; no archive extraction, imported execution or formulas.

Packages need approved `manifest.json` (schema r0.1), subject request parameters, true
collection times, account/Region scope, original hashes and honest coverage/errors.
A single JSON export requires collection timestamp/context, optional format/operation
selection and request-parameter JSON. Server detection handles known unambiguous response
containers; GetRolePolicy/policy-version/singleton shapes may require explicit operation.
Single-file coverage stays PARTIAL. Known formats are AWS JSON and Prowler OCSF 5.10.0;
unsupported formats/services are rejected, not silently converted to findings.

Limits include 64 MiB/file, 256 MiB/package, 256 source descriptors plus manifest,
30 staged upload attempts per server session, 8 active/queued jobs and backend parser/
evaluation budgets. Browsing is paginated, with at most 100 records per API page (UI uses
30). Source diagnostics are bounded by package size. Uploads and reports are retained;
there is no destructive automatic cleanup. Queued jobs can be cancelled; running import/
assessment/report work cannot be interrupted safely and is allowed to finish. Job status
is session-local; persisted runs/decisions/reports survive restart. Run/report selectors
currently expose the newest 200 entries. These limits do not establish enterprise scale.

Framework telemetry is explicitly disabled, including environment-requested automatic
configuration. The API enforces exact loopback Host/Origin, fragment-secret session bootstrap, HttpOnly
SameSite session cookie, separate CSRF token for mutations, bounded request/upload sizes,
no CORS, no-store responses, CSP, nosniff and frame denial. Reopen through the launcher
when a new server session starts; a bare URL is not enough to bootstrap a new session.
Do not paste customer logs, reports or evidence into external AI or web services.

**Actual export compatibility remains unverified.** Use
[field-acceptance checklist](RELEASE_0.7.0.md) in the customer-controlled
environment before claiming field security correctness. Unsupported authorization
semantics and manual exploitation prerequisites remain documented in IAM_EVALUATION.md.

## Rebuild and test (development only)

Python >=3.11, Node >=22.12 and npm are development prerequisites; approved dependency
installation uses the network. Runtime launches require none of those Node tools.
```sh
.venv/bin/python -m pip install -e '.[dev,application]'
npm --prefix frontend ci
npm --prefix frontend run build
npm --prefix frontend test
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```
React/Vite output is bundled under `src/offline_analyzer/api/assets` and included in
Python wheels. The compiled bundle is delivered with this working tree, so rebuilding
is not required to use the exact launch command above. `frontend/.npmrc` skips optional
peer resolution (the test runner's optional browser/devtools peer chain is unused);
package-lock.json pins the build dependency tree. No Vite server is launched in production.

Practical browser tests use synthetic input and deny all non-loopback browser requests:
```sh
.venv/bin/python -m pip install playwright
PLAYWRIGHT_BROWSERS_PATH=artifacts/playwright-browsers .venv/bin/python -m playwright install chromium
RUN_GUI_BROWSER=1 PLAYWRIGHT_BROWSERS_PATH=artifacts/playwright-browsers \
  .venv/bin/python -m pytest tests/test_gui_browser.py -q
```
Browser runtime download is development-only and requires approved network access.
This test executes folder/file selection → validate → import → assess → view → review →
reload → reimport → inspect all screens → generate/download/open Excel, and separately
checks the launcher's initialization/browser URL/clean shutdown and workspace lock.
Screenshots from actual synthetic UI runs live in ignored artifacts/gui-screenshots/.

Windows can later use `.venv\Scripts\python.exe -m offline_analyzer.launcher`. Package
compiled assets alongside FastAPI/uvicorn/multipart dependencies, then build and validate
on Windows (launcher, browser opening, OS locks, ACLs, imports and Excel). No Windows
binary/build/runtime validation is claimed. A pinned offline wheelhouse/OS network denial
and 143-account performance test remain release gates.
