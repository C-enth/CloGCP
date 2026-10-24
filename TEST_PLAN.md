# CloSec regression and release validation

Use deterministic synthetic fixtures generated in pytest temporary directories. No
customer inputs, pre-generated assessment files or cloud access are required. Private
methodology reconciliation is local-only and skips when the authorized workbook is absent;
its pinned hash/specifications are unchanged. Do not weaken assertions to remove data files.

## Commands

From the repository root, with approved developer dependencies and Chromium installed:

```sh
.venv/bin/ruff check .
.venv/bin/ruff format --check src tests tools
.venv/bin/python -m compileall -q src tests tools
.venv/bin/python -m pip check
RUN_GUI_BROWSER=1 PLAYWRIGHT_BROWSERS_PATH=artifacts/playwright-browsers .venv/bin/python -m pytest -q --tb=short
npm --prefix frontend test
npm --prefix frontend run build
.venv/bin/python -m offline_analyzer.contracts.schema artifacts/schemas-new
.venv/bin/python tools/source_release.py --output artifacts/source-audit-new
```

Chromium workflows use the actual compiled frontend and local API; no mocked dashboard
substitutes for assessment. They exercise AWS folder/ZIP import, GCP native package import,
assessment, provider/domain filters, evidence-backed candidates and qualified investigations,
technical confirmation, independent recommendation/narrative approvals, clipboard readback,
RTF/Excel downloads, reimport, reload and actual server restart. Non-loopback requests fail.

## Maintained security and correctness assertions

- Strict versioned contracts, UTC/scope checks, checksums, project/account mismatch refusal,
  raw provenance, bounded input, credential rejection, unsafe archive/path refusal and rollback.
- Missing/denied/partial/paginated/unsupported evidence does not establish scope PASS.
- AWS IAM trust, allow/deny/SCP/boundary and network reasoning retain existing semantics;
  static relationships and configuration never establish exploitation.
- GCP rule families include positive, negative, incomplete and unsupported contexts;
  IAM inheritance uncertainty, public-storage prerequisites and SCC/native traceability persist.
- No invented cross-cloud transitions or merged identities; scope denominators, coverage,
  consolidated domains/findings/path views and Excel reconcile to stored assessment data.
- Immutable review/report revisions, independent approval gates, current-evidence revalidation,
  client-field separation, formula-neutralized reports, restart and backup/restore.
- Historical AWS fixture bytes are pinned by SHA-256 in test source instead of committed JSON.
- Production archive assembly excludes acceptance evidence, while the separate test archive
  is deterministic, checksummed, importer-validated and refused inside source directories.
- Source/index/history audits block unknown/private/new evidence paths and credential signatures.
  Exact previously reviewed synthetic example paths remain historical notices, not new exceptions.
- Bundled contract JSON equals generated Pydantic schemas. Metadata/pin/hash checks remain
  required; do not describe schema equality as a separate JSON Schema metaschema check.

## End-to-end development exercise

```sh
PYTHONPATH=src .venv/bin/python -m tools.multicloud_scale --output artifacts/multicloud-cleanup-new --projects 3
.venv/bin/python tools/build_wheelhouse.py --output artifacts/wheelhouse-new
PYTHONPATH=src:. .venv/bin/python tools/collector_contract.py --check
```

The combined exercise generates evidence outside tracked directories, imports/assesses AWS
and GCP, creates an enterprise snapshot, exports/reopens Excel, reconciles provider rows and
runs the release audit. The browser suite supplies dashboard, findings, paths, approvals and
RTF acceptance. Low-density benchmarks are not maximum-estate or Windows certifications.

## Validation record

Pre-cleanup 0.5.0rc1 baseline: 571 tests passed with six Chromium workflows, three frontend
cases and a production bundle build. Focused cleanup fixture/publication/packaging checks:
24 passed in 10.73 seconds before the added separate-acceptance cases. Final cleanup:
576 passed in 142.87 seconds, zero failures/skips, six Chromium workflows. Three frontend
cases, TypeScript/Vite build, Ruff (140 files), compileall, pip check, 25-schema export and
bundled equality passed. Windows wheel integrity: 30 verified. See the release handoff.

No Windows host is available. PE build/execution, collector PowerShell execution, native
Word/Excel, full OS outbound-denial, signing/EDR and customer analyst acceptance remain
unvalidated. Real-export compatibility requires approved tool-generated evidence; the
owner requested synthetic-only testing. No history rewriting is part of this task.

## 0.5.1 operational regression additions

Temporary deterministic legacy fixtures test Windows separators, CRC/path/collision/link/
size/ratio security, partial collections, source integrity limitations and UTF-8 BOM JSON.
Scope lifecycle tests exercise both providers, replacement rollback/history, exact typed
confirmation, journal recovery, scoped raw deletion, approval invalidation, cross-scope
reassessment, reimport, workspace restart and backup/restore. An additional Chromium
workflow uses compiled assets and real API/storage for import, findings, both scoped
deletions, reimports, provider focus/hover/reload and consolidated Excel download.

All inputs are generated in temporary directories. Browser screenshots/results are
ignored artifacts. Real-evidence and Windows gates require actual local validation.

Validation recorded 2026-10-12: 628 Python/API tests passed with RUN_GUI_BROWSER=1,
including seven real Chromium workflows against compiled frontend assets. One existing
Starlette/httpx test-client deprecation warning remains. Frontend Vitest: 3 passed;
TypeScript/Vite production build, Ruff lint/format, pip check and compileall passed.
Bundled equality/schema and private methodology reconciliation passed in the full suite.
The synthetic 3-project multi-cloud smoke exported/reconciled 44 findings, 193
evaluations and 105 resources; release audit PASS. This is not estate-capacity certification.
Windows 30-wheel hash verification passed; Windows execution was unavailable.

## 0.5.1rc2 folder-selection regression

tests/test_pilot_import_browser.py uses actual compiled assets, local API/storage and
Chromium file choosers for both pilot-1.2.2 ZIP and complete-folder selections. The
synthetic folder contains 65 files (32 stdout JSON, 32 stderr and original manifest),
retaining 8 SUCCESS / 5 EMPTY / 19 FAILED declarations. Nested relative paths and
original hashes are checked; no uploaded JSON is rewritten. The browser checks the
pending-import controls before the POST returns, imports/assesses and reviews findings,
reimports across transports into the same run, imports AWS through both transports,
exports workbooks tied to each selected run, verifies all provider dashboards and
reopens the persisted database after server exit. External requests/page errors fail.
The separate Windows acceptance generator includes the same ZIP/folder test inputs.

This demonstrates the documented pilot transport, not original customer compatibility.
The earlier 76 focused checks alone did not validate the complete folder GUI flow.

Validation recorded 2026-10-13: complete suite with RUN_GUI_BROWSER=1 passed 632 tests
in 235.24 seconds, zero failures/skips, including nine real Chromium workflows.
Frontend Vitest 3 passed; TypeScript/Vite production build, Ruff lint/format (154 files),
compileall, pip check, 29-schema bundled equality and private reconciliation passed.
One existing Starlette/httpx deprecation warning remains. Both new pilot workflows
reopened the persisted GCP run with 9 observations, 20 evaluations and 1 candidate;
AWS had 78 observations, 97 evaluations and 8 candidates. Excel finding rows reconciled
to those runs, source hashes were unchanged and no external requests/page errors occurred.
The Windows 30-wheel integrity check and separate acceptance archive integrity passed.
No original customer package or Windows executable was processed in this session.

Development attempts exposed the old-run submission race and also required correcting
new test assumptions about drawer closure, asynchronous report completion and the
existing AWS workbook layout. An initial full-suite collection failed after moving
the shared fixture; its compatibility export was restored. These failures preceded
the final passing full suite and no existing assertion or safety gate was weakened.

## 0.5.1rc3 recovery validation — 2026-10-13

Full macOS suite: 645 passed, zero failed/skipped, 425.35 seconds. Fourteen browser
workflows include Chromium and WebKit pilot ZIP/folder and retry cases; actual launcher
children supplement the existing production-asset/API workflows. Three frontend tests,
TypeScript/Vite production build, Ruff and dependency verification pass. Thirty-one bundled
schemas reconcile. Original private methodology reconciliation remains unchanged and passes.
Use the full command above with both browsers installed, adding
`-W error::pytest.PytestUnraisableExceptionWarning` to reject cleanup errors.

Failures during development were corrected, not waived: screen navigation could be
overridden at assessment completion; broad status locators and early completion assumptions
did not identify the current job; compatibility projection dropped its fixed validation
classification; cancelled workbook generators/ZIP streams were not closed. The first full
attempt had five failures (639 passed); the final full rerun passed all 645 checks after
the added report-cancellation regression. No assertions or security safeguards were disabled.
Original customer evidence and actual native Windows execution remain separate gates.

Critical actual-launcher workflows repeated: 8 passed in 148.36 seconds. Byte-scale AWS
collector v0.3.0 input expanded to 233,427,235 bytes; GUI import/assessment/export completed
with 144.35 MiB observed backend RSS and 0.033-second maximum concurrent health latency
on that run (low resource density, not estate capacity certification). A restored synthetic
143-account/38,905-observation workspace completed real GUI analysis cancellation in
0.258 seconds, retry in 503.84 seconds and Excel export in 97.95 seconds. All 4,192 health
samples succeeded; maximum health/job-poll latency was 0.531/0.446 seconds, backend peak
RSS 657.86 MiB. Excel reconciled 13,299 candidates and 25,883 evaluations; database audit
passed. A separate 100-project GCP + AWS benchmark reconciled all consolidated rows.

## Portable delivery verification (0.5.1rc3)

The repaired application passed 645 Mac tests, including 14 browser workflows, and
eight repeated critical launcher/import workflows. A separate clean checkout passed
643 tests with one private-methodology skip and one packaging-test failure caused by
matching `private` in the checkout's `/private/tmp` ancestor. The assertion now checks
source paths relative to the repository and retains destination/extension protections.
The 24 targeted portable/source/Windows-input tests pass after this correction.
Portable ZIP verification checks the positive source allowlist, compiled assets,
runtime-only pins and source hashes; customer compatibility and native Windows execution
require separate authorized local acceptance. Avoid another full suite unless runtime
changes or material failures require it.

## P0 pilot-1.5 manifest correction

Metadata-only diagnosis identified a legitimate pilot-1.5 contract rejected by the
pilot-1.2.2-only guard. The strict new contract covers collector summary fields, required
API/pages metadata, denied/disabled/authentication statuses and the exact asset-type summary
artifact. Unknown versions, fields and statuses remain rejected. The new deterministic
generator contains synthetic payloads only; no original evidence or derived report is tracked.
Original-evidence folder and ZIP-equivalent GUI acceptance was performed locally in the
authorized development environment; results/reports stay in ignored local/private storage.

Focused importer/recovery checks: 45 passed. Focused browser regressions: 6 passed,
including pilot-1.5 rejection/retry and existing Chromium/WebKit pilot-1.2.2 transports.
Final full suite: 656 passed, zero failures/skips, 416.07 seconds. Frontend: 3 passed;
TypeScript/production build, Ruff (173 files), 32-schema equality and pip check passed.
One existing Starlette TestClient deprecation warning remains. The initial full run had
655 passes and one source-distribution failure because its tracked-asset inventory still
named the replaced frontend bundle. The rename was staged; focused checks and the final
full run passed without changing that assertion. No rules, dashboards or packaging inputs
were changed; no release kit was rebuilt.

## AR-01 final validation — 2026-10-14

683 passed, no failures/skips, 500.86s; 3 frontend tests; production TypeScript/Vite build,
Ruff, schema equality and dependency checks passed. Critical expanded Chromium folder/ZIP
and WebKit folder workflows were repeated; actual local pilot-1.5 folder/ZIP and synthetic
v0.3 AWS folder/ZIP reached persisted analysis and Excel export. One test-only Starlette
TestClient deprecation warning.
Actual expanded exports, real AWS and Windows native execution remain unverified.

## 0.6.0 integrated readiness validation — 2026-10-14

New suites: `test_collector_v030_native.py` (real v0.3 journal format, parity with the
collector's record keys via AST, page merge, defined absence, truncation, tamper rejection,
CLI ZIP import without modifying the source, contract drift), `test_gcp_expanded22.py`
(2.2 checksums/gaps/interruption, 145-dataset field distribution), `test_workflow_api.py`
(pending import → Import and analyze → labelled run), `test_guided_workflow_browser.py`
(field PACKAGE_READY defect across restart) and `test_integrated_acceptance_browser.py`
(AWS ZIP + GCP folder → analyst approval → Excel/RTF → reconciliation all PASS →
consolidated → restart).

Results: 681 passed (non-browser); 25 browser workflows passed; frontend 3 passed; ruff,
format, pip check, contract check and source audit clean. Collector checks outside the
analyzer venv: `tools/aws_registry_audit.py` (botocore, 0 problems) and the collector run
against a local AWS emulator (synthetic). Real cloud collection and native Windows remain
field-acceptance gates (docs/RELEASE_0.6.0.md).

## 0.6.1 assessment-ready validation — 2026-10-14

673 passed (non-browser), 26 browser workflows passed, frontend 3 passed; ruff, contract
check and source audit (tree, index, history; retired ADR-007 paths secret-scanned) clean.
Executable-kit tests were removed with the PyInstaller kit (ADR-007); runtime delivery
tests remain in `test_runtime_delivery.py`.

## 0.8.0 SRE validation workflow validation — 2026-10-15

685 passed, 2 skipped (non-browser, 182s); 20 browser workflows passed (Chromium/WebKit,
280s, including `tests/test_sre_browser.py`); frontend 3 passed; TypeScript/Vite build,
Ruff check/format and bundled-schema equality passed. New: `tests/test_sre.py` (stage SQL
equals Python, SRE workbook/Finalized exports, formula-literal SRE text), facet and
explanation-coverage tests, SRE purge on scope deletion. A first browser run failed 18
workflows because the compiled GUI still recorded 0.7.0 after the version bump; rebuilding
the GUI fixed all. Windows execution remains unverified.

## 0.8.1 faster assessment validation — 2026-10-15

688 passed, 2 skipped (non-browser); 20 browser workflows passed (including bulk marking,
per-account report filtered by marking, Remove / replace shortcut and attack-path
diagrams in `tests/test_sre_browser.py`); frontend 3 passed; Ruff and build passed. Three
existing browser tests first failed because a new "Analyst identity for bulk marking" label
matched their non-exact "Analyst identity" lookup; the new labels were renamed.

## 0.8.2 assessor-final review validation — 2026-10-15

691 passed, 2 skipped (non-browser, 183s); 20 browser workflows passed (258s); frontend 3
passed; Ruff check/format and build passed. New tests: login-name default and assessor-only
finalization, finding detail built from collected evidence (integrity, locator, actual
values, highlighted fields, technical finding text), credential masking with policy
documents kept, browser flow without name prompts and with optional SRE. Synthetic data
only; Windows execution unverified.

## 0.8.3 GCP collector 2.2.2 validation — 2026-10-15

693 passed, 2 skipped (non-browser); 20 browser workflows passed; Ruff passed. New: 2.2.1
and 2.2.2 manifests accepted; static ordering test that the sign-in check precedes any
output and never writes the token; collector contract regenerated and verified. PowerShell
is not available on the build Mac, so collector 2.2.2 was not executed here.

## 0.8.4 report template and collected-project scope validation — 2026-10-15

696 passed, 2 skipped (non-browser); 20 committed browser workflows pass. The only browser
failure is an uncommitted local edit of tests/test_gcp_browser.py that still expects the
removed Checklist Coverage and Remediation Roadmap sheets. New tests: three-part report
structure and section order, Finalized downloads in the shared template, collected-scope
filter (keep/drop cases), org-wide fixture now asserts no outside-project data is stored,
collector 2.2.3 org/folder search only behind the switch. Collector 2.2.3 not executed in
PowerShell here.

## GCP configuration increment validation — 2026-10-16

Branch: `feature/offline-security-analyzer`; no commit, push or release build performed.
Synthetic inputs only. The 23 configuration evaluators have explicit positive/negative,
missing/malformed and applicable/inapplicable cases, with guided retention and inherited
policy outcomes tested separately. Native expanded-2.2 import covers evidence references,
per-verdict severity/class/exposure, stored limitations, finding-detail guidance, review
preservation after reassessment/reimport, raw-input hash preservation and confirmed-only
Excel/Word (RTF) exports. Disabled Compute/SQL/KMS API evidence remains UNKNOWN.

Actual checks:

- `PYTHONPATH=src .venv/bin/python -m pytest -q --tb=short`: **779 passed, 22 skipped**,
  199.97s. Skips include opt-in browser tests; this is not a full browser-suite claim.
- Final focused `tests/test_gcp_config.py`: **90 passed**, 5.68s, after adding seven
  final combined-CIDR/external-metadata regression cases and their conservative handling.
- `tests/test_methodology_audit.py`, `tests/test_cloud_checklist.py` and generated GCP
  document/schema equality: **12 passed**, 4.05s, including local private reconciliation.
- Actual compiled-frontend Chromium/WebKit workflows: **4 passed** across
  `test_gcp_browser.py`, `test_gcp_expanded_browser.py` and `test_sre_browser.py`.
  The expanded/SRE batch passed 3; the corrected multicloud test passed 1 in 17.75s.
- Ruff lint/format (209 files), compileall, dependency check, 34-schema export,
  generated collector-contract check and `git diff --check` passed. No frontend code
  changed, so the existing compiled bundle was used without rebuilding.
- `data/private` and `artifacts` remain ignored. The supplied workbook hash still
  equals the pinned source hash. Changed-file signature review found no issues.

Development failures corrected: the first full attempt had 772 passes, two failures
and 22 skips: stale generated GCP documentation and a subprocess import failure from
omitting `PYTHONPATH=src`. Browser tests first hit sandbox loopback restrictions and were
rerun with permission. The prior uncommitted report test expected retired sheet names;
it now asserts the existing three-sheet report, without changing report functionality.
Test-development errors were corrected before the final focused pass. One existing
Starlette TestClient deprecation warning remains.

`tools/source_release.py` still returns **REVIEW_REQUIRED**. Its report is retained in
ignored `artifacts/source-audit-gcp-config-20261016`: existing synthetic signatures in
`tests/test_sre.py`, launcher allowlist/history/mode flags and index/worktree mismatches.
The working tree was deliberately left unstaged; no history or security-audit exceptions
were changed to force PASS. No new changed-file signature issues were found. This is not
a clean release-audit claim. Native Windows execution, actual collector-export verification
and native Office acceptance remain unperformed.

## Requested CloSec.zip refresh — 2026-10-16

Built and installed an owner-requested working-tree snapshot without committing or pushing.
The outer `CloSec/` launcher package now contains
`release/CloSec-0.8.4-update-20261016-portable-source.zip`; its unique name prevents reuse of
an older per-release extraction. Both outer runtime source and nested application include
the new GCP configuration module and every changed runtime file. Both manifests identify
uncommitted source truthfully; this is not a clean-commit release/audit certification.
The previous ZIP is preserved as `CloSec.before-gcp-update-20261016.zip` beside the installed
`CloSec.zip`. Build/install verification records stay under ignored
`artifacts/closec-zip-update-20261016/`.

Validation: outer ZIP CRC and per-file manifest hashes passed; nested portable verifier
passed for 296 files. All 64 reused platform wheels match their hash locks and current
runtime pins (22 Windows x64, 21 macOS arm64, 21 macOS x86_64). No evidence, workspaces,
credentials, test fixtures or development runtimes were bundled. Fresh macOS x86_64 setup
installed from the bundled wheels offline and passed pip check. Using the extracted
package and its fresh environment, 90 GCP configuration tests passed (14.26s), including
native synthetic import, assessment, review/reimport and confirmed-only exports. The real
packaged launcher, health and compiled Chromium GUI smoke passed with zero external
requests/page errors. Windows wheels were hash-verified only; no native Windows execution
or actual cloud-export validation was performed.

Installed outer ZIP SHA-256:
`6c28b4e1f274372bf083a20e857f61a9320d8837a70c62feb56fded28388980c`.
Application version remains 0.8.4; snapshot ID is `gcp-config-d15303cda7533c61`.

## Assessment sprint CloSec.zip refresh — 2026-10-17

Working-tree snapshot `d63de543a540` (base 374d4c8, uncommitted; not a clean-commit release).
Nested `release/CloSec-0.8.4-update-20261017-sprint-d63de543a540-portable-source.zip`;
previous ZIP retained as `CloSec.before-sprint-20261017.zip`. Build/install records stay in
ignored `artifacts/closec-zip-update-20261017/`.

Validation: final source-only full suite with browsers 826 passed, 1 failed (WebKit
expanded-folder timeout under load; passed twice in isolation). New synthetic tests:
`tests/test_file_deletion.py` (7) and `tests/test_file_deletion_browser.py` (1) for
individual-file deletion, plus an AWS-only safeguard test in `tests/test_assessment_sprint.py`.
All 38 regenerated schemas match. Outer/nested archives contain no images, PDFs, Office
files, databases, artifacts or evidence; the release scanner flags only manifest SHA-256
digests. Nested verifier passed (308 files); fresh macOS x86_64 offline setup and pip check
passed; 141 modules import and `/api/health` returned ready. Native Windows execution and
actual collector-export validation were not performed.

## Collector 2.2.5, UI type scale and readiness check — 2026-10-17

Source-only full suite with `RUN_GUI_BROWSER=1`: 835 passed, 0 failed (9 min 35 s). Ruff check,
Ruff format, Prettier, TypeScript/Vite build and 3 frontend tests passed; collector contract
regenerated and `--check` verified. New static tests in `tests/test_gcp_expanded22.py`
reject unparenthesized `'--flag='+$var` items in collector argument arrays (they catch both
2.2.4 defects) and the `locations/-` REST lists. Synthetic probes (ignored `artifacts/readiness/`):
GCP 2.2.5 accepted, 2.3.0 and 1.0 rejected (`LEGACY_GCP_MANIFEST_INVALID`); AWS 0.3.2 accepted,
0.4.0 rejected (`COLLECTOR_VERSION_PROFILE_UNSUPPORTED`); frozen GCP, AWS and consolidated
editions identical after a full process restart. Collector not executed on Windows.

## Exclusions, backend purge and dark mode (2026-10-17)

Synthetic data only. New: `tests/test_exclusions.py` (reason rules; hidden from rows,
Finalized, report model/ZIP, dashboard with excluded count; evidence/evaluations unchanged;
Undo; survives re-evaluation, enterprise rebuild, restart; frozen edition unchanged),
`tests/test_scope_purge.py` (three-scope workspace: purge one GCP project, others untouched,
verification finds references before and zero after, consolidated draft stripped and marked
for review, A2 reconciliation PASS, backup restorable, backup opt-out, AWS remaining
references counted, interruption before and after publication, frozen edition blocks),
`tests/test_theme_contrast.py` (WCAG AA tokens in both themes, severity colours fixed, no
hardcoded colours), `tests/test_theme_browser.py` (toggle, persistence, no-flash with the
bundle blocked, blocked storage, seven screens screenshotted in both themes, exclusion/Undo
and purge UI). Screenshots: `artifacts/theme-browser/` (ignored).

`RUN_GUI_BROWSER=1 PLAYWRIGHT_BROWSERS_PATH=artifacts/playwright-browsers` full suite:
**852 passed, 0 failed** (665 s). Ruff check, ruff format --check, Prettier, TypeScript,
3 frontend tests and production build passed. Schemas regenerated (ExclusionRequest,
FindingExclusion, ScopeDelete). Not tested: purge against real data; native Windows.

### Owner decisions: frozen-edition override, A3 rule, separated verification (2026-10-17)

New/updated synthetic tests in `tests/test_scope_purge.py` (override refusals: no
override, wrong typed ID, short reason, backup declined; backup not holding the edition;
edition kept unchanged and marked superseded; digest-only audit; restore from backup holds
the edition; A3 block and override; draft title redaction; CLEAN vs RETAINED_REFERENCES)
and `tests/test_purge_override_browser.py` (blocked by default, override enables purge,
backup enforced, file removal blocked). Full suite with all browser cases: **857 passed,
0 failed** (687 s). Ruff, format, Prettier, TypeScript, 3 frontend tests and build passed.
Schemas regenerated (ScopeDelete, FileDelete).

## Attack-path hop model, report template, PDF withdrawal — 2026-10-17

New: `tests/test_attack_path_hops.py` (8), `tests/test_report_template.py` (4),
`test_sre::test_withdrawn_pdf_reports_are_hidden_and_not_downloadable`; extended
`tests/test_gcp_browser.py` (hop chain, Hop table, evidence drawer, STRIDE surface, no false
truncation alert, AWS group never blank). Changed for the new template / PDF withdrawal:
test_sre, test_gcp_browser, test_assessment_sprint; deleted test_pdf_report. Full suite with
all browser cases: 867 passed, 1 failed (test_operational_browser scope-delete timeout under
load; passed twice in isolation). Ruff, format, Prettier, TypeScript, 3 frontend tests and
build passed. Real-data diagnostics were counts-only on a deleted read-only database copy.
Not tested: native Word/Excel, native Windows, real-workspace evidence drawer and exports.
Details: docs/SPRINT_ASSESSMENT_CHANGELOG.md (Attack-path sprint).

## GCP collector 2.2.6 — 2026-10-18

New `tests/test_gcp_collector_226.py` (46, synthetic). Updated: test_gcp_expanded22 (2.2.6
accepted; run/function IAM argument form), test_workflow_api (download name and version).
Full suite with all browser cases: 916 passed, 0 failed (724 s). Ruff check, ruff format
--check, collector contract --check, Prettier, TypeScript, 3 frontend tests and production
build passed. No PowerShell available here: the collector itself was not executed; Windows
PowerShell 5.1 array handling, ZIP entry names, encoding, retries and fallbacks are first-run
checks on Windows.

## Workspace location and 2.2.6 coverage reasons — 2026-10-18

New: tests/test_workspace_location.py (26), tests/test_workspace_launcher.py (3, real
launcher with a temporary CLOSEC_CONFIG_DIR), tests/test_workspace_browser.py (2, light and
dark), tests/test_gcp_coverage_notes.py (6), tests/test_gcp_contract_sync.py (4). Full suite
with all browser cases: 956 passed, 1 failed (WebKit file-chooser timeout under load in
test_import_recovery_browser; passed twice in isolation). Ruff, format, contract check,
Prettier, TypeScript, 3 frontend tests and build passed. Synthetic data only. Not tested:
native Windows (launcher scripts, drive-type detection, msvcrt lock, long paths beyond text
checks), PowerShell execution of the collector (no pwsh here), real workspaces.

## GCP collector 2.2.7 — 2026-10-18

New tests/test_gcp_collector_227.py (32: quota-project classification by project number, COMMAND_ERROR,
pre-check exemption list, effective-policy normalisation and 11-constraint baseline, fallback
suppression, 16 GCP-GOV-KEYS effective shapes, end-to-end synthetic 2.2.7 package with all 48
GCP rules producing results and distinct gap reasons, 2.2.4-2.2.6 equal results). Updated
2.2.6 tests (versions, classifier emulation). Full suite with all browser cases: 990 passed,
0 failed. Ruff, format, contract check, Prettier, TypeScript, 3 frontend tests and build passed.
No PowerShell available; the collector was not parsed or executed.

## GCP identity resolution E1/E2 — 2026-10-18

New tests/test_gcp_identity.py (11, synthetic): trust classes and documented patterns; one
policy with same-project accounts by number and by ID, cloudservices, default compute and
gcp-sa agents, an in-scope other-project account, an out-of-scope foreign account and a
conditional binding (only the foreign account is a finding, the in-scope link is
informational, the conditional binding is UNKNOWN); missing project number gives UNKNOWN;
org rules and XP-02 edges follow the same classes; end-to-end import and assessment; hygiene
rule outcomes equal with the opt-in disabled; analyst reviews match by stable finding ID;
opt-in set and version bumps limited to the identity rules; the default compute service
account with Editor on its own project is still a finding, and with another project's number
it is cross-project.

## Per-principal role lookup — 2026-10-18

tests/test_gcp_principals.py (12, synthetic rows in a temporary workspace and one imported
expanded package): same account with roles in two projects; conditional binding; account with
no binding; narrow account; group listed as a group without members; parent IAM denied gives
UNRESOLVED; project under a folder not collected gives UNRESOLVED; custom role without detail
UNRESOLVED and with detail listing permissions; privileged list equals the rule lists; latest
import per project; directory; performance with 45 projects and 5,000 bindings (build under
10 s, lookup under 1 s). tests/test_principals_browser.py: the view and a finding's "View
roles" link in light and dark themes.

## Ownership classes and GCP-GOV-KEYS — 2026-10-18

tests/test_gcp_ownership.py (12, synthetic): account classes and owners for every documented
form; one IAM policy with the cloudservices agent and a gcp-sa agent (Editor), same-project
default compute, other-project default compute and a foreign user-managed account (Owner) and
a conditional binding (agents: no finding; GCP-IAM-BASIC fires for the same-project default
account; GCP-IAM-CROSSPROJECT for the other-project default and foreign accounts; condition
rendered); "Actual configuration" rows; the per-principal view labels PLATFORM_AGENT;
GCP-GOV-KEYS with Creation and Upload unenforced (two findings, each naming its own
constraint, observed value, managed note and command), managed Creation enforced (no Creation
finding) and a missing record (UNKNOWN); observed-value rendering; outcome table of every other
GCP rule unchanged on six synthetic fixtures. tests/test_gcp_principals.py adds the
"no parent recorded" case.

## False positives and pitch-black theme — 2026-10-18

tests/test_false_positive.py (9, synthetic): reason mandatory; single mark and restore with the
rule result unchanged; bulk mark/restore (all-or-nothing, bounded); exclusion from severity
totals, report findings, Word and both Excel finding sheets with the "Excluded findings"
appendix (grouped by rule and reason, IDs in Excel); finalized list; attack path flagged
"depends on a false-positive finding", excluded from report paths, review fingerprint
unchanged; consolidated snapshot and member runs reflect each other; carry-over to a new
import only on an exact match (marked), never across projects or with different principals;
workbench hide/show/only filter, FP tag and counts. tests/test_false_positive_browser.py: the
same flows in the GUI in dark and light, screenshots of dashboard, findings, attack paths,
coverage, IAM intelligence, network analysis and evidence explorer.
tests/test_theme_contrast.py (7): pitch-black tokens, text >= 4.5:1, marks and boundaries
>= 3:1, tokens only, Dark default. tests/test_gcp_ownership.py asserts exactly 2 FAIL and no
UNKNOWN for GCP-GOV-KEYS on the 2.2.7 shape.

## Collector 2.2.8 and E5 context — 2026-10-19

tests/test_gcp_collector_228.py: custom-role describe arguments for project and organization
scopes, odd shapes skipped, parenthesised concatenation, COMMAND_ERROR classification, no write
verbs, synthetic 2.2.8 import resolving custom-role permissions (PowerShell not executed).
tests/test_gcp_principal_context.py: attached service-account context for the VM and firewall
rules (raised, labelled, unresolved cases; other rules unchanged; finding IDs stable).

## Safe defaults and carry-over (Phase 3) — 2026-10-19

tests/test_phase3_defaults.py (11, synthetic AWS + GCP): report scope defaults to confirmed with a
cover notice otherwise; excluded findings leave metrics, run list, readiness counts, STRIDE path
counts and evaluation listings ("excluded (reason)"); enterprise issues whose findings are all
excluded are not counted; workbook sheet counts AWS-only 28, GCP 40, mixed 40; snapshot default =
latest import per project, superseded imports listed, GCP refresh and staleness keyed by scope;
path reviews apply only on an identical fingerprint; custom limitations rendered after the fixed
limitations; size limits explained; additive migration with backup keeps every status.

## Root-cause grouping (Phase 4) — 2026-10-19

tests/test_phase4_groups.py (4, synthetic AWS + GCP): group keys per kind and fallback; groups
identical across member runs and the snapshot, excluded findings never members, group bulk
confirm; group report edit member limit 2,000, one changed member NEEDS_REVIEW while the others
keep the group text (including immediate mitigation); grouped Word headings and affected-resources
tables, "Grouped Findings" sheet, cover counts, totals per finding, ungrouped option.

## Faster data deletion — 2026-10-19

tests/test_deletion_speed.py (4, synthetic AWS + GCP): compaction copies every table exactly and
leaves no WAL; verification scan counts equal the one-query-per-column definition, including
prefixes of longer project IDs and account numbers; file search across chunk boundaries keeps
token boundaries; scope deletion reports its stages in order with re-assessment n of m.
frontend/src/api.test.ts: a read refused because a job owns the database is retried; a write is
never retried.
Added for the preview timeout: the deletion preview's statement count does not grow when the
scope's observations are multiplied; GCP relationship edges are identical with evidence=False.

## GCP correctness release candidate — 2026-10-20

Synthetic only; tools/fixtures/gcp_estate.py builds collector 2.2-format projects (41-project
estate and 10-project subset; SUCCESS, EMPTY, TRUNCATED, PARTIAL, TIMEOUT, API_DISABLED,
ACCESS_DENIED and QUOTA_PROJECT_DENIED datasets; organization/folder ancestor IAM per project).
tests/test_gcp_completeness.py (21): SUCCESS is COMPLETE with pagination verified, EMPTY gives
NOT_APPLICABLE, TRUNCATED and REST PARTIAL stay partial, each of 11 failure statuses stays
insufficient and never PASS, interrupted and 2.1 packages stay partial; organization rows for no
search, project search only, complete organization search without match, truncated search.
tests/test_gcp_pass_defects.py (23): GCP-KEY-PRIVILEGED PASS only with a complete IAM
hierarchy, FAIL with Owner/Editor, UNKNOWN with denied or absent ancestors; GCP-LOG-AUDIT
PASS / own and inherited FAIL / UNKNOWN / resource policies NOT_APPLICABLE; GCP-LOG-EXCLUSION
filter parsing (10 filters) and the empty scope row; GCP-ORG-FEDERATION provider states.
tests/test_gcp_omitted_fields.py (9, written first; 2 failed before the change): API key
without restrictions FAIL (combined rule) from complete evidence, UNKNOWN from truncated or 2.1
evidence; KMS key without a rotation schedule FAIL, one field only or PARTIAL UNKNOWN,
non-symmetric NOT_APPLICABLE.
Acceptance (synthetic estate, pre-sprint analyzer vs RC): scripted before/after comparison of
per-rule outcomes, scope UNKNOWN rows, findings, analyst state and timings; see
docs/SPRINT_ASSESSMENT_CHANGELOG.md.

## GCP Excel observation register — 2026-10-23

Reporting-only change on `feature/offline-security-analyzer`; no commit or push. The
owner's forty supplied headers are pinned independently in the Excel regression. New
`GCP_Observation_Register`, `GCP_Evidence_Index` and `GCP_Evidence_Details` sheets retain
native tables/filters, literal values, stable IDs and internal navigation. Configuration
comes from locally hash-verified raw JSON, with credential masking and numbered excerpt
parts. Existing candidate classes, criterion outcomes, grouping, review decisions and
report-model inclusion remain independent. Missing evidence and collection failures are
explicit limitations; successful/NA/manual evaluations remain observations.

Actual results (synthetic inputs only):

- Initial focused source regression: **24 passed**, including existing report-template,
  AWS sheet-count, finding-detail, Excel formula-safety and private-methodology checks.
  One existing Starlette TestClient deprecation warning.
- Final dedicated Excel regression after the classification/denied-only refinements:
  **8 passed**. Covers forty headers/order; actual raw-pointer excerpts; stable mappings;
  tables/filters/hyperlinks; missing/tampered/failed sources; complete multi-part excerpts;
  credential/formula safety; project isolation; persisted review/risk/inclusion fields;
  all-table database equality; raw-source hashes; and AWS's existing 28-sheet contract.
- The same **8 Excel tests passed against the clean nested release extraction**. Import
  location was checked to prevent accidentally testing the checkout's newer analyzer.
- **6 baseline-versus-patched export comparisons passed**: AWS, GCP and consolidated,
  for both assessment-document Excel and comprehensive Excel. The same persisted
  synthetic assessments were used. Report models and all database rows matched exactly.
  Every existing worksheet XML payload matched; AWS workbook entries matched apart from
  generated document-property timestamps. No existing finding, severity, approval or
  inclusion decision changed.
- Repository Ruff passed; changed-file format checks passed; all **40** generated schemas
  equal the bundled schemas; dependency check and `git diff --check` passed.
- Five rendered synthetic views covered the register, review columns, evidence index and
  configuration details. Native Excel tables/filter/hyperlink definitions were reopened
  and checked in OOXML. Native Microsoft Excel was not available.
- Outer and nested release CRC and manifest checks passed (**267 / 333** listed files,
  including the final validation notes in the manifest).
  Existing dependency wheels, launchers, compiled GUI, collectors, rules, normalizers,
  storage schemas and APIs are byte-identical to the original release.
- Fresh macOS x86_64 setup installed only the bundled hash-locked wheels with `--no-index`;
  pip check passed. The real packaged launcher passed startup, authenticated session,
  health, compiled-GUI HTTP delivery, workspace query and graceful shutdown against an
  isolated synthetic workspace. No client database was opened by the smoke test.
- Preservation guard: **66 existing workspace/config/report files hash-unchanged**. The
  guard uses file reads only, with no client database connection or migration. Private
  paths/artifacts remain ignored and the methodology source retains its pinned hash.

Development checks corrected before release: a manifest check found that the original
outer ZIP listed wheelhouses present only inside its nested ZIP. The updated outer
manifest lists actual outer files and hashes the embedded archive; wheel/deployment-script
bytes were not changed. A denied-only assessment exposed the need to gate the appendix
on GCP sources rather than normalized observations. The first launcher probe used a
synthetic path inside the source tree (correctly refused); the next needed sandbox
loopback permission. The final isolated, permitted startup check passed.

The release is a patch of the existing ZIP, not a rebuild from the unrelated dirty
checkout. Historical built reports and editions are not rewritten. Standalone Finalized/
SRE workbooks retain their prior format; GUI register querying is an optional separate
sprint. No Windows artifact was built or executed, no native Office acceptance was run,
and no actual customer collector-export compatibility is claimed. Release verification,
backup location and installed SHA-256 are retained under ignored
`artifacts/gcp-register-sprint/` and in the final handoff.
