# CloSec readiness report — 2026-10-17

Data-free verification of the analyzer and both collectors. Synthetic data only. During
this check no workspace, evidence, draft or finalised edition was opened. Branch
`feature/offline-security-analyzer`, base `374d4c8` plus uncommitted owner-requested
changes. Nothing was committed or pushed.

## Gates

| Gate | Result | Evidence |
|---|---|---|
| Full pytest, `RUN_GUI_BROWSER=1`, `PLAYWRIGHT_BROWSERS_PATH=artifacts/playwright-browsers` | **835 passed, 0 failed** (9 min 35 s) | `artifacts/full_suite_final.log` (ignored) |
| `ruff check .` | PASS | all checks passed |
| `ruff format --check .` | PASS | 261 files formatted |
| Prettier | PASS | `prettier --check src` |
| TypeScript + Vite build | PASS | `npm run build` (`tsc -b && vite build`) |
| Frontend tests | PASS | `npm test`, 3 passed |
| Collector contract current | PASS | `tools/collector_contract.py --check` |

## Verification matrix

| Area | Status | Evidence |
|---|---|---|
| Collector→analyzer contract (versions, schema, format) | **PASS** | Contract `2.0.0`. GCP 2.2.5 / `assessment-expanded-2.2` / `gcp-expanded-2.2-adapter-1`; AWS 0.3.2 / `closec-provisional-0.3` / `closec-v030-native-1`. Synthetic probe `artifacts/readiness/version_probe.py`: GCP 2.2.5 and AWS 0.3.2 accepted; GCP 2.3.0 and 1.0 and AWS 0.4.0 rejected with no run. Tests: `tests/test_gcp_expanded22.py::test_collector_221_and_222_manifests_are_accepted[2.2.5]`, `tests/test_collector_v030_native.py`. |
| Version-mismatch messages | **PARTIAL** | The import fails closed. The GCP wrong-version message `LEGACY_GCP_MANIFEST_INVALID` mentions the pilot contract, which is misleading. AWS `COLLECTOR_VERSION_PROFILE_UNSUPPORTED` has no explanation entry in `ingestion/errors.py`. Not blockers. |
| GCP project identity (ID / number / name, mismatch, number required) | **PASS** | `tests/test_assessment_sprint.py::test_identity_compares_id_and_number_without_display_name_joins`, `::test_identity_details_are_session_only_and_never_saved_or_exported`, `tests/test_gcp.py` (`GCP_PROJECT_NUMBER_REQUIRED`) |
| Multi-project evidence | **PASS** | `tests/test_gcp_expanded.py::test_parent_scope_summaries_keep_only_the_collected_project`, `::test_expanded_import_assessment_and_reopen[mixed]` |
| Duplicate imports | **PASS** | `tests/test_foundation.py::test_manifest_window_and_duplicates`, `GCP_DUPLICATE_DATASET` in `tests/test_gcp_expanded.py`, `tests/test_iam.py::test_15_duplicate_and_incomplete_collections` |
| File removal / backend scope removal with explicit confirmation | **PASS** | `tests/test_file_deletion.py` (7), `tests/test_file_deletion_browser.py`, `tests/test_scope_management.py`, `tests/test_operational_browser.py::test_operational_import_scope_delete_and_navigation` |
| Missing evidence never PASS; Effective Coverage / Partial / Error | **PASS** | Definitions in `reporting/cloud.py:14` are rendered in the UI. `tests/test_foundation.py::test_unknown_is_not_pass`, `tests/test_gcp_config.py::test_missing_fields_never_establish_pass_or_finding`, `tests/test_gcp_expanded22.py::test_field_distribution_is_preserved_and_never_passes`, `tests/test_cloud_checklist.py::test_checklist_matrix_never_passes_and_marks_absent_clouds` |
| Finding fields (description, impact, root cause, misuse, recommendation, verification, evidence refs, severity) | **PASS** | Structure in `findings/detail.py:540-620`. A registry check this session found all 67 rules with misuse text, risk, remediation and severity rationale. The 10 `GCP-ORG-*` rules use the rule remediation instead of a detailed template. |
| Quality gate / auto-validation | **PASS** | `findings/quality.py`; `tests/test_assessment_sprint.py::test_quality_never_auto_readies_contradictions_or_low_confidence`, `::test_findings_quality_coverage_choices_and_strict_feasibility` |
| Attack paths + STRIDE (GCP, AWS, consolidated; diagram; reports when confirmed) | **PASS** | `tests/test_assessment_sprint.py::test_cloud_reports_drafts_native_office_and_freeze_are_consistent` (STRIDE on paths, confirmation, "3 Attack paths" in DOCX, Findings Validation sheet), `tests/test_gcp_browser.py`, `tests/test_sre_browser.py`. UI: Dashboard → cloud → **Attack Paths** tab. |
| IAM Intelligence / Network Analysis / Cross Account Explorer | **PASS** | GCP: `tests/test_gcp_expanded_browser.py`. AWS: `tests/test_gui_browser.py`, `tests/test_integrated_acceptance_browser.py`. Consolidated: `tests/test_enterprise_api.py::test_enterprise_browser_separate_imports_to_graph_review_report` |
| Dashboards (findings first, pie click-through, static summary, posture, enterprise build validation) | **PASS** | Pie to severity filter: `tests/test_gcp_browser.py:95`. Enterprise validation (counts, scopes, omitted imports): `tests/test_assessment_sprint.py::test_enterprise_reconciles_exact_ids_scopes_and_omitted_imports`. Scope summaries: `tests/test_gcp_browser.py:236` |
| Filters are data-driven dropdowns | **PASS** | Inspection of every `<input>` in `frontend/src/*.tsx`. The remaining text inputs are identity, note, deletion confirmation and import-context fields; no free-text filter is left. `api/facets.py` feeds the dropdowns. |
| Draft location shown after save | **PARTIAL** | Implemented: `findings/report_ready.py:379`, `frontend/src/ReportFinding.tsx:253,322`. No test asserts the text. |
| Consolidated downloads in 3 scopes; DOCX/XLSX open | **PASS** | `tests/test_assessment_sprint.py:171-197` (GCP, AWS; DOCX parsed, XLSX loaded, no formulas or external links); consolidated "" scope at `:220` |
| Frozen editions per cloud + consolidated survive restart | **PASS** | Browser reload: `tests/test_gcp_browser.py:239-248`. Full process restart: synthetic probe `artifacts/readiness/freeze_restart_probe.py` gave GCP 1, AWS 1, consolidated 2 findings, identical before and after. |
| macOS | **PASS** | Fresh offline setup from the new CloSec.zip: `pip check` clean, 141/141 modules import, `/api/health` 200, synthetic 2.2.5 import→assess→reconcile all PASS |
| Windows | **NOT-TESTED** | `setup-windows.ps1`, `start-windows.ps1`, `CloSec.cmd`, the GCP collector on PowerShell 5.1, and the AWS collector on Windows |
| Privacy: secret/identifier scan | **PASS** | `tools.source_release.findings` over 348 working-tree files flagged one file, `tests/test_sre.py`, at two obvious placeholders (all-zero account at line 275, alphabet-sequence key at line 377). Release archive: only the SHA-256 digests in `portable-manifest.json` are flagged. |
| Privacy: fixtures synthetic, nothing real in git or the archive | **PASS** | No `.duckdb`/`.wal`/evidence/workspace files tracked. The archive contains no `tests/`, `artifacts/`, `data/`, images, PDFs or Office files, and its manifest says `customer_evidence_included: false`. |
| Config integrity | **PASS** | `git diff` on `pyproject.toml`, `requirements*`, `locks/`, `frontend/package*.json`, `collectors/aws/*.example.*`, `.gitignore`: no changes |

## Changes made in this session before this check (owner-requested, disclosed)

These were made on the owner's explicit request, before the readiness brief that keeps the
collectors read-only:

1. **GCP collector 2.2.4 → 2.2.5.**
   - It repairs the 6 Cloud Run/Functions IAM calls that always failed with
     `COMMAND_ERROR`.
   - It removes 2 REST calls that always returned HTTP 400; their inventory is still
     collected by gcloud.
   - Contract, version pins, docs and static tests were updated.
   - The evidence format is unchanged (`assessment-expanded-2.2`), and 2.2.0–2.2.4
     packages are still accepted.
2. **UI type scale.** `frontend/src/style.css` has 8 size tokens instead of 19 ad-hoc
   sizes, and the rebuilt assets are in `src/offline_analyzer/api/assets/`.
3. **No code change was made during this readiness check.** Only these files were
   written: `docs/handoff/*`, `docs/SPRINT_ASSESSMENT_CHANGELOG.md` and `TEST_PLAN.md`.

## Package

| Item | Value |
|---|---|
| Installed archive | `/Users/dev/CloudAssessmentScripts/CLoSec/CloSec.zip` |
| Size | 64,271,806 bytes |
| SHA-256 | `34b2e194df80ae312f730bf7c197448240c316077b0f84cf3caa65fb8bf1e045` |
| Nested package | `release/CloSec-0.8.4-update-20261017-sprint-e91fd8f3c15a-portable-source.zip` (308 manifest files, hash in `release/SHA256SUMS.txt` verified) |
| Previous archive | `/Users/dev/CloudAssessmentScripts/CLoSec/CloSec.before-collector225-20261017-170059.zip` |
| Collectors | **Included.** Under `collectors/aws` (0.3.2) and `collectors/gcp` (2.2.5), and downloadable in the app from **Evidence import → 1. Collect evidence** |
| Build record | `artifacts/closec-zip-update-20261017-c225/build-verification.json` (ignored) |

The handoff files live in the repository and are not inside CloSec.zip.

## Not tested

- Actual collector exports and a pilot scan. Real-export compatibility is not claimed
  under AGENTS.md.
- Native Windows: the analyzer setup/start scripts, GCP collector 2.2.5 on PowerShell 5.1,
  and the AWS collector on Windows.
- AWS collector 0.3.x against real accounts. The developer used moto only.
- A test assertion for the draft-location text.
