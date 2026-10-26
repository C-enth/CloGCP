# Assessment sprint 2026-10-16

Owner decisions applied (2026-10-17). Synthetic data only; no workspace, evidence, draft or
finalised edition opened; no config change; collectors unchanged.
- Frozen editions: purge stays blocked by default (`FROZEN_EDITION_DECISION_REQUIRED`). One
  explicit override, "Purge and mark edition superseded": typed account/project ID, reason
  (10-2000 characters) and the pre-purge backup are required; the backup is checked to hold
  each edition (manifest digest and edition rows) before anything is removed. The edition
  record is never deleted or changed; a new `finalized_supersessions` record marks it
  superseded with time, reason, action, scope digest and backup location. The audit entry
  (`DELETE_SUPERSEDE`) names the scope by digest. Unfreezing is not offered.
- A3 single-file removal: no longer deletes finalised editions; same block and override
  (typed ID of the file's account/project). Its audit entries now use the scope digest.
- Verification: separate references removed (before/after counts), cross-account
  references retained in other accounts' evidence, analyst-written drafts still mentioning
  the identifier (redacted title, revision count), superseded frozen editions retained, and
  other; status CLEAN only when nothing remains, otherwise RETAINED_REFERENCES.
- Docs: OPERATOR_GUIDE and OPERATIONS updated; pre-purge backups hold the purged data and
  need the same handling, retention and deletion rules as the evidence.
- Tests: override refusals, unverified backup, kept and marked edition, restore from backup,
  A3 block/override, draft redaction (tests/test_scope_purge.py); browser override and
  file-removal block (tests/test_purge_override_browser.py).
- Results: full suite with all browser cases 857 passed, 0 failed; Ruff, format, Prettier,
  typecheck, 3 frontend tests and build passed.
- CloSec.zip rebuilt (snapshot 4aaf3865ed72, 317 nested files; scanner hits only the
  manifest SHA-256 digests); fresh macOS offline setup, pip check, 144 module imports and
  health check passed. Prior archive kept as a timestamped backup. The packaged copy of this
  changelog predates this line.

Exclusions, backend purge and dark mode (owner-requested, 2026-10-17). Synthetic data
only; no workspace, evidence, draft or finalised edition opened; no config, threshold, scope
or credential change; collectors unchanged.
- Exclude from report: new append-only `finding_exclusions` table beside the report drafts,
  keyed by the stable finding ID (`stable_id("finding", [rule_id, resource_id])`, no run in
  the key, so it survives re-evaluation, enterprise rebuilds and restarts). Reason required
  (OTHER needs a note); evidence and evaluated findings unchanged. Hidden from Finalized
  findings, SRE workbooks, approved narratives, the assessment/finalised Word/Excel/PDF
  exports, the technical workbook finding register and dashboard counts; "N excluded"
  shown on the pie, Finalized metrics and report summary. Excluded findings section with
  Undo. Frozen editions unchanged (exclusion on a frozen run is refused; editions frozen
  earlier render without the new summary line). No single-finding hard delete.
- Purge: preview split into removed / affected-but-kept counts; consolidated drafts with
  other scopes keep their other members and need review; exclusions, display labels and
  job records naming the scope are removed; audit rows use a scope digest; pre-purge
  backup (default on) beside the workspace; post-publication verification of every DuckDB
  text column, database/WAL file and workspace file. Previously, scope deletion also
  removed frozen editions; it now refuses while one is affected (decision pending).
  AWS synthetic purge leaves references only inside other accounts' own evidence
  (Organizations listings, policy resources), reported by count.
- Dark mode: 223 hardcoded CSS colours and 3 inline TSX colours replaced by semantic tokens;
  Light/Dark/System header selector; `public/theme-init.js` applies the choice before first
  paint (CSP 'self'); severity colours identical in both themes; input borders now 3:1.
  WCAG AA token contrast tested in both themes. Reports do not depend on the theme.
- Tests: tests/test_exclusions.py, tests/test_scope_purge.py, tests/test_theme_contrast.py,
  tests/test_theme_browser.py (toggle, persistence, no-flash, blocked storage, screenshots
  of seven screens in both themes, exclusion/Undo and purge UI). Full suite with all
  browser cases: 852 passed, 0 failed; Ruff, format, Prettier, typecheck, 3 frontend tests
  and build passed.
- CloSec.zip rebuilt (snapshot 023c0e6943f0, 317 nested files; scanner hits only the
  manifest SHA-256 digests); fresh macOS offline setup, pip check, 144 module imports and
  health check passed. Prior archive kept as a timestamped backup. The packaged copy of this
  changelog predates this line.
- Decisions (resolved by the owner decisions above): (1) purge when a frozen edition includes the scope: block, purge with
  the edition marked superseded, or require unfreezing; (2) whether references to a purged
  AWS account inside other accounts' evidence should be redacted. Not tested: purge on real
  data, native Windows.

Final session 2026-10-17: privacy review of tests/test_sre.py and the new sprint tests found
only obvious placeholders (alphabet-sequence key, repeated-digit accounts, RFC 5737 addresses,
example.com). No config, lock, requirements, threshold, scope or credential file changed;
collector scripts unchanged. A3 individual-file deletion added with API, UI, schemas
and synthetic unit/API/browser tests; H3 AWS-only synthetic test added. Final full suite
(source-only, all browser cases): 826 passed, 1 failed — the WebKit expanded-folder case
timed out under full-suite load at a different step than before; it passed twice in
isolation, so timeouts were not changed. Ruff, format, Prettier, typecheck, 3 frontend
tests and production build passed. CloSec.zip rebuilt from the working tree (snapshot
d63de543a540, 308 nested files); release scanner clean apart from manifest SHA-256 digest
false positives; fresh macOS x86_64 offline setup, pip check, 141 module imports and
health check passed. Previous CloSec.zip retained as a dated backup. The packaged copy of
this changelog predates this paragraph.

Follow-up 2026-10-17: guided JSON imports whose resource names carry a project number
while none was declared now stop with `GCP_PROJECT_NUMBER_REQUIRED` and ask for the
number, instead of the generic identity mismatch. A wrong declared number still
yields `GCP_PROJECT_IDENTITY_MISMATCH`. Synthetic test added. Full suite 826 passed,
2 WebKit folder cases timed out under load and passed in isolation. CloSec.zip rebuilt
(snapshot b72571d6afc2) and reinstalled; clean offline setup, 141 module imports,
health and the new guided error verified. Prior ZIP kept as a dated backup.

Collector 2.2.4 (owner-requested): `gcloud compute images list` returned Google's public
image catalog, whose `selfLink` names other projects, so actual collector output stopped
with `GCP_PROJECT_IDENTITY_MISMATCH` (reproduced synthetically). The collector now passes
`--no-standard-images`; the analyzer drops public catalog images from earlier outputs before
storage (ADR-010 amendment), so existing packages import without recollection. Workforce
pool and access-policy listings now send the required organization parent. Capability
recheck: all 38 GCP rules are fed by collected datasets; remaining gaps are listed in the
handoff for decision. PowerShell was not available locally: collector changes are verified
by static tests only; native Windows execution remains unverified.
Full suite 832 passed, 0 failed. CloSec.zip rebuilt (snapshot 9064470d23dd) and
reinstalled; clean offline setup, 141 module imports, health and a public-image package
import verified in the installed build. Prior ZIP kept as a dated backup.

Collector 2.2.5 and readiness check (owner-requested, 2026-10-17): Cloud Run service and
Cloud Functions IAM calls passed `--region=` and the region as two arguments (PowerShell
comma precedence), so every call was COMMAND_ERROR; arguments are now grouped. The Cloud
Run jobs and Artifact Registry REST lists used `locations/-` and always returned HTTP 400;
both duplicate calls are removed (gcloud `cloud_run_jobs` and `artifact_repositories`
collect the same inventory). Static regression tests added. UI type scale: 19 font sizes
(8-54px) replaced by eight tokens (12-48px) in `frontend/src/style.css`; SVG diagram labels
unchanged. Full suite with all browser cases 835 passed, 0 failed; Ruff, format, Prettier,
typecheck/build and 3 frontend tests passed. Data-free handoffs in `docs/handoff/`. No
configuration, threshold, scope or credential changes; native Windows execution of the
collector remains unverified.

Branch: `feature/offline-security-analyzer`. Existing pending GCP configuration work
is retained. Code and synthetic inputs only; no assessment workspace is opened.
No configuration, thresholds, credentials or scope settings changed. Collector code
changed only in the owner-requested 2.2.4 and 2.2.5 reworks above.

Recovery 2026-10-17: all six specified cutoff changes verified present. The source-only
full suite is running with browser tests enabled; no private workspace is available to
it. Ruff, frontend tests, TypeScript and production build passed. Browser regression
selectors are being updated for dropdowns and Client Reporting. No tests weakened.

Statuses describe implementation; remaining verification gates are listed below.

- A1 DONE — distinguish project ID/number/display labels; bounded file/identity details are session-only; actual offending evidence deliberately uninspected.
- A2 DONE — reconcile snapshot source/artifact/observation/reference sets, scopes and omitted imports; surface discrepancies.
- A3 DONE — explicit backend scope removal plus individual-file removal by content digest: preview, typed 12-character digest and checkbox; staged, reassessed, journaled publish; nothing deleted without the UI action.
- A4 DONE — pending validated-package card removed from the main dashboard.
- B1 DONE — observed findings and clickable severity chart lead; enterprise builder sits at the bottom.
- B2 DONE — static imported estate summary and separate AWS/GCP domain coverage columns.
- B3 DONE — consolidated posture, STRIDE states, evidence limitations and key metrics.
- B4 DONE — Methodology section removed from the dashboard; checklist retained separately.
- B5 DONE — consistent effective coverage/status definitions and missing-evidence limitations.
- C1 DONE — analytical text filters replaced with bounded, data-derived dropdowns; truncation disclosed.
- D1 DONE — automatic completeness, evidence, confidence and contradiction blockers; populated explanations.
- D2 DONE — Technical Analysis read-only; Client Reporting owns edits and approval.
- D3 DONE — finding drawer widened with responsive sizing.
- D4 DONE — explicit immutable finalised enterprise edition with cloud and overall exports.
- E1 DONE — canonical path diagrams aligned with results; synthetic cloud diagrams and interpretation confirmation visually/browser checked.
- E2 DONE — STRIDE and existing scenario references on paths; unknown enforcement cannot establish feasibility.
- E3 DONE — path/STRIDE in Word and Excel; confirmed interpretations in Findings Validation.
- E4 DONE — AWS, GCP and consolidated attack path sections.
- E5 DONE — cloud-specific and consolidated cross-account/project views.
- E6 DONE — IAM cache/error handling and GCP IAM/network views verified with focused synthetic tests and browser module checks.
- F1 DONE — saved drafts display local database, record and revision location.
- F2 DONE — consolidated all-import report scopes: GCP, AWS and both.
- F3 DONE — native DOCX/XLSX plus separate PDF in consolidated ZIP, approved narratives and finalised downloads; PDF font limitation disclosed.
- G1 DONE — readable enterprise tables and wider details; synthetic visual review; large detailed metrics collapsed below posture.
- G2 DONE — consistent navigation, filters and posture; recovered imports have one action set; browser regression gate recorded below.
- H1 DONE — GCP checks and shared snapshot validation verified with synthetic tests; real-export compatibility remains unclaimed.
- H2 DONE — automatic quality readiness reduces review work without granting analyst approval.
- H3 DONE — shared safeguards apply to AWS; AWS-only synthetic reconciliation, quality, review and freeze verified. Live pilot remains unverified.

Decisions: F3 resolved by user: add a separate PDF alongside DOCX and XLSX.
No further user decision is currently required. Real-export compatibility, native
Windows validation and any live pilot remain unverified under this sprint's privacy
guardrail. The GCP collector changed only in the owner-requested 2.2.4 and 2.2.5 reworks; collector
contract documentation includes the pre-existing pending GCP coverage changes.

Phase 1 verification: 188 synthetic tests passed across GCP identity/expanded/config,
enterprise and sprint regressions. Ruff passed. No actual assessment inspected.
Focused reporting verification: 14 tests passed, including new separate PDF paths.
PDF rendered locally from synthetic text; pagination, escaping, Unicode disclosure
and page geometry checked. Source-only full-suite run still in progress.

Phase 2 verification: 109 synthetic IAM, verification, security-observation, checklist
and report-readiness tests passed; Ruff passed.
Phase 3 verification: 28 tests passed for scope management/API, enterprise/API and
sprint behavior; the opt-in browser case in this focused batch was not enabled and
is included in the independent browser-enabled full run. Ruff passed. Restored
pending-import resume only on Evidence import, keeping dashboard uncluttered.
Phase 4 verification: 36 report, finalisation, quality and PDF tests passed; Ruff
passed. Frozen path filters use project/account identity before relationship scope.
Dropdown search choices include relationship IDs/types even when titles also exist.
All 36 regenerated schemas match their checked-in public contracts.

Phase 5: synthetic visual review covers posture, report drawer, and cloud-specific
attack diagrams. Collapsed detailed AWS tables for a shorter overview; tests now
open those details before exercising their controls. UI production/typecheck build
and all 3 frontend tests passed; final browser suite gate pending.
Phase 6: automatic readiness rejects low/unassessed confidence and contradictions;
AWS shares reconciliation, frozen reports and review safeguards. The broad focused
batch had 237 passes and one subprocess import-path setup error; that test then
passed with the documented PYTHONPATH. A further 85 GCP/enterprise/sprint tests and
17 source-publication/packaging/sprint/PDF tests passed. No pilot with actual data run.

Second full source-only run: 809 passed, 4 failed, 1 private-workbook absence skip.
Duplicate import action defects were corrected; one WebKit file-chooser timeout
is being rechecked without concurrent browser suites. The release scanner now
recognizes only the generated 64-hex frontend_build_id in runtime assets, keeping
credential detection and all other account checks active; regression tests cover it.
The source-only credential scan retains pre-existing synthetic signatures in
test_sre.py as REVIEW_REQUIRED; no index/history audit PASS is claimed.

Candidate portable distribution: 306 manifest entries verified; fresh macOS x86_64
offline setup and pip check passed. PDF/DOCX generation and API construction passed
inside the clean bundled environment without ReportLab installed. Final archive
will be rebuilt after the remaining browser checks and data-free handoff update.

Baseline full suite (source-only checkout, all browser cases enabled): 804 passed,
8 browser failures, 1 private-workbook absence skip. Failures concerned dropdown
selectors, moved Client Reporting controls, import-resume visibility and moved
enterprise builder. Corrected and full suite restarted; final result pending.

## Attack-path sprint 2026-10-17 (owner brief: C then A, full attack-path scope)

Step C (done): local checkpoint commit 5a90bdf on feature/offline-security-analyzer, not
pushed. Staged paths checked: no artifacts/, workspace, evidence, backup, data, Office,
archive or database file. Privacy scan (`tools.source_release.findings`) over the 135
added/modified staged files flagged only the two known placeholders in tests/test_sre.py.
UI-audit screenshots (44 synthetic JPEGs, 12 MB) left uncommitted pending owner decision 10.
`pip install -e . --no-deps` in .venv; tests/test_r0.py 70 passed (the CLI-subprocess case
had failed only because the package was not installed).

Step A1 diagnosis (done). Real-workspace diagnostics were run counts-only; results are kept
outside the repository. Outcome about the code: attack paths were generated by the analysis
and returned by the API; the defect was in presentation, not generation. (1) Placement: the
diagrams rendered far below the fold, under the shell, explanation, filter and a raw-column
table. (2) False alert: a red role=alert stated the displayed paths were not a complete
attack-path assessment although the path list was complete; it fired because the separate
relationship list reached its row cap. (3) Unlabelled arrows: cross-project diagrams had
empty edge labels (no relationship, direction reason or status). (4) Paths appeared on one
dashboard sub-tab only. Also found in code: path-review fingerprints hash every path field,
so adding hop fields would turn existing analyst confirmations into NEEDS_REVALIDATION; the
new keys must be excluded.

Step A2 (done): hop model wired for every path kind. GCP investigations via
`from_transitions` (feasibility.gcp_paths), AWS AP-04/05/06 via `aws_hops` with per-key
evaluation evidence (feasibility.aws_evidence; AP-06 P1 cites the principal's role
observation; AP-06 P1/P2 are alternatives), XP/XC hops in cross.py (XC-01 privileged-grant hop
now cites grant observations; XP-03 hops form a chain Internet → endpoint → granted role and
the reachability assumption is dropped when the collected ingress setting proves it).
`hop()` no longer accepts a rule ID alone as evidence for PROVEN. Hop keys are excluded from
the path-review fingerprint (existing reviews stay valid); finalized views carry hop keys.
`feasibility`, `feasibility_reason`, `diagram` and severity calibration unchanged.
Edge-type → STRIDE mapping, hop status rules and per-path hop sources documented in
docs/RULE_SPECIFICATIONS.md. New tests/test_attack_path_hops.py (8): no PROVEN without a
source record, BLOCKED propagation, HYPOTHESIS names missing evidence, justification and
STRIDE on every edge, chain continuity, AWS alternatives/blocked/assumptions, fixtures for
XP-01/XP-03, AWS R1, GCP investigations, review-fingerprint stability. Related suites: 123
passed. Real-workspace check run counts-only; results are kept outside the repository.

Step A3 (done): UI. PathDiagram.tsx renders hops top to bottom (entry node, per hop an
arrowed edge with edge type, status badge, STRIDE badges, direction, justification, rules,
missing evidence, Evidence/Finding click-through to the existing drawers, then the reached
node) with a per-path Hop table fallback; legacy diagrams remain for pre-hop frozen editions.
Attack Paths tab: diagrams first under the project filter; explanation collapsed ("How to
read attack paths"); paths and relationships load independently; the red truncation alert
now fires only for truncated paths, the relationship cap is a muted note under that table.
Groups: GCP, AWS and, on Consolidated, GCP / AWS / Cross-cloud. Empty groups show the API's
new `coverage` reasons (counts per path kind and why a kind was not formed) instead of a
blank area; non-empty groups keep
them in a "Why other path kinds were not formed" disclosure. New "Attack surface by STRIDE"
table (paths, proven/hypothesis/blocked hops, entry points, filter). Overview shows an
"Attack paths" summary card linking to the tab. Colours reuse existing tokens; contrast test
passes. Real-workspace check run counts-only (results kept outside the repository); the
evidence drawer was verified on synthetic data. Synthetic screenshots (light/dark, 1440 and
390 px) in artifacts/attack-path-ui/. Tests: test_gcp_browser extended (hop chain, Proof, Hop table,
Evidence drawer, STRIDE surface rows, no false truncation alert, AWS group never blank);
test_gcp/sre/operational/theme browser 5 passed after AWS hops cite specification rules.

Step A4 (done): report template. Word (native OOXML, real grid tables with repeating header
rows, page breaks, `w` namespace prefix): cover (title, cloud scope GCP / AWS / GCP + AWS,
control table, basis), 1 Executive summary (severity, path proof status, accounts, key
risks), 2 Coverage and limitations (evidence coverage per account/project, UNKNOWN and
manual areas — never reported as passing, attack-path coverage reasons, limitations),
3 Attack surface (STRIDE table), 4 Attack paths (per path: proof, entry, objective, impact,
assumptions, missing evidence, legacy chain, then a hop table with direction justification
and evidence), 5 STRIDE and direction justification (edge-type mapping), 6 Findings,
Appendix A glossary/basis, Appendix B control coverage. Excel sheets: Cover, Executive
Summary, Coverage and Limitations, Attack Surface, STRIDE Matrix (one row per path, six
category columns), Attack Paths, Attack Path Hops (one row per hop, six STRIDE flag columns),
Technical Findings, Findings Validation, Edge STRIDE Mapping, Appendix; every table sheet has
a frozen header row and a filter. Report model adds `provider_scope`, `path_coverage` and
`unknown_areas` (frozen editions filter them per provider/scope); excluded findings are
removed from path and hop finding references too. Pre-hop frozen editions render with
"Hop model not recorded". Verification: new tests/test_report_template.py (4) reopens the
.docx (XML parse plus python-docx when installed) and .xlsx (openpyxl) for GCP, AWS and
GCP+AWS; rendered synthetic GCP+AWS report via Quick Look (page 1) and textutil HTML in
Chromium (all sections; HTML drops fixed column widths, Word keeps them). Not rendered in
Microsoft Word itself. Tests changed for the new template: test_sre (sheet list, section
order), test_gcp_browser (sheet list), test_assessment_sprint ("4 Attack paths").

Step A5 (done): PDF removed. Deleted src/offline_analyzer/reporting/pdf.py and
tests/test_pdf_report.py (it tested only the PDF writer). Assessment-report ZIP now holds
.xlsx + .docx + README; `finalized_files` offers xlsx/rtf/docx; `/api/runs/{run}/finalized.pdf`
returns 400 INVALID_EXPORT; report kind `approved-pdf` is no longer accepted (request model
422); earlier `approved-pdf` history entries are hidden and their download returns
REPORT_FORMAT_WITHDRAWN. UI: PDF links/buttons removed from Finalized findings (per-cloud
and per-account) and Report center; Report center and exclusion tooltip texts updated.
Docs: ADR-011 (PDF paragraph superseded), OPERATOR_GUIDE, UI redesign plan, UI status note.
Tests changed: test_assessment_sprint (no PDF in ZIP; finalized_files("pdf") raises;
frozen docx check), test_sre (finalized.pdf 400, approved-pdf refused), test_gcp_browser
(no PDF in ZIP, no approved-PDF button, no "GCP PDF" link, frozen "GCP DOCX" download),
test_pdf_report deleted. Focused suites: 33 passed.

Step A6 (done): readiness. Full suite with all browser cases
(`RUN_GUI_BROWSER=1 PLAYWRIGHT_BROWSERS_PATH=artifacts/playwright-browsers`): 867 passed,
1 failed in 676 s. The failure, test_operational_browser scope-delete step (scope button
still present after 5 s), is in the unchanged purge flow; it passed twice in isolation
(30 s each), so it is a load timeout, not a regression. Added afterwards and passed:
test_sre::test_withdrawn_pdf_reports_are_hidden_and_not_downloadable. Ruff check, ruff
format --check (233 files), Prettier, TypeScript, 3 frontend tests and production build
passed. Verdict: GO for completing the GCP assessment, with conditions: (1) install the
rebuilt CloSec.zip and open Attack Paths on the real workspace (the evidence drawer was
exercised on synthetic data only); (2) open one generated .docx/.xlsx in Microsoft
Word/Excel before sending; (3) where a path kind is absent, check the coverage reasons the
UI and reports state. No blocker found.
Not tested: native Microsoft Word/Excel rendering, native Windows, real collector-export
compatibility, evidence drawer and report export on the real workspace, non-AWS
federation paths (not modelled), concurrency of the running 0.8.4 app with the new release.

Step A7 (done): CloSec.zip rebuilt from the working tree (snapshot fea6d83c6d5d, base
5a90bdf, uncommitted changes; not a clean-commit release) with tools/portable_release.py and
the wheelhouse; nested CloSec-0.8.4-update-20261017-sprint-fea6d83c6d5d-portable-source.zip
(318 manifest files; 260 outer files). Contains the hop model and current UI bundle, no
pdf.py, tests, images, PDFs, Office files, databases or evidence; scanner hits only the
manifest SHA-256 digests (as before). Clean install: verify.py PASS, offline setup on Python
3.12.14 with pip check clean, installed launcher on an empty synthetic workspace returned
/api/health {"ready": true} and index 200. Installed at
/Users/dev/CloudAssessmentScripts/CLoSec/CloSec.zip, 64,385,359 bytes, SHA-256
2eef448c9780eafd162ea0e11f17c648634c381e25d56c3e3073f2c603facbd8; previous archive kept as
CloSec.before-attackpaths-20261017-225559.zip (SHA-256 10c7eb6a…d401). Records in ignored
artifacts/closec-zip-update-20261017-attackpaths/. The diagnostic copy of the real database
was deleted after use.

Step A8 (done): data-handling remediation approved by the owner. Changelog passages that
described the real environment were replaced with identifier-free, aggregate-free wording;
CloSec.zip rebuilt and reinstalled from this text; the previous archive is kept outside the
repository for the owner to delete. The attack-path build folder and two empty browser temp
folders were removed; the CLoSec folder's git no longer tracks zip archives (not committed).
Spotlight indexing disabled for artifacts/. Real-workspace diagnostics in this repository are
counts-only and in place; the workspace and database are never copied.

## GCP collector 2.2.6 (2026-10-18, owner brief; synthetic data only)

Collector (evidence format unchanged, assessment-expanded-2.2):
- API-key and bucket detail loops read their lists with `Read-EvidenceArray` (no
  `Get-Content -Raw | ConvertFrom-Json` left anywhere; the folder-describe read uses
  `-InputObject`); counters advance only after the name check.
- Run/Functions IAM: when `run_services_rest` / `functions_rest` is not usable, targets come
  from the gcloud `cloud_run` / `functions` lists; each substitution is written to the new
  manifest field `dependency_fallbacks` (family, failed dependency and status, fallback
  source and status, target count) and printed.
- gcloud failures: `Get-GcloudFailureStatus` adds RATE_LIMITED, AUTH_ERROR and SERVER_ERROR;
  403/404 match only beside HTTP/status/code/error, a reason phrase or brackets. Up to 3
  retries (2/4/8 s) for RATE_LIMITED and SERVER_ERROR only, re-running the same read-only
  command; attempts are noted in the dataset's stderr file.
- gcloud stdout/stderr decoded as UTF-8 (`StandardOutputEncoding`, `PYTHONIOENCODING=utf-8`,
  `PYTHONUTF8=1`) for collection, the sign-in check and the REST token; project discovery
  switches the console encoding to UTF-8 and restores it.
- ZIP built entry by entry with forward-slash names, verified after writing; SHA-256 printed
  and written to `<package>.zip.sha256` (the manifest is inside the ZIP, so it cannot hold it).
- `iam_parent_hierarchy_attempted.json` written atomically, UTF-8 without BOM, always an array.
- New manifest field `detail_limits_reached` (service_accounts, buckets, api_keys,
  custom_roles, kms); -MaxDetailItems now also bounds custom-role and KMS key-ring/key
  expansion (default 0 = no limit, so default behaviour is unchanged).
- Limitations text: evidence may contain VM startup scripts and metadata, Cloud Run/Functions
  environment variables and Cloud Build substitutions; handle the package as sensitive.
Analyzer: 2.2.6 accepted (2.2.0-2.2.5 still accepted); `detail_limits_reached` and
`dependency_fallbacks` are optional, strictly typed manifest fields (unknown keys fail closed).
A collector version outside the range now fails with GCP_COLLECTOR_VERSION_UNSUPPORTED
("Accepted for assessment-expanded-2.2: 2.2.0 to 2.2.6") and the import preview names it;
LEGACY_GCP_MANIFEST_INVALID no longer refers to the pilot-1.2.2 contract. Contract JSON and
coverage matrix regenerated (version only; no dataset change). Schemas LocalJob and
SanitizedDiagnostic regenerated (one new fixed rejection phrase). Catalog line references for
the three Discovery Engine rows updated (781, 782, 794). No rule or dataset added.
Tests: new tests/test_gcp_collector_226.py (46: static source checks, classification table
emulating PowerShell -match in Python, synthetic 0/2/3-bucket packages, collapse simulation,
Run IAM fallback import, version acceptance/rejection, malformed new fields fail closed);
updated test_gcp_expanded22 and test_workflow_api for 2.2.6.
Not verified here (no PowerShell on this machine): any execution of the collector, including
Windows PowerShell 5.1 array handling, ZIP entry names, console/pipe encoding, retries and
fallbacks against real gcloud output.
Readiness 2.2.6: full suite with all browser cases 916 passed, 0 failed; ruff, format,
contract check, Prettier, TypeScript, frontend tests and build passed. CloSec.zip rebuilt
(snapshot 38ba8c482de7, uncommitted working tree on 5a90bdf); clean macOS install, offline
setup, pip check and /api/health ready; shipped collector script and contract file are
byte-identical to the repository copies. Previous archive kept outside the repositories.

## Decisions on 2.2.6 and workspace location (2026-10-18, owner brief; synthetic data only)

Part A (collector script unchanged, SHA-256 3a29374f0aea…6b7f):
- A1: -MaxDetailItems keeps limiting custom roles and KMS. Collector README and
  OPERATOR_GUIDE now say a non-zero value lowers coverage to Partial and must not be used
  during an engagement.
- A2/A3: the analyzer consumes the 2.2.6 fields. `ingestion/gcp_expanded.collection_notes`
  adds per-dataset reasons: DETAIL_LIMIT_REACHED_<FAMILY> on the limited family;
  IAM_TARGET_LIST_INCOMPLETE on the REST list and its run/function IAM datasets when the list
  is PARTIAL/TRUNCATED (no fallback); IAM_TARGETS_FROM_GCLOUD_LIST / IAM_TARGETS_FALLBACK_USED
  when the fallback was used; IAM_TARGETS_UNAVAILABLE when the list failed and the fallback
  also failed or was absent (ERROR coverage, no evidence, never PASS). Expanded GCP sources
  are never COMPLETE (Effective Coverage) by construction, so these stay Partial or Error.
  RATE_LIMITED and AUTH_ERROR are ERROR coverage with plain-language reasons. Reasons appear
  as `coverage_reason` in the Coverage tab's collection-gaps table and in the Word/Excel
  "Collection gaps and limitations" table (report model `coverage_notes`; frozen editions
  filter it by scope). Tests: tests/test_gcp_coverage_notes.py (6).
- Contract sync: tests/test_gcp_contract_sync.py (4) fails when the collector can emit a
  dataset name or manifest/dataset-entry field missing from the catalog, the contract JSON or
  the manifest models (a mutation case proves it). Coupling checklist added to
  docs/handoff/GCP_HANDOFF.md; its stale note about the misleading version message replaced.
- A4: pwsh is not installed on this Mac; no PowerShell parse or function run was possible.
- A5: readiness lines and the TEST_PLAN entry are written before the archive is built.

Part B (workspace location):
- Resolution at start: command-line folder, then CLOSEC_WORKSPACE, then the remembered
  location, then the default (unchanged default; start scripts now pass it as
  --default-workspace). An invalid remembered location starts a private empty setup folder
  that shows only the location screen and is removed on exit.
- storage/location.py: pointer file in the OS user-configuration folder (path + timestamp,
  0600); safety checks (block: source tree, CloSec release/application folder; warn with
  explicit acceptance: git repository incl. home-directory repository, sync folders, network
  or removable drives, not writable, low free space, long Windows paths, world-readable);
  read-only inspection (database, journal, environment file, schema, lock holder pid,
  counts); prepare_open run by the launcher (newer schema refused unchanged, older schema
  verified pre-migration backup beside the workspace then additive upgrade, leftover journal
  recovered, checkpoint, integrity and counts); verified whole-folder copy used for change
  location and backup (sizes, SHA-256, counts; staging removed on failure; source only read).
- Launcher: WorkspaceLock records the owner pid; a second launcher prints only that pid;
  restart loop after a switch; audit lines WORKSPACE_* with a one-way location hash only.
- API /api/workspace (show, check, apply, restart) and the "Workspace location" screen with
  header path and Copy path; every change needs Check location plus confirmation (and
  warning acceptance); nothing is moved or deleted; the old folder's path is shown after a
  copy. Backup note: backups hold client data.
- Scripts: CloSec.command, CloSec.cmd (CRLF kept; forwards arguments to the release),
  start-macos.sh, start-windows.ps1.
- Tests: tests/test_workspace_location.py (26), tests/test_workspace_launcher.py (3, real
  launcher), tests/test_workspace_browser.py (2, light and dark). Windows paths only as text.
Readiness (written before the archive build, so it ships): full suite with all browser cases
956 passed, 1 failed (745 s). The failure, test_import_recovery_browser[webkit], timed out
waiting for the WebKit file chooser before any workspace step (the known load timeout); the
file passed twice in isolation (Chromium and WebKit). Ruff check, ruff format --check (242
files), collector contract --check, Prettier, TypeScript, 3 frontend tests and production
build passed. Collector script byte-identical to 2.2.6 (SHA-256 3a29374f0aea…6b7f).
Not tested: native Windows (CloSec.cmd, start-windows.ps1, path handling beyond text checks,
drive-type detection, msvcrt lock), any PowerShell run of the collector, real workspaces.
Post-build (repository copy only; an archive cannot contain its own digest): CloSec.zip
snapshot 657f777dbdd7, 64,450,913 bytes, SHA-256
66383c6e296f0b593e43a811c5e56d1c26c7a60d3a0cb1b8b6923a112f3ef8da; clean macOS install, offline
setup and pip check passed; /api/health ready with a temporary HOME and config folder (default
resolution, nothing remembered); shipped collector and contract byte-identical; shipped
changelogs contain the readiness lines; no pointer file in the archive. Previous archive kept
outside the repositories.

## GCP collector 2.2.7 and analyzer (2026-10-18, owner brief; synthetic data only)

Collector (evidence format and dataset names unchanged; no new manifest field):
- A: `$PrecheckExempt` (iam, orgpolicy, recommender, accesscontextmanager, securitycenter,
  cloudasset, logging): always attempted and classified from the response; resource services
  keep the enabled-services pre-check (`Test-PrecheckSkip`, both gcloud and REST paths).
- B: `ConvertTo-ConstraintName` reduces bare, `constraints/x` and `.../policies/x` names; the
  11-constraint `$EffectivePolicyBaseline` comes first, discovered names follow, duplicates are
  removed, each is described with `--effective --project` as `effective_policy_N`; unlimited
  as in 2.2.6 (no new detail-limit field).
- C: `Resolve-DisabledService`: a disabled-service error naming another project number than
  the target's is QUOTA_PROJECT_DENIED (gcloud and REST); target number from the selected
  inventory record, refined from the collected project description; unresolved keeps
  API_DISABLED with a note in the dataset's error file. `not enabled on project` now matches.
- D: no dependency fallback is recorded or printed when the REST list was API_DISABLED.
- E: `argument --x: Must be specified` is COMMAND_ERROR.
Analyzer: 2.2.7 accepted (2.2.0-2.2.7; message and fixed rejection phrase updated; schemas
LocalJob and SanitizedDiagnostic regenerated); contract JSON version only; catalog line
references 827/828/840. GCP-GOV-KEYS 1.3.0 (own version; other GCP rules unchanged) parses v1
and v2 effective shapes via `constraint_name` / `boolean_enforcement` and accepts the boolean
`--effective` flag that expanded packages record (before, expanded packages always gave
UNKNOWN). API_DISABLED is presented as "Service not enabled (per enabled-services evidence)",
distinct from ACCESS_DENIED, QUOTA_PROJECT_DENIED and EMPTY, in the Coverage tab, finding
evidence (`coverage_reason`), collection requests and report notes; an API_DISABLED REST list
no longer carries IAM_TARGETS_UNAVAILABLE.
Tests: tests/test_gcp_collector_227.py (classification incl. project numbers, exemption list,
normalisation/baseline, fallback suppression, 16 GOV-KEYS shapes, end-to-end 2.2.7 package with
all 48 GCP rules producing results, 2.2.4-2.2.6 equal results); 2.2.6 tests updated.
pwsh is not installed here: no PowerShell parse or execution.
Readiness 2.2.7 (written before the archive build, so it ships): full suite with all browser
cases 990 passed, 0 failed (744 s). Ruff check, ruff format --check (243 files), collector
contract --check, Prettier, TypeScript, 3 frontend tests and production build passed.
Collector 2.2.7 SHA-256 74513f2a59998c4997233cca047c0175fc1cc50f236e60c2b8a9a78e9dd07b3e;
contract 01093d137defcb2a9638b01b8edf1f27b3d7b49f7118b974f0be83896b94ae5d.
Not verified (no PowerShell here): parse of the 2.2.7 script, Resolve-DisabledService on real
gcloud/REST error text, the always-attempted calls against real APIs, effective-policy output
of real `gcloud org-policies describe --effective`, and every Windows PowerShell 5.1 behaviour
listed for 2.2.6. Not tested: native Windows, real workspaces.
Post-build (repository copy only): CloSec.zip snapshot f009acfa9039, 64,460,761 bytes, SHA-256
ec7e7e131cce0591ba92bda85d4555af0871b5b199c148324ed0c9cc5ae84695; clean macOS install, offline
setup, pip check and /api/health ready (temporary HOME and config); shipped collector and
contract byte-identical; shipped changelogs contain the 2.2.7 readiness lines; previous
archive kept outside the repositories.

## GCP identity resolution E1/E2 (2026-10-18, owner brief; synthetic data only)

Root cause: GCP-IAM-CROSSPROJECT compared the text before `.iam.gserviceaccount.com` with the
analyzed project ID only, so same-project Google service agents (`service-NUM@gcp-sa-*`) and
service accounts of other collected projects were reported as cross-project; BASIC and
IMPERSONATION counted platform agents as removal targets; the org rules used an unnumbered
agent check and an ID-only home; XP-02 used a third home resolver.
Change: one shared resolver (rules/gcp_identity.py) by project ID and number, with trust
classes PLATFORM_MANAGED, SAME_PROJECT, IN_SCOPE_OTHER_PROJECT, IN_ORG_NOT_ASSESSED,
EXTERNAL_OR_UNKNOWN and UNKNOWN; opt-in set `IDENTITY_ENRICHED` in rules/registry.py. Versions:
GCP-IAM-BASIC, GCP-IAM-IMPERSONATION, GCP-IAM-CROSSPROJECT 1.3.0; GCP-ORG-SA-PRIVILEGED,
GCP-ORG-CROSSPROJECT-SA 1.1.0; all other rules unchanged. Finding text names the member, home
project and trust class; reclassified members are recorded with the matched evidence (org
pass: NOT_APPLICABLE or UNKNOWN per-resource results; an unresolved home keeps the
collection-scope result UNKNOWN). XP-02 edges use the same classes (agents of other projects
included, same-project and platform-managed excluded); path steps are unchanged, so path IDs
and review fingerprints are unchanged for paths that still exist. Collector unchanged.
Owner decision (2026-10-18): the Compute Engine default service account is not
platform-managed; it is SAME_PROJECT by number on its own project, so basic-role and
privileged-service-account findings for it remain, and with another project's number it is
cross-project. cloudservices and gcp-sa-* agents stay PLATFORM_MANAGED. Google agents of
another project are reported cross-project; changed finding text prompts revalidation of
existing reviews, which keep matching by finding ID (both accepted).
Tests: tests/test_gcp_identity.py (11).
Readiness E1/E2 (written before the archive build, so it ships): full suite with all browser
cases 1000 passed, 1 failed (757 s); the failure was a WebKit file-chooser timeout in the
pilot import browser test, which passed on an immediate rerun of that file (2 passed). Ruff
check, ruff format --check (288 files), Prettier, TypeScript, 3 frontend tests and production
build passed. Collector unchanged: SHA-256
74513f2a59998c4997233cca047c0175fc1cc50f236e60c2b8a9a78e9dd07b3e. Not tested: real
workspaces or live evidence (synthetic only), agent naming forms outside the documented
patterns, native Windows.

## Per-principal role lookup (E5 addendum, 2026-10-18; synthetic data only)

New analyzer-only resolver iam/gcp_principals.py (see RULE_SPECIFICATIONS "Per-principal role
lookup"): every observed binding of a principal across the imported projects with role, scope,
condition, source dataset and trust class; per-project resolution (project and parent IAM);
privilege summary that is never NARROW when unresolved; custom roles UNRESOLVED without
custom_role_detail; one documented privileged-role list (union of existing rule lists). API
GET /api/runs/{run}/gcp/principals and /gcp/principal; IAM intelligence "Principal roles" view;
finding detail lists its members and attached service accounts with "View roles" links. No
rule logic or version changed; the E5 enrichment itself is not implemented here.
Tests: tests/test_gcp_principals.py (12, incl. 45 projects / 5,000 bindings: index build
0.2 s, lookup 1 ms) and tests/test_principals_browser.py (light and dark).
Readiness: full suite with all browser cases 993 passed, 22 failed (1,053 s, slower than the
usual ~760 s). Two were timeouts in the AWS GUI workflow test (a workbench row not shown within
5 s after reload; an import button "not stable"); the remaining 20 failed with Playwright's
"Sync API inside the asyncio loop" error left by those failures. All 22 passed when rerun
together (312 s). Ruff check, ruff format --check (291 files), Prettier, TypeScript, 3 frontend
tests and production build passed. Collector unchanged (SHA-256 74513f2a...). CloSec.zip not
rebuilt for this addendum.

## Service-account ownership classes and GCP-GOV-KEYS correctness (2026-10-18, owner brief; synthetic data only)

Decisions applied: a missing `parent` in the collected project record is UNRESOLVED with the
reason "no parent recorded — verify standalone project"; custom roles with detail stay
unclassified (never NARROW); the per-principal resolver stays view-only (no rule uses it);
one archive rebuild at the end.
Fix 1 (false positive: GCP-IAM-CROSSPROJECT HIGH on the Google APIs service agent with
Editor, because the email's project number was compared with the project ID): account
classes PLATFORM_AGENT / DEFAULT_SA / USER_MANAGED with owner project ID and number
(rules/gcp_identity.account_class, extending the E1/E2 classifier), compared with the binding
project's collected ID and number; unresolvable is UNKNOWN. Applied to GCP-IAM-CROSSPROJECT,
GCP-IAM-BASIC, GCP-IAM-IMPERSONATION (1.4.0), GCP-ORG-SA-PRIVILEGED and GCP-ORG-CROSSPROJECT-SA
(1.2.0): PLATFORM_AGENT is never a finding (NOT_APPLICABLE "Google-managed service agent
(platform-managed)"); DEFAULT_SA is evaluated by GCP-IAM-BASIC and by the cross-project rules
only when its owner differs; USER_MANAGED unchanged. "Actual configuration" lists member,
account class, owner project, role and condition. The per-principal view shows the same class.
Attack paths unchanged.
Fix 2 (GCP-GOV-KEYS 1.4.0): constraint name, affected resource, observed value, evidence and the
verification command come from the same effective_policy record (the detail previously
hard-coded the Creation constraint and looked for an `enforced` field that v2 records do not
have, so it showed "Absent"); an unconditionally enforced managed successor constraint
suppresses the legacy finding (PASS citing it), otherwise "Managed constraint not observed" is
noted; a key constraint without its own effective record is UNKNOWN.
Regression: per-rule outcome counts of every other GCP rule on six synthetic fixtures are
identical before and after (tests/gcp_rule_outcomes_baseline.json). Changed counts: GCP-GOV-KEYS
UNKNOWN 1 -> 3 on the three expanded fixtures and 1 -> 2 on the simple fixture (constraints
without their own record); the other five rules' counts are unchanged on these fixtures (they
contain no platform agents).
Tests: tests/test_gcp_ownership.py (12), tests/test_gcp_principals.py (13),
tests/test_gcp_identity.py (11, updated), tests/test_principals_browser.py (updated).

## False-positive disposition, pitch-black theme, GOV-KEYS UNKNOWN scope (2026-10-18, owner brief; synthetic data only)

D0: the guard (`service-<n>@<id>.iam.gserviceaccount.com` with a collected or organization
`<id>` is USER_MANAGED) is accepted and tested. GCP-GOV-KEYS: a denied effective-policy
dataset for an unrelated constraint no longer makes the rule UNKNOWN; UNKNOWN only when a
legacy key constraint has no effective record; "Managed constraint not observed" is a
completeness note. On the 2.2.7 fixture with both legacy constraints unenforced and no
managed records: exactly 2 FAIL, no UNKNOWN. Outcome counts vs the pre-change baseline:
GCP-GOV-KEYS UNKNOWN 1 -> 2 on the three expanded fixtures and the simple fixture
(constraints without a record), 1 -> 0 on package_227; every other GCP rule unchanged.
Part E: false positives reuse the existing exclusion log (reason FALSE_POSITIVE, now with a
mandatory reason text, preset "Google-managed service agent (platform-managed)"); records add
the previous analyst state and the named principals; bulk endpoint POST
/api/runs/{run}/exclusions (all-or-nothing, at most 2,000); workbench filter (hide by
default / show with FP tag / only) with "N excluded as false positive"; facets and severity
totals exclude them; attack paths that cite one are flagged and left out of report sections
(the flag is not part of the path-review fingerprint); "Excluded findings" appendix in Word
(docx and RTF), the report Excel and the workbook (REPORT_SHEETS 27 -> 28); snapshot and member
runs reflect each other; carry-over to a new import of the same project only on an exact
finding-ID and principal match, marked "carried over from <import>". Rule evaluation is
unchanged.
Part F: dark theme is pitch black (#000000; surfaces #0a0a0a / #121212 / #171717; borders
#262626; text #ededed / #a3a3a3; muted #8a8a8a because #737373 measures 4.4:1 on black;
one accent #5ca8ff for links and focus) and the default; Light and System stay selectable.
Severity, status, chart, diagram and navigation tokens retuned; a new `--on-danger` token.
tests/test_theme_contrast.py checks every text pair >= 4.5:1 and marks/boundaries >= 3:1.
Tests: tests/test_false_positive.py (9), tests/test_false_positive_browser.py (2 themes),
tests/test_theme_contrast.py (7), updated theme, workspace, principal, exclusion and report
tests.
Readiness (written before the archive build, so it ships): first full run with all browser
cases 1037 passed, 3 failed (845 s): workbook sheet-count/name contracts in
tests/test_gui_browser.py and tests/test_r0.py still expected 27 sheets; updated to 28
("Excluded Findings"), no other change to those tests. Second full run: 1040 passed, 0 failed
(814 s); no AWS GUI timing failure occurred. Ruff check, ruff format --check (295 files),
Prettier, TypeScript, 3 frontend tests and production build passed. Collector unchanged:
SHA-256 74513f2a59998c4997233cca047c0175fc1cc50f236e60c2b8a9a78e9dd07b3e. Not tested: real
workspaces or live evidence, native Windows.


## Phase 1 — GCP collector 2.2.8 (custom_role_detail fix) — DONE (2026-10-19, owner brief; synthetic data only)

Defect: `gcloud iam roles describe` was called with the full resource name
(`projects/<id>/roles/<name>`), which gcloud rejects ("The role id should not include any
'projects/' or 'organizations/' prefix"), so every custom_role_detail_* dataset failed.
Fix: `Get-RoleDescribeArguments` passes the bare role ID positionally with `--project=<id>` or
`--organization=<number>` (dots and underscores in role IDs, domain-scoped project IDs);
other shapes are skipped with a console note and never crash; the counter advances only for
described roles; the gcloud prefix message is classified COMMAND_ERROR (added to the existing
COMMAND_ERROR pattern). No dataset or manifest change. Version 2.2.8 in script, header,
README and contract; analyzer accepts 2.2.0–2.2.8 (messages and schemas LocalJob /
SanitizedDiagnostic updated); catalog line references 830/831/843. No rule evaluates custom
roles directly; their permissions reach the per-principal resolver.
Tests: tests/test_gcp_collector_228.py (static argument construction for both scopes and odd
shapes, parenthesised concatenation, no pipeline JSON parsing, classification, no write verbs,
synthetic 2.2.8 import resolving custom-role permissions); 2.2.4–2.2.7 and 2.2.8 give equal
outcomes; existing 2.2.6/2.2.7 tests updated (version, accepted range, loop window).
Windows PowerShell 5.1 behaviour is not verifiable on this Mac (no pwsh); the script was not
parsed or executed.
Collector 2.2.8 SHA-256 11f59595710f95f0024ffad5c8d5cd76dd1add57c8ca77cff1fc1f543dd78368;
contract c5615f653a9916053451a4998a36fef971a7a31c1114613d9d1c2cd47d1321b2. AWS collector files
byte-identical.
Readiness (before the archive build): full suite with all browser cases 1056 passed, 1 failed
(846 s): the known WebKit file-chooser timeout in
tests/test_import_recovery_browser.py[webkit]; isolated rerun of that file 2 passed ("known
flaky browser timing under load, isolated rerun clean"). Ruff check, ruff format --check (298
files), Prettier, TypeScript, 3 frontend tests and production build passed.

## Phase 2 — E5 attached service-account context and principal role lookup — DONE (2026-10-19, owner brief; synthetic data only)

The per-principal resolver (iam/gcp_principals.py, already present) now classifies predefined
roles with one documented list: Owner, Editor, every `*Admin`/`*admin` role (optional .vN),
serviceAccountTokenCreator, serviceAccountUser, serviceAccountKeyAdmin and the IAM escalation
roles; it also records each binding's resource ID. New opt-in set
`registry.PRINCIPAL_CONTEXT_RULES` (GCP-VM-DEFAULT-SA, GCP-VM-FULL-API-SCOPE,
GCP-NET-FW-ADMIN/DB/ANY-INTERNET, all 1.2.0) and rules/gcp_principal_context.py: a FAIL gains the
attached account, its resolved roles, scopes and a reference to its GCP-IAM-BASIC finding;
PRIVILEGED raises DEFAULT-SA to HIGH and FULL-API-SCOPE to MEDIUM (HIGH with an external IP);
firewall rules keep their severity and gain context; NARROW and NONE_OBSERVED add a label;
UNRESOLVED adds "privileges unresolved: <reason>" and a missing-evidence entry. Severity is never
lowered; outcomes are unchanged; missing evidence never yields PASS. The rule-time resolver is
built over the assessed run only; the IAM intelligence view keeps all imports. Finding IDs are
unchanged; changed text makes existing decisions on these findings NEEDS_REVALIDATION after a
re-assessment. GUI per-principal view and finding links were already present (light and dark
tested earlier).
Tests: tests/test_gcp_principal_context.py (6: Editor raised, narrow labelled not lowered, no IAM
evidence / custom role without detail / parent IAM denied UNRESOLVED, other rules unchanged and
finding IDs stable); tests/test_gcp_principals.py updated for the documented list (two projects,
conditional, group, 45-project / 5,000-binding performance kept).
Readiness (before the archive build): full suite with all browser cases 1063 passed, 0 failed
(854 s). Ruff check, ruff format --check (300 files), Prettier, TypeScript, 3 frontend tests and
production build passed. Collector 2.2.8 unchanged in this phase.

## Phase 3 — Safe defaults, path-review carry-over, custom limitations — DONE (2026-10-19, owner brief; synthetic data only)

1a Report scope default is "confirmed" for Word and report Excel (API, model, GUI); "valid" and
"all" stay explicit options with a Report center warning and a cover "Report scope notice".
1b Excluded findings (every reason) leave every finding/risk count. Before → after:
dashboard severity, Cloud Overview, Cloud Domain Comparison, report and workbook finding sheets:
already excluded → unchanged; dashboard STRIDE path counts: counted paths depending on excluded
findings → not counted (evaluation counts unchanged); Tracker Staging: counted → not counted;
Enterprise Security Gaps / Affected Accounts and Resources / enterprise dashboard systemic count
and investigations list: listed → issues whose findings are all excluded are omitted; workbook
"Assessment Summary" candidate_findings: counted → not counted (excluded shown separately); run
list finding counts, GCP account list finding counts, finding facets, checklist finding counts,
readiness (auto-validation) counts: counted → not counted; repeated-control observations:
counted → not counted. Evaluations are unchanged; Control Assessment, Cloud Evaluations and the
GUI evaluation list gain "excluded (reason)". Attack paths depending on any excluded finding are
flagged ("depends on an excluded finding") and left out of report sections. Not changed
(integrity checks): reconciliation, purge counts, release audit.
1c Snapshot default membership = latest active import per scope by collection time (GCP
project; AWS partition + account + region, so complementary packages never supersede each
other); superseded imports are listed "superseded, not included" and selectable. Snapshot ID
rule unchanged. 1d Refresh keys by provider-neutral scope (GCP project, AWS account);
staleness covers GCP projects. 1e Workbook sheet-count contract tested for AWS-only (28),
GCP-present (40) and mixed (40).
3 Path reviews apply in any run where the path fingerprint is identical; a different fingerprint
stays NEEDS_REVALIDATION. 2d Custom scope-limitation text per run (Report center; additive table
report_limitations), rendered after the fixed limitations in Word, RTF and report Excel.
4a GCP 100,000 observations / 128 MiB per run and snapshot 2,048 members / 250,000
observations already fail closed (no truncation); they now carry plain-language explanations.
Upgrade proof: a workspace built with the Phase 2 code (decisions, exclusions incl. false
positive, SRE verdicts, report revisions, path reviews) opened with the new code: detected OLDER
(one missing table), verified pre-migration backup, migrated, integrity OK; every finding
status, stage, exclusion and report-revision state unchanged; no new NEEDS_REVALIDATION or
NEEDS_REVIEW; the snapshot now also shows CONFIRMED for paths reviewed in its member runs
(identical fingerprint, intended).
Tests: tests/test_phase3_defaults.py (11); updated tests that relied on the old defaults
(test_sre, test_sre_browser, test_report_template; test_enterprise selects both imports of one
account explicitly).
Readiness (before the archive build): first full run 1065 passed, 5 failed, 4 errors (tests
still assuming the old defaults and an AWS scope key without partition/region, corrected; one
WebKit file-chooser timeout); second full run with all browser cases 1074 passed, 0 failed
(884 s). Ruff check, ruff format --check (303 files), Prettier, TypeScript, 3 frontend tests and
production build passed. Collector 2.2.8 unchanged.

## Phase 4 — Root-cause grouping — DONE (2026-10-19, owner brief; synthetic data only)

2a Findings that share a root cause form one group (findings/groups.py). The key kind per rule
is declared in rules/registry.py:GROUP_KEYS: "principal" (GCP IAM basic/impersonation/
cross-project, key persistence/age/privilege, org privileged and cross-project service accounts,
R1 instance-role privilege and role-trust conditions; an R1 IAM finding without a named
principal keys on the role itself), "resource" (GCP-NET-FW-ADMIN/DB/ANY-INTERNET, R1 sensitive
security-group ingress, latent security-group exposure) and "org_node" (GCP-ORG-* rules, keyed
on the organization or folder). Any other rule, or a key without a value, falls back to one
group per rule. The group ID depends only on (rule, kind, value), so a group is identical in
every member run and in the snapshot. Grouping is a view: finding IDs, evaluations, decisions
and outcomes are unchanged. Excluded findings are never group members (the group shows an
excluded count). GUI: a groups view (severity = highest member, member count, status mix),
`GET /api/runs/{run}/finding-groups`, and finding-list filtering by group.
2b Group-level bulk actions (review, send to SRE, exclude) act on the member findings through
the existing bulk paths: at most 2,000 members, all-or-nothing.
2c One report text per group (optional immediate mitigation), member limit 2,000. When a member
finding changes, that member becomes NEEDS_REVIEW and the other members keep the group text.
2d Word and report Excel are grouped by default: one entry per group with an
affected-resources table, a "Grouped Findings" sheet, and the cover line "N grouped findings /
M affected resources". Totals still count every finding. `grouped: false` (Report center
option) restores one entry per finding. Section 7 of docs/METHODOLOGY_INPUT.md ("no view groups
findings") is superseded.
Tests: tests/test_phase4_groups.py (4: group keys per kind and fallback; groups identical
across member runs and snapshot, excluded never members, group bulk confirm; group report edit
member limit and per-member NEEDS_REVIEW incl. immediate mitigation; grouped and ungrouped Word
and Excel); tests/test_groups_browser.py (1: group view and group mark valid in the compiled
GUI).
Readiness (before the archive build): first full run 1049 passed, 30 failed (every failure a
browser launch without PLAYWRIGHT_BROWSERS_PATH=artifacts/playwright-browsers, no assertion
failures); second full run with all browser cases and the documented browser path 1079
passed, 0 failed (841 s). Ruff check, ruff format --check (306 files), Prettier, TypeScript, 3
frontend tests and production build passed (rebuilt assets carry the same content hashes as the
tested bundle). Collector 2.2.8 unchanged.

## Faster data deletion and no busy errors during jobs — DONE (2026-10-19, owner request; synthetic data only)

Scope and file deletion keep their safety model (private working copy, verified backup,
journalled database swap, before/after verification); only the mechanics changed.
- Verification scan (`assessment/purge_verify.py:scan`): one SQL pass per table instead of one
  query per text column and identifier; each workspace file is read once (previously once per
  identifier) and the token regex runs only on chunks that contain the literal identifier.
  Results are identical to the previous definition (tested).
- Compaction (`assessment/manage.py:compact`): rows move column-wise in bounded batches (2,000
  rows / 32 MiB) instead of 128-row `executemany`; external access stays disabled (no ATTACH).
  A working-copy column unknown to the current layout fails closed with
  SCOPE_COMPACT_SCHEMA_MISMATCH before anything is published.
- Analyst records of removed findings are deleted in one statement per table.
- Deletion jobs report stages: backup, references before, private copy, removal, re-assessment
  (n of m), compaction, database install, verification. The GUI job panel names each stage.
- GUI: a read refused with WORKSPACE_OPERATION_IN_PROGRESS while a job owns the database is
  retried every 0.75 s until the job ends (at most the 1-hour job budget) instead of showing an
  error; writes are never retried.
Measured on synthetic workspaces (GCP scope deletion with backup): 110 MiB workspace 16.9 s →
3.4 s; 150,000-observation workspace compaction 56 s → 4.4 s and both verification scans
15.5 s → 3.6 s. Re-assessment of an affected consolidated snapshot is unchanged (required for
correct findings) and remains the largest part on large workspaces.
Tests: tests/test_deletion_speed.py (4: compaction copies every table exactly with no WAL left;
scan counts equal the per-column definition incl. prefix IDs; file search across chunk
boundaries keeps token boundaries; stages reported in order with re-assessment n of m);
frontend/src/api.test.ts (2: busy read retried, write never retried).
Readiness: full suite with all browser cases 1083 passed, 0 failed (934 s); after a final
explanation-text addition, deletion, scope and explanation tests 203 passed. Ruff check, ruff
format --check, Prettier, TypeScript, 5 frontend tests and production build passed.
Pre-commit source scan: three 12-digit identifiers in new tests (test_gcp_collector_227/228,
test_gcp_principals) were not on the documented synthetic list; replaced with listed synthetic
values (61 tests in those files passed). The two remaining scanner hits in tests/test_sre.py
were already in the committed tree.

## Deletion preview timeout on large projects — DONE (2026-10-19, owner report; synthetic data only)

Owner report: "Local API did not answer within 15 seconds" when deleting; the tool appeared stuck.
Cause: the deletion preview (`assessment/manage.py:plan`) ran one query per owned observation
(and one per artifact) to decide whether raw evidence is shared; on a synthetic project with
75,000 observations the preview took 534 s, the GUI gave up after 15 s and every later read queued
behind it on the single database worker.
- Both checks are now one set-based query each. Every reference of an owned observation is
  checked (previously the first one returned); synthetic data has exactly one reference per
  observation, so results are unchanged there and can only be stricter elsewhere.
- The preview counts GCP relationship edges without loading their evidence
  (`inventory/cloud.py:relationships(evidence=False)`); the relationship view loads evidence once
  per observation instead of once per edge; `Store.observations(project=...)` filters one project
  in SQL before parsing. Edges are identical (compared for every run, project and limit).
- File deletion removes observations and their evidence references in one statement each.
- GUI: deletion previews and the file list allow 3 minutes; while a preview is prepared its button
  is disabled and shows "Preparing deletion preview…", so repeated clicks cannot queue more work.
Measured (75,000-observation synthetic project): preview 534 s → 2.5 s; whole deletion job 11 s,
verification CLEAN.
Tests: tests/test_deletion_speed.py now 6 (added: preview statement count does not grow with
observations; relationship edges identical without evidence). Full suite with all browser cases
1085 passed, 0 failed (846 s); Ruff, Prettier, TypeScript, 5 frontend tests and production build
passed. Installed as CLoSec/CloSec.zip (sha256 3bcf79ae…, backup of the previous archive kept);
clean install health check passed.

## GCP correctness release candidate (2026-10-20; synthetic data only) — DONE (phases 1-3; phase 4 not done)

Input: docs/GCP_CONTROL_AUTOMATION_AUDIT.md. Analyzer only: the GCP collector stays
11f59595710f95f0024ffad5c8d5cd76dd1add57c8ca77cff1fc1f543dd78368 and the AWS collector files
are byte-identical. Baseline installed archive CloSec.zip SHA-256
3bcf79aed19c6645afc7ab885d165a1ccd0aca004d201119a55854bf67f543fd (not overwritten). The
paused AWS readiness work is parked as git stash@{0} plus an AWS-only patch and file copies in
the ignored artifacts/parked-aws-readiness-20261020/ (AWS Phase 1 done, Phase 2 not done); the
touched files were restored to their pre-sprint content and the patch applies cleanly.
Acceptance workspace: tools/fixtures/gcp_estate.py builds a synthetic estate in the collector
2.2 format (41 projects, and a 10-project subset; varied resources and a realistic status mix
including API_DISABLED, ACCESS_DENIED, QUOTA_PROJECT_DENIED for Cloud Asset, EMPTY,
TRUNCATED, TIMEOUT), one import per project plus a consolidated snapshot carrying analyst
decisions, exclusions, SRE verdicts, an approved grouped report revision and a path review.

### Phase 1 — Coverage completeness at import — DONE

- `ingestion/gcp_expanded.py`: a collector 2.2 dataset (verified checksums, record counts
  checked at import) with status SUCCESS or EMPTY is declared COMPLETE, with
  `pagination_complete` true and without COLLECTOR_PAGINATION_UNVERIFIED. TRUNCATED and
  PARTIAL stay PARTIAL; interrupted collections, datasets with detail-limit or IAM-target
  notes, and 2.1 packages (no checksums) stay PARTIAL; every failure status stays ERROR with
  its reason. Nothing is ever PASS from missing, denied, disabled or incomplete evidence.
- `ingestion/coverage.py:collection_facts`: expanded datasets are parsed by their typed dataset
  contract and are no longer downgraded for an operation absent from the legacy parser table.
- Scope rows (`rules/gcp.py:assess_gcp`, logic unchanged): complete datasets with resources
  need no blanket scope row (the resource results stand); an EMPTY successful list gives
  NOT_APPLICABLE.
- Organization scope rows (`rules/gcp_org.py`, brought forward from phase 2 because complete
  searches would otherwise turn a project-only search into an organization-wide PASS): PASS
  only with a complete organization-scope Cloud Asset IAM search (records carrying only the
  ADR-010 parent-scope qualifier count as complete) and no unresolved member, citing the search
  records; project/folder searches alone, partial/truncated searches, or no search at all give
  explicit UNKNOWN rows (previously no rows were written when no search records existed).
  Versions: the 8 matching organization rules 1.0.0 -> 1.1.0 (SA-PRIVILEGED and
  CROSSPROJECT-SA 1.2.0 -> 1.3.0).
- Existing workspaces keep the coverage recorded at import: re-import a package to apply the
  new declaration (stored source records are not rewritten).
Outcome changes (synthetic fixture table tests/gcp_rule_outcomes_baseline.json, refreshed): for
2.2 fixtures each project rule loses its collection-scope UNKNOWN row; the legacy fixture
without IAM search gains 8 organization UNKNOWN rows; 2.1 fixtures unchanged; no resource
outcome changed.
Acceptance (41 synthetic projects, before -> after): collection-scope UNKNOWN rows 1,500 ->
215 (-85.7%); API-key scope rows 99 UNKNOWN + 24 N/A -> 48 N/A; no resource-level outcome
changed for any rule; findings 458 -> 458; analyst decisions, exclusions, SRE verdicts and
report statuses identical. Timings after: dashboard 2.68 s (before 3.12 s), findings list
0.07 s, Excel workbook 14.4 s, Word+Excel assessment report 3.4 s. (Measured on the first
version of the estate; the estate's ancestor-policy fixtures were corrected in phase 2 and
the pre-sprint baseline re-measured, so phases 2 and 3 compare against 467 findings.)
Tests: tests/test_gcp_completeness.py (21: SUCCESS complete, EMPTY N/A, TRUNCATED and REST
PARTIAL stay partial, each of 11 failure statuses insufficient, interrupted and 2.1 packages
partial, organization rows for no search / project search only / complete organization
search / truncated organization search); tests/test_gcp_identity.py version expectations.
Checks: full suite with all browser cases 1106 passed, 0 failed (941 s); ruff check, ruff
format --check, Prettier, TypeScript, 5 frontend tests and production build passed (bundle
identical to the installed one).

### Phase 2 — PASS defects — DONE

- GCP-KEY-PRIVILEGED 1.2.0 -> 1.3.0 (`rules/gcp.py:key_rule`, `iam_hierarchy`): PASS when the
  key's service account is resolved and the project IAM policy and every collected
  organization/folder IAM policy of the project are COMPLETE with no Owner/Editor binding of
  the account. No parent policy collected, or any denied/failed/partial policy, stays UNKNOWN
  with the missing policy named; conditional bindings stay UNKNOWN as before.
- GCP-LOG-AUDIT 1.2.0 -> 1.3.0 (`rules/gcp.py:audit`): the criterion is "Data Access audit-log
  exemption configured". Project policy: FAIL for exemptions on the project or inherited from a
  collected organization/folder policy (named); PASS when the project and its complete parent
  policies carry no exemption (Data Access enablement per service is stated as a separate
  question); UNKNOWN when parents are not completely collected. Organization/folder policy:
  FAIL with exemptions, otherwise NOT_APPLICABLE (evaluated through its projects).
  Resource-level IAM policies (buckets, service accounts, Cloud Run) are NOT_APPLICABLE: audit
  configuration exists only on project, folder and organization policies.
- GCP-LOG-EXCLUSION 1.2.0 -> 1.3.0 (`rules/gcp.py:exclusion`, `log_selectors`): plain
  conjunctions are parsed; a positive Cloud Audit Logs selector (log_id or logName, URL-encoded
  names decoded) FAILs as before for data_access and now for any audit log; a positive selector
  of non-audit logs only PASSes (the exclusion cannot drop audit entries); OR, NOT, negation,
  grouping or no log selector stays UNKNOWN. Scope rows read both exclusion sources (the
  exclusions list and exclusions embedded in sinks); complete evidence without any exclusion
  is NOT_APPLICABLE (previously the scope row checked the sinks dataset only).
- GCP-ORG-FEDERATION 1.0.0 -> 1.1.0 (`rules/gcp_org.py:providers`, `provider_state`): the pool's
  collected provider records decide where complete: the whole pool granted (`principalSet://.../*`)
  with an enabled provider without an attribute condition FAILs; a pool whose providers are all
  disabled or deleted PASSes; otherwise MANUAL with the conditions listed. No or incomplete
  provider evidence stays MANUAL as before.
- Organization scope rows: delivered with phase 1 (see above).
Outcome changes (synthetic fixture table): GCP-LOG-AUDIT only — resource-level IAM policies
UNKNOWN -> NOT_APPLICABLE in the expanded fixtures; no other rule changed.
Acceptance (41 synthetic projects, pre-sprint analyzer -> phase 2): scope UNKNOWN rows 1,500 ->
186 (-87.6%); resource-level changes only in listed rules: GCP-KEY-PRIVILEGED +1 PASS (from
UNKNOWN), GCP-LOG-AUDIT +3 PASS, +1 FAIL (inherited organization exemption), +152
NOT_APPLICABLE (resource-level policies), UNKNOWN 265 -> 109; findings 467 -> 468 (the new
inherited-exemption FAIL); analyst decisions, exclusions, SRE verdicts and report statuses
identical. 10-project subset: scope UNKNOWN 371 -> 46 (-87.6%), findings 121 -> 121, analyst
state identical. Timings (41 projects, after): dashboard 3.12 s (before 2.77 s; target 3 s
missed by 0.12 s, run-to-run variance about 0.4 s), findings list 0.08 s, Excel 16.1 s,
Word+Excel report 3.7 s.
Tests: tests/test_gcp_pass_defects.py (23).
Checks: full suite with all browser cases 1129 passed, 0 failed, 9 deselected (the phase 3
omitted-field tests, written before the rule change) (917 s); ruff check, ruff format
--check, Prettier, TypeScript, 5 frontend tests and production build passed.

### Phase 3 — Omitted fields — DONE

Tests written first (tests/test_gcp_omitted_fields.py, 9; 2 failed before the change). Absence
is read only where Google documents it and only from COMPLETE collection evidence (collector
2.2, SUCCESS/EMPTY, verified checksums); otherwise the outcome stays UNKNOWN. References in
docs/RULE_SPECIFICATIONS.md ("GCP coverage completeness and omitted fields").
- GCP-API-APP, GCP-API-API, GCP-API-BOTH 1.2.0 -> 1.3.0 (`rules/gcp.py:restrictions`): an API key
  without `restrictions` is unrestricted ("If no restrictions are specified, all targets are
  allowed", apikeys v2 reference): GCP-API-BOTH FAIL, the single-criterion rules defer to it
  (NOT_APPLICABLE) exactly as for an empty restrictions object. Truncated or 2.1 evidence stays
  UNKNOWN.
- GCP-KMS-ROTATION 1.1.0 -> 1.2.0 (`rules/gcp_config.py:kms_rotation`): an ENCRYPT_DECRYPT key
  with neither `rotationPeriod` nor `nextRotationTime` has no automatic rotation (Cloud KMS
  "Rotate a key": disabling clears both) -> FAIL. One field only, or PARTIAL evidence, stays
  UNKNOWN; non-symmetric keys stay NOT_APPLICABLE.
Outcome changes (synthetic fixture table): GCP-API-BOTH UNKNOWN -> FAIL (3 keys each in the
expanded 2.2 and 2.2.7 fixtures), GCP-API-APP/API UNKNOWN -> NOT_APPLICABLE for the same keys;
no other rule changed.
Acceptance (41 synthetic projects, pre-sprint analyzer -> RC): scope UNKNOWN rows 1,500 -> 186
(-87.6%); resource-level changes only in listed rules: GCP-API-BOTH +8 FAIL, GCP-API-APP/API
+8 NOT_APPLICABLE each (from UNKNOWN), GCP-KMS-ROTATION +20 FAIL (from UNKNOWN), plus the phase 2
KEY-PRIVILEGED and LOG-AUDIT changes; findings 467 -> 496 (+8 API keys, +20 KMS keys, +1
inherited audit exemption); analyst decisions, exclusions, SRE verdicts and report statuses
identical. 10 projects: scope UNKNOWN 371 -> 46 (-87.6%), findings 121 -> 128, analyst state
identical. Timings (41 projects): dashboard 3.19 s (target 3 s missed; before 2.77 s), findings
list 0.06 s, Excel 15.2 s, Word+Excel report 3.7 s; 10 projects: dashboard 0.74 s.
Checks: full suite with all browser cases 1138 passed, 0 failed (938 s); ruff check, ruff
format --check, Prettier, TypeScript, 5 frontend tests and production build passed (bundle
identical to the installed one).

### Phase 4 — VM, storage, SQL and flow-log omitted fields — NOT DONE

Not started: each needs an omitted-field test and a documented absence semantic. Unchanged and
still UNKNOWN on omission: VM accessConfigs, serviceAccounts and shieldedInstanceConfig; storage
versioning; SQL authorizedNetworks and requireSsl; subnet logConfig.

### Collector 2.2.8 reference check (no collector change)

The analyzer accepts 2.2.0-2.2.8 (`contracts/gcp_expanded.py`); the shipped collector is 2.2.8
(hash above). Matched against its commands: list statuses SUCCESS/EMPTY/TRUNCATED and REST
PARTIAL (unreachable locations), INTERRUPTED collection status; ancestor IAM as parent_org_iam /
parent_folder_iam (governance) and organization_N_iam / folder_N_iam (identity), matched by
operation not category; organization and folder IAM searches only with
-IncludeOrganizationSearch, with distinct families (a folder search is never an organization
pass); REST logging exclusions and sinks; workload identity providers; per-ring KMS REST lists.
Limitation: a project without an organization or folder parent has no ancestor IAM, so
GCP-KEY-PRIVILEGED and GCP-LOG-AUDIT stay UNKNOWN for it.

## AWS readiness phases 0-2 (2026-10-20/21; synthetic data only)

Input: docs/AWS_ANALYSIS_READINESS.md and docs/AWS_CONTROL_AUTOMATION_AUDIT.md (both
uncommitted). The work parked as stash@{0} during the GCP correctness release candidate is back
in the working tree; the stash itself was not dropped.
- Phase 0 — dependent collection scope — DONE (audit change 1). `rules/engine.py:dependent_scope`,
  `registry.DEPENDENT_PARENTS`: scope rows of per-resource AWS datasets are decided by the parent
  listing (empty complete: NOT_APPLICABLE; failed: COLLECTION_ERROR; every listed resource with
  dependent evidence: no scope row). R1-S3-BUCKET-PUBLIC-ACCESS, SEC-KMS-WILDCARD-PRINCIPAL,
  SEC-KMS-ROTATION, SEC-CLOUDTRAIL-LOGGING, SEC-CLOUDTRAIL-MANAGEMENT-EVENTS 1.2.0; resource
  predicates unchanged. Specification: docs/RULE_SPECIFICATIONS.md "Dependent collection scope".
  Tests: tests/test_aws_dependent_scope.py (incl. the GCP counterpart).
- Phase 1 — shared code (truncation honesty, per-scope snapshot membership, exclusion-aware
  enterprise counts, account-qualified group keys) — DONE. tests/test_aws_readiness_phase1.py.
- Phase 2 — platform-managed identity classification, trust conditions, organization-control
  awareness, AP-06 prerequisites, workload-identity context (`rules/aws_identity.py`,
  `registry.AWS_IDENTITY_ENRICHED`, `AWS_PRINCIPAL_CONTEXT_RULES`) — tests pass (the 3 failures
  recorded at parking are resolved). tests/test_aws_readiness_phase2.py.
- Not done: audit changes 2 (Aurora `describe_db_clusters`), 3 (bucket ownership controls) and
  Phase 3 (root SCP/RCP content, collector change).
Checks (2026-10-21): AWS suites 50 passed; full suite with RUN_GUI_BROWSER=1 1188 passed,
0 failed, 0 skipped (937 s); ruff check and ruff format --check passed. Prettier, TypeScript,
5 frontend tests and the production build passed with the bundled Node 22.22.0
(artifacts/node-runtime/bin; not on PATH by default); the rebuilt bundle is byte-identical to
the one in the tree. Nothing committed.

## AWS batch collection sprint (2026-10-21, owner brief; synthetic data only)

Release candidate only (separate artifacts folder, installed CloSec.zip not overwritten).
Baseline: GCP RC archive c7145092e6b24a660611cad2e6a1dc3989a169bf922fb01f400b4eba62b81889
(verified); GCP collector 11f59595710f95f0024ffad5c8d5cd76dd1add57c8ca77cff1fc1f543dd78368
(unchanged). AWS collector before: assessment.py 0.3.2
7847487b8cc0089f39b6dc24d1ea99eabba1540307b03e88ace77cd2af95db06. Node: none on PATH; the
bundled runtime artifacts/node-runtime/bin (Node 22.22.0, npm 10.9.4) runs every frontend
check; nothing installed. boto3/botocore/moto are not installed on this host: collector code
was exercised only against tools/fixtures/aws_fake_cloud.py (in-process fake of the boto3
surface the collector uses; refuses any non-read call), and tools/aws_registry_audit.py
(botocore model check) could not run. `aws_triage.py` named in the brief does not exist in
the repository or on this host; its triage (status histogram, defect datasets, Region coverage,
version) is implemented in collectors/aws/batch.py:triage.
GCP equality: tools/gcp_equality.py (10 synthetic projects + consolidated snapshot, analyst
decisions, one false-positive exclusion; outcomes, findings, statuses, coverage, dashboard,
report model, Excel cells, Word text) on the baseline source and on the working tree.

### Phase A — Access design and pre-flight probe — DONE

- tools/aws_access_policy.py generates docs/AWS_COLLECTION_ACCESS.md (also shipped as
  collectors/aws/AWS_COLLECTION_ACCESS.md) and collectors/aws/policies/*.json from the
  collector source (AST) and a dated snapshot of SecurityAudit v94 and ViewOnlyAccess v47
  (tools/data/aws_managed_policies.json, retrieved 2026-10-21 from the AWS Managed Policy
  Reference). 133 calls; SecurityAudit grants all but macie2:GetMacieSession and
  resource-explorer-2:ListIndexes (the latter only in ViewOnlyAccess). Member role:
  SecurityAudit + inline CloSecReadOnlySupplement (those two actions plus an explicit Deny of
  data-plane reads). StackSet CloudFormation (JSON) template, organization-bound trust
  (aws:PrincipalArn + aws:PrincipalOrgID), hub and management-account policies, 3600 s
  sessions (role chaining limit).
- collectors/aws/INLINE registry replaces the hard-coded inline list in
  tools/collector_contract.py (contract output unchanged by this refactor).
- collectors/aws/preflight.py + fleet.py: 41 families, per-account table, fleet summary of
  repeated denials, statuses ALLOWED / DENIED / REGION_NOT_ENABLED / SERVICE_NOT_IN_USE /
  THROTTLED / CREDENTIALS_EXPIRED / TIMEOUT / CONNECTION_ERROR / ERROR, masked IDs.
- Tests: tests/test_aws_collection_access.py (7): generated design current, read-only
  (registry verbs, no write-verb method calls in any collector script, every api() call site
  registered), policies read-only and covering every call, StackSet role, probe actions, probe
  run on a 3-account synthetic fleet.

### Phase B — Collector 0.3.3 (analyzer accepts 0.3.0-0.3.3) — DONE

- Collector: classify() with distinct outcomes THROTTLED, CREDENTIALS_EXPIRED, TIMEOUT,
  CONNECTION_ERROR, SERVICE_NOT_IN_USE, REGION_NOT_ENABLED; botocore retries off, bounded
  collector retries (exponential backoff, full jitter, global Throttle shared by workers),
  one manifest entry per retry; configurable timeouts; opted-out Regions journaled instead of
  aborting (no enabled Region refuses before evidence is written); SCP and RCP chain with
  policy content at every node including the root; organization ID, management account and
  access state recorded; dependency fallbacks and detail limits recorded; `--resume` into a
  new run (verified carry-over, original start time kept); UTF-8/LF files, forward-slash
  entries, `<zip>.sha256` sidecar; collect_account() shared by CLI and batch.
- Analyzer: VERSIONS + 0.3.3; 0.3.3 outcomes accepted only from 0.3.3 journals
  (REGION_NOT_ENABLED → SKIPPED, others FAILED; never PASS); `collection_facts` validated
  (known keys, bounded, UTF-8) into the stored summary; business group validated;
  reporting/aws_collection.py maps AWS error codes to reason categories (dashboard coverage
  rows, finding evidence, report coverage notes) and manifest facts to report coverage notes
  (FACT_CONSUMERS: every fact key has a consumer). Contract 2.1.0 (AWS outcomes, mapping,
  manifest facts); GCP section unchanged.
- Derived-output change (AWS only): AWS sources with errors now carry a coverage reason
  (previously blank); 0.3.3 packages add AWS_* coverage notes. No rule predicate changed.
- Tests: tests/test_aws_collector_033.py (14); test_collector_v030_native and
  test_workflow_api updated for 0.3.3 and the extended kit.

### Phase C — Batch collector orchestrator — DONE

- collectors/aws/batch.py (Python like the collector: Windows, macOS, Linux; no PowerShell
  variant needed): CSV/text input with business group, role, session duration, concurrency
  (default 4), Regions, output folder; in-process workers on collect_account with one shared
  throttle; per-account isolation; checkpoint after every account; restart skips finished
  accounts; `--retry-failed` resumes non-READY accounts; expired hub sign-in stops scheduling
  and finalizes running accounts INTERRUPTED; batch-manifest.json, accounts-result.csv,
  fleet-rollup.json, fleet-limitations.md; verdict READY / RE-COLLECT / ACCESS GAP
  (organization policy denials in member accounts are reported as "organization controls not
  assessed", not as an access gap); masked terminal output, no credentials printed.
- Not verifiable without a real account: real STS/SSO expiry timing, real throttling rates,
  real Region opt-in responses, botocore parameter validation of the probe and 0.3.3 calls.
- Tests: tests/test_aws_batch.py (4).

Checks at the A-C boundary: full suite with RUN_GUI_BROWSER=1 1213 passed, 0 failed (956 s);
ruff check and ruff format --check passed; Prettier, TypeScript, 5 frontend tests and the
production build passed (bundle byte-identical). GCP equality: baseline and working-tree
fingerprints identical (SHA-256 21c6254b7c7f52d2df88ecf58c93e4fc5e2cfd72748efb40bf7689c2fc9d25b7;
11 runs, 259 findings). AWS collector after: assessment.py
17ddf5bbb6d2160c99c19f73e830ef10774068235305e8668067546ced897f0c; contract
f2dbea9cbe7445f8a7f38a91b94abce553d72418ef8c44f2ed5b0125ed9e24c8 (README edited after these
hashes were taken; README is not hashed here).

### Phase D — Batch import and scale — DONE with accepted exceptions (owner, 2026-10-22)

Delivered and tested:
- Bulk import (src/offline_analyzer/ingestion/bulk.py; POST /api/bulk-import, GET
  /api/bulk-import/{id}; GUI panel on Evidence import): every package ZIP of a local folder,
  safe unpack and full validation per package, one result row each, sidecar check, latest
  collection per account wins (older SUPERSEDED, also against newer workspace imports); when the
  newest package is invalid the next newest is imported and the account is flagged "latest
  package invalid, fell back to older" (row and report `fallbacks`); resumable per folder
  (bulk-imports/<id>.json); reconciliation against an expected account list (missing,
  unexpected, duplicate).
- Business-group shards (src/offline_analyzer/enterprise/shards.py; shard plan, sharded
  assessment, combined view, shard banner): used when a selection exceeds the snapshot caps
  (250,000 observations, 2,048 imports, now named constants in enterprise/snapshot.py);
  every shard report carries SHARDED_ENTERPRISE_ASSESSMENT; cross-group relationships are
  stated as not correlated. Additive tables enterprise_shards and gcp_frozen_editions
  (storage/consolidation_schema.py); an existing database is copied to schema-backups/
  before they are created.
- No silent truncation: every numeric cap is classified as recorded (truncation record with
  shown/total, GUI banner, report coverage note, Excel row) or refused (explicit error);
  tests/test_aws_bulk_import.py::test_every_cap_is_reported_or_refused fails on an
  unclassified new cap.
- Performance (outputs unchanged): per-resource observation and evidence-reference queries
  replaced by one ordered pass and one reference index; results written in columnar batches;
  the evaluation's source map built once per assessment instead of per call; related-evidence
  lookups indexed (route tables, detectors, key rotation, instances, coverage); already loaded
  observations reused; attack-path interface lookups batched; report revisions prefetched;
  report table cells reuse one styled cell per column. Snapshot outputs (evaluations, findings,
  finding_resources, security_investigations) byte-identical before/after on the 143-account
  workspace; Excel workbook parts and Word/Excel report parts identical except generation
  timestamps.

Benchmark (tools/aws_fleet_benchmark.py; 143 synthetic accounts, size 8, two Regions, one
account per package, 22.8 MB of packages; 34,749 observations, 36,751 evaluations, 7,578
findings, 28,314 edges in the snapshot; this Mac, single process; peak RSS 1.45 GB):

| Stage | Before | After |
|---|---|---|
| Bulk import + per-package assessment (143) | 676.1 s | 545.9 s (3.8 s per package) |
| Snapshot build | 10.5 s | 9.9 s |
| Snapshot assessment | 836.9 s | 39.6 s |
| Correlation | 26.7 s | 20.7 s |
| Attack paths | 20.5 s | 6.6 s |
| Dashboard | 36.1 s | 18.1 s |
| Facets | 9.4 s | 8.0 s |
| Word + Excel report | 64.2 s | 30.3 s |
| Excel workbook | 159.5 s | 112.8 s |

Profiler discrepancy (17.6 s vs about 200 s) explained by measurement: on the 143-account
snapshot, wall clock was 767.4 s and 789.1 s without the profiler and 1044.8 s under cProfile,
while cProfile's own total was 121.6 s and listed no DuckDB call. Timing every DuckDB call
directly showed 477.2 s of the 772.8 s wall in 141,051 queries (evidence references per
observation 56,771 calls / 238.4 s; observations per resource 26,598 / 159.8 s). cProfile does
not attribute the time spent in DuckDB's native calls made from the Store.rows generator
(shown as 306222/0 calls), so its summary undercounts; the profiler adds overhead, it never
made the run faster. After the fixes DuckDB time is 5.8 s in 705 queries.

Accepted exceptions (owner decision 2026-10-22; above the 30 s target, accepted as is):
- Analysis workbook (Excel workbook) 112.8 s: 107 MB, 221,611 rows, 4.57 M cells (Evidence
  Register 55,487 rows, Control Assessment 36,754, Cross-Account Relationships 28,317); cost is
  proportional to cells (row XML 30 s, cell sanitizing 24 s, JSON cells 8 s, ZIP 9 s).
- Snapshot assessment 39.6 s: remaining time is spread (attack-path calibration about 8 s,
  raw-evidence re-verification 3.2 s, IAM model 2.1 s, rule evaluation and model validation).
- Dashboard 18.1 s.
- Bulk import 3.8 s per package (545.9 s for 143), linear, dominated by per-file path
  confinement and JSON inspection of about 1,100 evidence files per package; one cancellable
  job with progress.
Post-engagement option (not implemented): one analysis workbook per business group, or the
evidence registers as separate CSV files.

Report timing on the same snapshot (Word + Excel assessment report, 7,578 findings and 1,716
attack paths with include=all): report model 13.0 s, report Excel 8.3 s (4.4 MB), report Word
7.5 s (1.2 MB); about 30 s for the full export including the ZIP. With the default scope
(confirmed findings; none recorded in the synthetic workspace) the model takes 13.1 s and
both files under 0.5 s.

Tests: tests/test_aws_bulk_import.py (10). Checks: full suite with RUN_GUI_BROWSER=1 1222 passed,
0 failed (1045 s); ruff check and ruff format --check passed; Prettier, TypeScript, 5 frontend
tests and the production build passed (bundle rebuilt: new bulk-import and shard panels). GCP
equality: working-tree fingerprint identical to the baseline
(21c6254b7c7f52d2df88ecf58c93e4fc5e2cfd72748efb40bf7689c2fc9d25b7).

### Phase E — GCP frozen-edition feed for the consolidated view — DONE

- src/offline_analyzer/reporting/gcp_feed.py. Export (GCP workspace, read-only): ZIP
  `CloSec-GCP-frozen-edition-<id>.zip` built only from the finalized edition document, with
  whitelisted fields: findings (ID, rule, title, severity, status, group, resource, project,
  Region, domain, STRIDE, control), STRIDE mapping, attack paths with hops and status, coverage
  and limitation summary, excluded findings, project list, edition metadata (edition ID, freeze
  date, collector versions); manifest.json with SHA-256 per file; signature.json = HMAC-SHA256
  of the manifest with a per-export key returned once in the API response (never stored, not in
  the job journal). No evidence references, observation IDs, configuration or narrative text
  quoting configuration.
- Import (AWS workspace): exact file layout and size caps, signature then hashes verified,
  fields validated against the whitelist, excluded findings must be absent; stored read-only in
  gcp_frozen_editions with the bundle bytes under frozen-editions/ (re-verified on every read);
  re-import of different content under the same edition ID refused; no decision, exclusion or
  path-review API reaches frozen findings. Linking requires an AWS run without live GCP data.
- Consolidation (only when an edition is linked; unlinked runs unchanged): report model, Word
  and Excel (GCP only / AWS only / both), dashboard providers, posture rating, STRIDE coverage,
  attack-path view and coverage notes include the frozen GCP data labelled by source and
  edition; cross-cloud correlation with frozen data is stated as not assessed. Automated
  reconciliation (AWS live + GCP frozen = consolidated, severity totals, excluded findings
  absent, frozen findings identical to the edition) blocks report export on mismatch.
- API: GET /api/gcp-editions, POST /api/runs/{run}/gcp-edition/export, GET
  /api/gcp-editions/exports/{name}, POST /api/gcp-editions/import, POST/GET
  /api/runs/{run}/gcp-edition. GUI: Report center panel (export with key shown once, import,
  link) and a dashboard notice.
- Signing decision: stdlib HMAC-SHA256 with an out-of-band key; an asymmetric signature needs a
  new runtime dependency (`cryptography` is a development dependency only) and an ADR.
- Tests: tests/test_gcp_frozen_feed.py (8): no raw evidence in the bundle, consolidated counts,
  GCP-only/AWS-only/both reports, reconciliation mismatch blocks export, tampered or wrongly
  keyed bundles rejected, read-only edition and GCP data unchanged, live-GCP runs refused,
  API endpoints (key never written to the workspace).

### Phase F — AWS rule correctness (shared audit) — DONE

- docs/AWS_CONTROL_AUTOMATION_AUDIT.md completed: four questions answered on current code
  (no rule fails to reach PASS on complete evidence, at resource or scope level; empty lists
  N/A including dependent datasets; omitted-field semantics unchanged); per-rule classes and
  status; every Phase F item mapped to its implementation and test; shared-code fixes with
  proof for both providers; two decisions (Aurora clusters, bucket ownership controls).
- Identity features (platform-managed classifier, trust-condition rendering, SCP awareness,
  AP-06 P2 with hop/STRIDE mapping, instance profile x open SG x public ENI) were delivered in
  AWS readiness phase 2 and are now exercised on collector 0.3.3 output.
- tools/fixtures/aws_fake_cloud.py: `compliant` account variant (every evaluated configuration
  compliant) for PASS reachability.
- Tests: tests/test_aws_rule_correctness.py (2): all 19 AWS rules emit PASS on a complete,
  compliant synthetic account and no collection-scope row remains; identity enrichment never
  lowers a severity silently (enrichment on versus off; the only lower severity is the
  evidenced organization access role, stated as "Reclassified from POTENTIAL_EXPOSURE/HIGH to
  BASELINE_DEVIATION/MEDIUM ...").
- New cap constants of the feed (MAX_FILE, MAX_BUNDLE) classified as refused in the cap
  registry test.

Checks at the E/F boundary: full suite with RUN_GUI_BROWSER=1 1232 passed, 0 failed (1729 s).
Two earlier full runs each had one failure that passed on its own repeatedly and again in the
clean run: test_api.py::test_scoped_views_and_resource_inventory (run concurrent with the
equality proof; 17/17 passed three times in isolation) and
test_pilot_import_browser.py::[Folder-webkit] (file-chooser timeout; passed three times in
isolation). ruff check and ruff format --check passed; Prettier, TypeScript, 5 frontend tests
and the production build passed (bundle rebuilt for the edition panel and notice). GCP
equality after E and after F: identical to the baseline
(21c6254b7c7f52d2df88ecf58c93e4fc5e2cfd72748efb40bf7689c2fc9d25b7).
