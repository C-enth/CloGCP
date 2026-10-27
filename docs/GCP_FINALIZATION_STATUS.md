# GCP finalization readiness — Phase 0 status audit (2026-10-27)

Read-only audit. No code, configuration, workspace or evidence was changed.

## Audited source

| Tree | Location | State |
|---|---|---|
| **CloGCP (shipped product)** | `artifacts/clogcp-publication-20261026` (ignored clone of `C-enth/CloGCP`) | `main` = tag commit `8f535dd`, runtime source `bd5693a`, clean |
| CloSec working tree | this repository, `feature/offline-security-analyzer` | `d232bb5` + 59 uncommitted paths |

The CloGCP release is a strict superset of this working tree's `src/`. It adds
`rules/gcp_domains.py`, `rules/gcp_public_context.py`, `rules/gcp_context.py`,
`findings/clogcp_reconcile.py`, `reporting/clogcp_assurance.py`, `api/run_cache.py`,
`clogcp.py` and `clogcp_profile.py`, and changes 11 more modules. **Statuses below are for
CloGCP `8f535dd`** (the release that B1/B2 were assessed with). Where this working tree
differs, it is noted. Paths are relative to the CloGCP clone.

## Summary

| # | Item | Status |
|---|---|---|
| 1a | Cloud Run IAM / ingress semantics (`invokerIamDisabled=None`) | **Full** |
| 1b | Evidence-to-claim consistency | **Partial**: one contradiction (GCP-ORG-PUBLIC-SERVERLESS) |
| 1c | Expected state | **Partial**: generic templates |
| 1d | Remediation | **Partial**: one rule is overprescriptive |
| 1e | Duplicate narratives | **Partial**: native/CAI deduplicated; text duplicated within a finding |
| 1f | Severity vs exploitation | **Full** for native rules, **Partial** for org rules |
| 2 | Canonical identity / console URLs | **Partial**: no URLs at all; legacy zone self-link becomes the region |
| 3 | Attack-path engine 2.0.1 | **Full** (catalogue deliberately partial) |
| 4 | Targeted collector + delta import | **Full (synthetic only)** |
| 5 | Finalizer + QA register | **Partial**: layout-compatible; passes the register defects through |
| 6 | 40-column register | Headers **Full** (40/40, same order); content **Partial** (8 columns) |
| 7 | Windows recovery / evidence / Finalized view | Recovery **Full** (native CI); Finalized view **Missing** performance work |
| 8 | Real-data count snapshot | **Not performed**: B1/B2 workspace not on this machine |
| 9 | Released versions / SHA-256 | Recorded below |

## 1. Cloud Run

**1a. IAM and ingress (Full).** `rules/gcp_domains.py:serverless_public` treats only `True`/`"true"`
as disabled, so `None` is never "disabled". Any other value is UNKNOWN. With no unconditional public
binding and the check not disabled, the result is MANUAL_VALIDATION_REQUIRED. A conditional binding
gives UNKNOWN. Internal ingress (all six spellings) or IAP gives MANUAL_VALIDATION_REQUIRED. Open or
unrecorded ingress gives FAIL MEDIUM, with the observed values in the reasoning. For Functions, the
Gen1/Gen2 invoker role differs and Gen2 defers to its Cloud Run service.
`rules/gcp_public_context.py:_public_context` applies the same check to CAI policy rows. It requires
the service snapshot to be within 24 h, else UNKNOWN. If a native finding exists within 5 min, it
marks the CAI row as supporting evidence instead of raising a second finding.
Tests: `tests/test_clogcp_domains.py::test_serverless_invoker_and_internal_ingress`,
`tests/test_clogcp_public_context.py::test_run_internal_ingress_and_native_equivalence`,
`::test_stale_conflicting_or_missing_service_context_is_unknown`.
**Gap:** no test asserts `invokerIamDisabled=None` without a public binding, or
`invokerIamDisabled=true` without a binding (FAIL path).
*This working tree:* `rules/gcp_org.py:matches` fires on the binding alone and never reads ingress
or `invokerIamDisabled` (**Missing**).

**1b. Evidence-to-claim (Partial).** `rules/gcp_org.py` (`ORG_CORRECTED`) rewrites the
GCP-ORG-PUBLIC-SERVERLESS risk to say that ingress and reachability are unresolved. However,
`findings/explanations.py:explain` still serves `MISUSE["GCP-ORG-PUBLIC-SERVERLESS"]`
("Anyone on the internet can call the service without authentication … run up cost") because the
rule is not in `SPECS`. The same finding therefore states both "unresolved" and "anyone can call".

**1c. Expected state (Partial).** For `SPECS` rules, `findings/gcp_recommendations.py:template_for`
sets `expected_posture = spec.title + ": applicability and required security posture reviewed
with the owner."`. For GCP-RUN-PUBLIC this reads "RUN public invocation configuration: …". For
GCP-ORG-* rules there is no template, so `findings/detail.py` falls back to "Secure baseline for
this control (see recommendation)" / "Secure baseline restored". Neither states a checkable value.

**1d. Remediation (Partial).** GCP-RUN-PUBLIC remediation is proportionate (confirm the audience,
then restrict invoker or ingress). GCP-ORG-PUBLIC-SERVERLESS still prescribes "front public endpoints
with a load balancer and Cloud Armor, and restrict ingress" (`rules/gcp_org.py:ORG_RULES`).

**1e. Duplicate narratives (Partial).** Cross-source duplicates are suppressed (1a). Within a
finding, `explain()` returns `misuse = spec.risk + qualifier` and `impact = spec.risk` for every
`SPECS` rule. The same sentence therefore appears in both the "misuse" and "impact" sections of the
detail, report and register output.

**1f. Severity (Full / Partial).** Native rules state that exploit prerequisites are unverified
and rate exposure MEDIUM. The org rule rationale reads "Severity reflects observed binding scope and
exposure", with no statement that exploitation is unverified.

## 2. Canonical resource identity (Partial)

- No console URL is generated anywhere (`grep` of `src/` and `frontend/src/`). Canonical IDs are
  shown as plain text. Nothing is invented, but there is also no validated link (**Missing**).
- Cloud Run v1/v2 identity is fixed in `normalization/gcp.py:gcp_records` (gcp-native-1.1.0). The
  region comes from the location label, a namespace mismatch is rejected, and a bare name without
  a region produces no identity.
- Expanded contracts: `normalization/gcp_expanded.py:canonical_native` reads the project and
  location from `selfLink` / `name`, and splits a URL-form zone to its last segment. This applies to
  Compute, GKE, Cloud SQL, Storage and the other expanded types.
- **Defect:** the legacy (non-expanded) path in `gcp_records` sets
  `region = config.get("location") or raw.get("zone") …` without splitting. For
  `gcp:compute.instances.list`, the API's `zone` is a self-link URL, so `region` (and the stored
  `resource_id`) carries a URL. Correcting the stored value changes resource and finding IDs, so
  the fix must be presentation-only (decision D2).
- Org rows (`rules/gcp_org.py:assess_org`) always use `region="global"`, including regional Cloud
  Run services. The native ID keeps the true location.

## 3. Attack-path engine 2.0.1 (Full)

`attack_paths/gcp_engine.py` (`VERSION="2.0.1"`) and `iam/gcp_permissions.py` keep the following
permissions separate: `iam.serviceAccounts.actAs`, `getAccessToken`, ID-token creation and signing.
Unknown roles, CEL conditions, deny exceptions, PABs and federation fail closed. Exact unconditional
denies give CONTRADICTED. `contracts/gcp_attack_path.py` defines SUPPORTED / CONDITIONAL / BLOCKED /
INSUFFICIENT_EVIDENCE / UNSUPPORTED, and PROVEN is never a basis for SUPPORTED.
`attack_paths/versioned.py:recalculate` creates immutable versions and keeps legacy statuses as
history. New evaluations never inherit approval. Tests: `tests/test_gcp_attack_engine.py` (25),
`tests/test_gcp_final_workflow.py::test_side_by_side_open_and_independent_recalculation_preserve_every_record`.
**UI:** run → GCP → *Attack-path investigations* heading, top panel
(`frontend/src/CloudDashboard.tsx:CloudPaths` → `PathRecalculation.tsx`), endpoint
`POST /api/runs/{run}/attack-path-evaluations` (`api/app.py:recalculate_attack_paths`).

## 4. Targeted collector and delta import (Full, synthetic only)

`src/clogcp_delta/` (1.0.0rc1) collects bucket IAM, folder IAM / metadata and Discovery Engine
engines / data stores / resources. It is read-only, rate-limited, and redacts before persistence.
`ingestion/gcp_delta.py` is a strict offline adapter. `evidence/composition.py` references the base
run plus the supplementary imports **in a new analysis version**. It never rewrites the source run,
and it handles precedence and conflicts by collection timestamp. Existing findings and decisions in
B1/B2 are untouched. In the new version, unchanged findings keep their fingerprint, so decisions
remain valid. Changed evidence produces NEEDS_REVALIDATION, never an inherited approval. Tests: 9 in
`tests/test_gcp_final_workflow.py` (planner, dry run, retries, pagination, redaction, interruption,
precedence, export scope). No real collector run or tool-generated input verification has been done.

## 5. Finalizer and QA register (Partial)

`src/clogcp_report_finalizer` `VERSION="1.0.0rc1"`. Release ZIP SHA-256 is listed in §9.
- **Input:** an analyzer xlsx with `GCP_Observation_Register` whose row-1 headers equal the 40
  columns, plus optional evidence workbooks, guidance, attack-path, coverage, history and
  acceptance JSON. There are at most 20 inputs and 128 MiB in total. It needs a new output directory.
- **Real export layout:** the code path matches. `reporting/excel.py` calls
  `gcp_register.add_sheets` with the same sheet names, `INDEX_COLUMNS` and `DETAIL_COLUMNS`
  that `clogcp_report_finalizer/evidence.py:exported_evidence` reads. It has not been run on a real
  export.
- **Output:** a new workbook (client register, consolidated issues, focused evidence, QA register,
  limitations, reconciliation, provenance) plus `Assessor-QA-Exceptions.json`. Only column 11 is
  rewritten. The other 39 columns are reconciled cell by cell, and the input hash is checked before
  and after.
- **QA categories:** contradiction (`OBSERVATION_EVIDENCE_CONTRADICTION`, `NARRATIVE_EXCEEDS_EVIDENCE`,
  `UNSUPPORTED_ATTACK_CONCLUSION`), missing evidence (`MISSING_SOURCE_REFERENCE`,
  `MISSING_FOCUSED_EVIDENCE`, `ASSERTION_EVIDENCE_UNAVAILABLE`), duplicates
  (`DUPLICATE_REPORTABLE_OBSERVATIONS`, `UNCERTAIN_CONSOLIDATION`), and manual validation
  (`MISSING_VERIFICATION`, `MISSING_REVIEW`). There is no single "manual-validation item" list
  for MANUAL_VALIDATION_REQUIRED outcomes.
- **Gap:** because 39 columns are protected, the register defects in §6 reach the client sheet
  unchanged.
- Tests: `tests/test_report_finalizer.py` (7), plus `tools/fixtures/finalizer_workbook.py`.

## 6. Excel register: column comparison

Export header (`reporting/gcp_register.py:COLUMNS`) vs target: **40/40 identical, same order;
none missing, renamed or misordered** (checked programmatically against the pasted list).
Content per column, from `reporting/gcp_register.py:_record`:

| # | Column | Kind | Current source / issue |
|---|---|---|---|
| 1 | Record ID (internal) | Auto | finding ID |
| 2 | Observation / gap | Auto | title (or approved report edit) |
| 3 | Affected asset / scope | Auto | project |
| 4 | Affected objects / services | Auto | native ID + operations |
| 5 | Criticality | Auto (analyst may override) | suggested severity |
| 6 | Why this criticality? | Auto | severity rationale |
| 7 | Rating confidence (automatic) | Auto | evidence confidence |
| 8 | Possible business impact | Analyst | blank (not derivable from configuration) |
| 9 | Recommended action | Auto | remediation (see 1d) |
| 10 | Assessor record type | Auto | finding class |
| 11 | What the evidence shows | Auto | **Partial**: whole located node (e.g. full allow policy), cut at 600 chars; the finalizer replaces it with a focused selection |
| 12 | Evidence reference | Auto | file#pointer + index link |
| 13 | Expected control / requirement | Auto | **Partial**: approved edit, else the methodology ID, not the expected state |
| 14 | Evidence at assessment | Auto | coverage statuses |
| 15 | What the evidence does not establish | Auto | **Partial**: `missing_evidence` + rule limitation prose + coverage; identical to 22, not coverage-reason based |
| 16 | Possible attack scenario | Auto (derivable) | **Partial**: approved edit only, else blank |
| 17 | Conditions needed for the scenario | Auto | validation requirements |
| 18 | Source-reported result | Auto | SCC/native source status |
| 19 | Domain / tool | Auto | domain + GCP + operations |
| 20 | Control area | Auto | methodology ID + criteria |
| 21 | Evidence type | Auto | "CLI/API configuration" |
| 22 | Evidence limits / data quality | Auto | **Partial**: same value as 15 |
| 23 | Assessor conclusion / evidence basis | Auto | reasoning + decision note |
| 24 | Related observations | Auto | same group key |
| 25 | Attack-path evidence level | Auto | **Partial**: legacy `feasibility` projection, not the engine 2.0.1 class |
| 26 | Assessor evidence result (automatic) | Auto | rule outcome |
| 27 | Report sequence (automatic) | Auto | sequence |
| 28 | Common asset reference | Auto | native ID |
| 29 | Issue group / summary title | Auto | **Partial**: stable hash ID, not a title |
| 30 | Risk rating decision | Analyst | approved risk acceptance, else "Pending" |
| 31 | Show in Overall? | Analyst | report inclusion, else "Pending" |
| 32 | Shown in Overall (automatic) | Auto | inclusion flag |
| 33 | Record count (automatic) | Auto | **Partial**: always 1; consolidation count only in the finalizer sheet |
| 34 | Applicability (SPOC) | Analyst/SPOC | blank ✔ |
| 35 | SPOC assessment | Analyst/SPOC | **Rule conflict**: filled with SRE verdict or "Pending" |
| 36 | SPOC justification / comments | Analyst/SPOC | **Rule conflict**: SRE reason |
| 37 | Supporting evidence / reference | Analyst | approved edit references |
| 38 | Reviewed by | Analyst | **Rule conflict**: tool decision's analyst name |
| 39 | Review date | Analyst | **Rule conflict**: tool decision timestamp |
| 40 | Final review conclusion (automatic) | Auto | status/stage, else "Pending" |

Not derivable from evidence: 8 (and the business half of 5/6). Columns 30, 31 and 37 are derivable
only from analyst actions recorded in the tool.

## 7. Windows

- **Workspace recovery (Full):** release 0.8.5-clogcp.2 streams complete-file hashes, uses a
  private incomplete-marked container, and refuses links, junctions and traversal. Native Windows
  CI passed 19/19 (Actions run 40311957277). See `docs/clogcp/HOTFIX_0.8.5_2.md` and
  `storage/side_by_side.py`.
- **Evidence loading:** unchanged ingestion limits. Not re-measured on Windows in this audit.
- **Findings Finalized view (Missing):** the cause, from reading the query path
  `GET /api/runs/{run}/finalized` → `reporting/sre_reports.py:finalized`, is that every request
  rebuilds all of the following:
  1. `rows()`: every candidate with `explain()`, `recommendation()` and `describe()`
     (bulk-loaded, no N+1);
  2. `attack_paths/feasibility.py:attack_paths`: `cross_paths(limit=None)` over all observations,
     plus `investigations`, `gcp_paths` and `aws_paths`, only to keep paths linked to confirmed
     findings;
  3. `findings/exclusions.py:listing` for a single count.

  `api/run_cache.py` (a state-stamped cache) exists but **is not wired to any endpoint**. A frozen
  edition returns quickly (`finalisation.frozen`). Timings are not yet measured (Phase 3).

## 8. Real-data snapshot: not performed

No workspace pointer exists on this Mac (`~/Library/Application Support/CloSec/workspace-location.json`
is absent). The only local workspace is `workspaces/assessment-20261014T055644Z`, an 800 KB pilot
from 2026-10-14 with a `.gui-owner.lock` file. It is not B1/B2 and was not opened. No counts are
reported (decision D3).

## 9. Released versions and SHA-256

Latest release: `v0.8.5-clogcp.2` (prerelease, published 2026-10-26). Application 0.8.5rc2,
engine 2.0.1. Hashes were re-verified locally against
`artifacts/clogcp-release-v0.8.5-clogcp.2-verified/`.

| Asset | Version | Bytes | SHA-256 |
|---|---|---|---|
| CloGCP.zip (analyzer) | 0.8.5rc2 | 63,781,657 | `1b8eabf1b2410e75bb44e046c9974e58d0c1751c899acb1c984ef5e209a7d688` |
| CloGCP-source.zip | 0.8.5-clogcp.2 | 1,872,401 | `aa005e6acff888474bcbd2af462086035c22d04f27c98410dd8185fcc46b6ba1` |
| CloGCP-Delta-Collector.zip (targeted) | clogcp-delta 1.0.0rc1 | 7,661,817 | `f931e752da8c43d7111de8008d90b9f0ec97a11fe74e4657cbddb036ccc87505` |
| CloGCP-Report-Finalizer.zip | 1.0.0rc1 | 8,504,348 | `f078ffc455aba99f86db35fd0ab3651d036ae08c0e1b044e124c17843711431e` |

GCP evidence collector: `collectors/gcp/GCP_Security_Evidence_Collector.ps1` ships inside
CloGCP.zip, so it has no separate hash. Its version is stated in the collector file.
`/Users/dev/CloudAssessmentScripts/CloGCP.zip` (`abb87926…`, 2026-10-24) is an older local
download.

## Decisions needed before Phase 1

- **D1 — target tree.** Phases 1–3 should change CloGCP (`artifacts/clogcp-publication-20261026`,
  on a new local branch from `main`, uncommitted). This CloSec working tree lacks the shipped GCP
  modules, so fixing it here would rebuild existing features.
- **D2 — legacy zone URL in region.** Fix at presentation and register level only (validated
  region and canonical ID; the stored IDs stay unchanged). Changing the normalizer would alter
  finding IDs for legacy-contract runs.
- **D3 — real-data snapshot.** Provide the B1/B2 workspace path on this machine (app closed), or
  run the count-only script on the Windows machine.
- **D4 — columns 35, 36, 38 and 39.** The rule says blank, but the tool currently fills them from
  recorded SRE and analyst decisions. Blank them in the client register (keeping the values in a
  separate audit sheet), or keep them.

## Outcome — Phases 1–4 (0.8.5-clogcp.3 candidate, 2026-10-27)

Local branch `feature/gcp-finalization` in this clone, from `main` `8f535dd`. Nothing was
committed or pushed. Decisions D1, D2 and D3 were applied as answered (CloGCP target,
presentation-only identity fix, count script run by the owner). For D4, the owner's
register rule was applied (cells left blank, recorded values in `GCP_Review_Audit`).

| # | Before | After | Change (file:function) |
|---|---|---|---|
| 1a | Full | Full + defect fixed | `rules/gcp_domains.py:serverless_public`: integer 1/0 is UNKNOWN, not "disabled" (`1 == True` in Python) |
| 1b | Partial | Full | `findings/explanations.py:MISUSE` org public-serverless text is conditional on ingress |
| 1c | Partial | Full (39 rules) | `findings/gcp_recommendations.py:EXPECTED` and the org template in `template_for` |
| 1d | Partial | Full | `ORG_ACTIONS` replaces the LB + Cloud Armor prescription |
| 1e | Partial | Full | `explanations.py:DOMAIN_SCENARIO` keeps misuse distinct from impact |
| 2 | Partial | Partial | `findings/location.py:display_region` at the four display sites; console URLs still not built |
| 5 | Partial | Full (synthetic) | `clogcp_report_finalizer/core.py:_qa` MANUAL_VALIDATION_ITEM, PREFILLED_REVIEW_FIELDS; 1.0.0rc2 |
| 6 | Partial | Full (content rules) | `reporting/gcp_register.py:_record`, `_focus`, `_engine_levels`; `GCP_Review_Audit` |
| 7 | Missing | Partial | `reporting/cloud.py:dashboard`, `sre_reports.py:finalized`, `api/app.py` cache wiring, `api/run_cache.py:stamp`, `coordinator.py:generation` |

Screen timings: 41-project synthetic estate (537 findings, 5,970 evaluations, 150 confirmed),
macOS x86_64, seconds, `tools/screen_timings.py`. "Cold" is the first request of the
process, so the first row also includes application warm-up.

| Screen | Before cold | Before warm | After cold | After warm |
|---|---|---|---|---|
| Dashboard | 0.89 | 0.70 | 1.33 | 0.77 |
| Cloud dashboard (GCP) | 4.34 | 4.08 | **3.87** | **0.28** |
| Attack paths (GCP) | 1.27 | 1.29 | 0.06 | 0.05 |
| Findings Finalized (GCP) | 1.73 | 1.67 | 1.80 | **0.04** |
| Findings Finalized (all) | 1.67 | 1.68 | 0.46 | 0.04 |
| Collection | 0.63 | 0.61 | 0.63 | 0.63 |
| Finding detail | 0.53 | 0.57 | 0.53 | 0.58 |
| All 10 other screens | ≤ 0.45 | ≤ 0.45 | ≤ 0.42 | ≤ 0.42 |

The first Cloud dashboard open per state is still above 3 s (3.9 s): `attack_paths` takes
1.37 s and `validate_snapshot` 0.95 s, and neither was restructured. Later opens, and any
other view after the paths are built, use the shared cache. Windows was not timed.

Equality proof (`tools/finalization_equality.py`, same 41-project estate, released `main`
vs branch): identical run ID, 537 finding IDs, fingerprints, rule versions, severities,
classes, resource IDs, regions and review statuses, and 5,970 evaluation IDs and outcomes
(`findings_sha256` 25ac43f0…, `evaluations_sha256` 06ca7038…). In-workspace preservation:
`tests/test_gcp_finalization.py::test_exports_change_no_stored_identity_decision_or_edition`.

Item 8 is still not performed by the agent. The owner runs
`python tools/workspace_counts.py WORKSPACE` with CloGCP closed; it refuses while the
database is locked or a WAL is pending, and prints counts only.
