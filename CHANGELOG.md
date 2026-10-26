# Changelog

## 0.8.5-clogcp.2 — P0 recovery hotfix, 2026-10-26

Dedicated streaming workspace SHA-256 removes the accidental ingestion-size cap from
workspace inventory. Ingestion limits remain unchanged. Staged, disk-checked copying
verifies all files and rows before publishing a destination, refuses unsafe links and
incomplete containers, and retains historical recovery manifests. Engine/reporting
source is unchanged. See [safe retry instructions](docs/clogcp/HOTFIX_0.8.5_2.md).

## 0.8.5-clogcp.1 — 2026-10-26

Independent versioned attack-path recalculation; engine 2.0.1; preserved B1/B2 and review
history; targeted delta collection/native import; new-version evidence composition;
external 40-column Excel finalizer; explicit copy-only additive upgrade and read-only
CloGCP opening. Existing CloGCP corrections/startup fixes remain. Published as a prerelease.
See [release notes](docs/clogcp/RELEASE_0.8.5.md) and [upgrade/rollback](docs/clogcp/UPGRADE_0.8.5.md).

## 0.8.4 report template and collected-project scope — 2026-10-15

Only collected projects appear in CloSec (ADR-010): IAM search results about other projects
or unrelated folders are dropped at import, so findings, account lists, paths and reports
contain only projects whose collector output was imported. GCP collector 2.2.3 runs
folder/organization IAM searches only with `-IncludeOrganizationSearch` and typed
confirmation. Packages imported earlier must be deleted and re-imported to apply this.


Every assessment report download (all accounts or one account) and every Finalized findings
download uses one document template in Word and Excel: title page with document control
(scope, run, generation time, findings included, evidence basis), 1. Executive summary
(overview, findings by severity, findings by account/project with projects seen only through
the organization-wide IAM search labelled as not collected, key risks, basis and
limitations), 2. Technical findings grouped by severity as labelled tables, and 3. Attack
paths last as A -> B -> C chains with unresolved prerequisites. Excel has exactly three
sheets. Control coverage, checklist coverage and the remediation roadmap are no longer in
this report; the comprehensive register (Report center > Generate Excel) keeps coverage.
Finalized downloads are titled "Confirmed Vulnerabilities Report" and add who confirmed
each finding and any SRE response.

## 0.8.3 GCP collector 2.2.2 sign-in check — 2026-10-15

A field run failed every GCP dataset (60 FAILED with "Reauthentication failed. cannot
prompt during non-interactive execution", 31 AUTH_ERROR) yet was marked COMPLETE: the
gcloud session had expired and the collector runs gcloud non-interactively. Collector 2.2.2
checks `gcloud auth print-access-token` (read-only; token discarded) after project
confirmation and before creating any output, stopping with "run gcloud auth login" when the
session needs reauthentication, and warns at the end if datasets failed because the session
expired mid-run. The analyzer accepts collector 2.2.2 (evidence format unchanged), the
compatibility summary names the 2.2 parser instead of UNSUPPORTED, and catalog line
references follow the script. PowerShell execution of 2.2.2 is not yet verified.

## 0.8.2 assessor-final review and detailed findings — 2026-10-15

The assessor's marking is final (ADR-008 revised): Confirm makes a confirmed vulnerability
and lists it in Finalized findings with or without an SRE response; SRE input is optional
and collapsed. No name is asked for: decisions, bulk marking, SRE entries and report drafts
record the local login name (editable "Recorded as"). Finding details follow the detailed
use case: a Quick summary (what is wrong, misuse, impact, recommended action, Copy technical
finding) and expandable Technical analysis — overview, observed parameters (actual from
evidence versus expected), security gap and principle, the collected configuration at the
evidence locator with credentials masked and responsible fields highlighted (ADR-009),
misuse with confirmed versus unverified prerequisites, impact and severity rationale,
remediation with a reviewable command where verified, read-only validation command and
expected state, and evidence completeness. The client report draft is pre-filled from the
same analysis. Excel and Word reports use restrained formatting (bold grey headers, frozen
header rows, filters, labelled fields, page breaks). The menu follows the workflow.

## 0.8.1 faster assessment — 2026-10-15

Every assessment report download (all accounts or one account, Excel + Word) follows the
analyst's marking: by default findings marked not valid (rejected, e.g. known or accepted)
or No gap (BAU) are excluded; "only valid (confirmed)" and "all findings" are selectable,
and the report states which rule applied. A not-valid marking now takes precedence over
any SRE stage (ADR-008). Bulk marking in the findings table: select a page or all matching
findings and mark valid, not valid (reason required), send to SRE or record an SRE verdict
in one action (atomic). Each account row offers its own Excel + Word report and a
"Remove / replace data" shortcut into Manage Assessment Data. Finalized findings downloads
per account. Attack paths are drawn as start -> step -> step chains showing the resource,
what allows each step (role, binding, trust) and, for AWS prerequisites, the evidence
status and rule; the same chain is written into the Excel and Word reports. Launchers
extract each release to its own folder so a newer ZIP is never shadowed by an older one.

## 0.8.0 SRE validation workflow (pilot feedback) — 2026-10-15

Findings workbench filters are built from the run's actual values (domain, checklist
control, region, validation status, account/project dropdown with counts) plus Clear
filters; the previous hard-coded domain list could not select 10 of 44 rules. An optional
"Findings by account" view shows severity and review status per account and filters on
click. Every finding states Why flagged, How it can be misused (potential; not
demonstrated), Impact and Recommendation in the finding detail, the Excel register, the
assessment report (Excel and Word) and new client-report drafts (`finding-explanations-1.0.0`,
attached at display/export, so stored findings and analyst decisions are unchanged). The 15
GCP rules sharing one generic risk sentence get rule-specific impact text.

SRE validation (ADR-008): an append-only `sre_validations` record per finding (Sent to SRE,
Gap confirmed, No gap (BAU) with required justification, Needs info), separate from analyst
decisions and purged with the finding's scope. A colour-coded stage (Analyst triage, With
SRE, No gap (BAU), Gap confirmed by SRE, Confirmed vulnerability, Rejected, Evidence
changed) appears as a column, filter and per-account count. Per-account SRE workbooks
(single or ZIP) carry instructions, definitions, the explanation columns and a verdict
dropdown; verdicts are recorded in the app, not imported. **Finalized findings** lists only
vulnerabilities confirmed by both SRE and the analyst, by severity and account, with Excel
and Word exports and the attack paths (including cross-account) that involve them. Double-
click launchers `CloSec.command` / `CloSec.cmd` self-set-up from a bundled release.

## 0.7.0 checklist-driven assessment — 2026-10-14

The approved checklist drives classification and reporting for AWS and GCP; every rule maps
to a checklist control. GCP expanded-2.2 typed parsing fixed; organization-wide GCP IAM rules,
cross-project and cross-cloud attack paths; Assessment checklist page and report sheet.
GCP collector 2.2.1 discovers projects when projects.json is missing or not JSON.

## 0.6.2 collector discovery — 2026-10-14

AWS collector 0.3.2 discovers accounts through Organizations, offers a name/ID search and
numbered selection with typed confirmation (allowlist enforced), and writes evidence plus
an account-named ZIP to `evidence/` beside the script. GCP collector unchanged (2.2.0).

## 0.6.1 assessment-ready release — 2026-10-14

Collector downloads in Evidence import (AWS 0.3.1 ZIP, GCP 2.2.0, README, contract, hashes);
SEC-EC2-SG-LATENT-EXPOSURE observation (R1 reachability rule unchanged); record counts show
Loading until data arrives. Removed the PyInstaller executable kit, old pilot GCP collector,
executable-only tools/tests and sprint-era documents (ADR-007; history retained). Real GCP
expanded-2.1 package reconciled through the GUI on the 0.6.0 release.

## 0.6.0 integrated assessment readiness — 2026-10-14

Guided workflow: a validated-but-unimported package is shown on every page with **Import and
analyze** (existing importer, then existing assessment, in one worker job); completed
analysis exposes **Open assessment results**; historical validation cards no longer replace
page content; runs are labelled by provider, account/project and finding count; distinct
empty states for not imported, not analyzed and no evidence. Fixes the field report where a
completed `assessment-expanded-2.1` validation (PACKAGE_READY) appeared on every page with
no next step.

AWS: new adapter `closec-v030-native-1` for the real collector v0.3 journal (the earlier
v0.3 profile matched no real output). botocore-generated operation names, page merging,
AWS-defined absence, residual-token truncation, KMS key ARN resolution and identity binding.
Collector 0.3.1 fixes CloudTrail `TrailName`, dead IAM enrichment, Windows `resource`
import, Prowler exit code 3, silent truncation, absence classification and adds Lambda
resource policies, instance-profile associations and the SCP chain. New SEC rules (analyst
review, no methodology mapping): CloudTrail logging and management events, GuardDuty,
AWS Config recording, Security Hub, KMS rotation.

GCP: collector 2.2.0 and analyzer `assessment-expanded-2.2` (bounded commands, REST retry,
pagination guard, UNEXPECTED_SCHEMA/PARTIAL/TIMEOUT/QUOTA_PROJECT_DENIED/
UNSUPPORTED_ENDPOINT gaps, location-aware Discovery Engine, optional approved quota
project, verified checksums); 2.1 and pilot packages remain supported.

Shared contract and coverage matrix generated from registries; reconciliation API, CLI and
Report Center panel; offline hash-locked wheelhouses for Windows x64 and macOS; package
file-count bounds raised to 20,000 (byte limits unchanged).

## 0.5.1rc4 enterprise assessment stabilization — 2026-10-14

Implement the audited `assessment-expanded-2.1` contract: 115 dataset families, bounded
indexed names, explicit gcloud/REST transport shapes, strict counts/statuses, local
integrity hashes and retained collection limitations. Canonical native identities merge
equivalent source observations without treating Asset Inventory summaries as detailed
configurations. Truncated or unverified project-number evidence cannot produce PASS.
Make shared account/project, IAM, evidence, network and investigation views provider-aware;
reconcile coverage and Excel projections with the selected persisted assessment.
Accept bounded `.DS_Store` sidecars after normal safety checks; original evidence remains
unchanged. No new rules, provider, runtime dependency, collector modification or framework.
Original pilot-1.5 folder/ZIP counts remain 74 supported / 86 unsupported observations,
35 evaluations and 2 candidates. Expanded actual exports, real AWS and Windows native
acceptance remain unverified. Full regression results are recorded in TEST_PLAN.md.

## 0.5.1rc3 operational recovery — 2026-10-13

Move upload/package verification off the HTTP loop onto the existing local worker.
Persist validation/import/assessment/export states and progress independently of DuckDB;
add cancellation checkpoints, interruption recovery, restricted local logs and allowlisted
diagnostic exports. Pin compiled frontend/backend identity and reject stale running code.
Make the validation action visible beside file selection, restore jobs after reload,
respect navigation after assessment, and close/discard cancelled Excel streams safely.
No new provider, rule, methodology mapping, infrastructure or runtime dependency.
Actual launcher acceptance covers 65-file pilot ZIP/folder in Chromium and WebKit,
AWS ZIP/folder, approvals/copy, RTF/Excel and consolidation. Full regression: 645 passed;
original customer evidence and native Windows execution remain unvalidated.

## 0.5.1rc2 import workflow validation — 2026-10-13

Prevent assessment of a previous active run while a new import is being submitted;
hold GUI job controls until persisted-run selection completes. Add real browser
regression for 65-file pilot-1.2.2 folder and ZIP selection, idempotent cross-transport
reimport, AWS import, findings review, dashboards and Excel export. The separate
synthetic Windows acceptance archive now contains the same legacy ZIP/folder inputs.
No accepted manifest versions, security rules or methodology mappings changed.
Original customer-evidence compatibility and Windows runtime remain separate gates.

## 0.5.1rc1 operational fixes — 2026-10-12

Secure Windows ZIP path compatibility, explicit pilot-1.2.2 native GCP adapter, original
status/integrity limitations, sanitized actionable import errors and local ZIP verifier.
Scoped AWS/GCP deletion and immutable replacement use exact identity, independent
confirmation, full reassessment, approval invalidation and recoverable publication.
Stable selected/hover/focus states and accessible provider navigation. Existing AWS/GCP
security rules and shared findings/report engines retained; no new runtime dependencies.
Actual customer export and Windows runtime validation remain separate gates.

## 0.5.0rc1 repository hardening — 2026-10-12

Removed tracked generated AWS assessment packages and obsolete sprint/recovery documents,
while preserving local copies. Moved development-only fixture/scale generators outside the
production Python package. Tests pin historical synthetic bytes and generate temporary
inputs. Production Windows distributions exclude synthetic evidence; a deterministic
separate acceptance archive is generated on demand. Expanded ignore/security checks and
retained concise current operations/build documentation. No rule, authorization, database
or methodology semantics changed; no shared history rewrite.

## 0.5.0rc1 multi-cloud — 2026-10-12

AWS/GCP/Consolidated persisted dashboards, native GCP evidence contract and imports,
15 deterministic GCP criteria, provenance, scope/readiness, qualified investigations,
narrow SCC correlation and shared findings/report approvals. Existing AWS engines retained.

## 0.4.2rc1 report-ready findings

Registry-derived coverage, additional IAM/KMS configuration observations, versioned
remediation and immutable analyst-edited narratives with independent approvals,
clipboard and approved RTF/text exports. Streamed Excel performance preserved.

## 0.4.1rc1 collector integration

Versioned collector/aggregate IAM integration, bounded ZIP import, explicit readiness,
targeted evidence requests and safe full enterprise refresh. STS/partition validation,
exact supplementary Prowler profiles and bulk Excel export.

## 0.4.0rc1 enterprise foundation

Offline import/normalization and deterministic AWS rules; bounded IAM/organization/network
reasoning; methodology criteria and qualified attack prerequisites; multi-import enterprise
snapshots and relationship views; local API/React launcher; workspace isolation,
release audit and backup/restore; pinned Windows onedir tooling.

Real exports, Windows execution and analyst/production acceptance are independent gates;
see the current release handoff for actual validation and limitations.
