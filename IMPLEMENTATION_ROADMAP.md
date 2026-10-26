# CloSec implementation status

## Implemented GCP attack-path correction candidate (2026-10-25)

Engine 2.0.0 traces/corrects the actual XP-01 generator, separates authentication and
workload permission mechanisms, discovers bounded candidates independently of findings,
and exports an isolated five-state register from existing evidence using read-only
Store access. Historical findings, decisions, SRE validations, editions and reports
are not reassessed or migrated. Generic legacy chains split by mechanism with prior
status retained; unmatched legacy records remain explicit reconciliation ambiguities.
See [usage and remaining semantics](docs/GCP_ATTACK_ENGINE.md).

Complete inherited deny/PAB/CEL/group/federation/service authorization, generalized
reachability and exploitation verification remain unimplemented. Workload execution
permission checks do not resolve image, service-agent or organization-policy context.
The operator must execute this candidate locally with authorized client evidence
before any Batch 1 correction claim. Current validation results are in TEST_PLAN.md.

## Implemented GCP configuration increment (2026-10-16; synthetic validation)

Completed the previously unfinished 23 evaluators: network/firewall, Compute metadata,
Storage, Cloud SQL, KMS rotation and guided log retention. Added recommendation/detail
support, risk-context persistence, field/missing-data regressions, private mapping
reconciliation and collector-contract regeneration. Registry: 19 AWS + 48 GCP, including
guided evaluations; no full-control automation claim. The supplied workbook remains the
pinned 204-control source. See docs/GCP_CONFIGURATION_COVERAGE.md and TEST_PLAN.md.

Remaining requested expansion: persisted guided-manual control workflow, per-project
control dashboards, more GKE/serverless/data/DevOps checks and richer cross-project graph
analysis. Existing collectors and workflows remain in place; native Windows and real-export
validation remain separate acceptance gates.

## Implemented 0.8.4 report template and collected-project scope (synthetic-tested)

One Word/Excel template (executive summary, technical findings, attack paths) for whole-run,
per-account and Finalized downloads. Only collected projects appear (ADR-010): out-of-scope
IAM search results are dropped at import; collector 2.2.3 makes org/folder IAM search
opt-in. Collector 2.2.3 not executed in PowerShell here.

## Implemented 0.8.3 GCP collector sign-in check (static-tested)

Collector 2.2.2 stops before collecting when gcloud cannot issue a token non-interactively
and warns when the session expires mid-run; analyzer accepts 2.2.2. Not executed in
PowerShell here (no PowerShell on the build Mac); first Windows run is the acceptance test.

## Implemented 0.8.2 assessor-final review and detailed findings (synthetic-tested)

Assessor confirmation finalizes without SRE; login-name defaults; detailed finding analysis
from collected evidence (ADR-009) with Copy technical finding; pre-filled client report
draft; restrained Excel/Word formatting; workflow-ordered menu. Remediation commands exist
for rules with a single verified CLI change; others state that guidance applies. The
per-rule expected values and commands are engineering guidance awaiting analyst review.

## Implemented 0.8.1 faster assessment (synthetic-tested)

Report contents follow analyst/SRE marking (valid / confirmed / all) for whole-run and
per-account Excel + Word reports; analyst "not valid" overrides SRE stages; atomic bulk
marking; per-account report and Remove / replace shortcuts; attack-path chain diagrams in
UI and reports; per-release launcher folders. The comprehensive Report center register
("Generate Excel") intentionally stays complete, with status and stage per finding.

## Implemented 0.8.0 SRE validation workflow (synthetic-tested)

Pilot feedback: data-driven findings filters and per-account view; versioned plain-language
explanations (`finding-explanations-1.0.0`) for all 44 rules in dashboard, Excel and Word;
SRE validation track and derived stages (ADR-008); per-account SRE workbooks; Finalized
findings tab with Excel/Word exports and attack paths involving confirmed vulnerabilities;
double-click self-setup launchers. Not implemented: importing SRE verdicts from returned
workbooks (declined; manual recording), automatic re-ranking of attack paths by confirmed
vulnerabilities, network reachability across accounts. The misuse texts are engineering
paraphrases awaiting analyst review; Windows execution of the launcher is unverified.

## Implemented 0.6.0 integrated readiness (synthetic- and emulator-tested)

Guided Import and analyze workflow; native AWS collector v0.3.x adapter; corrected AWS
collector 0.3.1 and GCP collector 2.2.0; `assessment-expanded-2.2`; six AWS service-state
observations; generated collector contract and coverage matrix; per-run reconciliation;
offline wheelhouses. Unverified: the corrected collectors against real AWS/GCP APIs, native
Windows execution, real AWS evidence and real `assessment-expanded-2.x` exports.

## Implemented AR-01 stabilization (0.5.1rc4)

Strict expanded GCP manifest/dataset adapter, typed metadata normalization, canonical
source identities, evidence provenance, collection/evaluation coverage and provider-aware
shared views are implemented. Unsupported legacy observations remain retained. No new
rule catalog or effective-permission claim is introduced. Remaining field gates are an
actual expanded collector export, actual AWS evidence and Windows x64 operation; collector
timeout/pagination defects require a separately reviewed Windows collector correction.

This records maintained capability and unresolved work for 0.5.0rc1, rather than sprint logs.
No feature expansion is part of the repository-cleanup release.

## Implemented and synthetic-tested

- Offline bounded ZIP/folder/guided JSON import, integrity checks, immutable raw evidence,
  provider-aware normalization, DuckDB persistence, workspace/snapshot isolation and backup.
- Existing AWS configuration rules, bounded IAM policy/SCP/boundary reasoning,
  qualified network/resource relationships and cross-account investigations.
- GCP versioned native contract, 22 profiles, 15 deterministic criteria, explicit scope
  and collection statuses, narrow SCC/native deduplication and qualified candidate paths.
- Persisted AWS/GCP/Consolidated GUI, inventory, domain comparisons, coverage denominators,
  evidence gaps, filters and paginated investigations.
- Shared independent technical decisions, recommendations, editable evidence-bound report
  revisions, approvals, copy, approved-only RTF/text and comprehensive streamed Excel.
- Loopback FastAPI/session/CSRF security, local React assets and one-process launcher.
- Windows pinned offline onedir build and integrity tooling. Reproducible acceptance
  generators are separate development tooling; no evidence is in production distributions.
- Provider-aware methodology visibility with original AWS mappings retained and GCP
  source-clause mappings explicitly unresolved.

## Independent acceptance gates

Actual Windows build/runtime, normal-user/paths/EDR/signing, native Word/Excel, outbound
network-denial and Windows collector execution require an approved Windows host.
Real-export compatibility requires the local verifier with --origin tool-generated on
actual collector files, followed by analyst source-evidence review. No customer exports
were supplied; the owner requested synthetic evidence only. Analyst and production
acceptance remain separate from passing regression tests.

## Unimplemented or unresolved

- Reviewed GCP source-clause methodology mappings and owner approval of proposed AWS
  mappings/ambiguities (see METHODOLOGY_COVERAGE.md).
- Complete GCP inherited allow/deny/condition/boundary context and effective authorization.
- Broader workload/vulnerability checks, generalized network reachability, complex
  cross-cloud federation paths, drift and selective reassessment.
- Remaining AWS credential/monitoring/organization objectives shown as unsupported in
  the methodology matrix; no resource count substitutes for control coverage.
- Generalized STRIDE/exploitation engine and full same-account resource/session semantics
  beyond the bounded IAM scope documented in docs/IAM_EVALUATION.md.

Next deployment work: run the portable release on a Windows x64 host and complete the
field-acceptance checklist in docs/RELEASE_0.7.0.md.

## Implemented 0.5.1rc1 operational changes

- Explicit legacy GCP pilot import, portable secure ZIPs, UTF-8 BOM support and qualified
  local verification; genuine customer archive compatibility remains unestablished.
- Manage Assessment Data: exact-scope preview/deletion, independent typed confirmation,
  atomic snapshot replacement, full reassessment, report invalidation and crash recovery.
  Shared raw configurations block permanent scope deletion. External backups are retained.
- Stable provider/subtab selection, hover/focus and keyboard provider navigation.
- Windows module/schema/asset inclusion remains source-verified, not Windows-executed.

## Implemented 0.5.1rc2 import workflow changes

- GUI job submission holds assessment/run selection through import persistence,
  preventing a quick follow-up action from assessing the previous run.
- The 65-file pilot-1.2.2 ZIP/folder workflow is an explicit browser regression.
  Separate Windows acceptance tooling generates matching synthetic inputs.
- This extends engineering verification; original customer compatibility and native
  Windows build/runtime acceptance still require authorized environment validation.

## Implemented 0.5.1rc3 operational recovery

- Worker-owned package validation, real stage/count/time feedback and durable jobs.
- Cancellation checkpoints, interrupted-job recovery, reserved scratch cleanup and
  workspace backup/restore of job history; serialized DuckDB access is retained.
- Frontend/backend identity checks, visible failures, sanitized diagnostics and
  report-stream cleanup. Completed assessment respects explicit user navigation.
- Actual launcher/compiled GUI regressions cover Chromium/WebKit, AWS/GCP ZIP/folder,
  analyst review/approval, RTF/Excel, consolidation, retries and restart recovery.
- Original customer evidence and native Windows execution remain field-validation gates.

## GCP final-workflow integration candidate — implemented 2026-10-26

- Independent stored-evidence path action, immutable evaluations and old/new comparison.
- Read-only compatibility preflight; verified explicit side-by-side workspace copy.
- One multi-project delta plan/job with successful-operation skipping, shared-folder
  deduplication, bounded workers/pacing/retries/pagination, explicit partial/access states.
- Immutable native supplementary import and versioned evidence composition; resource/date
  precedence, conflicts, reconciliation and stable repeated-run identities.
- Existing shared IAM evaluators operate in the new version as a documented broader-analysis
  fallback. Fine-grained rule-result caching is not implemented; the baseline stays intact.
- Separate finalizer with the exact 40-column schema, focused evidence, conservative issue
  consolidation, retained source records/ratings/approvals, internal navigation and separate QA.
- New report exports retain selected versioned path JSON/comparison and composition history.

Pending field/platform gates: actual approved collector execution and tool-generated input
verification, customer B1/B2 validation, native Windows build/execution, native desktop Excel
and Tk file-picker acceptance. Missing exact bucket and Discovery collection scopes remain
pending in private operator material; no resource identities or permissions are guessed.
