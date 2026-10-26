# CloSec architecture
Status: Phase 0 architecture retained. R0 implements offline CLI ingestion, normalization,
scanner correlation, candidate generation, DuckDB persistence/analyst decisions and
standalone Excel reporting. R1 adds the methodology audit/coverage specification, eight
methodology-mapped rules (R0 three + R1 five), relationship-aware evaluation, attack-path
prerequisite specifications with AP-04/AP-05 correlation, and tracker staging. Sprint 1 now implements the local API,
launcher and frontend. General graph and STRIDE engines remain unimplemented.

### R1 implementation notes
- `rules/registry.py` is the single rule registry. Rules declare `scope` (REGIONAL or
  GLOBAL per account), `contextual` evaluation with bounded related evidence
  (`rules/context.py`), and `family_gated` gap reporting (gap rows only when the
  evidence family was supplied; otherwise *Methodology Coverage* says NOT_SUPPLIED).
- `rules/methodology_links.py` pins each rule to an original control ID, the exact
  criterion keys it evaluates and the reviewed workbook hash. `full_coverage=False`
  everywhere, so reporting cannot turn sub-criteria into a control Pass.
- `methodology/coverage_spec.py` classifies all 204 controls; `methodology/audit.py`
  parses the reviewed layout locally and fails closed on drift.
- `attack_paths/specs.py` types prerequisites for AP-01..30; `prerequisites.py`
  derives records at report time from stored evaluations (no schema migration).
  EXPLOITATION prerequisites are never verified automatically.
- `reporting/tracker.py` projects results onto the tracker columns without writing
  analyst fields. See docs/REPORTING_ALIGNMENT.md.

## Module boundaries and flow

GCP attack-path evaluation v2 adds `iam/gcp_permissions.py` for bounded permission
semantics and `attack_paths/gcp_engine.py` for finding-independent discovery from existing
normalized records. A separate CLI opens Store read-only, verifies retained evidence,
and exports a new versioned register. Assessment tables and frozen editions are not
migrated. See [GCP attack-path engine](docs/GCP_ATTACK_ENGINE.md) for limits.
| Module | Owns | Depends on |
|---|---|---|
| ingestion | integrity, manifests, parser protocol, bounded imports | contracts |
| normalization | source-specific adapters; no control decisions | contracts, ingestion |
| contracts | versioned canonical records | Pydantic |
| inventory | resource identity, observed architecture relationships | contracts |
| rules | deterministic executable specifications and evaluations | contracts, inventory |
| correlation | evidence-backed security gaps | rules |
| stride | threat preconditions, separately verified exploitation | correlation, inventory |
| attack_paths | typed prerequisite and blocker evaluation | inventory, contracts |
| risk | technical and approved business factors | contracts |
| findings | candidate findings, review, remediation lifecycle | contracts |
| provenance | source references, immutable run metadata, audit events | contracts |
| reporting | consolidated reports, safe Excel exports | contracts |
| api | loopback application boundary | application services |
| frontend | React/TypeScript/Vite and bounded SVG views | local API |
| methodology | local lossless extraction and reviewed mappings | ingestion |

Raw immutable files -> validated manifest -> streaming parsers -> normalized observations
-> inventory -> rules -> gaps/threat/path candidates -> independent risk/review -> reports.
Each run pins source hashes, parser/schema/rule/methodology versions and evaluation time.
Never join identities by resource name alone. Scope account, partition, region/global
and native ID; retain deleted/history records by run. Cross-account edges need evidence
of trust AND effective permissions/conditions; topology does not establish reachability.

## Decisions and trade-offs
Pydantic v2 validates boundaries. DuckDB is the implemented R0 analytical store with one
application process owning writes; transactions and serialized jobs protect run state.
No database server. Graphs use NetworkX only for bounded account/resource subgraphs;
cap nodes, edges, depth and paths, with truncation reported as incomplete.
Keep raw files out of the database; separate normalized, evaluation, review and report
namespaces. Transactional audit/review workload performance must be measured before
adding storage. Do not add another database preemptively.
FastAPI serves bundled assets and API on loopback. Analysis does not import FastAPI.
Frontend views do not implement authorization or attack-path reasoning.
Dependency ranges are developer constraints, not a release lock; release requires
pinned, hashed OS-specific wheel inventory, licenses, SBOM and offline install test.

## Deployment
One launcher owns one backend process and one local workspace lock. Per-user writable
workspace outside install directory, portable pathlib paths, no admin requirement.
PyInstaller onedir is preferred for inspectability and fewer extraction surprises;
Windows build/validation required. Browser opened only after health and session setup.
No Docker, Electron, external database, cloud calls or remote frontend assets.

## Threat mitigations and residual risks
Bound archive members, uncompressed bytes, ratios, rows, cells and file bytes. Reject
traversal, encrypted archives, macros, external workbook links and executable inputs.
Do not evaluate formulas. R0 rejects duplicate JSON keys and enforces depth/record budgets.
Resolve workspace paths and symlinks; later file opening needs TOCTOU-resistant handles.
SHA-256 detects mutation but proves neither authenticity nor collection completeness.
Audit hash chains detect modification only against an independently retained checkpoint;
local user with full filesystem access can rewrite both logs and checkpoints.
Reports must neutralize leading =,+,-,@ and whitespace/control-prefixed spreadsheet
formulas. Logs omit values and paths with customer identifiers.
Loopback alone is insufficient: planned token, exact Host/Origin checks, no permissive
CORS, CSP, request limits, CSRF protection and no arbitrary filesystem path endpoints.
R0 disables DuckDB extension auto-download/install and external file/network SQL access;
SQL is internal, parameterized and never supplied by imports. Offline network denial
and browser asset tests are release gates. Secret detection/redaction must occur before
persistence; rejection is default for credential-bearing exports.

References: [DuckDB concurrency](https://duckdb.org/docs/lts/connect/concurrency),
[PyInstaller platform builds](https://www.pyinstaller.org/en/stable/),
[Pydantic strict validation](https://docs.pydantic.dev/latest/concepts/strict_mode/).

## R1.2 implementation notes
`iam/` owns bounded policy authorization and investigations, consuming normalized
observations through rule context; adapters still make no control decisions. Typed
observed/evaluated relationships, cross-account AssumeRole and EC2/Lambda PassRole
prerequisites feed reporting and AP-04/AP-06 records. This does not implement a general
graph, STRIDE engine or live AWS simulator. See docs/IAM_EVALUATION.md for exclusions.

## Sprint 1 operational GUI (2026-10-10)
ADR-002 activates the selected FastAPI/React/TypeScript/Vite stack. `api/app.py` owns
loopback HTTP/session/CSRF boundaries and bounded multipart uploads. `api/coordinator.py`
serializes database reads/writes and observable jobs; `api/services.py` projects existing
Store, metrics, IAM, finding decision and reporting services. `launcher.py` owns socket,
OS workspace lock, startup/browser lifecycle and shutdown. Compiled assets are Python
package data under `api/assets`; frontend source/build lock lives in `frontend/`.

The browser chooses local files, not server filesystem paths. Temporary uploads are
validated before retained publication; rejected inputs are removed from temporary
staging. Raw files and policy contents are not HTTP resources. Bounded normalized
redaction/traceability is available within the authenticated local session. Database
schema and reasoning modules remain unchanged; IAM views are recomputed/cached from
persisted evidence. Remarks/exceptions use existing evidence-bound decision notes.

Exact Host/Origin, fragment bootstrap, HttpOnly SameSite cookie, independent mutation
CSRF token, request/file budgets, CSP/no-store/nosniff/frame denial are implemented.
Framework tracing, metrics, logs and telemetry auto-configuration are explicitly disabled.
Queued jobs can be cancelled; running synchronous analyzer transactions finish safely.
Job diagnostics are session-only; runs, reviewer decisions and report files persist.
No general network/path engine or collector was introduced. See docs/GUI_USAGE.md.

0.5.1rc2 holds frontend job submission from the initial POST until job completion and
persisted-run selection. Run selection, assessment and export controls are disabled
through that interval; a synchronous submission guard prevents overlapping GUI jobs.
This changes UI sequencing only, retaining the coordinated backend writer and all
ingestion, normalization and security-rule semantics.

## Windows delivery boundary (Sprint 2)

ADR-003 selects PyInstaller onedir with compiled local GUI assets and existing services.
Frozen Windows mutable data lives under LOCALAPPDATA, separately from the read-only
bundle. Source runs preserve their existing artifacts workspace default. Packaging uses
an offline pinned wheelhouse and excludes private workbooks/evidence/databases. Windows
execution remains an explicit acceptance gate. Import inserts now use bounded columnar
batches inside the existing transaction; canonical IDs/provenance/schema/rules are unchanged.

## Sprint 3 enterprise correlation boundary

ADR-004 adds immutable enterprise snapshots of explicitly selected original import runs.
`enterprise/snapshot.py` materializes SQL unions of normalized facts and all evidence
locators, verifies raw hashes and reuses the existing rule engine. No raw file is copied
or removed. Original runs and decisions remain available. Mixed parser versions are
rejected rather than choosing an observation arbitrarily at a shared raw locator.

`contracts/enterprise.py` defines partition-aware typed edges and snapshot metadata.
`storage/enterprise_schema.py` adds indexed snapshot, edge, issue and projection tables
to existing DuckDB databases. `enterprise/correlate.py` projects explicit references and
partition-scoped R1.2 IAM decisions; it is not a new authorization evaluator. Ownership
comes from exact identifiers/owner fields, not names or the account collecting a shared
VPC. Missing ownership remains a dependency. `enterprise/queries.py` implements bounded
NetworkX views, SQL-filtered pagination, approved account groups and independently reviewed
shared-anchor investigations. Imports do not trigger whole-workspace graph rebuilding.

`normalization/enterprise_adapters.py` adds reference-only structural profiles. Parsers
make no control decisions. S3/KMS authorization and network reachability are deliberately
unevaluated. `reporting/enterprise.py` adds eight persisted-data worksheets; existing
reports/rules remain. The existing React app adds enterprise selection, a cross-account
screen, bounded interactive SVG graph and drilldowns. API mutations continue through the
same coordinated writer, local session and CSRF checks. See docs/ENTERPRISE_USAGE.md.

## 0.5.0 provider-aware extension

ADR-005 retains the monolith, DuckDB, serialized writer, loopback session and existing AWS
engines. contracts/gcp.py defines the native manifest and typed transition contract.
Source/Normalized/Result/Candidate add explicit GCP identity while retaining historical
AWS serialization, IDs and fingerprints. Account IDs remain AWS-only.

ingestion/gcp.py translates bounded validated manifests and partial guided JSON into the
existing importer; normalization/gcp.py has 25 native profiles without control logic.
rules/gcp.py evaluates 15 configuration criteria independently of AWS authorization.
correlation/gcp.py sees uncommitted writer evaluations for exact SCC/native deduplication.
GCP relationships and investigations derive from persisted facts with bounded output;
credential possession, effective IAM and network compromise remain unresolved prerequisites.
Enterprise unions reject incompatible provider parser versions and conflicting project
identities. No cross-cloud transition or generalized effective GCP authorization is claimed.

Reporting, evidence-bound review/approval and streaming Excel are shared. The React app
adds persisted provider dashboards, filters and domain drilldowns. Native gcloud collection
is separate trusted PowerShell tooling, never executed by analyzer imports or runtime.
Windows build kit/EXE packaging includes schemas, modules and compiled assets, with no
synthetic evidence. Development fixture generators live under tools/fixtures; separate
acceptance archives are generated on demand. Actual Windows build/runtime remains unvalidated.

## 0.5.1 scoped lifecycle and legacy evidence

ADR-006 adds exact provider/scope lifecycle operations inside the existing coordinated
writer. Temporary DuckDB copies stage full reassessment and compact publication; a
checked journal/OS lock enables startup recovery. No new service or persistent database
is introduced. Historical replacement evidence remains immutable. Deletion blocks shared
raw configurations, invalidates affected report revisions and removes exact managed files.

ingestion/gcp_legacy.py translates only pilot-1.2.2 into the shared importer. Portable ZIP
canonicalization precedes safety checks, file matching and streamed CRC validation.
Legacy local hashes never imply source integrity/authenticity or collection completeness.
See docs/OPERATIONS_0.5.1.md for operational boundaries and real-evidence verification.

0.5.1rc3 retains the serialized local worker. Multipart transfer uses disk-backed
staging; package inspection executes on the worker, not the API event loop. Versioned
job sidecars in storage/job_journal.py persist states, timings and terminal results.
Progress/health do not acquire DuckDB; database views return an actionable busy result
while a job owns the writer. Optional provenance/execution.py checkpoints supply bounded
cancellation without making parsers/rules depend on API code. Startup marks unfinished
jobs INTERRUPTED and removes only their reserved scratch directories. Backup includes
journals. Diagnostic exports use an explicit Pydantic allowlist; runtime identity pins
backend source and compiled frontend compatibility. No service/framework was added.

## Versioned GCP final workflow candidate (2026-10-26)

ADR-011 in `docs/adr/` extends existing services without a new framework or database.
The app checks stored-schema compatibility read-only before opening a workspace and does
not perform scope recovery, table migration, report cleanup or persisted job recovery on
opening. Explicit side-by-side copying verifies all files and every table row.
`attack_paths/versioned.py` is an independent path-only service and GUI action; its
versioned artifacts never update assessment or review tables. `evidence/composition.py`
references immutable base/delta runs and materializes precedence-qualified observations
in a new run. Shared IAM context currently requires existing evaluators in that new run;
the baseline is never reassessed. Collection dates remain separate, conflicting/failed
attempts fail closed, and unchanged review validity follows existing fingerprints.

`clogcp_delta` is a separate explicit-execution collector. Its output enters the existing
bounded import/normalization pipeline; the analyzer never executes cloud reads.
`clogcp_report_finalizer` is a separate reporting-only entry point, with no analyzer or
DuckDB dependency. See `docs/GCP_FINAL_WORKFLOW.md` for supported flows and limitations.

The 0.8.5-clogcp.1 distribution retains the isolated CloGCP profile. Its launcher workspace
preflight is read-only and does not invoke implicit checkpoint/recovery/migration. An
explicit `side_by_side --upgrade-additive` command verifies a new workspace copy, creates
only known missing empty consolidation tables there and checks every original row/hash.
The original remains unchanged. Unknown schemas and pending journals stop for operator action.

P0 recovery hotfix 0.8.5-clogcp.2 separates unbounded-total workspace integrity hashing
(1 MiB reads) from bounded untrusted-ingestion hashing. A private destination-drive
container holds unverified copies; the requested destination is published only after
full file/table verification. Incomplete containers and descendants cannot be opened.
No reasoning, reporting, evidence schema or runtime framework changes are introduced.
