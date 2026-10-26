# CloGCP versioned final-assessment workflow (candidate)

Implemented in the existing offline application on `feature/offline-security-analyzer`.
This candidate uses synthetic validation. It does not replace an existing installation,
migrate a customer workspace on opening, or establish production/Windows acceptance.

## Side-by-side opening and recovery

Extract the updated source application into a new installation directory. Close the old
application before selecting its workspace. Existing compatible databases are inspected
read-only before the app opens them. Opening does not rebuild runs, add tables, recover a
pending scope transaction, delete partial reports or rewrite saved job history. Pending
transactions, WALs and incompatible schemas stop with explicit recovery/upgrade errors.
The prior release and workspace remain available.

For a verified copy, explicitly run from the updated installation:

```
python -m offline_analyzer.storage.side_by_side --source OLD_WORKSPACE --target NEW_WORKSPACE
```

The target must be a new sibling directory. Every file hash and every row of every database
table is compared before a recovery manifest is written to the new copy. Symlinks and open
or pending-operation workspaces are refused. Launch with the new workspace selected; do not
point two running applications at one database. A table-incompatible historical workspace
requires a separately approved versioned migration; no automatic migration is implemented.

## Independent attack-path action

Select any existing GCP assessment, including a finalized Batch 1 or a pre-existing Bulk
Enterprise Assessment. In **GCP → Attack Paths**, choose **Recalculate Attack Paths**.
The action verifies retained raw hashes, reads already-normalized resources and observed
relationships, and invokes only the corrected path engine. No Bulk Enterprise rebuild,
collector import or security-rule assessment is required. Each invocation writes a new
immutable evaluation directory under `attack-path-evaluations/RUN/EVALUATION`.

The screen shows old/new path IDs, states and reconciliation reasons, current mandatory
prerequisites and saved version count. The prior evaluation or frozen path history remains
available. No finding, analyst/SRE validation, frozen edition or original report is changed.
Configuration support never verifies exploitation; new path review is independent. Unmatched
legacy paths remain explicit history. Discovery bounds and incomplete context remain visible.

## One supplementary collection job

The collector is a separate tool. CloGCP never executes it. Export the selected stored
inventory without changing the database:

```
python -m offline_analyzer.evidence.inventory --workspace WORKSPACE --run RUN --output inventory.json
```

Use `python -m clogcp_delta.planner --help` to prepare one plan from the private missing-access
matrix, source inventory, selected projects and approved folders. Previously observed bucket
names and Discovery Engine parents can supply resource identities. Explicit selected scope
files can supply approved additional identifiers. Counts alone never identify resources;
missing bucket names or Discovery location/collection scopes are listed in `pending-scopes.json`.
Successful complete operations are skipped. Shared folder requests remain associated with
all selected projects but have one wire request per operation/resource. Optional IAM
recommendations are explicitly unsupported rather than silently treated as complete.

The private matrix shape is `bucket_iam: [{project,bucket_count}]`,
`folder_iam: [{folder,projects: [...]}]`, `discovery_configuration: [project,...]`,
`optional_recommendations: [project,...]`. Bucket/discovery scope files map project IDs to
lists of exact approved bucket names / `projects/.../locations/.../collections/...` parents.
The planner's selected folders use `folders/NUMBER`. Use synthetic identifiers in samples.

Review the resulting exact plan. An approved identity/time, reconciled catalogue and the
unchanged matrix SHA-256 are required. The CLI defaults to a dry run and acquires no token:

```
python -m clogcp_delta --plan approved-plan.json --output NEW_DRY_RUN
python -m clogcp_delta --plan approved-plan.json --matrix private-matrix.json --execute --output NEW_DELTA
```

Execution uses existing gcloud authentication. The tool only invokes enumerated IAM/metadata
reads and allowlisted Discovery Engine GET/list endpoints, never API enabling, IAM writes,
secret values or document content. OAuth tokens remain in memory. Concurrency is 1–4,
default 2; per-API pacing defaults to 2 requests/second. Retryable failures have bounded
backoff; pagination, response bytes, total spool bytes and request counts are capped.
An individual denial/quota/API failure does not abort unrelated resources. All outcomes,
collection times, coverage, hashes, redactions and shared/equivalent requests are recorded
in one new package. Failed/partial collection cannot become complete coverage.

## Import, compose and reconcile

Import the supplementary ZIP/folder through **Evidence import** first. It becomes its own
immutable import; never give raw collector packages to the external finalizer for analysis.
Return to the existing base assessment's **Attack Paths → Apply supplementary evidence**,
select the imported supplementary snapshot, and choose **Create affected analysis version**.

The versioned composition references both original runs and their content-addressed raw
artifacts. Source observations are materialized without overwriting either import. Later
resource-specific attempts supersede older policy records. A fresh failure suppresses stale
success; older evidence stays historical, equal-time disagreement is unresolved, and
semantically equivalent policy evidence retains the original review basis. Collection times,
precedence and conflicts remain explicit. The combined evidence is not a simultaneous
configuration snapshot; path prerequisites retain a temporal-coherence limitation.

Existing evaluators use shared IAM context, so the current implementation assesses the
new run using those evaluators. This broader-analysis fallback affects only the new version;
it does not reassess the finalized baseline or rebuild the enterprise union. The screen
reconciles unchanged/changed/new/not-reproduced findings. Existing evidence-bound reviews
remain valid for identical finding fingerprints; changed findings need revalidation. Review
records are never copied or edited. Reimporting identical packages and repeating the same
composition reuses stable run and logical finding identities. Interrupted new-version
analysis can resume without altering its source runs.

Refresh assessments, select the new version, then independently recalculate its paths.
Export the consolidated assessment from Report center after assessor reconciliation. New
exports include the selected version's path evaluation/comparison and full JSON, plus the
composition reconciliation, while preserving earlier reports and original source records.

## Independent report finalizer

Run `python -m clogcp_report_finalizer --gui` or its CLI from the standalone package.
It needs no analyzer workspace, database, backend, collector, cloud access or new service.
It uses the existing Python/openpyxl/Pydantic/defusedxml stack. Choose the exact consolidated
Excel export and optional exported evidence, path/coverage/history JSON and guidance files.
All reads are explicit selections; source raw reference paths are never dereferenced.

```
python -m clogcp_report_finalizer --input consolidated.xlsx --output NEW_REPORT_DIRECTORY
```

The output is `CloGCP-client-report.xlsx`, `Assessor-QA-Exceptions.json` and `qa-summary.json`.
Original tabs and source values remain intact. The new reader view has the exact approved
40 headers; only its focused-evidence presentation is refined. All finding IDs, risk ratings,
analyst/SRE approvals, inclusion flags and path classifications are retained. Narrative
suggestions live in supplemental sheets; material technical corrections stay open in the QA
register for the assessor to resolve in CloGCP. Safe exact-equivalence grouping retains every
source record and reconciliation link. Missing canonical evidence requires review.

Full IAM policies are retained in source/detail views. Precise guidance selectors identify
relevant bindings or fields, preserve conditions/denies and qualifying settings, and never
invent missing values. Without supported selectors, evidence detail is explicitly unavailable.
Read-only verification commands require an explicit supported control/parameter mapping;
unsupported cases request a procedure. No command is executed. Formula text is literal;
macros, external links, unsafe archives, duplicate JSON keys and credentials are refused.

The finalizer remains usable when IAM is missing. The summary, evidence-limitations view and
QA register prominently retain those limitations. A review copy does not certify the attack
engine. `--final` additionally requires an explicitly selected acceptance record and matching
verification-report hash; the tool never invents assessor sign-off. Native Excel/Windows
rendering and actual customer-export verification remain separate acceptance gates.

The final integration pins attack-path engine **2.0.1**, retaining readable **2.0.0**
history. For a newly composed version, old/new comparison uses the saved base-analysis
paths, not a projection already computed with the new evidence. Historical blockers are
retained as qualifications when mixed collection dates leave their concurrent applicability
unverified; they do not become a false current BLOCKED conclusion. Inventory export also
uses normalized resource names when older adapters omitted folder/Discovery request
parameters, so completed identifiable operations can still be skipped without guessing.

Versioned path exports obey the selected provider/project and the existing finding review
and exclusion policy. A scoped export does not include unrelated composition details.
Legacy path sections are labeled historical; current finding path summaries reference the
versioned calculation. Complete history remains in the immutable saved evaluation.
Discovery Engine configuration is normalized and available for inventory/manual validation;
this integration does not introduce new automated Discovery security criteria.

Approved Discovery scopes may use a project ID or a previously recorded project-number
alias. The planner retains verified inventory identity mappings, deduplicates equivalent
scope aliases and rejects conflicting/unrecorded identities. Responses must match that
same approved identity before normalization; no project-number discovery is guessed.

## Published CloGCP upgrade

For previous CloGCP workspaces lacking the two additive consolidation tables, use the
explicit `side_by_side --upgrade-additive` command in `docs/clogcp/UPGRADE_0.8.5.md`.
It verifies a new copy, adds empty tables there and checks every original table row.
CloGCP launcher opening now performs only read-only compatibility preflight; pending
recovery or unknown schemas stop for explicit operator action. No original is upgraded.
