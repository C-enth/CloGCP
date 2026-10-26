# CloGCP attack-path engine 2.0.0 release candidate

This is an offline analysis correction. Existing findings, decisions, frozen editions,
collectors and application versions are retained. No actual Batch 1 correction is claimed.

## XP-01 source trace

`attack_paths/gcp.py:investigations` creates finding-triggered UNKNOWN candidates;
it is not the source of XP-01's PROVEN conclusion. `cross.py:classify` grouped
Service Account User, Token Creator and Workload Identity User grants together.
`cross_paths` joined them to administrative service-account bindings, stating that
actAs or token minting established impersonation. Empty project deny/PAB exports
could remove the remaining configuration gaps. `model.py:summarize` marked every-hop
PROVEN chains PROVEN, while credential possession stayed outside the hop conclusion.

`feasibility.py:attack_paths` combines these paths with investigations and AWS
methodology scenarios. `reporting/assessment_report.py`, `report_document.py`,
`docx.py`, `sre_reports.py` and `contextual.py` consume that projection. `gcp_feed.py`
projects frozen editions without recalculation. No other GCP-specific PROVEN converter
was found. AWS hop semantics and source AP/TS/control mappings are unchanged.

The corrected XP-01 source evaluates getAccessToken using shared permission semantics.
It explicitly states that actAs requires a separate workload execution mechanism.
Credential control/token execution remain unresolved. Legacy GCP cross-path projections
cannot produce end-to-end PROVEN/FEASIBLE from observed bindings alone. Existing path
functions and response keys are retained; v2 discovery produces a separate register.

## Read-only isolated reanalysis

Stop the application using the selected workspace, then run from the candidate source:

```sh
PYTHONPATH=src .venv/bin/python -m offline_analyzer.attack_paths.gcp_reanalysis \
  --workspace /absolute/path/to/existing-workspace \
  --run EXISTING_RUN_ID \
  --output /absolute/path/to/private/CloGCP-attack-path-evaluation-v2
```

For an editable developer installation, `python -m ...` also works. For the portable
Windows source candidate, after its existing offline setup, set `$env:PYTHONPATH` to
the extracted `src` directory and invoke `.venv\Scripts\python.exe -m
offline_analyzer.attack_paths.gcp_reanalysis` with the same arguments. Windows execution
has not been validated on this macOS host.

Choose a new output directory outside the historical workspace. In this checkout,
derived material belongs in ignored `artifacts/` or `data/private/`. DuckDB opens
read-only: no recovery, migration, checkpoint, reassessment or decision writes.
Retained raw hashes are checked before and after evaluation. Pending scope-operation
journals are refused. Select an existing enterprise snapshot to analyze multiple
projects; other runs are never silently added. No recollection or upload occurs.

Optional `--legacy-paths /private/original-paths.json` reads a bounded original JSON
path array. Matching requires source principal, target identity and shared observation
evidence. Generic old chains can split by mechanism, retaining old IDs, prior status
and a reason. Ambiguous records remain unmatched. No historical approval is imported;
without this file, today's projection is never used to invent past PROVEN statuses.

Outputs: full versioned `attack-path-evaluation-v2.json`, formula-neutralized
`attack-path-history.csv`, `active-attack-paths.csv`, and explanatory `README.txt`.
`legacy-reconciliation.json` lists matched chains and unmatched/ambiguous original IDs
with their previous status and reason, without importing review decisions.
BLOCKED paths stay in history and are excluded from active candidates. Canonical IDs
and root-cause groups retain individual technical chains. No old report is overwritten.

Configurable limits: `--max-nodes 10000`, `--max-depth 6`, `--max-candidates 1000`,
`--max-bindings 50000`. Depth bounds mandatory prerequisite chains including permission
and service context. The binding budget also bounds identity pair comparisons; each
traversal has a candidate budget. Truncation is explicit and prevents SUPPORTED claims
from incomplete discovery. Limits are not an estate-capacity certification.
Permission evaluation also bounds total grant/deny comparisons to ten times the binding
budget; resource/role indexes and restriction-context caches avoid repeated estate scans.

## Conclusions and evidence semantics

| State | Meaning |
|---|---|
| SUPPORTED | Every modeled mandatory configuration prerequisite has evidence; execution remains UNVERIFIED. |
| CONDITIONAL | Configuration support depends on an unevaluated binding condition. |
| BLOCKED | A cited decisive control contradicts a mandatory prerequisite of this chain variant. |
| INSUFFICIENT_EVIDENCE | A mandatory prerequisite is uncollected/incomplete. |
| UNSUPPORTED | The required mechanism or permission semantics are unimplemented. |

Missing evidence alone never produces SUPPORTED or BLOCKED. An observed blocker can
decide a specific variant despite other missing evidence. If missing and unsupported
requirements coexist, the overall state is INSUFFICIENT_EVIDENCE; individual prerequisite
states remain visible. Exploitation verification, finding validation, path review and
severity are independent. New paths start UNREVIEWED / NOT_INHERITED.

`iam/gcp_permissions.py` separates actAs, access tokens, ID tokens, JWT signing, blob
signing, workload attachment and individual deployment/execution mechanisms. It uses
exact reviewed permission projections and collected custom-role details. Unknown
predefined roles, including Owner/Editor, are not universal permission shortcuts.
Inherited grants need explicit ancestor relationships; conflicting role definitions
fail closed. Conditional grants, groups, federation, missing deny/PAB context and
service restrictions never create unconditional effective permissions. User-principal
PAB applicability stays unresolved. Google-managed targets remain candidates with
unresolved service restrictions, rather than assumed immune or exploitable.

Only exact unconditional deny rules with resolved scope, principal and permission can
block. Wildcards, principal sets, CEL and deny exceptions are not simulated. Nonempty
deny/PAB context otherwise stays unresolved. Empty project exports cannot establish
absence of inherited or identity-associated restrictions.

## Discovery and remaining verification

Finding-independent families cover service-account authentication; bounded cross-project
identity chains; actAs plus separate Compute/Run mechanisms; public VM to attached
identity; public serverless to runtime identity; GKE node/control-plane identity;
public storage/data access; and identity-mediated data bindings. Provenance retains
observation IDs, artifact locators and hashes. Findings from source resources provide
context, never inherited validation or execution evidence.

Individual workload permission sets cover Compute creation with identity/metadata,
Run job creation/execution, and Run service revision creation. Image/network access,
service agents, quota, organization policy and actual controlled execution remain
unresolved. Usual collector evidence therefore cannot fully support these workload
mechanisms. ID-token/signing permissions never become direct access-token proof;
audience, JWT exchange and signing-based access require separate verification.

VM compromise, active listeners, firewall priority/hierarchy, token possession, Kubernetes
RBAC/KSA mappings, federation, application authorization, service perimeters and data
sensitivity remain unresolved. VPC denies are potential blockers. Internal-only ingress
blocks the direct internet endpoint variant, not alternate frontends. Public access
prevention can block public storage. Structural identity references never prove compromise.

Official references reviewed:
[authentication permissions](https://docs.cloud.google.com/iam/docs/service-account-permissions),
[Compute identity attachment](https://docs.cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances),
[Run permissions](https://docs.cloud.google.com/run/docs/reference/iam/permissions),
[principal identifiers](https://docs.cloud.google.com/iam/docs/principal-identifiers),
[PAB scope](https://docs.cloud.google.com/iam/docs/principal-access-boundary-policies).

Authorized client evidence must be run locally and reviewed before claiming Batch 1
correction. Windows execution and native Office acceptance remain platform-specific gates.

## Final-workflow integration patch 2.0.1

New evaluations pin engine 2.0.1; the v2 contracts continue accepting retained 2.0.0
history. A composed analysis compares against the actual base analysis's saved path
version (or its frozen/legacy baseline), then against its own prior versions. Source
collection timestamps accompany path provenance. When composition spans collection dates,
historical blocking controls remain cited evidence, but cannot establish a current BLOCKED
conclusion without concurrent applicability. The path remains insufficient evidence rather
than being silently removed from active candidates. Existing baseline records and approvals
are unchanged. See `GCP_FINAL_WORKFLOW.md` for the independent GUI action and delta workflow.
