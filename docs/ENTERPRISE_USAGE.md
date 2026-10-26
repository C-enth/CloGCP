# CloSec — enterprise assessment workflow

Implemented locally on macOS, using synthetic evidence. Actual exports and Windows
execution remain unverified. No connection to AWS is made.

## Launch and combine accounts

From the repository root:

```sh
.venv/bin/python -m offline_analyzer.launcher
```

1. Use **Evidence import** to select, validate and import each approved package. Keep
   synthetic demonstrations labelled synthetic. Repeated imports retain unrelated runs.
2. In the header, optionally select original import runs, then **Build enterprise
   assessment**. No selection means all original imports. An enterprise snapshot cannot
   itself be selected as an input. Assessment runs as a visible serialized job.
3. Select the resulting **Enterprise** run. Dashboard, accounts, findings, IAM, evidence,
   network and reports use that snapshot. Original import runs remain selectable.
4. Import more evidence and build a new snapshot when ready. Existing snapshots, raw
   references and analyst history remain available. The dashboard lists newer imports
   that have not been included; an import alone does not refresh an old enterprise graph.
5. Review candidate findings and shared investigations explicitly, then generate/download
   Excel through **Report center**. Customer trackers are not updated or overwritten.

Evidence is unioned by canonical IDs, with duplicate raw locators retained. Contradictory
observations remain separate; the application does not choose the newest statement as
authoritative. Source pagination/scope metadata is preserved, not combined into a claim
of complete collection. Missing Organizations evidence does not prevent account analysis.
Snapshots verify original hashes, accept at most 2,048 original runs and 250,000 normalized
observations, and reject mixed normalization versions. Reimport historical original files
under the current normalizer into new runs, or select a compatible subset. Do not delete
old evidence to resolve this error. The original package/file upload limits still apply.

## Identity, account registry and groups

Accounts come from collection metadata, normalized resource ownership or explicit ARN/
configuration references. Referenced-only accounts are not counted as collected accounts.
Assessed means at least one persisted account evaluation, not every control completed.
Missing approved accounts is meaningful only when an approved registry is loaded; zero
without a registry is not proof of complete enterprise coverage. Workbook placeholders
are never imported as account identities.

The existing ignored private registry can supply optional `alias` and `groups` fields for
each entry. Load it using the existing CLI while the GUI is stopped:

```sh
.venv/bin/python -m offline_analyzer --workspace artifacts/gui-workspace accounts load data/private/approved-account-registry.json
```

Use the same workspace when launching. The path above is an example for an approved
local file, not a generated registry. Registry contents are never copied into the Windows bundle. Exact collected
Organizations parent links add OU filters; ambiguous/cyclic ancestry is not guessed.
Account Explorer supports search, filters and multiple-account selection. Selecting all
matching accounts is bounded to 512; select a narrower group for larger registries.

## Investigation and graph

**Cross-account explorer** has source/destination account, group/OU, relationship type,
domain, status, search, missing-dependency, privileged-target and outside-registry filters.
Account selections show both incoming and outgoing edges. The paginated register is the
complete filtered query up to the persisted projection budget; the graph is deliberately
bounded. Pan, zoom, select a node to highlight incident edges, or select an edge to inspect
its evidence, blockers, limitations, related candidates and request dependencies.

The graph uses at most 150 nodes and 200 edges; UI defaults are 60 nodes/100 edges. A
truncation notice means that graph is incomplete. Optional API focus traversal is at most
four hops **inside the bounded selected graph**, not an enterprise path search. Arrows
describe the named relationship; they are not traffic flow or proven exploitation.

| Status | Meaning |
|---|---|
| DIRECTLY_OBSERVED | Configuration explicitly establishes a reference/association |
| DERIVED_SUPPORTED | Existing IAM evaluator supports the specific authorization predicate |
| POTENTIAL | Candidate relationship with unresolved effective-access prerequisites |
| BLOCKED | Applicable evaluated deny/control blocks the particular IAM transition |
| UNKNOWN | Evidence is insufficient, conflicting or unsuitable for the conclusion |

Trust references never imply AssumeRole permission. Supported authorization is not proof
of attacker control, a usable live session or confirmed exploitation. Investigation
preconditions remain visible. An unresolved material dependency caps supported status.

Shared investigations require the same explicit configuration anchor and affected
endpoints; matching control IDs alone do not consolidate findings. A shared dependency
can be legitimate. Its record is not automatically a vulnerability and may have no
candidate finding or severity. Candidate review and shared-investigation review use
independent evidence-fingerprinted decisions. Exceptions remain NEEDS_VALIDATION. Changed
evidence requires revalidation; exact reimports and restarts preserve decisions.

## Supported references, not new authorization engines

Sixteen additional operation profiles are structurally synthetic-tested, not real-export
verified: S3 GetBucketPolicy; KMS GetKeyPolicy/ListGrants; Lambda ListFunctions; ECS
DescribeTaskDefinition; EC2 DescribeVpcs, DescribeVpcPeeringConnections,
DescribeTransitGateways, DescribeTransitGatewayAttachments, DescribeTransitGatewayRouteTables,
GetTransitGatewayRouteTableAssociations, GetTransitGatewayRouteTablePropagations,
SearchTransitGatewayRoutes; RAM GetResourceShares/ListResources/ListPrincipals.

S3/KMS policy Allow/Deny principal references are observed facts. Allow references generate
POTENTIAL resource-access candidates; identity permissions, service-specific authorization,
BPA, grants and restrictions are not combined into an effective-access conclusion here.
KMS KeyId needs an ARN for canonical key ownership; aliases/UUIDs remain unresolved.
Lambda/ECS execution identities and CloudTrail destination references are configuration
facts only. No rotation, new monitoring-control rule or live collector is implemented.

VPC/TGW/peering/RAM associations, routes and propagations remain configuration references.
ENI/instance/route-table ownership does not establish ownership of a shared VPC. Explicit
DescribeVpcs or attachment ownership resolves identities; otherwise owner is UNKNOWN and
the edge requests the missing operation. Attachments/routes never prove end-to-end traffic,
firewall traversal, inspection, segmentation failure or full network reachability.

## Local authenticated queries

These are implemented API query parameters, not CLI flags. They require the launcher's
local session; do not disable authentication to script them. Substitute an active run ID
and approved account IDs. All routes below start `/api/runs/{run}/enterprise/`.

| Question | Route and parameters |
|---|---|
| Accounts/roles trusting A | `relationships?kind=TRUST_POLICY_ALLOW_REFERENCE&source=A` |
| All outgoing references from A | `relationships?source=A` |
| AssumeRole involving B | `relationships?kind=ASSUME_ROLE&account=B`; filter `status` |
| Privileged target prerequisites | `relationships?kind=ASSUME_ROLE&privileged=true` |
| Other resources referenced by A policies | `relationships?source=A&kind=IDENTITY_POLICY_ALLOW_RESOURCE_REFERENCE` |
| Selected account pair | `relationships?source=A&destination=B` (repeat reversed for both directions) |
| Shared issues affecting multiple accounts | `investigations` |
| Unresolved evidence | `relationships?missing_only=true` |
| Shared network/security dependencies | `relationships?account=A&domain=NETWORK` or `MONITORING` |
| External approved-registry references | `relationships?outside=true` (requires approved registry) |

Relationship pagination: `offset`, `limit` (1–200); default 50. Combine filters. Graph accepts
the same filters plus `node_limit`, `edge_limit`, `depth`, `focus`. Accounts and shared
investigations are paginated separately. SQL is parameterized; browser input is never SQL.
Policy contents remain redacted in browser evidence detail; use approved local originals
when checking semantics. Redacted/sanitized policies cannot validate altered authorization.

## Reports and compatibility gates

The original 19 worksheets remain, with eight additions: Enterprise Account Summary,
Cross-Account Relationships, Cross-Account IAM Investigation, Shared Resource Access,
Shared Network Relationships, Enterprise Security Gaps, Cross-Account Evidence Gaps,
Affected Accounts and Resources. The IAM title is singular to respect Excel's 31-character
sheet-name limit. Enterprise Security Gaps includes qualified dependency investigations,
not just diagnosed vulnerabilities. Counts derive from persisted records, not all possible
account pairs. Technical status, evidence confidence, severity and reviewer status remain
separate. Existing tracker fields and source methodology are untouched.

The normalizer is r0.1.5. Imported artifacts remain immutable. The field verifier includes
the added operations' required fields, parameters and pagination diagnostics. Structural
acceptance and an operator's tool-generated declaration do not prove authenticity or
actual-export security correctness. Follow the field-acceptance checklist in
[RELEASE_0.7.0.md](RELEASE_0.7.0.md) in the authorized environment. No actual collector export was available during this sprint.
