# Evidence contracts v1.0

Expanded GCP 2.1 has a separate strict `ExpandedManifest` schema and an authoritative
115-family dataset catalog. It accepts object/array gcloud transports, flattened REST
arrays and explicitly validated aggregated Compute scope maps. Transport counts, native
resource identity and normalization counts are distinct. Failed, truncated and unsupported
collections remain visible; local hashes do not imply source authentication or complete
pagination. See [GCP collector contract](docs/GCP_COLLECTOR_CONTRACT.md).
Implemented Pydantic contracts are in src/offline_analyzer/contracts/models.py.
Unknown fields rejected; times must carry timezone; IDs scoped by run and resource.
Schema JSON can be exported using the schema CLI. Breaking semantics require a new
major schema and explicit migration, never silent coercion.

Manifest: run/source IDs, collector/version, UTC-aware collection window, scoped
account/region/service coverage, complete/partial/error/not-collected status, errors,
raw relative paths, SHA-256 and sizes. Empty or partial coverage never establishes PASS.
Raw references include artifact ID and locator (JSON pointer, row/cell or record ID).
Observations include parser/version, source, run, resource, predicate, JSON value,
time, provenance and limitations. Relationships are typed observed edges with evidence.
Rule specification records original control ID, version, prerequisites, applicability,
pass/fail definitions and manual limits, separately from methodology source text.
Evaluations retain scopes, evidence, reasoning, missing dependencies, confidence,
limitations and timestamp. PASS requires evidence and no missing dependencies; this
structural gate is necessary but not proof that the rule is valid.
Path states SUPPORTED/BLOCKED/UNKNOWN/NOT_APPLICABLE describe feasibility, not exploitation.
Severity and analyst approval must be separate downstream fields.

## Parser plugin boundary
Only explicitly registered trusted Python adapters; never load code from an import.
Protocol returns observation iterator, with parser ID/version and supported format.
Errors and coverage travel through manifest, not fabricated observations.
Planned adapter matrix (none implemented): Prowler OCSF/native versioned exports;
AWS CLI/boto3 offline JSON; Organizations/SCP; IAM Access Analyzer; CloudSplaining;
Config; Security Hub ASFF; GuardDuty; CloudTrail configuration/authorized event metadata;
VPC/TGW/Network Firewall; EC2/ECS/Lambda/S3/RDS/KMS; approved third-party exports.
Each needs version fixture, bounded parser and semantic mapping review. Scanner status
is an observation, never automatically a methodology outcome.

Incremental processing keys are source hash + parser version + schema version; rule
cache also pins methodology/rule/config versions. Changed inputs invalidate dependents.
Raw, normalized, results, review decisions and reports occupy separate run directories
and storage tables. No such storage or caching is implemented yet.

## Implemented R0 profile
contracts/r0.py adds schema r0.1 without weakening Phase 0 Resource/Observation contracts.
Normalized identity is nullable when unresolved, avoiding invented accounts/resources.
Package/source descriptors, normalized observations, results, candidates and decisions
have exported JSON schemas. Source account IDs now require 12 ASCII digits (also tightened
in the shared Phase 0 alias). See docs/R0_USAGE.md for file profiles, budgets and commands.

R0 trusted adapters explicitly select AWS DescribeInstances/DescribeDBInstances/
DescribeTrails JSON or Prowler 5.10.0 AWS OCSF. No plugin code is loaded from evidence.
DuckDB stores canonical records plus per-occurrence artifact/pointer links; raw JSON
is content-addressed separately. Only selected configuration fields are normalized;
all accepted unknown raw fields are preserved. No generic rule-cache implementation.
Other source adapters in the Phase 0 matrix remain planned.

## R1 additions (2026-10-10; schema r0.1, normalizer r0.1.2)
Additive only: existing stored records stay valid. `NORMALIZATION_VERSION` moved to
r0.1.2 because RDS observations now retain `PubliclyAccessible`; run IDs therefore change
for re-imported packages (R0 fixture: `run-40be8540…`).

| Operation (`aws-json-v1`) | Records | Resource type / identity | Retained configuration |
|---|---|---|---|
| ec2:DescribeSecurityGroups | `SecurityGroups[]` | AWS::EC2::SecurityGroup, `sg-…`, row `OwnerId` | GroupId, GroupName, VpcId, IpPermissions |
| ec2:DescribeNetworkInterfaces | `NetworkInterfaces[]` | AWS::EC2::NetworkInterface, `eni-…`, row `OwnerId` | Status, InterfaceType, RequesterManaged, VpcId, group IDs, public IPv4 (primary and per address), IPv6 count, attachment instance/status |
| iam:GetAccountAuthorizationDetails | `RoleDetailList[]` | AWS::IAM::Role, role ARN, Region `global` | RoleName, Path, parsed AssumeRolePolicyDocument, document encoding |
| iam:ListRoles | `Roles[]` | same as above (equivalent evidence) | same; URL-encoded documents decoded with duplicate-key rejection |
| s3control:GetPublicAccessBlock | singleton | AWS::S3::AccountPublicAccessBlock, native = account, Region `global` | four flags, or `configured=false` for the AWS-defined `NoSuchPublicAccessBlockConfiguration` response |

`global` is a resource label for non-Regional configuration; collection Region stays on
the observation and is never a Regional scope. Global rules evaluate one scope per account.
Partition for the account BPA resource comes only from a standard collection Region.
Unreadable interface group lists and unparseable trust documents are unresolved fields:
they downgrade declared completeness so that no latent-exposure PASS rests on them.
The BPA absence response is accepted only with no declared errors and HTTP 404/absent
status; any other error body is a collection error.

Results and candidates now carry `methodology_id`, `mapping_status` (`UNRESOLVED` or
`PROPOSED`), `methodology_criteria` (criterion keys) and `methodology_sha256`. PROPOSED
requires all three. Candidates also carry source-linked `attack_paths`, `stride_category`
and `methodology_inherent_severity`, kept separate from `suggested_severity` (technical),
evidence confidence and analyst decisions. Relationship evidence (for example the public
interface behind a security-group FAIL) is cited in `evidence` and
`supporting_observations`.

## R1.1 additions (2026-10-10; normalizer r0.1.3)
Additive. New operations: `ec2:DescribeRouteTables` (associations, routes), and per-bucket
`s3api:GetPublicAccessBlock`, `s3api:GetBucketPolicyStatus`, `s3api:GetBucketAcl`. Bucket
identity is taken only from `request_parameters.Bucket`; a missing bucket name leaves
identity unresolved. `NoSuchBucketPolicy` and bucket `NoSuchPublicAccessBlockConfiguration`
are AWS-defined absences (clean 404 only). Per-bucket requests are always PARTIAL.
GetAccountAuthorizationDetails now also yields customer-managed `Policies` (default
version document); AWS-managed policies are recognized by ARN and not normalized. Roles
retain attached policy ARNs, inline documents, permissions boundary and a per-role
`PermissionsResolved` flag (gaps lower risk context; they never mark the inventory
incomplete). Interfaces retain `SubnetId`; RDS retains port, security groups, subnets and
VPC; instances retain container-orchestrator tag *keys* only.

Results/candidates add `finding_class`, `exposure_status`, `suggested_severity`
(CRITICAL added), `evidence_needed` (merged into candidate `missing_evidence`) and
`compensating_controls`. The private account registry (`inventory/accounts.py`, schema
`account-registry-1`) lives in the workspace with retained history; it requires source,
approver and approval time, unique account IDs and tracker keys, and rejects extra fields.

## R1.2 additions (2026-10-10; normalizer r0.1.4)

Additive canonical schema remains r0.1. Per-subject collections retain request parameters
and unresolved fields; attachment references are separate from resolved documents.
AWS-managed policy documents are now normalized as well as customer-managed documents.

| Operation | Response / required subject metadata |
|---|---|
| iam:GetRole | Role ARN, name and trust document |
| iam:ListAttachedRolePolicies | AttachedPolicies, IsTruncated; request RoleName |
| iam:ListRolePolicies | PolicyNames, IsTruncated; request RoleName |
| iam:GetRolePolicy | RoleName, PolicyName, PolicyDocument |
| iam:GetPolicy | Policy ARN, name, DefaultVersionId |
| iam:GetPolicyVersion | Document, VersionId, IsDefaultVersion; request PolicyArn/VersionId |
| iam:ListInstanceProfilesForRole | InstanceProfiles, IsTruncated; request RoleName |
| iam:GetInstanceProfile | Profile ARN/name and role ARNs; request InstanceProfileName |
| organizations:DescribeOrganization | Id, MasterAccountId, FeatureSet; defined non-membership response retained |
| organizations:ListRoots | Root IDs and PolicyTypes Type/Status |
| organizations:ListOrganizationalUnitsForParent | OU IDs; request ParentId |
| organizations:ListAccountsForParent | Account IDs; request ParentId |
| organizations:ListAccounts | Account IDs |
| organizations:ListParents | Parent Id/Type; request ChildId |
| organizations:ListPolicies | Policy Id/Type/AwsManaged; request Filter |
| organizations:DescribePolicy | PolicySummary and decoded Content; request PolicyId |
| organizations:ListTargetsForPolicy | TargetId/Type; request PolicyId |
| organizations:ListPoliciesForTarget | Policy Id/Type/AwsManaged; request TargetId/Filter |

Verifier required-field profiles cover all 18 new operations. Optional fields and
NextToken are observed separately; empty lists do not prove full collection. A defined
non-membership/error response may legitimately lack success fields. Identity, trust,
boundary, hierarchy, SCP/RCP and profile incompleteness remain explicit dependencies.
IAM investigations and relationships are typed analysis records with supporting,
blocking and missing evidence; observed and evaluated relationships have distinct bases.
See docs/IAM_EVALUATION.md for authorization scope and excluded semantics.

## Sprint 1 GUI transport
Canonical evidence/results/decisions remain r0.1; no ingestion or authorization schema
change. Pydantic API bodies reject unknown mutation fields. Browser-selected package
uploads preserve source manifest hashes, metadata and request parameters; single files
use backend context/detection with PARTIAL scope. Opaque upload/job/report IDs expose no
server filesystem path selection. Paged record projections omit raw configuration;
normalized detail redacts policy documents, conditions, tags and credential fields.
Exception remarks are existing NEEDS_VALIDATION notes, not a new approval status.

## Sprint 3 additive enterprise contracts

Normalizer r0.1.5 preserves earlier normalized records; it adds sixteen reference-only
profiles listed in docs/ENTERPRISE_USAGE.md. Source operation literals, required-field
verification and request/pagination diagnostics cover those profiles. New singleton
policies use request Bucket/KeyId, retaining decoded documents only inside local storage.
KMS aliases/UUIDs are not resolved to invented ARNs. Policy content is never a log value.
AdditionalRoutesAvailable and nonempty NextToken prevent complete-inventory inference.

`enterprise-1` snapshots record original member runs, approved registry context and target
scope. Edges record stable IDs, source/destination partition/account/identity, type,
service/domain/Region, evidence locators and observation IDs, collection and assessment
times, typed status, separate authorization conclusion, missing/blocking dependencies,
preconditions, confidence/limitations, linked findings/methodology IDs and target privilege.
Supported edges require evidence, no unresolved material prerequisites and matching AWS
partitions. Direct references are not effective access. Unknown ownership remains null.
Registry entries optionally include approved aliases/groups; no account is inferred from
the private methodology placeholders. Shared investigation decisions reuse the existing
append-only evidence-fingerprint contract, not an automatic vulnerability approval.

Canonical r0.1 tables remain readable. Four additive enterprise tables preserve originals;
snapshot unions deduplicate normalized IDs while retaining all distinct raw locators and
conflicting observations. Inputs with different normalization versions cannot be merged.

## 0.4.1 recovery (normalizer r0.1.6; canonical schema remains r0.1)

Source adds optional explicit AWS partition; absent partition serializes in the legacy shape,
preserving existing fixture bytes/source identifiers. Collector manifests pass the declared
partition through normalization. Existing records stay readable; mixed-normalizer enterprise
snapshots remain rejected. New registered metadata/reference profiles: STS GetCallerIdentity,
EC2 DescribeSubnets, DescribeNetworkAcls and DescribeInternetGateways. STS validates metadata
without an invented resource; network additions make no reachability decisions.

Exact Prowler 5.26.1 AWS OCSF profile is source-reviewed and synthetic-tested, not actual-export
validated. Ambiguous aggregate IAM default versions never resolve permission documents.
Collector manifest operation metadata contributes to immutable run identity; the sidecar
publishes atomically and is backed up. Pagination, UTC windows, Region/partition consistency,
unsupported artifacts and checksums are validated before import. Unsupported native operations
are retained and visible; unsupported formats fail closed.

EvidenceRequest has a public versioned Pydantic contract and JSON schema; every requested
operation is registered. Manual dependencies are separate. JSON and formula-neutralized CSV
are exported offline. No collection command is executed. See
collectors/collector-analyzer-contract.json, the generated analyzer/collector contract, for limits and inline-index conventions.
# 0.4.2 additive analyst reporting contracts

`report-finding-1` stores append-only report revisions separately from candidates and
technical decisions: approved/editable sections, inclusion, member finding fingerprints,
account/resource IDs, collection IDs/timestamps, evidence locators/SHA-256, reviewer
identity/time and independent recommendation/narrative/consolidation/risk approvals.
Plaintext is frozen in the revision. Any edit clears approvals; current-evidence and
technical-decision gates control copy/export. Historical evidence snapshot run stays
unchanged when approving equivalent conclusions in a later run. Approval records include
the assessment run being reviewed. Existing schema number remains 1 with additive tables.

`security-investigation-1` identifies additional rule-origin observations, linking stable
investigation/finding/evaluation IDs, domain, affected resources, evidence, hypothesis,
implications and missing validation. Original methodology ID remains null. Existing
decision records supply current analyst status. Export public schemas via
`python -m offline_analyzer.contracts.schema <new-directory>`.

## 0.5.0 additive provider contracts

closec-gcp-1 is a separate native collection manifest translated to the shared r0.1 source
contract; AWS collector compatibility and canonical IDs are preserved. GCP project ID,
project number and optional organization/folder are explicit. GCP canonical IDs include
provider, project, location, resource type and native name. The SQL account columns remain
null for GCP; providers never share resource identities by name alone. Source descriptors
retain original collection statuses, errors, scope and provenance.

All nine GCP statuses are accepted. Only successful complete declarations permit complete
collection semantics. EMPTY returns NOT_APPLICABLE scope results, never project PASS.
Failed, denied, unsupported, unknown and uncollected sources cannot generate PASS.
Partial collections can support only the observed resource's criterion. Manual JSON is
manual-unverified and always partial; unknown collection time remains unrecorded.

Raw bytes and checksums remain unchanged; normalization is separate. Credential strings,
private keys and token-bearing fields are rejected before persistence. Source and raw
project contradictions, count mismatches, unsafe paths and unlisted files are refused.
Native SCC identifiers/severity/state/times remain observations. Exact reviewed key-age
conditions may deduplicate candidates while preserving SCC evidence; stale/contradictory
conditions remain distinct.

cloud-transition-1 enforces evidence and resolved prerequisites for SUPPORTED transitions,
and observed blockers for BLOCKED. Candidate investigations never verify exploitation.
GCP findings use the existing candidate/decision/report-revision schemas and independent
approvals. Bundled JSON schemas are generated from 25 public contracts.

## Legacy GCP pilot transport (0.5.1)

contracts/gcp_legacy.py / PilotManifest.json explicitly define collection_manifest.json
schema_version pilot-1.2.2. The adapter accepts safe Windows ZIP separators, retains
SUCCESS/EMPTY/FAILED status and locally hashes unchanged evidence. Missing source checksum
declarations and unverified pagination remain visible; acknowledgment is required in
GUI/API import and replacement. Unsupported dataset operations remain inventory/coverage
limitations rather than fabricated evaluations. Existing AWS and closec-gcp-1 checksum
requirements are unchanged. ScopeRequest/ScopeDelete/ScopeReplace are versioned
scope-action-1 contracts with canonical identity and strict second confirmation.
The bundled public schema set now contains 31 files. LocalJob (local-job-1) defines
private durable job states/context; SanitizedDiagnostic (closec-local-diagnostic-1)
exports only allowlisted version, stage, timing, status-count and fixed-error fields.
Customer identities, resource values, source paths and arbitrary logs are excluded
from diagnostics. Supported evidence schemas and integrity requirements are unchanged.

## GCP pilot-1.5 compatibility

Pilot15Manifest adds an explicit, strict `pilot-1.5` branch for the original
`collection_manifest.json` transport. It retains the existing pilot adapter and rejects
other versions and extra fields. Its collection limits/API count/asset-type summary,
dataset `required_api`/optional `pages`, and optional error exit code are versioned fields.
API_DISABLED, AUTH_ERROR and ACCESS_DENIED retain their original statuses and ERROR
coverage; they never normalize failed output into usable configuration. The exact optional
`discovered_asset_types.json` metadata artifact must agree with the declared summary.
No operation parser or security rule is added. Existing native operations use the existing
normalizers; other operations remain unsupported. Source hashes and partial/unauthenticated
legacy integrity qualifiers are preserved. The public schema set now contains 32 files.
LocalJob and SanitizedDiagnostic include positively constrained manifest-detection metadata
before parsing, so unsupported versions retain actionable filename/version/adapter/reason
details without customer identities, paths or values.

## GCP attack-path evaluation v2 (2026-10-25)

`contracts/gcp_attack_path.py` adds `gcp-attack-path-2` and
`gcp-attack-path-register-2`, exported as GCPPathEvaluation/GCPAttackPathRegister JSON
schemas. The public set contains 42 schemas. These are separate artifacts, not a
database migration or a coercion of historical statuses. Mandatory prerequisites use
AVAILABLE / CONTRADICTED / CONDITIONAL / UNCOLLECTED / UNSUPPORTED; decisive positive
and blocking states require observation IDs. The path classification is validated
against these prerequisites. Execution remains UNVERIFIED, finding validation is
NOT_INHERITED, and path review starts UNREVIEWED. Source and canonical evidence schemas,
methodology mappings and original finding IDs are unchanged.

## Supplementary GCP evidence and composition candidate

`clogcp_delta.models` defines strict Pydantic v2 plan/result/manifest contracts
(`gcp-delta-plan-1`, `gcp-delta-1`). Explicit scope, approval/matrix hash, collection times,
coverage, pagination, redactions, raw/semantic digests and repeated-resource references are
retained. The native adapter verifies bytes, record counts, resource scope, semantic
hashes and normalization before accepting either GUI preview or import. Failed sources
remain gaps; skipped old operations do not become fabricated new evidence.

`EvidenceComposition.json` adds a versioned provenance contract without altering source
records or source IDs. References pin both original runs, collection dates, precedence,
conflicts, reconciliation and the materialized source/observation/ref digest. Broader
security analysis uses a distinct run; repeated composition reuses its stable ID. Source
raw artifacts are referenced, not overwritten. Independent attack-path evaluations and
old/new comparisons live in new immutable artifact directories, outside original tables.
