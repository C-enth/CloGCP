# Rule specifications (engine 1.5.1, normalizer r0.1.6)

AR-01 GCP execution version 1.0.1 retains the existing criteria and methodology gaps.
Truncated sources and unverified numeric project scope cannot yield PASS. Asset summaries
and detailed configurations may share canonical entity identity, but are evaluated in
separate typed groups so summaries cannot supply detailed rule prerequisites. No new rule
or source-control mapping is introduced; candidates still require independent analyst review.

Source clauses were re-verified against the approved workbook (SHA-256 `a9d7ef1b…`) on
2026-10-10. Criterion keys are defined in METHODOLOGY_COVERAGE.md; the text there is an
engineering paraphrase, and the workbook text is authoritative. All mappings are PROPOSED.

**Outcome and classification are separate.** The outcome answers the source clause
literally (PASS/FAIL/N/A/UNKNOWN/COLLECTION_ERROR/MANUAL). For FAIL results, a finding
class and technical severity are derived from the evidence available:
- `SUPPORTED_SECURITY_GAP`: evidence supports a configured exposure path, but it is not demonstrated end to end.
- `POTENTIAL_EXPOSURE`: exposure is plausible, but required evidence is missing.
- `BASELINE_DEVIATION`: the source baseline is violated, but evidence does not support exposure.

UNKNOWN, MANUAL and COLLECTION_ERROR results are *incomplete investigations*. No
candidate is confirmed without an analyst decision. Evidence confidence (HIGH/MEDIUM)
reflects observation quality, not severity. Severity never comes from scanner or
methodology inherent severity. No rule claims exploitation, access or reachability.

## R0-EC2-IMDSV2 1.3.0 (AWS-19 P1/F1)
- **Predicate:** with `MetadataOptions.State == applied` and `HttpEndpoint == enabled`, `HttpTokens == required` gives PASS and `optional` gives FAIL. Terminated instances or a disabled endpoint give N/A. Pending/absent options or an unknown state give UNKNOWN.
- **Fields and scope:** ec2:DescribeInstances `State.Name` and `MetadataOptions` per Region; a complete, unfiltered collection is needed for scope coverage.
- **Conclusion:** the instance accepts token-less metadata requests (baseline). FAIL is a `BASELINE_DEVIATION` at MEDIUM. Non-running instances are annotated "setting applies when it runs".
- **Not evaluated:** SSRF exposure and general least privilege (P3). P4/F3 are evaluated by the instance-role rule below. Internet-exposed instances are correlated through AP-04 records only.

## R1-EC2-IMDS-HOP-LIMIT 1.1.0 (AWS-19 P2/F2)
- **Predicate:** same applicability guards as above; an integer `HttpPutResponseHopLimit` of 1 gives PASS and greater than 1 gives FAIL. A missing value, a non-integer or a boolean gives UNKNOWN.
- **Conclusion:** `BASELINE_DEVIATION` at LOW. This is never a credential-exposure finding.
- **Compensating context:** container-orchestrator tag keys (`eks:cluster-name`, `aws:eks:cluster-name`, `kubernetes.io/cluster/*`, `AmazonECSManaged`) are reported as a possible documented requirement for hop limit 2, with "approved exception" as required evidence. The source requirement (1) is preserved as the baseline.

## R0-RDS-ENCRYPTION 1.3.0 (AWS-22 P2/F2)
- **Predicate:** boolean `StorageEncrypted`. Aurora gives UNKNOWN (cluster evidence is needed); docdb/neptune give N/A; unreviewed engines give MANUAL.
- **Conclusion:** `BASELINE_DEVIATION` at MEDIUM. Native configuration decides; a contradicting Prowler `rds_instance_storage_encrypted` result lowers confidence to MEDIUM and adds a review-queue entry.

## R1-RDS-PUBLIC-ACCESS 1.2.0 (AWS-22 P1/F1)
- **Predicate:** boolean `PubliclyAccessible` (FAIL if true) for reviewed RDS/Aurora engines.
- **Context (FAIL only):** the attached `VpcSecurityGroups` (ec2:DescribeSecurityGroups) are checked for the endpoint `Port` from 0.0.0.0/0 or ::/0, and the DB subnet routes (ec2:DescribeRouteTables) are checked for a default route to an internet gateway.
- **Classification:**
  - internet-sourced rule and a subnet with an internet-gateway default route: `POTENTIAL_EXPOSURE`, HIGH
  - internet-sourced rule but route evidence missing: `POTENTIAL_EXPOSURE`, MEDIUM
  - security-group evidence missing: `POTENTIAL_EXPOSURE`, MEDIUM
  - restricted security groups, or no internet route: `BASELINE_DEVIATION`, LOW (compensating control recorded)
- **Missing evidence listed:** NACLs, database authentication, and the approved list for specific public CIDRs.

## R0-CLOUDTRAIL-VALIDATION 1.3.0 (AWS-07 P1.validation/F2)
- **Predicate:** boolean `LogFileValidationEnabled`; home Region must match the ARN. Shadow-only scopes give UNKNOWN.
- **Conclusion:** `BASELINE_DEVIATION` at LOW. This does not prove logging, delivery or digest integrity.

## R1-EC2-SG-SENSITIVE-INGRESS 1.2.0 (AWS-15 P1/F1)
- **Predicate:** an ingress rule from 0.0.0.0/0 covering TCP 22, 3389, 1433, 3306, 5432, 6379, 9200 or 27017 (or all traffic) on a group referenced by an in-use, customer-managed interface with a public IPv4 address gives FAIL (the literal F1 condition).
  - No listed port open to the internet gives PASS.
  - A latent rule (no public interface) gives PASS only with complete interface evidence; with incomplete interface evidence it gives UNKNOWN.
  - Specific public CIDRs/prefix lists, unlisted internet-open ports, UDP, managed (load balancer) interfaces and IPv6 `::/0` give MANUAL. IPv6 is reported with its own `::/0` route status because F1 names 0.0.0.0/0 only.
- **Fields and scope:** `IpPermissions`, interface `Groups`, `Status`, `RequesterManaged`, `InterfaceType`, public IPs, `SubnetId`/`VpcId`, and route-table associations and routes.
- **Classification (FAIL):**
  - an exposed interface subnet with an active `0.0.0.0/0` route to an internet gateway: `POTENTIAL_EXPOSURE`, HIGH
  - route evidence missing (no explicit association found and the route listing is incomplete): `POTENTIAL_EXPOSURE`, MEDIUM
  - default route via NAT/TGW/other, or none: `BASELINE_DEVIATION`, LOW
  - The main-table fallback is used only with a complete route-table listing.
- **Missing evidence:** NACL entries, host firewall and listening service. Ingress routing and gateway edge associations are not modeled.

## R1-IAM-ROLE-TRUST-CONDITIONS 1.2.0 (AWS-04 P1/F1)
- **Predicate:** for Allow statements granting `sts:AssumeRole`:
  - a wildcard or account-root principal in another account with no `Condition` gives FAIL (the literal F1 condition).
  - every cross-account grant carrying a concrete `aws:PrincipalOrgID` or `sts:ExternalId` (StringEquals/IgnoreCase, or StringLike without wildcards) gives PASS. Either key satisfies the source PASS clause; ExternalId is not required where an org binding exists.
  - specific principals without binding, non-binding conditions (MFA, IfExists, set operators, Null, OrgPaths), Deny/NotPrincipal/NotAction and unresolved principals give MANUAL.
  - service and federated trust, or same-account trust, give N/A.
- **Fields and scope:** the trust document (object or URL-encoded), the role ARN, and from GetAccountAuthorizationDetails: attached policy ARNs, inline documents, customer-managed `Policies` and the permissions boundary. ListRoles carries trust only. Scope is per account (global).
- **Classification (FAIL):** wildcard trust with evidenced target-side authorization (including applicable RCPs) is a `SUPPORTED_SECURITY_GAP`, HIGH. CRITICAL additionally requires resolved `ADMIN_EQUIVALENT` or `ESCALATION_CAPABLE` privilege from policy documents and evaluated authorization layers. External callers' control of their own identity policies is an explicit capability assumption, not an observed caller transition. A blocked RCP gives `BASELINE_DEVIATION`, LOW (MEDIUM if elevated); missing RCPs give `POTENTIAL_EXPOSURE`, MEDIUM (HIGH if elevated).
- Registered internal-account trust remains `BASELINE_DEVIATION`, LOW (MEDIUM if elevated); unregistered-account trust is `POTENTIAL_EXPOSURE`, MEDIUM (HIGH if elevated). Specific cross-account transitions are independently investigated from source identity permission, target trust and target RCPs.
- An AdministratorAccess attachment without its document is an unresolved privilege indication. It never establishes effective admin permission or CRITICAL severity. Boundaries and SCPs participate in privilege evaluation; missing dependencies appear on investigation records. Access Analyzer external findings remain missing evidence.
- See [IAM evaluation](IAM_EVALUATION.md) for supported semantics and exclusions.

## R1-S3-ACCOUNT-BPA 1.1.0 (AWS-11 P1/F1)
- **Predicate:** all four account flags true gives PASS. Any flag false, or the AWS-defined `NoSuchPublicAccessBlockConfiguration` response (clean 404 only), gives FAIL. Non-boolean flags give UNKNOWN.
- **Conclusion:** `BASELINE_DEVIATION` at MEDIUM. This never means a bucket is public. Missing evidence: bucket-level evidence and organization-level S3 policies.

## R1-S3-BUCKET-PUBLIC-ACCESS 1.1.0 (AWS-11 P2/F2)
- **Evidence:** per bucket, s3api GetBucketPolicyStatus (primary), GetPublicAccessBlock and GetBucketAcl, plus account-level BPA. Bucket identity comes only from the recorded `Bucket` request parameter.
- **Predicate:** effective `RestrictPublicBuckets` and `IgnorePublicAcls` are true if set at either level.
  - FAIL when `IsPublic=true` and neither level restricts it (both known false), or when the ACL grants AllUsers/AuthenticatedUsers and neither level ignores public ACLs.
  - PASS only when restrictions or evidence leave no anonymous path.
  - UNKNOWN when a required restriction, policy status or ACL is missing.
  - MANUAL when bucket policy and ACL are private but public ACLs are not ignored (object ACLs are not assessable).
- **Conclusion:** `POTENTIAL_EXPOSURE` at HIGH. Public policy status/ACL and BPA configuration do not establish data sensitivity, policy action semantics or actual access.
- **Scope:** per-bucket requests never establish complete bucket inventory on their own; since 1.2.0 the scope is decided by the bucket listing (see "Dependent collection scope" below).

## Dependent collection scope (AWS readiness phase 0, `rules/engine.py:dependent_scope`)
Rule versions 1.2.0: R1-S3-BUCKET-PUBLIC-ACCESS, SEC-KMS-WILDCARD-PRINCIPAL, SEC-KMS-ROTATION,
SEC-CLOUDTRAIL-LOGGING, SEC-CLOUDTRAIL-MANAGEMENT-EVENTS. Resource predicates are unchanged.
Their primary datasets are collected per resource of a parent listing
(`registry.DEPENDENT_PARENTS`: kms:ListKeys, cloudtrail:DescribeTrails, s3api:ListBuckets);
collector 0.3.x calls the dependent API only after a COMPLETE parent. The latest parent journal
rows per account and Region (from the stored collection summary, or the members' summaries for
an enterprise snapshot) decide the collection-scope row:
- parent complete and empty: NOT_APPLICABLE (no account-wide PASS is asserted);
- parent failed: COLLECTION_ERROR (no dependent call was made);
- parent listed n resources and every one has error-free dependent evidence (COMPLETE, or
  PARTIAL only because the request names one resource): no scope row;
- parent listed resources but dependent evidence is missing for some: UNKNOWN, as before.
Truncated, disagreeing or pre-0.3 journal rows leave the previous behaviour unchanged.

## R1-IAM-INSTANCE-ROLE-PRIVILEGE 1.0.0 (AWS-19 P4/F3)
- **Predicate:** for an evidenced instance-profile role, a resolved identity-policy Allow with Action `*`/`*:*`, or unguarded `iam:PassRole`, gives FAIL. Unguarded means any role resource without an `iam:PassedToService` condition; this interpretation awaits owner review under MR-H14. General least privilege (P3) is excluded.
- **Applicability:** no instance-profile membership gives N/A; missing membership or unresolved policies preventing exclusion of these patterns gives UNKNOWN. PASS excludes these patterns only and never yields a control-level Pass.
- **Classification:** supported PassRole escalation prerequisites give `SUPPORTED_SECURITY_GAP`, HIGH. Action wildcard gives `POTENTIAL_EXPOSURE`, HIGH; unresolved/potential escalation gives `POTENTIAL_EXPOSURE`, MEDIUM. Every evaluated combination blocked or not an escalation gives `BASELINE_DEVIATION`, LOW.
- **Prerequisites:** source permission, destination service trust, service-operation permission, profile context and relative privilege. Attacker control, SSRF/RCE and credential retrieval/execution are not verified; no escalation is confirmed.

## Correlations
AP-04 combines a security-group FAIL on an instance interface with IMDSv1 on the same
instance; AP-05 uses account BPA as a verified blocker. AP-04 additionally records instance-role privilege; AP-06 records IAM transition and PassRole investigation prerequisites. Records are never SUPPORTED.
## Additional security observations in 0.4.2

Since 0.7.0 (rule version 1.1.0) every additional observation is classified under one
checklist control with a check-area key (`<control>:CA.<topic>`); see
METHODOLOGY_COVERAGE.md section 0.7.0. No MITRE mapping is fabricated. Rule-origin investigation/evaluation/evidence
and analyst decisions are traceable; candidate detection never constitutes report approval.

| Rule/version | Evidence | FAIL predicate | Scope/confidence and risk limits |
|---|---|---|---|
| SEC-IAM-ROLE-WILDCARD 1.0.0 | IAM authorization details/GetRole/ListRoles plus resolved managed/inline policy documents | Supported Allow statement has Action `*` or `*:*` in a non-instance-profile role | Configuration pattern only; missing policy documents/unsupported statements prevent clean conclusions. Boundaries, conditions, explicit denies, SCP/RCP and workload intent remain authorization dependencies. POTENTIAL_EXPOSURE, MEDIUM; no effective privilege/escalation conclusion. |
| SEC-KMS-WILDCARD-PRINCIPAL 1.0.0 | GetKeyPolicy with explicit KeyId ARN and valid identity | Supported unconditional AWS Principal `*` Allow, KMS action, Resource `*` | Resource wildcard means this key. Conditions/malformed/unsupported statements are handled conservatively. Caller permissions, grants, restrictions, key state and data classification remain missing validation. POTENTIAL_EXPOSURE, HIGH; no decryption/exploitation or sensitive-data disclosure claim. |

PASS answers only absence of the named policy pattern in supported complete evidence;
it is never a control-level Pass or a claim of least privilege/secure key authorization.
New templates provide tested-rollout/workload/key-recovery considerations; current analyst
confirmation plus independent recommendation/narrative/scope approvals gate client export.
See docs/REPORT_FINDINGS_USAGE.md. AWS references are embedded in approved offline template
metadata. Existing instance-role predicate/mapping is unchanged; version 1.0.2 corrects the
overly strong wildcard compromise implication and retains applicable restriction dependencies.

## GCP 0.5.0rc1 rule specifications

Executable registry: rules/registry.py PROVIDER_RULES (legacy ALL_RULES remains the AWS
registry for compatibility). GCP rules declare provider GCP, version 1.0.0, resource type,
operation/context dependencies, domain, criterion, severity, risk, follow-up and offline
remediation. Since 1.1.0 each links to one checklist control by check area (no source clause
claimed, no control-level Pass).

| Rule | Supported criterion / limitation |
|---|---|
| GCP-API-APP / API / BOTH | 1.3.0: application/API restrictions metadata; combined missing condition is one candidate. No key leakage claim. An omitted `restrictions` field from a COMPLETE dataset means unrestricted (documented, see "Omitted fields" below): BOTH FAILs, APP/API defer to it (NOT_APPLICABLE). From incomplete evidence, or unsupported metadata, UNKNOWN. |
| GCP-KEY-PERSISTENT / AGE | User-managed key presence and validAfterTime age against manifest policy (default 90 days); disabled/system-managed keys are not applicable. |
| GCP-KEY-PRIVILEGED | 1.3.0: correlated key, service account and unconditional Owner/Editor binding (FAIL). PASS when the account is resolved and the project IAM policy and every collected organization/folder IAM policy are COMPLETE with no Owner/Editor binding of it; no parent policy collected or any denied/partial policy is UNKNOWN naming the missing policy. Conditional bindings UNKNOWN. Effective permissions remain unresolved. |
| GCP-IAM-BASIC | 1.4.0: observed Owner/Editor binding; conditions remain UNKNOWN. PLATFORM_AGENT members (account classes below) are never counted; a binding held only by them is NOT_APPLICABLE "Google-managed service agent (platform-managed)". DEFAULT_SA and USER_MANAGED members are evaluated (same-project default compute with Editor still fails). |
| GCP-IAM-PUBLIC | Known sensitive role and public principal; unknown role semantics stay UNKNOWN. Bucket policies use the storage-context rule. |
| GCP-IAM-IMPERSONATION | 1.4.0: broad Token Creator/Workload Identity User scope or broad principal set; no asserted effective impersonation. PLATFORM_AGENT members are never counted; a project-level grant held only by them is NOT_APPLICABLE with the same reason. |
| GCP-IAM-CROSSPROJECT | 1.4.0: Owner/Editor binding held by a DEFAULT_SA or USER_MANAGED account whose owner project (compared by ID and number with the binding project's collected metadata) is IN_ORG_NOT_ASSESSED or EXTERNAL_OR_UNKNOWN: FAIL, text names member, account class and owner project. PLATFORM_AGENT never; a binding whose service accounts are all agents is NOT_APPLICABLE. Same owner: no finding. IN_SCOPE_OTHER_PROJECT alone: NOT_APPLICABLE informational link. Owner not comparable: UNKNOWN, never PASS. External ownership is not proof of unauthorized access. |
| GCP-GOV-KEYS | 1.4.0: effective `iam.disableServiceAccountKeyCreation` / `iam.disableServiceAccountKeyUpload` from `gcloud org-policies describe --effective`. Names: bare, `constraints/x` or `.../policies/x`. Shapes: v1 `booleanPolicy.enforced` and v2 `spec.rules[].enforce` (with `inheritFromParent`; `dryRunSpec` never counts as enforcement). PASS only when every unconditional rule enforces; FAIL when every rule is explicitly unenforced, unless the managed successor (`iam.managed.disableServiceAccountKeyCreation` / `...Upload`) is effective and unconditionally enforced (then PASS citing it); a FAIL without an observed managed record notes "Managed constraint not observed". UNKNOWN for conditional, list-shaped, contradictory, reset, unset (no spec/rules), dry-run-only or unparseable policies, a non-effective call, a missing/denied dataset, or a key constraint without its own effective record. Constraint name, affected resource, observed value (for example `rules: enforce: false`), evidence and the verification command `gcloud org-policies describe <constraint> --effective --project=<project>` all come from the same record. Not confirmed against live 2.2.7 output: inherited policies whose effective spec omits rules, and Google's secure-by-default enforcement on unset constraints. |
| GCP-LOG-AUDIT | 1.3.0: criterion "Data Access audit-log exemption configured". Project policy: FAIL for exemptions on the project or inherited from a collected organization/folder policy (named); PASS when the project and its complete parent policies carry none (Data Access enablement per service is a separate question); UNKNOWN when parent policies are not completely collected. Organization/folder policy: FAIL with exemptions, otherwise NOT_APPLICABLE. Resource-level IAM policies (bucket, service account, Cloud Run): NOT_APPLICABLE. |
| GCP-LOG-EXCLUSION | 1.3.0: enabled exclusion whose filter is a plain conjunction with a positive Cloud Audit Logs selector (`log_id("cloudaudit.googleapis.com/...")` or `logName=".../logs/cloudaudit.googleapis.com%2F..."`): FAIL. A conjunction with a positive selector of non-audit logs only: PASS (cannot drop audit entries). OR, NOT, negation, grouping or no log selector: UNKNOWN. Scope evidence is the exclusions list plus exclusions embedded in sinks; complete evidence with no exclusion is NOT_APPLICABLE. |
| GCP-SCC-OBSERVATION | Active detector observation; independent MEDIUM candidate guidance, native/time validation required. Source severity is preserved separately. |
| GCP-STORAGE-PUBLIC | Public object-role binding plus bucket and effective inherited public-access-prevention evidence; blocking prevention yields per-binding PASS. IAM deny/ACL/intended-sharing validation remains explicit. |

IAM/storage candidates are POTENTIAL_EXPOSURE; other configuration observations are
BASELINE_DEVIATION. None claims confirmed exploitation. HIGH guidance applies to broad
privilege/public exposure/combined unrestricted keys; other native criteria default MEDIUM.
Confidence describes observed configuration, separately from technical severity, business
impact and approval. GCP remediation templates are gcp-remediation-1.0.0 with authoritative
Google references and workload dependencies. See GCP_USAGE.md for precise exclusions.

## GCP organization-wide rules 1.0.0 (0.7.0)

Evaluated over Cloud Asset IAM search results for the organization/folder (the allow
policy set directly on each resource). Inherited and deny policies, principal access
boundaries and conditions are not resolved: findings are POTENTIAL_EXPOSURE with
effective access unresolved; conditional bindings are skipped. Google-managed service
agents (gcp-sa-*, cloudservices, service-<number>@, system/robot accounts) are excluded.
Projects whose project IAM policy was collected directly are left to the project rules.
A rule with no match (1.1.0; SA-PRIVILEGED and CROSSPROJECT-SA 1.3.0) is PASS only when a
complete organization-scope search was evaluated (records carrying only the ADR-010
parent-scope qualifier count as complete), every search record came from complete evidence
and no member stayed unresolved; the PASS cites the search records. Project or folder searches
alone, partial or truncated searches, or no search at all give explicit UNKNOWN rows.

| Rule | Control | FAIL predicate | Severity |
|---|---|---|---|
| GCP-ORG-PUBLIC-SERVERLESS | 1.9.3 | allUsers/allAuthenticatedUsers on Cloud Run/Functions | MEDIUM |
| GCP-ORG-PUBLIC-DATA | 1.4.2 | public principal on bucket/dataset/table/secret/topic/registry | HIGH |
| GCP-ORG-PUBLIC-OTHER | 1.6.3 | public principal on any other resource | HIGH |
| GCP-ORG-BASIC-ROLE | 1.6.4 | Owner/Editor to user/group/domain on project/folder/org | HIGH |
| GCP-ORG-SA-PRIVILEGED | 2.8.2 | 1.2.0: Owner/Editor to a DEFAULT_SA or USER_MANAGED service account; PLATFORM_AGENT never (recorded as NOT_APPLICABLE "Google-managed service agent (platform-managed)") | HIGH |
| GCP-ORG-IMPERSONATION | 1.6.7 | Token Creator/SA User/SA Key Admin at project/folder/org level | HIGH; MEDIUM when only Firebase-provisioned defaults |
| GCP-ORG-CROSSPROJECT-SA | 1.6.5 | 1.2.0: DEFAULT_SA or USER_MANAGED account whose owner project is IN_ORG_NOT_ASSESSED or EXTERNAL_OR_UNKNOWN with a privileged role; PLATFORM_AGENT never; in-scope links and unresolved owners are stored as NOT_APPLICABLE / UNKNOWN results with the evidence | MEDIUM |
| GCP-ORG-DELETED-PRINCIPAL | 7.2.1 | deleted: principal still bound | LOW (baseline) |
| GCP-ORG-EXTERNAL-DOMAIN | 7.4.1 | MANUAL per email domain (org-owned vs third party) | - |
| GCP-ORG-FEDERATION | 2.5.1 | 1.1.0: per workload identity pool trust, decided from collected provider records when complete: the whole pool granted (`principalSet://.../*`) with an enabled provider without `attributeCondition` FAILs; all providers disabled or deleted PASSes; otherwise MANUAL with the conditions listed. No or incomplete provider evidence: MANUAL | MEDIUM |

## GCP coverage completeness and omitted fields (GCP correctness RC)

Collector 2.2 datasets (verified checksums, record counts checked at import) with status
SUCCESS or EMPTY are COMPLETE (`ingestion/gcp_expanded.py`); TRUNCATED, PARTIAL, interrupted
collections, detail-limited or IAM-target-fallback datasets and 2.1 packages stay PARTIAL; every
failure status (FAILED, API_DISABLED, ACCESS_DENIED, QUOTA_PROJECT_DENIED, COMMAND_ERROR,
AUTH_ERROR, TIMEOUT, RATE_LIMITED, NOT_FOUND, HTTP_ERROR, SERVER_ERROR, ...) stays ERROR with
its reason and never supports PASS. A complete dataset with resources needs no collection-scope
row; an EMPTY successful list is NOT_APPLICABLE (no resources). Coverage is recorded at import:
re-import a package to apply this to an existing workspace.

Google APIs omit unset fields. An omitted field is read only where Google documents what its
absence means, and only from a COMPLETE dataset; otherwise the outcome stays UNKNOWN.

| Field | Documented meaning | Rules | Source |
|---|---|---|---|
| API key `restrictions` absent | "API keys without application restrictions can be used from anywhere"; "API keys without API restrictions can be used with all APIs that accept keys generated by Google Cloud"; REST reference for `apiTargets`: "If no restrictions are specified, all targets are allowed." | GCP-API-BOTH FAIL; APP/API NOT_APPLICABLE (combined rule) | Google Cloud "Manage API keys" (docs.cloud.google.com/docs/authentication/api-keys); API Keys REST v2 `projects.locations.keys` |
| Cloud KMS `rotationPeriod` and `nextRotationTime` both absent (ENCRYPT_DECRYPT) | Automatic rotation is disabled by clearing the rotation schedule ("rotationPeriod": null, "nextRotationTime": null; console "Never (manual rotation)"). One field alone is not that state: UNKNOWN. | GCP-KMS-ROTATION 1.2.0 FAIL | Cloud KMS "Rotate a key", "Disable automatic rotation" (docs.cloud.google.com/kms/docs/rotate-key); REST `keyRings.cryptoKeys` |

Not changed (absence semantics not verified against a Google reference in this release):
Compute Engine `accessConfigs`, `serviceAccounts` and `shieldedInstanceConfig`; Cloud Storage
`versioning`; Cloud SQL `authorizedNetworks` and `requireSsl`; subnet `logConfig`. These stay
UNKNOWN when omitted.

## Service-account identity resolution (rules/gcp_identity.py, E1/E2)

Opt-in only (`registry.IDENTITY_ENRICHED`): GCP-IAM-CROSSPROJECT, GCP-IAM-BASIC,
GCP-IAM-IMPERSONATION, GCP-ORG-SA-PRIVILEGED, GCP-ORG-CROSSPROJECT-SA, XP-01 (identity labels
only) and XP-02. Other rules are not enriched. A member's home project is resolved from the
email by project ID (`<id>.iam.gserviceaccount.com`, `<id>@appspot.gserviceaccount.com`) or by
project number (the patterns below), against the analyzed project's collected ID and number,
the other projects collected in the run and the organization search project index.

| Class | Meaning | Effect |
|---|---|---|
| PLATFORM_MANAGED | platform pattern whose number equals the analyzed project's number | never cross-project, never a removal target; evidence recorded |
| SAME_PROJECT | home ID or number equals the analyzed project | never cross-project |
| IN_SCOPE_OTHER_PROJECT | home is another collected project | informational link |
| IN_ORG_NOT_ASSESSED | home in the organization index, not collected | cross-project finding |
| EXTERNAL_OR_UNKNOWN | home resolved but not known | cross-project finding |
| UNKNOWN | home not determinable, or a number form while the analyzed number is missing | UNKNOWN, never PASS, never dropped |

Platform-managed patterns (whole email, NUM = project number): `NUM@cloudservices.gserviceaccount.com`,
`service-NUM@gcp-sa-<service>.iam.gserviceaccount.com`,
`service-NUM@{compute-system,container-engine-robot,serverless-robot-prod,firebase-sa-management}.iam.gserviceaccount.com`,
`NUM@cloudbuild.gserviceaccount.com`. A pattern with another project's number is resolved by
that number. The Compute Engine default service account `NUM-compute@developer.gserviceaccount.com`
is customer-operated, never PLATFORM_MANAGED: SAME_PROJECT when NUM is the analyzed project's
number (GCP-IAM-BASIC and GCP-ORG-SA-PRIVILEGED still flag its Owner/Editor grants), otherwise
resolved by NUM like any other member (cross-project when outside the assessed scope). Reclassification never lowers a severity; finding IDs exclude the rule version,
so analyst reviews keep matching (changed text prompts revalidation as before).

The table above (classify_member) still drives XP-01/XP-02. The five rules and the
per-principal view use the account ownership classes (`account_class`, 2026-10-18):

| Account class | Forms (whole email; NUM = project number) | Owner |
|---|---|---|
| PLATFORM_AGENT | `NUM@cloudservices.gserviceaccount.com`; `service-NUM@<domain>.gserviceaccount.com` (gcp-sa-*, compute-system, container-engine-robot, gs-project-accounts, ...); any other `*.gserviceaccount.com` domain that is neither `*.iam.gserviceaccount.com` nor a DEFAULT_SA form | NUM when present |
| DEFAULT_SA | `NUM-compute@developer.gserviceaccount.com`, `<project-id>@appspot.gserviceaccount.com`, `NUM@cloudbuild.gserviceaccount.com` | NUM or project ID |
| USER_MANAGED | `<name>@<project-id>.iam.gserviceaccount.com` | project ID |

The owner is compared with the binding project's collected ID and number; an owner that
cannot be compared is UNKNOWN, never assumed. A `service-NUM@<id>.iam.gserviceaccount.com`
address whose `<id>` is a collected or organization project is a customer-created account
(USER_MANAGED), not an agent. For the five rules, "Actual configuration" lists each member
with account class, owner project, role and condition ("none" when unconditional).

## Per-principal role lookup (iam/gcp_principals.py)

Analyzer-only, view-only resolver (no rule uses it during this engagement; owner decision
2026-10-18), shown in IAM intelligence ("Principal roles") and
as "View roles" links from a finding's members and attached service accounts. It lists every
allow binding observed for a service account, user or group: role, scope (project, service
account, bucket, folder, organization, other), condition, source dataset(s), account class,
owner project and trust class (account classes above, relative to the binding's project; folder/organization bindings
relative to the collecting project). Groups are listed as groups; membership is not collected,
no member is inferred and group roles are never attributed to a user. Projects in view: the
selected enterprise snapshot, otherwise the latest active import per GCP project plus the
selected run.

Resolution: RESOLVED only when the project IAM policy was collected and every parent
(folder/organization) IAM policy was collected. A project with no parent recorded is
UNRESOLVED with the separate reason "no parent recorded — verify standalone project" (a
missing `parent` field is not proof of a standalone project). Denied or missing parent IAM, a parent chain that does not
reach the organization, or a project under a folder not collected gives "project-level roles
only; inherited roles not collected" and UNRESOLVED. Privilege for severity decisions:
PRIVILEGED (a privileged role observed), NARROW (RESOLVED and only non-privileged predefined
roles), NONE_OBSERVED (RESOLVED, no binding), otherwise UNRESOLVED, never NARROW. Custom roles:
permissions shown only when custom_role_detail was collected, never classified; without detail
the role and the principal are UNRESOLVED.

Privileged-role list (single documented list, `iam/gcp_principals.py:privileged`): roles/owner,
roles/editor, every predefined role whose name ends in `admin`/`Admin` (optionally `.vN`, e.g.
roles/compute.instanceAdmin.v1, roles/storage.admin), roles/iam.serviceAccountTokenCreator,
roles/iam.serviceAccountUser, roles/iam.serviceAccountKeyAdmin and the IAM escalation roles
roles/iam.serviceAccountOpenIdTokenCreator, roles/iam.workloadIdentityUser, roles/iam.roleAdmin,
roles/iam.organizationRoleAdmin, roles/iam.securityAdmin, roles/iam.serviceAccountAdmin,
roles/resourcemanager.projectIamAdmin, roles/resourcemanager.folderIamAdmin,
roles/resourcemanager.organizationAdmin.

## Attached service-account context (E5, rules/gcp_principal_context.py)

Opt-in only (`registry.PRINCIPAL_CONTEXT_RULES`): GCP-VM-DEFAULT-SA, GCP-VM-FULL-API-SCOPE,
GCP-NET-FW-ADMIN-INTERNET, GCP-NET-FW-DB-INTERNET, GCP-NET-FW-ANY-INTERNET, all 1.2.0. The base
rule decides the outcome as before; a FAIL gains the attached account (the default compute
account for the two VM rules; every account of the matched exposed instances for the firewall
rules), its resolved roles, scopes and a reference to its GCP-IAM-BASIC finding when one exists.
Roles come from the per-principal resolver built over the assessed run only (a result never
depends on other imports).

| Privilege | GCP-VM-DEFAULT-SA (MEDIUM) | GCP-VM-FULL-API-SCOPE (LOW) | GCP-NET-FW-*-INTERNET |
|---|---|---|---|
| PRIVILEGED | HIGH | MEDIUM; HIGH when the instance also has an external IP | severity kept (HIGH when exposed); context added |
| NARROW | kept; "attached service account holds only narrow roles (list)" | same | same |
| NONE_OBSERVED | kept; "no role binding observed (resolved)" | same | same |
| UNRESOLVED | kept; "privileges unresolved: <reason>" and a missing-evidence entry | same | same |

Severity is never lowered and missing evidence never yields PASS. Finding IDs are unchanged;
the changed text means existing decisions on these findings show NEEDS_REVALIDATION after a
re-assessment.

## Cross-project and cross-cloud paths (attack_paths/cross.py)

XP-01 impersonation of privileged service accounts (one path per source grant), XP-02
cross-project trust through a privileged service account, XP-03 public principal on a
serverless/data resource, XC-01 AWS role -> GCP workload identity pool -> service account
(correlated with any AWS account evidence in the workspace), XC-02 AWS role trusting any
Google identity without sub/oaud binding. A path is FEASIBLE only when every
evidence-checkable step is observed; deny policies/PABs must be collected and empty,
otherwise INSUFFICIENT_EVIDENCE. Attacker-side prerequisites are listed, never verified.
GCP project rules 1.1.0 additionally report NOT_APPLICABLE when the collector observed the
required API disabled in the project (SCC excepted: disabled detection is not "no risk").

## Attack-path hop model (attack_paths/model.py, contract path-hop-1)

Every path record (GCP investigation, AWS AP-04/05/06, XP-01/02/03, XC-01/02) carries
additive fields `entry_point`, `objective`, `impact`, `hops`, `assumptions`, `proof_status`,
`missing_evidence_named` and `hop_stride`. The existing `feasibility` verdict, `diagram`
and analyst review are unchanged; the hop keys are excluded from the review fingerprint,
so reviews recorded before the hop model stay valid without re-import.

A hop is one directed edge `source → target` with an edge type, a direction
justification (why access flows that way), a STRIDE mapping and its evidence (rule IDs,
finding IDs, observation IDs, source locators). Hop status:

| Status | Condition |
|---|---|
| PROVEN | the configuration that creates the edge is in collected evidence **and** the hop cites at least one observation ID or source locator (a rule ID alone is not a source record) |
| HYPOTHESIS | plausible, but evidence is missing or UNKNOWN; `missing_evidence` names what is missing |
| BLOCKED | collected evidence shows the edge does not exist (prerequisite verified absent, internal-only ingress) |

Path `proof_status`: BLOCKED if any hop is BLOCKED, PROVEN only if every hop is PROVEN,
otherwise HYPOTHESIS with the union of the hops' missing evidence named. A record with no
evidence-backed edge is HYPOTHESIS with that stated. `proof_status` can be stricter than
`feasibility` (for example a FEASIBLE XP-03 whose ingress hop is BLOCKED); both are shown.
Attacker-side prerequisites (credential possession, workload compromise, exploitation:
AP-04.P3, AP-06.P3, the GCP "Hypothetical attacker" transition) are `assumptions`, never
edges and never verified. Data classification (AP-05.P4) stays a HYPOTHESIS hop.

Proposed STRIDE mapping per edge type (engineering proposal, not verified exploitation):

| Edge type | Meaning | STRIDE |
|---|---|---|
| network-reachable | traffic can reach the endpoint | Tampering, Information Disclosure, Denial of Service |
| can-invoke-anonymously | unauthenticated callers are authorized to invoke | Spoofing, Elevation of Privilege |
| can-read-anonymously | unauthenticated callers can read | Information Disclosure |
| can-impersonate | holder can act as / mint tokens for a service account | Spoofing, Elevation of Privilege |
| authenticates-as | credential or workload authenticates as an identity | Spoofing |
| holds-role | identity is a member of a role binding | Elevation of Privilege |
| can-access | binding or credential grants a role on a resource | Elevation of Privilege, Information Disclosure |
| can-call-api | API key can call services in a scope | Information Disclosure, Spoofing |
| reads-credentials | workload can read credentials (instance metadata) | Information Disclosure, Spoofing |
| can-assume | principal can assume a role through its trust policy | Spoofing, Elevation of Privilege |
| federates-as | external identity federates into a cloud identity | Spoofing, Elevation of Privilege |
| can-escalate | permissions enable privilege escalation | Elevation of Privilege |
| not-blocked-by | no guardrail (SCP, boundary) is evidenced to stop it | Elevation of Privilege |
| stores | resource holds data of unknown classification | Information Disclosure |

Repudiation is not mapped to any edge: no edge type removes audit evidence. An AWS hop
cites the specification rules of all its prerequisites but only the evidence (observations,
locators, findings) of those that establish it. Hop sources:

| Path | Hops (evidence) |
|---|---|
| GCP investigation | one hop per observed transition: key → service account (authenticates-as), service account → privileged binding (holds-role), API key → usage scope (can-call-api), otherwise grant holder → scope (can-access); PROVEN only for STRUCTURAL_ONLY/OBSERVED transitions with locators |
| AP-04 | Internet → instance (P1, R1-EC2-SG-SENSITIVE-INGRESS), instance → metadata credentials (P2, R0-EC2-IMDSV2), credentials → role permissions (P4, IAM engine) |
| AP-05 | Internet → bucket (P1 R1-S3-ACCOUNT-BPA, P2/P3 R1-S3-BUCKET-PUBLIC-ACCESS), bucket → sensitive data (P4, classification) |
| AP-06 | principal → elevated principal (P1 **or** P2; P1 cites the principal's role observation), elevated principal → administrative access (P4, organization evidence) |
| XP-01 | principal → impersonable service accounts (can-impersonate), service accounts → privileged scopes (holds-role); HYPOTHESIS while deny policies/PABs are not verified empty |
| XP-02 | workloads/keys of the home project → service account (HYPOTHESIS: not correlated), service account → foreign-project binding (holds-role) |
| XP-03 | Internet → serverless endpoint from the collected ingress setting (all: PROVEN; internal-only: BLOCKED; load-balancer only or not collected: HYPOTHESIS), endpoint → granted role (can-invoke-anonymously); data resources: one can-read-anonymously hop |
| XC-01 | trusted AWS principal → AWS role (can-assume), AWS role → GCP service account (federates-as, HYPOTHESIS: provider attribute conditions), service account → privileged scopes (holds-role) |
| XC-02 | Google identity token → AWS role trusting accounts.google.com without sub/oaud (can-assume) |

Not modelled: GitHub or other non-AWS workload identity federation (the pool binding is
reported by GCP-ORG-FEDERATION as MANUAL), and SCC/third-party detections.

## GCP configuration increment (2026-10-16)

`rules/gcp_config.py` 1.1.0 adds 23 evaluators with proposed check-area links. The exact
rule/evidence/field matrix, outcome conditions, technical severity and known limits are
in [GCP_CONFIGURATION_COVERAGE.md](GCP_CONFIGURATION_COVERAGE.md). GCP assessment execution
1.2.0 retains verdict severity, class, exposure and limitations. These are partial criteria;
no control-level PASS, effective reachability, Editor privilege or exploitation is inferred.
The previous broad disabled-API statement above applies only to the historical narrow
API-key/Storage handling, not Compute, SQL, KMS or GKE resource absence.

## Root-cause groups (findings/groups.py, `registry.GROUP_KEYS`)

Group key per rule: default the rule ID; "principal" (rule ID + canonical principals named by
the finding): GCP-IAM-BASIC, GCP-IAM-IMPERSONATION, GCP-IAM-CROSSPROJECT, GCP-KEY-PERSISTENT,
GCP-KEY-AGE, GCP-KEY-PRIVILEGED, GCP-ORG-SA-PRIVILEGED, GCP-ORG-CROSSPROJECT-SA,
R1-IAM-INSTANCE-ROLE-PRIVILEGE, R1-IAM-ROLE-TRUST-CONDITIONS (the role when no principal is
named); "resource" (rule ID + the rule's own resource): GCP-NET-FW-ADMIN/DB/ANY-INTERNET,
R1-EC2-SG-SENSITIVE-INGRESS, SEC-EC2-SG-LATENT-EXPOSURE; "org_node" (rule ID + organization or
folder node): GCP-ORG-BASIC-ROLE, GCP-ORG-IMPERSONATION, GCP-ORG-DELETED-PRINCIPAL,
GCP-ORG-PUBLIC-*. A key without a value falls back to the rule ID. Group ID = hash of the key, so
a group is the same in every run and snapshot. Grouping changes no finding ID, evaluation or
decision. Group severity = highest member severity; report totals count member findings.

## GCP attack-path evaluation 2.0.0 (configuration semantics)

The versioned evaluator in `attack_paths/gcp_engine.py` and the corrected XP-01 source
use `iam/gcp_permissions.py`. actAs, access tokens, ID tokens, signing, attachment and
individual workload mechanisms are independent questions. See
[the GCP engine specification and limits](GCP_ATTACK_ENGINE.md). Existing control
rules, finding classes, source mappings and methodology prerequisite IDs are unchanged.

SUPPORTED describes mandatory modeled configuration evidence, with execution always
UNVERIFIED. Missing evidence alone cannot support or block a chain. Conditional and unsupported
contexts stay explicit. New path severity is HIGH only when an observed technical chain
includes an Owner/Editor binding indicating potential administrative impact; otherwise
it is MEDIUM with downstream privilege/data-sensitivity limitations. This is potential
technical impact, not scanner severity, business risk or analyst approval. New path
review starts UNREVIEWED and existing finding validation is never inherited as path proof.
