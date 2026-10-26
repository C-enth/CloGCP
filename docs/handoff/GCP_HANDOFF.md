# GCP handoff — CloSec 0.8.4 with GCP collector 2.2.7

Data-free. Every statement below comes from source files in this repository (paths given)
as of 2026-10-17, branch `feature/offline-security-analyzer`, uncommitted working tree on
base `374d4c8`. No real evidence, workspace or finding content was used to write it.

## a. Collector state

| Item | Value | Source |
|---|---|---|
| Collector | `GCP_Security_Evidence_Collector.ps1` (Windows PowerShell 5.1, native `gcloud` + read-only REST) | `collectors/gcp/` |
| Version | `$CollectorVersion = '2.2.7'` | `collectors/gcp/GCP_Security_Evidence_Collector.ps1:58` |
| Manifest schema | `assessment-expanded-2.2` (`collection_manifest.json`) | same file, `$SchemaVersion` |
| Analyzer adapter | `gcp-expanded-2.2-adapter-1` | `src/offline_analyzer/ingestion/gcp_expanded.py:19` |
| Accepted collector versions | 2.2.0–2.2.7 | `src/offline_analyzer/contracts/gcp_expanded.py:124` |
| Also accepted | `assessment-expanded-2.1`, legacy `pilot-1.2.2`, `pilot-1.5` (these need an explicit no-checksum acknowledgment) | `collectors/collector-analyzer-contract.json` |
| Contract version (both clouds) | `2.0.0` | `collectors/collector-analyzer-contract.json` |
| Package | one folder + ZIP per project: `collection_manifest.json`, `checksums.sha256` (required for 2.2), `<domain>/<dataset>.json`, `<dataset>.stderr.txt` per failed dataset | `collectors/gcp/README.md` |
| Download name | `CloSec_GCP_Collector_v2.2.7.zip` (generated from the contract version) | `src/offline_analyzer/api/collectors.py:78` |

**Datasets collected** (118 contract rows; 23 feed rules, 95 are normalized for inventory
and views only). Generated from `collectors/collector-analyzer-contract.json`:

| Domain | Datasets | Feeding rules | Rules fed |
|---|---|---|---|
| ai | 4 | 0 | 0 |
| api | 4 | 2 | 3 |
| compute | 9 | 1 | 11 |
| data | 7 | 1 | 4 |
| devops | 4 | 0 | 0 |
| governance | 9 | 1 | 5 |
| identity | 15 | 4 | 8 |
| inventory | 10 | 0 | 0 |
| logging | 9 | 5 | 2 |
| messaging | 2 | 0 | 0 |
| monitoring | 3 | 0 | 0 |
| network | 19 | 3 | 6 |
| security | 12 | 3 | 2 |
| serverless | 8 | 0 | 0 |
| storage | 3 | 3 | 4 |

Operations that feed rules: `apikeys.keys.list`, `cloudkms.cryptoKeys.list`,
`compute.firewalls.list`, `compute.instances.list`, `compute.networks.list`,
`expanded.cloud_sql`, `expanded.subnets`, `iam.serviceAccountKeys.list`,
`iam.serviceAccounts.list`, `logging.buckets.list`, `logging.sinks.list`,
`orgpolicy.getEffectivePolicy`, `projects.getIamPolicy`, `securitycenter.findings.list`,
`storage.buckets.get`, `storage.buckets.getIamPolicy`, `storage.buckets.list` (all `gcp:`).
Organization rules (`GCP-ORG-*`) use `gcp:cloudasset.organizationIamSearch`, which is
collected only with `-IncludeOrganizationSearch`.

**Read-only permissions** (`collectors/gcp/README.md`): viewer-level project access such as
`roles/viewer`, `roles/iam.securityReviewer`, `roles/cloudasset.viewer`,
`roles/securitycenter.findingsViewer`, `roles/discoveryengine.viewer`; plus
`roles/serviceusage.serviceUsageConsumer` on an approved quota project when `-QuotaProject`
is used. Organization IAM policy and workforce pools need organization-level read
access. The collector never enables APIs, changes IAM or reads secret values or data.

**How it is run** (`collectors/gcp/README.md`, `docs/OPERATOR_GUIDE.md` §2):
`gcloud auth login`, then `powershell -NoProfile -File .\GCP_Security_Evidence_Collector.ps1`
in the unzipped folder. Choose the project number and type YES. Projects come from
`organization\projects.json`, or read-only discovery if that file is missing. Output goes to `projects\`.
Optional: `-QuotaProject <id>` (typed confirmation) and `-IncludeOrganizationSearch`
(typed `ORG` confirmation). The sign-in check runs before any output is written.

**2.2.5 changes (this session, owner-requested):**
- Cloud Run service and Cloud Functions IAM calls passed `--region=` and the region as two
  arguments, because of PowerShell comma precedence. Every call failed with `COMMAND_ERROR`;
  the arguments are now grouped.
- The Cloud Run jobs and Artifact Registry REST lists used `locations/-` and always
  returned HTTP 400. Both calls are removed; the same inventory comes from the
  `cloud_run_jobs` and `artifact_repositories` gcloud datasets.
- Static regression tests are in `tests/test_gcp_expanded22.py`.

**Known gaps and limitations:**
- Not collected at all:
  - project info / OS Login metadata
  - essential contacts
  - access approval
  - KMS key, Secret Manager, Pub/Sub and Artifact Registry IAM policies
  - HMAC keys
  - HTTPS/SSL proxies
  - Shared VPC
  - organization log sinks and firewall policies
  - Dataproc
  - Binary Authorization
- Datasets that need a quota project with user credentials: Cloud Asset list, monitoring
  alert policies. Without one they record `QUOTA_PROJECT_DENIED`.
- Org-wide IAM search is opt-in, so the 10 `GCP-ORG-*` rules stay UNKNOWN without it.
- Never executed natively on Windows PowerShell 5.1 by the developer. The script is
  statically tested only, because PowerShell is not available on the build Mac.

## b. Analyzer assessment logic

**Import and validation** (`ingestion/gcp.py`, `ingestion/gcp_expanded.py`,
`ingestion/gcp_legacy.py`):
- Checks before import: manifest schema and collector version, every dataset against the
  audited catalog (`contracts/gcp_expanded_catalog.py`, bounded name patterns), file
  references, record counts, the REST array shape, duplicates, and `checksums.sha256`.
- Any violation fails closed with a code (for example `GCP_TRANSPORT_RECORD_COUNT_MISMATCH`,
  `GCP_DUPLICATE_DATASET`, `MANIFEST_FILE_REFERENCE_MISMATCH`) and no run is created
  (`tests/test_gcp_expanded.py::test_expanded_rejects_invalid_contract_without_run`).
- Unknown versions are rejected; see section d for the misleading message.
- Imports are untrusted input with bounded size and depth
  (`ingestion/json_input.py`: `MAX_PACKAGE_FILES=20000`, `MAX_DEPTH=40`,
  `MAX_RECORDS=100000`, `MAX_STRING=65536`).

**Project identity** (`normalization/gcp.py::validate_identity`,
`normalization/gcp_identity.py`):
- Project ID and project number are compared with their own metadata fields; display
  names are never identity.
- A conflict stops the import with `GCP_PROJECT_IDENTITY_MISMATCH`, showing session-only
  details (file, field, declared versus observed).
- A number-named resource in a guided JSON import with no declared number gives
  `GCP_PROJECT_NUMBER_REQUIRED`.
- Folder/org IAM search results and public catalog images are reduced to the collected
  project before storage (ADR-010, `docs/adr/ADR-010.md`).
- Tests: `tests/test_assessment_sprint.py::test_identity_*`, `tests/test_gcp.py`,
  `tests/test_gcp_expanded.py::test_parent_scope_summaries_keep_only_the_collected_project`.

**Normalization:** identity and metadata only (`normalization/gcp.py`,
`normalization/gcp_expanded.py`); control logic lives in the rules.

**Coverage status** (`reporting/cloud.py:14 COVERAGE_DEFINITIONS`, shown in the UI):
- `effective_coverage` describes collection usability, not a pass rate:
  - `COMPLETE`: complete scope and pagination are declared.
  - `PARTIAL`: usable but incomplete (scope, pagination, provenance or dependencies).
  - `ERROR`: collection or validation failed; cannot support PASS or prove absence.
- Collector statuses that are always gaps:
  - `FAILED`, `API_DISABLED`, `ACCESS_DENIED`, `QUOTA_PROJECT_DENIED`
  - `COMMAND_ERROR`, `AUTH_ERROR`, `TIMEOUT`, `RATE_LIMITED`
  - `NOT_FOUND`, `HTTP_ERROR`, `SERVER_ERROR`
  - `UNEXPECTED_SCHEMA`, `INVALID_OUTPUT`, `UNSUPPORTED_ENDPOINT`
- `TRUNCATED` and `PARTIAL` are partial.
- Rule outcomes are `PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE` and
  `MANUAL_VALIDATION_REQUIRED`. Missing or malformed fields stay `UNKNOWN` and never give
  PASS (`tests/test_gcp_config.py::test_missing_fields_never_establish_pass_or_finding`,
  `tests/test_gcp_expanded22.py::test_field_distribution_is_preserved_and_never_passes`).
  There is no account-wide PASS (`rules/engine.py`).

**Checks evaluated:** 48 GCP rules (38 in `rules/gcp.py` and `rules/gcp_config.py`, 10 in
`rules/gcp_org.py`), listed in the table at the end of this file. Severity is the rule's
`suggested_severity`, with a rationale string per finding. Attack-path calibration may
raise it, never lower it, and states why (`attack_paths/feasibility.py`). Finding class is
`BASELINE_DEVIATION`, `POTENTIAL_EXPOSURE` or `SUPPORTED_GAP`
(`docs/RULE_SPECIFICATIONS.md`).

**Finding generation** (`findings/generate.py`, `findings/detail.py`,
`findings/explanations.py`):
- One candidate per FAIL evaluation with a resolved resource, scope, Region and native ID.
- The detail view carries:
  - summary/description
  - observed parameters and expected posture
  - the gap (`what_is_wrong`, `principle_violated`), i.e. the root cause
  - evidence references (artifact, locator, collection status)
  - a misuse scenario, qualified "not demonstrated"
  - technical impact
  - severity and its rationale
  - remediation (`recommended_action`, immediate, permanent, review-only command)
  - validation (procedure, verify command, expected state, closure)
  - completeness (missing information, collection errors, false-positive conditions)
- Every one of the 48 rules has misuse text, risk, remediation and severity rationale
  (checked against the registry this session). The 10 `GCP-ORG-*` rules have no specific
  recommendation template (`findings/gcp_recommendations.py::template_for`) and fall back
  to the rule's remediation text.

**Auto-validation** (`findings/quality.py`):
- `READY_FOR_CONFIRMATION` requires all of:
  - required fields present
  - all evidence references resolve
  - a supporting FAIL evaluation exists
  - no missing evidence, contradictions or missing dependencies
  - confidence not LOW or UNASSESSED
- Anything else is `NEEDS_VALIDATION`.
- Auto-validation never grants approval: the analyst confirms, and bulk "Mark valid"
  exists (`findings/sre.py`, `MAX_BULK=2000`).

**Attack paths and STRIDE:**
- Sources:
  - GCP candidate investigations (`attack_paths/gcp.py`)
  - cross-project paths XP-01 (impersonation chain), XP-02 (SA privileged in another
    project), XP-03 (public principal to a serverless or data resource)
  - cross-cloud path XC-01 (AWS role to GCP workload identity) (`attack_paths/cross.py`)
- `FEASIBLE` only when every evidence-establishable prerequisite is verified. Attacker-side
  prerequisites are never auto-verified, and unknown enforcement cannot establish
  feasibility (`attack_paths/feasibility.py`).
- A path's STRIDE categories come from its linked findings' `stride_category`
  (`rules/methodology_links.py`). It is labelled a proposed mapping, or `UNMAPPED`.
- A path goes into the Word/Excel Findings Validation only after the analyst confirms the
  interpretation (`attack_paths/review.py`, `reporting/report_document.py`,
  `reporting/excel.py`).
- UI: **Dashboard → GCP → Attack Paths** tab (`frontend/src/CloudDashboard.tsx:24`), with
  the diagram in `frontend/src/PathDiagram.tsx`.

**IAM and network:**
- GCP IAM views are configuration bindings only. Inherited, deny, principal access
  boundary and conditional policies are not resolved, so org findings are
  `POTENTIAL_EXPOSURE` (`rules/gcp_org.py`).
- Network correlation (firewall × instance × network) is candidate exposure only, never
  reachability (`rules/gcp_config.py`).
- UI: **IAM intelligence**, **Network analysis**, **Cross-account explorer**
  (`tests/test_gcp_expanded_browser.py`).

**Consolidation** (`enterprise/snapshot.py`, `enterprise/validation.py`,
`enterprise/correlate.py`):
- An immutable union of the selected imports.
- Validation reconciles source, artifact, observation and reference counts and scope
  identities against each import, and reports omitted imports.
- AWS accounts and GCP projects stay distinct. No cross-cloud edge exists without evidence.

## c. Current analyzer settings (names and values from code; no client values)

| Setting | Value | Source |
|---|---|---|
| `max_key_age_days` (GCP-KEY-AGE) | default 90 (manifest field, 1–3650) | `contracts/gcp.py:76`, `rules/gcp.py:131` |
| `MAX_ROTATION_SECONDS` (KMS rotation) | 90 days | `rules/gcp_config.py:35` |
| Log retention | no fixed threshold; observed days shown for comparison with the objective | `rules/gcp_config.py:633` |
| Workspace environment | `SYNTHETIC` or `ASSESSMENT`, set once; ASSESSMENT requires `tool-generated` origin | `inventory/environment.py`, `cli.py` |
| `CLOSEC_ENVIRONMENT` | default `assessment` | `start-macos.sh`, `CloSec.command` |
| Server bind | loopback, `--port 0` (random free port) | `CloSec.command` |
| `STALE_AFTER_DAYS` (enterprise snapshot staleness) | 7 | `enterprise/queries.py:27` |
| `PATH_LIMIT` (paths per report) | 100 | `reporting/report_document.py:16` |
| `MAX_EDGES` (enterprise graph) | 100000 | `enterprise/correlate.py:23` |
| `MAX_RELATED_PER_SCOPE` | 250000 | `rules/context.py:6` |
| `MAX_BULK` (bulk marking) | 2000 | `findings/sre.py:26` |
| `SNIPPET_LIMIT` (evidence snippet) | 12000 chars, secrets masked `***MASKED***` | `findings/detail.py:21` |
| `REPORT_SHEETS` (Excel workbook) | 27 | `reporting/excel.py:60` |
| Collector `-CommandTimeoutSeconds` | 300 (10–3600) | collector param block |
| Collector `-HttpTimeoutSeconds` / `-HttpMaxRetries` | 45 / 3 (0–6) | collector param block |
| Collector `-PageHardCap` / `-MaxApiPages` / `-MaxDetailItems` | 2000 / 0 (follow all) / 0 (no limit) | collector param block |
| Collector `-IncludeOrganizationSearch` | off | collector param block |
| Feature: org-wide IAM search | opt-in collector switch | ADR-010 |

No settings were changed by this work (`git diff` on config, lock and requirements files is empty).

## d. Known issues, untested areas, what to watch

- **Native Windows run of 2.2.5 is unverified.** Review the dataset status distribution of
  the first run before relying on it. The COMMAND_ERROR count for `run_iam_*` and
  `function_iam_*` should now be zero.
- **A wrong collector version is named (fixed in 2.2.6).** A 2.2-format manifest with an
  unsupported version is rejected with `GCP_COLLECTOR_VERSION_UNSUPPORTED` ("Accepted for
  assessment-expanded-2.2: 2.2.0 to 2.2.7"); it fails closed and creates no run.
- **Some gaps can only be closed with access:** `QUOTA_PROJECT_DENIED` needs an approved
  `-QuotaProject`; `ACCESS_DENIED` on the organization needs an org-level role. Both are
  recorded as gaps and drive UNKNOWN results.
- **API_DISABLED datasets** (for example SQL, SCC, Org Policy, API Keys when unused) are
  correct limitations, not failures.
- **Re-collecting is the only way to clear a gap.** Gaps from 2.2.4 packages (the 6 IAM
  calls and the two REST lists) remain in packages already imported. Re-collect with
  2.2.5 to close them.
- **Business criticality is never inferred.** Severity rationale states this assumption.
- **Real-export compatibility is not claimed.** It is not established by the local
  verifier with `--origin tool-generated` on actual files (AGENTS.md rule).

## e. Parity gaps versus AWS

| Area | GCP | AWS |
|---|---|---|
| Rules | 48 | 19 |
| IAM authorization engine | none; bindings only | bounded evaluator (identity policy, boundary, SCP; AssumeRole/PassRole) in `iam/evaluator.py` |
| Methodology attack paths AP-01..AP-30 | not mapped; uses GCP investigations and XP-01..03 | typed specs `attack_paths/specs.py` |
| Org-wide view | Cloud Asset org IAM search (opt-in) | Organizations SCP chain (member accounts usually denied) |
| Network exposure | firewall × instance candidate exposure | SG 0.0.0.0/0 on sensitive port + public ENI (`rules/network.py`) |
| Collector integrity | `checksums.sha256` required (2.2) | `checksums.sha256` + journal |
| Collector runtime | Windows PowerShell 5.1 only | Python 3.9+, Linux or Windows |

## Rules evaluated (generated from `rules/registry.py`)

| Rule ID | Title | Domain | Primary operation | Suggested severity | Finding class |
|---|---|---|---|---|---|
| `GCP-STORAGE-PUBLIC` | Potential public Cloud Storage object access | Data Protection | `gcp:storage.buckets.getIamPolicy` | HIGH | BASELINE_DEVIATION |
| `GCP-API-APP` | API key lacks application restrictions | Credentials and API Security | `gcp:apikeys.keys.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-API-API` | API key lacks API restrictions | Credentials and API Security | `gcp:apikeys.keys.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-API-BOTH` | API key lacks application and API restrictions | Credentials and API Security | `gcp:apikeys.keys.list` | HIGH | BASELINE_DEVIATION |
| `GCP-KEY-PERSISTENT` | User-managed service-account key present | Credentials and API Security | `gcp:iam.serviceAccountKeys.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-KEY-AGE` | Service-account key exceeds age policy | Credentials and API Security | `gcp:iam.serviceAccountKeys.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-KEY-PRIVILEGED` | Persistent key on an observed privileged service account | Identity and Access | `gcp:iam.serviceAccountKeys.list` | HIGH | BASELINE_DEVIATION |
| `GCP-IAM-BASIC` | Broad Owner or Editor binding | Identity and Access | `gcp:projects.getIamPolicy` | HIGH | BASELINE_DEVIATION |
| `GCP-IAM-PUBLIC` | Public principal has a sensitive role binding | Network and Exposure | `gcp:projects.getIamPolicy` | HIGH | BASELINE_DEVIATION |
| `GCP-IAM-IMPERSONATION` | Broad service-account impersonation binding | Identity and Access | `gcp:projects.getIamPolicy` | HIGH | BASELINE_DEVIATION |
| `GCP-IAM-CROSSPROJECT` | Cross-project service account has an Owner or Editor binding | Identity and Access | `gcp:projects.getIamPolicy` | HIGH | BASELINE_DEVIATION |
| `GCP-GOV-KEYS` | Service-account key governance is unenforced | Governance | `gcp:orgpolicy.getEffectivePolicy` | MEDIUM | BASELINE_DEVIATION |
| `GCP-LOG-AUDIT` | Data Access audit-log exemption configured | Monitoring and Detection | `gcp:projects.getIamPolicy` | MEDIUM | BASELINE_DEVIATION |
| `GCP-LOG-EXCLUSION` | Logging exclusion requires security-event review | Monitoring and Detection | `gcp:logging.sinks.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-SCC-OBSERVATION` | Active Security Command Center observation | Vulnerability and Risk | `gcp:securitycenter.findings.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-NET-FW-ADMIN-INTERNET` | Firewall rule allows SSH/RDP or other administrative ports from the internet | Network and Exposure | `gcp:compute.firewalls.list` | HIGH | BASELINE_DEVIATION |
| `GCP-NET-FW-DB-INTERNET` | Firewall rule allows database ports from the internet | Network and Exposure | `gcp:compute.firewalls.list` | HIGH | BASELINE_DEVIATION |
| `GCP-NET-FW-ANY-INTERNET` | Firewall rule allows all ports from the internet | Network and Exposure | `gcp:compute.firewalls.list` | HIGH | BASELINE_DEVIATION |
| `GCP-NET-DEFAULT-NETWORK` | Default VPC network exists | Network and Exposure | `gcp:compute.networks.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-NET-FLOW-LOGS` | VPC Flow Logs disabled on subnet | Monitoring and Detection | `gcp:expanded.subnets` | LOW | BASELINE_DEVIATION |
| `GCP-NET-PRIVATE-GOOGLE-ACCESS` | Private Google Access disabled on subnet | Network and Exposure | `gcp:expanded.subnets` | LOW | BASELINE_DEVIATION |
| `GCP-VM-EXTERNAL-IP` | VM instance has an external IP address | Workload Security | `gcp:compute.instances.list` | MEDIUM | POTENTIAL_EXPOSURE |
| `GCP-VM-DEFAULT-SA` | VM instance uses the default compute service account | Workload Security | `gcp:compute.instances.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-VM-FULL-API-SCOPE` | VM instance uses the default service account with full API access | Workload Security | `gcp:compute.instances.list` | LOW | BASELINE_DEVIATION |
| `GCP-VM-SERIAL-PORT` | Interactive serial console enabled on VM instance | Workload Security | `gcp:compute.instances.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-VM-OSLOGIN` | OS Login disabled on VM instance | Workload Security | `gcp:compute.instances.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-VM-PROJECT-SSH-KEYS` | Project-wide SSH keys allowed on VM instance | Workload Security | `gcp:compute.instances.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-VM-SHIELDED` | Shielded VM protections disabled | Workload Security | `gcp:compute.instances.list` | LOW | BASELINE_DEVIATION |
| `GCP-VM-IP-FORWARD` | IP forwarding enabled on VM instance | Workload Security | `gcp:compute.instances.list` | LOW | BASELINE_DEVIATION |
| `GCP-STORAGE-UBLA` | Uniform bucket-level access disabled | Data Protection | `gcp:storage.buckets.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-STORAGE-PAP` | Public access prevention not enforced on bucket | Data Protection | `gcp:storage.buckets.list` | LOW | BASELINE_DEVIATION |
| `GCP-STORAGE-VERSIONING` | Object versioning disabled on bucket | Data Protection | `gcp:storage.buckets.list` | LOW | BASELINE_DEVIATION |
| `GCP-SQL-OPEN-NETWORK` | Cloud SQL instance authorizes all internet addresses | Network and Exposure | `gcp:expanded.cloud_sql` | HIGH | POTENTIAL_EXPOSURE |
| `GCP-SQL-PUBLIC-IP` | Cloud SQL instance has a public IP address | Network and Exposure | `gcp:expanded.cloud_sql` | MEDIUM | POTENTIAL_EXPOSURE |
| `GCP-SQL-TLS` | Cloud SQL instance allows unencrypted connections | Data Protection | `gcp:expanded.cloud_sql` | MEDIUM | BASELINE_DEVIATION |
| `GCP-SQL-BACKUP` | Cloud SQL automated backups disabled | Data Protection | `gcp:expanded.cloud_sql` | MEDIUM | BASELINE_DEVIATION |
| `GCP-KMS-ROTATION` | KMS rotation period exceeds the 90-day engineering baseline | Data Protection | `gcp:cloudkms.cryptoKeys.list` | MEDIUM | BASELINE_DEVIATION |
| `GCP-LOG-RETENTION` | Log bucket retention requires validation | Monitoring and Detection | `gcp:logging.buckets.list` | LOW | BASELINE_DEVIATION |
| `GCP-ORG-PUBLIC-SERVERLESS` | Serverless service allows unauthenticated invocation | Network and Exposure | `gcp:cloudasset.organizationIamSearch` | MEDIUM | POTENTIAL_EXPOSURE |
| `GCP-ORG-PUBLIC-DATA` | Data resource grants access to public principals | Data Protection | `gcp:cloudasset.organizationIamSearch` | HIGH | POTENTIAL_EXPOSURE |
| `GCP-ORG-PUBLIC-OTHER` | Resource policy grants a role to public principals | Identity and Access | `gcp:cloudasset.organizationIamSearch` | HIGH | POTENTIAL_EXPOSURE |
| `GCP-ORG-BASIC-ROLE` | Human principal holds Owner or Editor in the resource hierarchy | Identity and Access | `gcp:cloudasset.organizationIamSearch` | HIGH | POTENTIAL_EXPOSURE |
| `GCP-ORG-SA-PRIVILEGED` | Service account holds Owner or Editor in the resource hierarchy | Identity and Access | `gcp:cloudasset.organizationIamSearch` | HIGH | POTENTIAL_EXPOSURE |
| `GCP-ORG-IMPERSONATION` | Service-account impersonation granted on a project, folder or organization | Identity and Access | `gcp:cloudasset.organizationIamSearch` | HIGH | POTENTIAL_EXPOSURE |
| `GCP-ORG-CROSSPROJECT-SA` | Service account from another project holds a privileged role | Identity and Access | `gcp:cloudasset.organizationIamSearch` | MEDIUM | POTENTIAL_EXPOSURE |
| `GCP-ORG-DELETED-PRINCIPAL` | Deleted principal still holds a role binding | Identity and Access | `gcp:cloudasset.organizationIamSearch` | LOW | BASELINE_DEVIATION |
| `GCP-ORG-EXTERNAL-DOMAIN` | Principals from an email domain have access (third-party validation) | Identity and Access | `gcp:cloudasset.organizationIamSearch` | MEDIUM | POTENTIAL_EXPOSURE |
| `GCP-ORG-FEDERATION` | External workload identity can act as a service account | Identity and Access | `gcp:cloudasset.organizationIamSearch` | MEDIUM | POTENTIAL_EXPOSURE |

## Collector–analyzer contract coupling checklist

When the GCP collector changes, every item below changes in the same commit (each is
enforced by a test):

1. `$CollectorVersion` in the script, `collector_version` in `tools/collector_contract.py`
   (then `python -m tools.collector_contract` regenerates
   `collectors/collector-analyzer-contract.json` and `docs/ASSESSMENT_COVERAGE.md`;
   `--check` fails on drift — `tests/test_collector_v030_native.py`).
2. The accepted range `collector_version` in `contracts/gcp_expanded.py`
   (`ExpandedManifest22`), the fixed rejection phrase in `contracts/gcp_legacy.py` and the
   `GCP_COLLECTOR_VERSION_UNSUPPORTED` text in `ingestion/errors.py`
   (`tests/test_gcp_collector_226.py`, `tests/test_gcp_collector_227.py`). Keep the
   classifier emulation in those tests in step with `Get-GcloudFailureStatus` and
   `Resolve-DisabledService`.
3. Every dataset name the script can emit (`Run`, `RestList`, `Invoke-RestEvidence`,
   `Add-ManifestEntry`) matches a row in `contracts/gcp_expanded_catalog.py`, and every
   catalog row is in the contract JSON (`tests/test_gcp_contract_sync.py`, which fails for a
   new dataset without a catalog row).
4. Every manifest summary field and dataset-entry field the script writes exists in
   `ExpandedManifest22` / `ExpandedDataset22` (new fields optional, strictly typed); the
   `dependency_fallbacks` and `detail_limits_reached` shapes match `DependencyFallback` and
   `DetailLimitsReached` (`tests/test_gcp_contract_sync.py`).
5. New manifest fields are consumed, not only accepted: `ingestion/gcp_expanded.py`
   (`collection_notes`) and `reporting/coverage_reasons.py` give each a coverage reason
   (`tests/test_gcp_coverage_notes.py`).
6. Line references for the 2.2 extension rows in the catalog
   (`test_catalog_extension_lines_match_corrected_collector`).
6a. Effective-policy shapes consumed by rules (`rules/gcp.py`: `constraint_name`,
   `boolean_enforcement`) when the collector changes how policies are named or described
   (`tests/test_gcp_collector_227.py`); bump that rule's own version.
7. Docs: collector README (corrections table), OPERATOR_GUIDE, GCP_USAGE, this handoff,
   README and the changelog; then rebuild CloSec.zip and confirm the shipped script is
   byte-identical to the repository copy.
