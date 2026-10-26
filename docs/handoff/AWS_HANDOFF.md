# AWS handoff — CloSec 0.8.4 with AWS collector 0.3.2

Data-free. Every statement below comes from source files in this repository (paths given)
as of 2026-10-17, branch `feature/offline-security-analyzer`, uncommitted working tree on
base `374d4c8`. No real evidence, workspace or finding content was used to write it.
The AWS collector and the AWS analysis path were **not changed** in this session.

## a. Collector state

| Item | Value | Source |
|---|---|---|
| Collector | `assessment.py` (Python 3.9+, boto3/botocore) | `collectors/aws/` |
| Version | `VERSION = "0.3.2"` | `collectors/aws/assessment.py:25` |
| Journal/manifest schema | `closec-provisional-0.3` | `collectors/aws/assessment.py:645` |
| Analyzer adapter | `closec-v030-native-1` | `src/offline_analyzer/ingestion/collector_v030_native.py:31` |
| Accepted collector versions | 0.3.0, 0.3.1, 0.3.2 | `collectors/collector-analyzer-contract.json` |
| Contract version (both clouds) | `2.0.0` | `collectors/collector-analyzer-contract.json` |
| Operation names | botocore 1.43.113 model table (135) | contract `operation_names` |
| Package | `evidence/<AccountName>__<AccountID>__<run>/` and `.zip` (`AWS-EVIDENCE/`): `manifest.json`, `operations.jsonl` journal, native page JSON under `accounts/<id>/...`, `collection-summary.json`, `retry-requests.json`, `checksums.sha256` | `collectors/aws/README.md` |
| Download name | `CloSec_AWS_Collector_v0.3.2.zip` | `src/offline_analyzer/api/collectors.py:73` |

**Operations collected** (131 contract rows: 23 feed rules, 19 normalized only, 89 retained
unparsed). Generated from `collectors/collector-analyzer-contract.json`:

| Service | Ops | Evaluated | Normalized only | | Service | Ops | Evaluated | Normalized only |
|---|---|---|---|---|---|---|---|---|
| ec2 | 28 | 4 | 11 | | organizations | 5 | 0 | 5 |
| s3api | 16 | 3 | 1 | | cloudtrail | 4 | 3 | 0 |
| iam | 13 | 3 | 0 | | elbv2 | 4 | 0 | 0 |
| rds | 8 | 1 | 0 | | lambda | 4 | 0 | 1 |
| kms | 7 | 4 | 0 | | network-firewall | 3 | 0 | 0 |
| config | 6 | 1 | 0 | | securityhub | 3 | 1 | 0 |
| guardduty | 2 | 2 | 0 | | s3control | 1 | 1 | 0 |
| dynamodb, ecs, eks, route53resolver | 2 each | 0 | 0 | | ram | 1 | 0 | 1 |

There is one operation each for accessanalyzer, apigateway, apigatewayv2, cloudfront,
cloudwatch, ecr, efs, events, fsx, inspector2, logs, macie2, resource-explorer-2,
resourcegroupstaggingapi, route53, secretsmanager, ssm and wafv2. All are retained and none
is evaluated.

Operations that feed rules:
- **CloudTrail:** `DescribeTrails`, `GetEventSelectors`, `GetTrailStatus`
- **Config:** `DescribeConfigurationRecorderStatus`
- **EC2:** `DescribeInstances`, `DescribeNetworkInterfaces`, `DescribeRouteTables`,
  `DescribeSecurityGroups`
- **GuardDuty:** `GetDetector`, `ListDetectors`
- **IAM:** `GetAccountAuthorizationDetails`, `GetPolicyVersion`, `ListRoles`
- **KMS:** `DescribeKey`, `GetKeyPolicy`, `GetKeyRotationStatus`, `ListGrants`
- **RDS:** `DescribeDBInstances`
- **S3:** `s3api:GetBucketAcl`, `GetBucketPolicyStatus`, `GetPublicAccessBlock`,
  `s3control:GetPublicAccessBlock`
- **Security Hub:** `DescribeHub`

**Read-only permissions** (`collectors/aws/README.md`):
- The spoke role needs AWS-managed `SecurityAudit` plus `ViewOnlyAccess`.
- The identity running the script needs `organizations:ListAccounts` for account discovery.
- No write or admin permissions. No object bodies, secret values or function code are read.

**How it is run:**
1. `cp config.example.json config.json`, then
   `cp approved_accounts.example.txt approved_accounts.txt`.
2. `python assessment.py collect --no-prowler`.
3. Search, choose the account number, type YES.

Accounts outside the allowlist are refused. `python assessment.py verify <run folder>`
re-checks hashes. Prowler 5.x is optional and never proves coverage.

**Known gaps and limitations** (`collectors/aws/README.md`):
- Not collected:
  - resource control policies
  - effective SCP evaluation
  - Identity Center
  - some per-resource detail
- 89 collected operations are retained unparsed. They are visible as coverage and never
  evaluated.
- Member accounts usually get AccessDenied on the Organizations SCP chain. This is
  journaled, never treated as "no policy".
- Each operation is one bounded attempt (`MAX_PAGES = 5000`; reaching it gives PARTIAL).
- The developer has not run it against real accounts: only a local moto emulator with
  synthetic resources.

## b. Analyzer assessment logic

**Import and validation** (`ingestion/collector_v030_native.py`, `ingestion/collector.py`):
- Checks: the journal maps onto the shared collector contract; every file must be listed
  in `checksums.sha256` (mismatch or omission fails closed); collector version against the
  profile.
- An unsupported version, for example 0.4.0, is rejected with
  `COLLECTOR_VERSION_PROFILE_UNSUPPORTED`. Verified with a synthetic probe this session.
- Journal outcome mapping (contract `journal.outcome_mapping`):
  - `COMPLETE` with a residual pagination token becomes PARTIAL coverage.
  - `PARTIAL` means TRUNCATED pagination.
  - `ACCESS_DENIED`, `API_ERROR`, `NOT_COLLECTED` and `NOT_ENABLED` are gaps.
- Bounds: `MAX_OPERATIONS=20000` (`ingestion/collector.py:36`) plus the shared
  `ingestion/json_input.py` limits.
- Tests: `tests/test_collector_v030_native.py`, `tests/test_collector.py`.

**Identity and scope:**
- Each source is bound to its collection account and Region.
- An optional private approved-account registry (`cli.py accounts load`,
  `inventory/accounts.py`, file `account-registry.json` in the workspace) maps IDs to
  tracker keys for export.
- Scope deletion and single-file deletion need a preview plus typed confirmation
  (`assessment/manage.py`, `tests/test_scope_management.py`,
  `tests/test_file_deletion.py`).

**Normalization:** resource identity and metadata adapters only
(`normalization/adapters.py`, `normalization/iam_adapters.py`).

**Coverage status:** the same definitions as GCP (`reporting/cloud.py:14`):
- `COMPLETE`, `PARTIAL` and `ERROR` describe collection usability, not a pass rate.
- Missing evidence is `UNKNOWN`, never PASS (`tests/test_foundation.py::test_unknown_is_not_pass`).
- There is no account-wide PASS (`rules/engine.py`).
- Readiness separates declared Regions from unsupported access denial
  (`tests/test_recovery.py`).

**Checks evaluated:** 19 AWS rules, listed in the table at the end of this file:
- R0 checks in `rules/configuration.py`
- R1 methodology-mapped rules in `rules/r1.py` and `rules/network.py`
- the instance-role privilege rule in `rules/iam_privilege.py`
- additional observations in `rules/security_observations.py`

Severity is the rule's suggested severity plus a rationale. Path calibration may raise it,
never lower it. Finding class and severity are documented in `docs/RULE_SPECIFICATIONS.md`.

**Finding generation and auto-validation:** shared with GCP
(`findings/generate.py`, `findings/detail.py`, `findings/explanations.py`,
`findings/quality.py`):
- The detail fields are: description, observed parameters, root cause (`gap`), evidence
  references, misuse scenario, impact, severity and rationale, remediation, validation
  and completeness.
- All 19 rules have misuse text, risk, remediation and severity rationale.
- `READY_FOR_CONFIRMATION` means the analyst only confirms. It never auto-approves
  (`tests/test_assessment_sprint.py::test_aws_only_estate_shares_reconciliation_quality_review_and_freeze`).

**IAM analysis** (`iam/evaluator.py`, `iam/analysis.py`, `docs/IAM_EVALUATION.md`):
- A bounded, three-valued evaluator for role principals: identity policies, permissions
  boundary and applicable SCPs.
- It covers `iam:PassRole`, service operations and cross-account `sts:AssumeRole`.
- Session policies and generic resource-based authorization (S3/KMS) are not evaluated.
- Bounds: `MAX_TRANSITIONS=20000`, `MAX_PASSROLE=20000`. Truncation is reported.

**Network** (`rules/network.py`):
- A FAIL needs both:
  - a security group open to 0.0.0.0/0 on a sensitive TCP port
    (`SENSITIVE_TCP = 22, 3389, 1433, 3306, 5432, 6379, 9200, 27017`)
  - an in-use, customer-managed ENI with a public IPv4 address referencing that group
- Without the ENI the result is latent exposure (`SEC-EC2-SG-LATENT-EXPOSURE`).
- NACLs, routes and host firewalls are not evaluated, so this is configuration exposure,
  not reachability.

**Attack paths and STRIDE:**
- Typed prerequisite specs AP-01..AP-30 (`attack_paths/specs.py`, 30 paths) with the kinds
  CONFIG, IAM_ENGINE, REACHABILITY, ORG_EVIDENCE, CLASSIFICATION, DETECTION, MANUAL and
  EXPLOITATION.
- `FEASIBLE` only when every evidence-establishable prerequisite is verified. EXPLOITATION
  and MANUAL prerequisites are never auto-verified (`attack_paths/feasibility.py`).
- STRIDE comes from linked findings' `stride_category` (`rules/methodology_links.py`), and
  `stride_scenarios` from the path spec threats.
- A path goes into the Word/Excel Findings Validation only after the analyst confirms it.
- Cross-cloud path XC-01 (AWS role to GCP workload identity) is in `attack_paths/cross.py`.
- UI: **Dashboard → AWS → Attack Paths** tab (`frontend/src/CloudDashboard.tsx:24`).

**Consolidation:** shared with GCP (`enterprise/snapshot.py`, `enterprise/validation.py`,
`enterprise/correlate.py`). Cross-account correlation runs across separate imports
(`tests/test_enterprise.py`). A transit gateway attachment never establishes reachability
(`tests/test_enterprise.py::test_tgw_attachment_never_establishes_network_reachability`).

## c. Current analyzer settings (names and values from code; no client values)

| Setting | Value | Source |
|---|---|---|
| `SENSITIVE_TCP` | 22, 3389, 1433, 3306, 5432, 6379, 9200, 27017 | `rules/network.py:16` |
| `WEB_TCP` | 80, 443 | `rules/network.py:18` |
| `MAX_TRANSITIONS` / `MAX_PASSROLE` | 20000 / 20000 | `iam/analysis.py:28` |
| `MAX_OPERATIONS` (per package) | 20000 | `ingestion/collector.py:36` |
| Import bounds | files 20000, depth 40, records 100000, string 65536, events 2,000,000 | `ingestion/json_input.py:13` |
| Workspace environment | `SYNTHETIC` / `ASSESSMENT`; ASSESSMENT requires `tool-generated` | `inventory/environment.py` |
| `CLOSEC_ENVIRONMENT` | default `assessment` | `start-macos.sh` |
| `STALE_AFTER_DAYS`, `PATH_LIMIT`, `MAX_EDGES`, `MAX_BULK`, `SNIPPET_LIMIT`, `REPORT_SHEETS` | 7, 100, 100000, 2000, 12000, 27 | see `docs/handoff/GCP_HANDOFF.md` §c |
| Collector retries / timeouts | botocore `max_attempts=4` (standard), connect 10 s, read 60 s | `collectors/aws/assessment.py:28` |
| Collector `MAX_PAGES` | 5000 per operation | `collectors/aws/assessment.py:30` |
| Collector config keys (names only) | `assessment_id`, `approved_accounts_file`, `approved_regions`, `spoke_role_name`, `prowler_executable`, `dataset_origin` (example value `TOOL_GENERATED`) | `collectors/aws/config.example.json` |

No settings were changed by this work.

## d. Known issues, untested areas, what to watch

- **Real-account execution of 0.3.x has not been performed by the developer.** Review
  `collection-summary.json` outcome counts on the first run. A PARTIAL summary is normal.
- **Windows collection** works from 0.3.1 onward, but has not been validated on Windows in
  this repository.
- **89 operations are retained but not parsed.** They show as coverage, not as evaluated
  controls; do not read them as checked.
- **SCP evaluation from member accounts is usually AccessDenied.** IAM decisions then stay
  UNKNOWN or POTENTIALLY_ALLOWED rather than DENIED.
- **`COLLECTOR_VERSION_PROFILE_UNSUPPORTED` has no plain-language explanation entry** in
  `ingestion/errors.py`. The code is still shown, and the import fails closed.
- **Real-export compatibility is not claimed** (AGENTS.md rule).

## e. Parity gaps versus GCP

| Area | AWS | GCP |
|---|---|---|
| Rule count | 19 | 48 |
| Org-wide IAM view | SCP chain only (often denied) | Cloud Asset org IAM search (opt-in) with 10 `GCP-ORG-*` rules |
| Key/credential age | no access-key age rule | `GCP-KEY-AGE` (90-day default) |
| KMS rotation | `SEC-KMS-ROTATION` (enabled/disabled) | `MAX_ROTATION_SECONDS` 90 days |
| Logging | CloudTrail logging, management events, validation; Config recording | audit logs, sinks, exclusions, bucket retention |
| IAM engine | bounded evaluator | none (bindings only) |
| Attack-path specs | AP-01..AP-30 | GCP investigations + XP-01..03 |
| Collector runtime | Python, Linux/Windows | Windows PowerShell 5.1 only |

## Rules evaluated (generated from `rules/registry.py`)

| Rule ID | Title | Domain | Primary operation | Suggested severity | Finding class |
|---|---|---|---|---|---|
| `R0-EC2-IMDSV2` | EC2 metadata endpoint permits IMDSv1 | Compute security | `ec2:DescribeInstances` | MEDIUM | BASELINE_DEVIATION |
| `R0-RDS-ENCRYPTION` | RDS instance storage encryption is disabled | Data protection | `rds:DescribeDBInstances` | MEDIUM | BASELINE_DEVIATION |
| `R0-CLOUDTRAIL-VALIDATION` | CloudTrail log-file validation is disabled | Logging and monitoring | `cloudtrail:DescribeTrails` | LOW | BASELINE_DEVIATION |
| `R1-EC2-SG-SENSITIVE-INGRESS` | Security group exposes sensitive ports to the internet on a public interface | Network exposure | `ec2:DescribeSecurityGroups` | HIGH | POTENTIAL_EXPOSURE |
| `R1-IAM-ROLE-TRUST-CONDITIONS` | IAM role trusts another account without binding conditions | Identity and access | `iam:GetAccountAuthorizationDetails` | HIGH | POTENTIAL_EXPOSURE |
| `R1-S3-ACCOUNT-BPA` | Account-level S3 Block Public Access is not fully enabled | Data protection | `s3control:GetPublicAccessBlock` | MEDIUM | BASELINE_DEVIATION |
| `R1-S3-BUCKET-PUBLIC-ACCESS` | S3 bucket permits anonymous public access | Data protection | `s3api:GetBucketPolicyStatus` | HIGH | POTENTIAL_EXPOSURE |
| `R1-RDS-PUBLIC-ACCESS` | RDS instance is publicly accessible | Data protection | `rds:DescribeDBInstances` | MEDIUM | POTENTIAL_EXPOSURE |
| `R1-EC2-IMDS-HOP-LIMIT` | EC2 metadata response hop limit exceeds 1 | Compute security | `ec2:DescribeInstances` | LOW | BASELINE_DEVIATION |
| `R1-IAM-INSTANCE-ROLE-PRIVILEGE` | Instance role allows Action:* or unguarded iam:PassRole | Identity and access | `iam:GetAccountAuthorizationDetails` | MEDIUM | POTENTIAL_EXPOSURE |
| `SEC-IAM-ROLE-WILDCARD` | Role policy contains broad wildcard actions | Identity and access | `iam:GetAccountAuthorizationDetails` | MEDIUM | POTENTIAL_EXPOSURE |
| `SEC-KMS-WILDCARD-PRINCIPAL` | KMS key policy permits unconditional wildcard principals | Data protection | `kms:GetKeyPolicy` | HIGH | POTENTIAL_EXPOSURE |
| `SEC-EC2-SG-LATENT-EXPOSURE` | Security group allows sensitive ports from the internet (latent exposure) | Network and exposure | `ec2:DescribeSecurityGroups` | MEDIUM | BASELINE_DEVIATION |
| `SEC-CLOUDTRAIL-LOGGING` | CloudTrail trail is not logging | Logging and monitoring | `cloudtrail:GetTrailStatus` | HIGH | BASELINE_DEVIATION |
| `SEC-CLOUDTRAIL-MANAGEMENT-EVENTS` | CloudTrail trail does not capture management events | Logging and monitoring | `cloudtrail:GetEventSelectors` | MEDIUM | BASELINE_DEVIATION |
| `SEC-GUARDDUTY-ENABLED` | GuardDuty is not enabled in the Region | Threat detection | `guardduty:ListDetectors` | MEDIUM | BASELINE_DEVIATION |
| `SEC-CONFIG-RECORDING` | AWS Config is not recording in the Region | Logging and monitoring | `config:DescribeConfigurationRecorderStatus` | MEDIUM | BASELINE_DEVIATION |
| `SEC-SECURITYHUB-ENABLED` | Security Hub is not enabled in the Region | Threat detection | `securityhub:DescribeHub` | INFO | BASELINE_DEVIATION |
| `SEC-KMS-ROTATION` | Customer-managed KMS key rotation is disabled | Data protection | `kms:DescribeKey` | LOW | BASELINE_DEVIATION |
