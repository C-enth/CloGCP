# CloSec AWS collector 0.3.3

Downloaded as `CloSec_AWS_Collector_v0.3.3.zip`: one `CloSec_AWS_Collector/` folder with
`assessment.py` (one account), `preflight.py` (access probe), `batch.py` (many accounts),
`fleet.py` (shared helpers), this README, `AWS_COLLECTION_ACCESS.md` (every API action and the
IAM policies), `policies/` (member role StackSet template, supplement, trust, hub and
management-account policies), `config.example.json`, `approved_accounts.example.txt`,
`accounts.example.csv`, the analyzer contract and `evidence/`.

## 0.3.3 (journal schema `closec-provisional-0.3`; fields and outcomes added)

- Distinct outcomes: ACCESS_DENIED, THROTTLED, CREDENTIALS_EXPIRED, TIMEOUT, CONNECTION_ERROR,
  SERVICE_NOT_IN_USE (AWS subscription code or endpoint not offered), REGION_NOT_ENABLED
  (opted-out Region journaled, no longer aborts the run). All are gaps; none is compliant.
- Bounded read-only retries with exponential backoff and jitter (botocore retries off, so every
  retry is journaled: `attempts`, `retried_statuses`, and one manifest entry per retry).
  Configurable `timeouts` / `retries` in config.json (`connect_timeout`, `read_timeout`,
  `operation_timeout`, `max_attempts`, `backoff_base`, `backoff_cap`, `session_duration`).
- Organizations: SCP and RCP chain from the account to the root with policy content (root
  included); organization ID and management account recorded; missing access recorded
  explicitly (`collection_facts.organization.access`).
- `collect --resume <run folder> [--services ...] [--regions ...]`: a new run that copies
  COMPLETE evidence after re-verifying its SHA-256 and re-attempts only failed or missing
  operations.
- Package integrity: UTF-8 with LF on every OS, forward-slash ZIP entries, `<zip>.sha256`
  sidecar, manifest `collection_facts` (retries, detail limits, dependency fallbacks, Regions
  attempted / succeeded / partial / not enabled, organization access, resume).
- Expired credentials stop the run and finalize it as INTERRUPTED (resume after signing in).

Pre-flight before a large collection:

```sh
python preflight.py --accounts accounts.csv --role CloSecEvidenceReadOnly --regions ap-south-1
```

Batch (one package per account, checkpointed, `--retry-failed` resumes incomplete accounts):

```sh
python batch.py --accounts accounts.csv --role CloSecEvidenceReadOnly --regions ap-south-1 \
    --output batch-2026-10 --assessment-id ACME-2026 --concurrency 4
```

Both are Python like the collector and run on Windows, macOS and Linux. Account IDs are masked
in terminal output; credentials are never printed or stored.

Read-only Python/boto3 evidence collector. One operator-selected account per run, through
an approved spoke role (STS AssumeRole with refreshable credentials), restricted to an
approved-account allowlist and approved Regions. Writes native page JSON, an
`operations.jsonl` journal, `collection-summary.json`, `retry-requests.json`,
`checksums.sha256` and an immutable `AWS-EVIDENCE/` ZIP. The journal schema is still
`closec-provisional-0.3`; 0.3.1 only adds fields, so CloSec reads 0.3.0 and 0.3.1 packages
through the same adapter (`closec-v030-native-1`).

Organizations discovery additionally needs `organizations:ListAccounts` on the identity
running the script; the spoke-role permissions are unchanged.

## 0.3.1 corrections (demonstrated defects)

| Defect in 0.3.0 | Effect | Correction |
|---|---|---|
| `get_event_selectors` called with `Name` | ParamValidationError on every trail | uses `TrailName` |
| IAM policy-version enrichment inside the Regional loop | never executed | runs in the global phase, only when a default document is missing |
| `import resource` | collector cannot start on Windows | optional; peak RSS reported per OS |
| Prowler exit code 3 treated as failure | completed scans recorded PARTIAL/API_ERROR | exit 0 or 3 with output is COMPLETE |
| Non-paginatable responses with `NextMarker`/`NextToken` | silent truncation | PARTIAL; WAFv2 markers are followed |
| `ReplicationConfigurationNotFoundError`, `AWSOrganizationsNotInUseException` | absence journaled as API_ERROR | NOT_ENABLED |
| KMS calls used key UUIDs | key policies could not be correlated offline | key ARNs |
| No interruption handling | Ctrl+C left no summary | journal finalized with status INTERRUPTED, no ZIP |

Also added: `ec2:DescribeIamInstanceProfileAssociations`, `lambda:GetPolicy` per function,
the Organizations SCP chain (`ListParents`, `ListPoliciesForTarget`, `DescribePolicy`;
member accounts normally receive AccessDenied, which is journaled, never treated as "no
policy"), a 5,000-page bound per operation and `api_operation`/`truncation` journal fields.
The registry was validated offline against botocore 1.43.113 service models
(`tools/aws_registry_audit.py`).

## Prerequisites and permissions

Python 3.9+ with boto3/botocore on the approved collection host (the existing Linux/SSM
workflow is unchanged; Windows also works from 0.3.1). The spoke role needs read-only
access: AWS-managed `SecurityAudit` plus the two-action `CloSecReadOnlySupplement`
(`policies/member-supplement-policy.json`); see `AWS_COLLECTION_ACCESS.md`. Do not
grant administrative or write permissions. No object bodies, secret values or function code
are retrieved. Optional Prowler 5.x is supplementary and never proves coverage.

## Run (0.3.2: search, choose, evidence beside the script)

```sh
cp config.example.json config.json            # set approved Regions and the spoke role
cp approved_accounts.example.txt approved_accounts.txt   # recommended allowlist
python assessment.py collect --no-prowler
```

1. Type a search (account name or ID, blank for all). Accounts come from
   `organizations:ListAccounts` using your current read-only credentials (management or
   delegated-administrator account). If that is denied, the current account and the
   allowlist are offered instead.
2. Enter the list number. Accounts outside `approved_accounts.txt` are shown but refused.
   Without an allowlist you must retype the account ID to confirm authorization.
3. Type YES. Evidence is written to `evidence/` beside the script:
   `evidence/<AccountName>__<AccountID>__<run>/` and `<AccountName>__<AccountID>__<run>.zip`.

Options: `--search payments` skips the search prompt; `--account 123456789012` skips
selection (automation); `--config` points elsewhere; `output_directory` in config.json
overrides the evidence folder. `python assessment.py verify <run folder>` re-checks hashes.

Transfer the resulting ZIP unchanged to the CloSec workstation through the approved channel and import it
with **Import AWS Evidence ZIP**. Do not edit, rename or restructure files.

## Limits

Each registered operation is one bounded collection attempt; services not in the registry
are out of scope. ACCESS_DENIED, API_ERROR and NOT_COLLECTED rows are evidence gaps and are
never compliant. Resource control policies, effective SCP evaluation, Identity Center and
some dynamic per-resource detail remain uncollected. Real-account execution of 0.3.1 has not
been performed by the developer; it was exercised against a local AWS API emulator (moto)
with synthetic resources only. 0.3.3, the probe and the batch collector were exercised only
against an in-process synthetic fake of boto3 (`tools/fixtures/aws_fake_cloud.py`); request
parameters were not validated against botocore service models on this host.
