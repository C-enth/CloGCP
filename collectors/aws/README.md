# CloSec AWS collector 0.3.2

Downloaded as `CloSec_AWS_Collector_v0.3.2.zip`: one `CloSec_AWS_Collector/` folder with
`assessment.py`, this README, `config.example.json`, `approved_accounts.example.txt`, the
analyzer contract and `evidence/`, where each collected account's folder and ZIP are written.

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
access; AWS-managed `SecurityAudit` plus `ViewOnlyAccess` cover the registered calls. Do not
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
with synthetic resources only.
