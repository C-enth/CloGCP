# CloSec 0.7.0 — checklist-driven assessment release

Release identifier: **CloSec 0.7.0**, branch `feature/offline-security-analyzer`. The source
revision and SHA-256 hashes are in the release folder's `portable-manifest.json` and
`SHA256SUMS.txt`. Earlier releases (0.6.0 `03d083a`, 0.6.1 `e790c82`, 0.6.2 `bf90ab5`) are unchanged.

## 0.7.0 changes over 0.6.2

- **One checklist for AWS and GCP.** The approved workbook (unchanged, pinned hash) is the
  assessment plan for both clouds. Every control has a per-cloud applicability and outcome
  (FAIL / INSUFFICIENT EVIDENCE / MANUAL VALIDATION / NOT APPLICABLE / NOT ASSESSED; never an
  automatic PASS) and, for GCP, the evidence and check area. New **Assessment checklist**
  page; findings show checklist control, domain and subject; report gains a checklist sheet.
- **Classification fixed.** All 44 rules (AWS, GCP project, GCP organization) link to one
  checklist control; AWS additional observations (SEC-*) and GCP rules were unmapped.
- **GCP expanded-2.2 normalization fixed.** 2.2 packages were parsed as unsupported; org IAM
  search, BigQuery, logging settings and other expanded datasets are now typed.
- **Organization-wide GCP rules** (GCP-ORG-*): public serverless/data, Owner/Editor grants,
  hierarchy-level impersonation, cross-project service accounts, deleted principals,
  external domains (manual), workload identity federation (manual).
- **Cross-project and cross-cloud attack paths** (XP-01..03, XC-01..02), including AWS role
  -> GCP workload identity -> service account, correlated with imported AWS evidence.
- GCP rules report NOT_APPLICABLE when the collector observed the required API disabled.
- Severity calibration never raises baseline deviations and caps unconfirmed exposure at HIGH.
- **GCP collector 2.2.1**: when `projects.json` is missing or not JSON (the field error
  "Invalid JSON primitive: PROJECT_ID"), discovers projects read-only with
  `gcloud projects list --format=json` and saves them. Evidence format unchanged (2.2);
  the analyzer accepts collector 2.2.0 and 2.2.1. Parsed with PowerShell 7; discovery
  exercised with a stub gcloud. Not yet executed on Windows PowerShell 5.1 against GCP.
- Collector downloads are collector-named ZIPs, each one folder with README and working
  subfolders: `CloSec_AWS_Collector_v0.3.2.zip` (`evidence/`) and
  `CloSec_GCP_Collector_v2.2.1.zip` (`organization/`, `projects/`). GCP 2.2.1 defaults to
  those script-local folders; explicit `-ProjectsFile`/`-OutputRoot` still apply.
- AWS collector unchanged (0.3.2).

## 0.6.2 changes over 0.6.1

- **AWS collector 0.3.2**: search (account name or ID) over `organizations:ListAccounts`
  with the operator's read-only credentials, numbered selection, typed YES; accounts outside
  the allowlist are listed but refused; without an allowlist the operator retypes the
  account ID. Falls back to the current account when Organizations is unavailable. Evidence
  and the ZIP are written to `evidence/` beside the script, named
  `<AccountName>__<AccountID>__<run>`. `config.json` beside the script is the default.
- **GCP collector**: unchanged at 2.2.0 (as run in the field; no redesign).
- The analyzer accepts AWS collector 0.3.0–0.3.2; evidence formats are unchanged.
- Verified: AWS selection, allowlist refusal, typed-ID confirmation, Organizations
  fallback and a full collection against the local AWS emulator (synthetic organization).
  AWS 0.3.2 has not run against real AWS APIs.

## 0.6.1 changes over 0.6.0

- **Collectors in the application**: Evidence import → *1. Collect evidence* downloads AWS
  collector 0.3.1 (`closec_collector_v0.3.1.zip`, original flat layout), GCP collector 2.2.0,
  its README and the contract, each with its SHA-256; fixed allowlist, no path input.
- **SEC-EC2-SG-LATENT-EXPOSURE**: sensitive ports open to 0.0.0.0/0 or ::/0 with no in-use
  public interface are now a MEDIUM baseline-deviation candidate. R1-EC2-SG-SENSITIVE-INGRESS
  is unchanged (reachability semantics; PASS with latent note). No double counting: the
  observation is NOT_APPLICABLE when R1 evaluates an active exposure.
- Record counts show *Loading…* until data arrives (0.6.0 briefly showed "0 records").
- Repository: the PyInstaller Windows executable kit, the old pilot GCP collector,
  executable-only tests/tools and sprint-era documents are removed (ADR-007); the portable
  macOS/Windows application is the only delivery.

## Real GCP evidence (assessment-expanded-2.1, 145 datasets), release 0.6.0 GUI audit

Validate → Import and analyze → results → Dashboard → Findings Workbench → IAM → Evidence
Explorer → Excel on a clean extraction, ASSESSMENT workspace, 0 page errors, 0 outbound
requests: 145 datasets → 145 sources → 519 resources (580 observations) → 52 evaluations
(18 PASS, 1 FAIL, 16 UNKNOWN, 17 N/A) → 1 candidate finding; database, API, Dashboard,
Findings Workbench and Excel register each 1; Evidence Explorer 580. Only 25/145 datasets
were usable (39 ACCESS_DENIED, 61 API_DISABLED, 20 NOT_FOUND); the 16 UNKNOWN evaluations
must not be reported as compliant. Recollect with collector 2.2.0.

## Client reporting of rules without methodology mappings

The seven SEC observations (CloudTrail logging, CloudTrail management events, GuardDuty,
AWS Config, Security Hub, KMS rotation, latent internet ingress) are labelled additional
observations requiring analyst review. They appear as candidates and in the Excel register,
not in methodology control results; report them only after analyst approval, as additional
observations with technical (not business) severity.

## Gate 1 — diagnosis

**Stuck PACKAGE_READY workflow (field report).** The newest job was restored from history at
startup and rendered above every screen, so a completed *validation* became the main content
everywhere. Import existed only inside the import-screen preview, no page indicated a
validated-but-unimported upload, assessment was a third separate action, and the run picker
showed internal IDs. Fixed by the guided workflow (below) and demonstrated by
`tests/test_guided_workflow_browser.py` (validate → restart → pending import on every page →
Import and analyze → Open assessment results → refresh).

**Collector-to-analyzer mismatch matrix**

| Contract point | AWS collector v0.3.0 (actual) | Analyzer before 0.6.0 | 0.6.0 |
|---|---|---|---|
| Journal row status field | `outcome` | required `status` | native adapter reads `outcome` |
| Operation identity | `service` + boto3 snake_case | `service:PascalCase` regex | botocore-generated name table (135) |
| Response files | `files[]`, one per API page | single `path` | pages merged into derived artifact; page hashes kept |
| Error detail | `error{code,message}` | `error_code` | mapped; original retained |
| Defined absence (e.g. NoSuchPublicAccessBlock) | NOT_ENABLED, no file | needs error body artifact | derived AWS error body, labelled |
| Identity | `accounts/<id>/identity.json` | `sts:GetCallerIdentity` operation | bound as identity source |
| KMS subject | key UUID | key ARN required | resolved from same-package ListKeys |
| Package size | thousands of page files | 1,025 files / 1,024 rows | 20,000 files; byte limits unchanged |
| Result | **real packages rejected** (`FIELD_PROFILE_INCOMPLETE`) | | imported, assessed, reconciled |

| Contract point | GCP collector 2.1 HostFix | 0.6.0 |
|---|---|---|
| gcloud wait | unbounded `WaitForExit()` | bounded, process tree terminated, TIMEOUT |
| REST errors | no retry; 403 SERVICE_DISABLED → ACCESS_DENIED | bounded retry/refresh; API_DISABLED, QUOTA_PROJECT_DENIED |
| Missing list property | EMPTY | UNEXPECTED_SCHEMA |
| Discovery Engine | global host GET for every CAI name (403/404) | location endpoints, dataStores/engines only, per-location lists, unsupported types recorded |
| Integrity / interruption | none / no manifest | checksums.sha256; manifest with `collection_status` |
| Schema | `assessment-expanded-2.1` | `assessment-expanded-2.2` (2.1 still accepted) |

## Delivered

- **A. AWS collector 0.3.1** (`collectors/aws/`): eight demonstrated defects fixed; 131
  registered operations validated offline against botocore 1.43.113, 0 problems.
- **B. GCP collector 2.2.0** (`collectors/gcp/`): stabilization above; parsed with
  PowerShell 7.4.
- **C. Shared contract**: `collectors/collector-analyzer-contract.json` (generated, drift-tested).
- **D. Analyzer**: native AWS v0.3 adapter; `assessment-expanded-2.2`; six AWS service-state
  observations (CloudTrail logging and management events, GuardDuty, AWS Config, Security
  Hub, KMS rotation) as analyst-review SEC rules with recommendation templates.
- **E. Dashboard** (0.6.0): guided stepper on every page, pending-import actions, Import and analyze,
  Open assessment results, provider/scope run labels, distinct empty states, reconciliation
  panel in Report Center; AWS | GCP | Consolidated retained.
- **F. Pilot workspace**: start with an empty workspace folder labelled ASSESSMENT
  (`start-*` scripts); no synthetic data is bundled.
- **G. Portable distribution**: offline hash-locked wheelhouses for Windows x64, macOS
  arm64 and x86_64; all 22 Windows wheel hashes match the previously approved Windows lock.
- **I. Coverage**: `docs/ASSESSMENT_COVERAGE.md` — AWS: 23 operations evaluated, 19
  normalized, 89 retained unparsed; GCP: 12 families evaluated, 106 normalized metadata.
- **J. Operator instructions**: `docs/OPERATOR_GUIDE.md`.

## Reconciliation evidence (same run per table)

Synthetic native v0.3 package through the GUI (`tests/test_integrated_acceptance_browser.py`):

| Stage | Count | Status |
|---|---|---|
| Collector operations | 24 | PASS |
| Imported source evidence | 18 | PASS |
| Normalized resources | 12 | PASS |
| Rule evaluations | 16 | PASS |
| Candidate findings | 7 | PASS |
| API-returned findings | 7 | PASS |
| GUI-visible findings | 7 | PASS |
| Reported findings (Excel) | 7 | PASS |

Unmodified collector code run against a local AWS API emulator (moto, synthetic resources;
0.3.1): 153 journal attempts → 45 sources (109 retained unparsed) → 163 resources → 30
evaluations → 12 candidate findings → 12 API. The 0.3.0 collector on the same emulator
reproduced the CloudTrail `ParamValidationError`; the analyzer reports that rule as
COLLECTION_ERROR rather than a result.

Original `pilot-1.5` GCP evidence, processed locally (counts only): 63 sources, 160
observations (74 supported + 86 retained unsupported), 146 resources, 35 evaluations, 2
candidate findings, 2 API — unchanged from the previous baseline.

Field 145-dataset GCP outcome mix (structural fixture): SUCCESS 14, EMPTY 11, ACCESS_DENIED
39, API_DISABLED 61, NOT_FOUND 20 preserved exactly; no PASS without usable evidence.

## Test results (macOS, Python 3.12.14, 0.6.1 release candidate tree)

| Check | Result |
|---|---|
| Python regression (non-browser) | 673 passed, 0 failed |
| Browser workflows: real launcher, compiled GUI, DuckDB, Chromium/WebKit | 26 passed |
| Includes: guided PACKAGE_READY regression; AWS+GCP+Consolidated acceptance with reconciliation | passed |
| Collector downloads: listed SHA-256 equals downloaded bytes; AWS ZIP layout; no path input | passed |
| Frontend unit tests / TypeScript / build | 3 passed / clean / built |
| Ruff lint + format; collector contract drift check | clean / verified |
| AWS collector registry vs botocore 1.43.113 (offline) | 131 operations, 0 problems |
| Source security audit (tree, index, all history) | PASS, 0 findings |

R1 fixture truth table: 10 candidates (8 methodology candidates + 2 latent-ingress
observations); one latent case states that attachment is unknown because the
network-interface inventory is incomplete. Active and service-managed public exposures
remain with R1 (latent observation NOT_APPLICABLE).

## Not verified — disclosed limitations

- Corrected collectors were **not** run against real AWS accounts or GCP APIs; AWS ran
  against a local emulator, GCP was parsed only. Discovery Engine 403/404 resolution must be
  confirmed in the authorized environment.
- No real AWS v0.3 evidence or real `assessment-expanded-2.x` export was available here.
- **Native Windows was not tested.** The Windows wheelhouse and scripts were prepared and
  hash-checked on macOS only.
- `R1-EC2-SG-SENSITIVE-INGRESS` is reachability-based: 0.0.0.0/0 to a sensitive port with no
  in-use public interface is PASS with a "latent exposure" note. Review those notes.
- 89 AWS operations (for example Security Hub findings, ELB listeners, S3 encryption and
  logging, RDS clusters) are retained but not parsed or evaluated; they appear only in
  collection coverage.
- New SEC rules are outside the approved methodology mapping and require analyst review.

## Field-acceptance checklist

1. Verify `SHA256SUMS.txt`, extract, run `setup-windows.ps1` on the target Windows x64 host
   with Python 3.12 and no internet; confirm `pip check` passes and no download is attempted.
2. `start-windows.ps1` opens the GUI on loopback; record version 0.6.0 and the source revision.
3. Run AWS collector 0.3.1 for one approved account on the approved host; confirm the
   CloudTrail `get_event_selectors` rows are COMPLETE and review ACCESS_DENIED rows.
4. Run GCP collector 2.2.0 on the authorized Windows workstation; compare the status
   distribution with the 2.1 run (expect fewer ACCESS_DENIED/NOT_FOUND for Discovery Engine;
   any QUOTA_PROJECT_DENIED needs an approved `-QuotaProject` decision).
5. Import both with **Import and analyze** into a fresh ASSESSMENT workspace; open results.
6. Build the consolidated assessment; review AWS, GCP and Consolidated views.
7. Review, confirm, edit, approve and copy at least one finding per provider; export Excel
   and RTF.
8. Report Center → Assessment reconciliation: every stage PASS for each run.
9. Stop and restart CloSec; confirm the same run and provider are selected.
10. Record outcomes; do not transmit evidence or screenshots outside approved systems.
