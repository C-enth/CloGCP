# Methodology coverage

Status as of 2026-10-10. Agent inspection of the approved workbook was authorized by the
project owner for local model processing on 2026-10-10. This file records **IDs, counts
and engineering classifications only**. Source requirement text, criteria and narratives
stay in the private workbook and the private audit outputs (`artifacts/`, ignored).

## 1. Verified methodology inventory
| Item | Value (derived from the workbook, not assumed) |
|---|---|
| Location | `data/private/` (ignored): one XLSX, the only methodology file present |
| SHA-256 | `a9d7ef1b075fa1eab9ea12cce654dc8ce65543bad810e8e233e7bb30761ae3cd` (unchanged before/after every run; equals the Phase 0 baseline) |
| Size / sheets | 392359 bytes / 17 worksheets; no macros, external links or embeddings (preflight) |
| Controls | 204 = 176 `original-checklist` (IDs `n.n.n`) + 28 `added-main-prompt` (`AWS-01`..`AWS-28`); no duplicates; `1.1.1` absent |
| STRIDE scenarios | 20 (`TS-01`..`TS-20`) |
| Attack paths | 30 (`AP-01`..`AP-15` original, `AP-16`..`AP-30` AWS-native) |
| Adversary scenarios | 22 (`AS-01`..`AS-22`), 22 MITRE rows, 20 SEBI CSCRF scenario mappings |
| Accounts | 143 placeholder keys `ACCT-001`..`ACCT-143`; no 12-digit IDs, environments, OUs or owners filled |
| Live tracker sheets | Account Control Results, Findings Register, Technical Evidence, STRIDE Validation, Attack Path Validation: all empty (formula column in Findings Register preserved) |

The workbook is a consolidation of four earlier workbooks (documented in its own Source
Reconciliation sheet). It is the single authoritative source; no conflicting duplicate
version exists locally. The previously reported counts (204/20/30/22/143) are now
**verified** by `offline_analyzer.methodology.audit` and its declared-count check.

Authoritative component by sheet: Control Library (controls, criteria, collection,
automation, severity/priority, AP/threat links), STRIDE Threat Library (scenarios),
Attack Path Library (paths), Adversary Scenarios + Kill Chain & MITRE + SEBI CSCRF Map
(scenario context), Data Dictionary + `_Lists` (vocabularies), live sheets (tracker).

## 2. Methodology inconsistency report
Automated checks (`AUD-*`) are re-run by the audit; hand-reviewed items are `MR-H*` in
`methodology/coverage_spec.py`. Nothing below is repaired in the source or in code.

| ID | Sev | Issue (IDs only) | Effect on automation |
|---|---|---|---|
| AUD-01 | High | 176 original controls share **7** criteria sets (group sizes 37/31/29/28/26/13/12) | Original criteria are category templates, not control-specific |
| AUD-02 | High | One identical validation instruction for all 176 originals | No per-control validation procedure |
| MR-H01 | High | Template topic mismatch for 18 controls: 1.1.3 1.3.3 1.3.5 1.3.7 1.4.1 1.4.2 1.4.7 1.5.3 1.5.5 1.5.6 1.6.5 1.6.6 1.7.3 1.7.4 1.8.3 1.9.1 1.9.4 1.9.6 | e.g. IMDS control carries secrets-scan criteria |
| AUD-03 | Med | SEBI Ref empty for all 204 controls; SEBI only at scenario level | No control-level SEBI mapping can be reported |
| AUD-04 | High | STRIDE library "Checklist IDs" empty for all 20 scenarios (source sheet claims they were preserved) | Threat→control links exist only in reverse |
| AUD-05 / MR-H12 | Low | Links use `#N`; IDs are `TS-NN` | Equivalence assumed; confirmation required |
| AUD-06 | Med | No threat link for all 28 AWS-nn controls and 18 originals | AWS controls cannot be traced to STRIDE scenarios |
| AUD-07 | Med | AP control lists disagree with control-side links: AP-05 16 17 18 19 23 25 27 29 30 | Mapping direction must be chosen by owner |
| AUD-08 | Med | AP-01..AP-15 list no controls (except AP-05) | Reverse links only |
| AUD-09 | Med | AP-30 cited by no control | Orphan path |
| AUD-10 | Low | 17 paths (AP-01, AP-08, AP-16..AP-30) have no threat link | |
| AUD-11 | High | AS-21/AS-22 reference XD-04/XD-03, absent from the path library | Scenarios cannot resolve to a path |
| AUD-12 | Med | Control 1.1.1 missing (source labels 177 vs 176 distinct) | Confirm no control was lost |
| AUD-14 | Low | AWS-nn: exploitability 28/28 and attack phase 27/28 unpopulated | |
| AUD-15 / MR-H11 | High | 143/143 accounts lack 12-digit IDs; tracker account column only accepts placeholders | Results cannot be keyed to tracker rows without an approved key map |
| AUD-16 | Low | STRIDE Validation status vocabulary: dictionary vs dropdown differ | |
| AUD-17 | Low | Dictionary fields not matching sheet headers (Account Inventory status; two Findings Register fields) | |
| AUD-18 / MR-H13 | Low | Scenario→threat link only by `D#-0NN` ordinal (STRIDE-consistent for all 20) | Inferred, not explicit |
| AUD-20 | Info | Severity/priority matrix (e.g. 29 Critical at P2, 1 High at P4) | Reported, not changed |
| MR-H02..H04 | Med | AWS-15: port list open-ended; HTTP carve-out assumed; approved CIDR list absent | Rule routes these to MANUAL |
| MR-H05..H06 | Med | AWS-04: MFA/OrgPaths status unclear; third-party test needs org account list | Rule routes these to MANUAL |
| MR-H07 | Med | AWS-22 "strong/weak auth" undefined | Not automated |
| MR-H08..H09 | Med | PASS clauses combine automatable and non-automatable criteria; org-wide claims need all-account evidence | No control-level Pass is emitted |
| MR-H14 | Med | AWS-19 unguarded PassRole interpreted as any role without PassedToService binding | Owner review required; source wording preserved in private audit |
| MR-H10 | Med | Tracker granularity (per account vs per resource) and import-writable columns ambiguous | Tracker staging keeps evidence in separate reference columns |

## 3. Control-to-evidence classification (all 204)
Generated from `src/offline_analyzer/methodology/coverage_spec.py` (spec 1.3.0, pinned to
the hash above). The private audit joins it with source text in
`methodology-audit.xlsx` → *Control Evidence Matrix* (evidence operations, reasons,
template group, related AWS-nn control, rules, source location per control).

| Status | Count | Control IDs |
|---|---|---|
| IMPLEMENTED_AND_VERIFIED | 0 | none (no real-export validation yet) |
| IMPLEMENTED_REQUIRES_VALIDATION | 0 | none at control level (sub-criteria only) |
| PARTIALLY_IMPLEMENTED | 10 | AWS-04 AWS-07 AWS-08 AWS-09 AWS-10 AWS-11 AWS-12 AWS-15 AWS-19 AWS-22 |
| NOT_IMPLEMENTED | 11 | AWS-05 06 13 14 18 20 23 24 25 26 27 |
| BLOCKED_BY_MISSING_EVIDENCE | 9 | 1.3.6 1.8.2 1.9.5 2.5.2 AWS-01 AWS-02 AWS-03 AWS-16 AWS-21 |
| REQUIRES_METHODOLOGY_CLARIFICATION | 80 | AWS-relevant originals with template criteria (1.1.3 … 8.4.2; full list in the spec) |
| MANUAL_VALIDATION_REQUIRED | 38 | process/SIEM/interview/active testing (incl. AWS-17, AWS-28) |
| OUTSIDE_CURRENT_AWS_SCOPE | 56 | GCP, AD, Entra ID, on-premises, network devices, repositories |

An original control is never reported as covered because a similar AWS-nn rule exists:
e.g. 1.3.2/1.5.2 relate to AWS-15 but keep REQUIRES_METHODOLOGY_CLARIFICATION until the
owner approves control-specific criteria.

### Criterion keys for mapped controls (engineering paraphrase; source text is authoritative)
| Key | Meaning | Rule |
|---|---|---|
| AWS-04:P1 / F1 | Cross-account trust carries PrincipalOrgID/ExternalId / wildcard or account-root trust with no condition | R1-IAM-ROLE-TRUST-CONDITIONS 1.2.0 |
| AWS-04:P2, F2 | Access Analyzer external findings / third-party role without ExternalId | not evaluated |
| AWS-07:P1.validation / F2 | Log-file validation enabled / disabled | R0-CLOUDTRAIL-VALIDATION 1.3.0 |
| AWS-07:P1.org-multi-region, P2–P4, F1, F3, F4 | Org multi-region trail, event scope, StopLogging SCP, immutable bucket | not evaluated |
| AWS-11:P1 / F1 | Account-level Block Public Access fully on / off or absent | R1-S3-ACCOUNT-BPA 1.1.0 |
| AWS-11:P2 / F2 | No public bucket / effective anonymous access (policy status or ACL not restricted by either BPA level) | R1-S3-BUCKET-PUBLIC-ACCESS 1.1.0 |
| AWS-11:P3, F3–F4 | Classification, Principal:* GetObject specifics, cross-account wildcard | not evaluated |
| AWS-15:P1 / F1 | No listed sensitive port open to 0.0.0.0/0 on internet-facing resources / open and attached to a public interface | R1-EC2-SG-SENSITIVE-INGRESS 1.2.0 |
| AWS-15:P2, V-NACL | Approved-CIDR restriction; NACL assurance | not evaluated (public CIDRs → MANUAL) |
| AWS-19:P1 / F1 | IMDSv2 required / IMDSv1 allowed | R0-EC2-IMDSV2 1.3.0 |
| AWS-19:P2 / F2 | Hop limit 1 / greater than 1 | R1-EC2-IMDS-HOP-LIMIT 1.1.0 |
| AWS-19:P4 / F3 | Instance role excludes Action:* and unguarded PassRole / either pattern present | R1-IAM-INSTANCE-ROLE-PRIVILEGE 1.0.0 (MR-H14) |
| AWS-19:P3 | General instance-role least privilege | not evaluated |
| AWS-22:P1 / F1 | Not publicly accessible / PubliclyAccessible=true | R1-RDS-PUBLIC-ACCESS 1.2.0 |
| AWS-22:P2 / F2 | Storage encrypted / unencrypted | R0-RDS-ENCRYPTION 1.3.0 |
| AWS-22:P3–P4, F3–F4 | Authentication strength, public snapshots | not evaluated |

All mappings are `PROPOSED` (engineering-reviewed, awaiting methodology-owner approval).
R1.1 re-verified every mapped clause against the workbook; predicates, classification and
evidence requirements per rule are in docs/RULE_SPECIFICATIONS.md.
Results carry `methodology_id`, `methodology_criteria` and `methodology_sha256`.

## 4. STRIDE mapping inventory
| Scope | Scenarios | AWS-evaluable prerequisites (via paths) |
|---|---|---|
| AWS | TS-01 TS-02 TS-03 TS-04 TS-05 TS-08 | TS-01: AP-04.P1/P2 (implemented); TS-02: AP-05.P1 (implemented), P2–P4; TS-03: AP-04.P2, AP-06.P1/P4; TS-04: AP-03.P1–P3; TS-05: AP-22.P1–P2; TS-08: AP-06.P2 (implemented), P1 |
| Partial AWS | TS-10 TS-14 TS-15 | AP-07.P1–P3; AWS WAF (AWS-18); AP-03.P3 |
| Outside AWS | TS-06 07 09 11 12 13 16 17 18 19 20 | AD, Entra ID, PAM, firewalls, VPN, switches, hypervisor, on-prem backup |

The private *STRIDE Inventory* sheet adds asset, entry point, trust boundary, preconditions,
risk and reverse-linked controls from source.

## 5. Attack-path prerequisite matrix
Specification: `src/offline_analyzer/attack_paths/specs.py` (1.1.0). Kinds: CONFIG,
IAM_ENGINE, REACHABILITY, ORG_EVIDENCE, CLASSIFICATION, DETECTION, MANUAL, EXPLOITATION.
EXPLOITATION prerequisites are hypotheses and are never automatically verified, so no
path can reach SUPPORTED from configuration evidence.

| Path | Scope | Implemented prerequisite evaluation | Remaining prerequisite kinds |
|---|---|---|---|
| AP-04 | AWS | P1 public sensitive-port exposure + P2 IMDSv1 correlated per instance | P3 EXPLOITATION; P4 instance-role evaluation implemented |
| AP-05 | AWS | P1 account BPA; all four settings on → BLOCKED (anonymous public variant) | P2–P3 CONFIG (adapter missing), P4 CLASSIFICATION |
| AP-06 | AWS | IAM transitions and PassRole prerequisite records implemented; no supported path | EXPLOITATION and unresolved authorization context |
| AP-02, AP-29 | AWS | P4/P2/P2 unconditioned trust (rule exists; no correlator yet) | ORG_EVIDENCE, IAM_ENGINE, EXPLOITATION |
| AP-19 | AWS | P1 PubliclyAccessible (rule exists; no correlator yet) | REACHABILITY, MANUAL |
| AP-01 03 07 08 16–18 20–28 | AWS/partial | none | see spec |
| AP-15, AP-30 | Partial | none | CLASSIFICATION, DETECTION, REACHABILITY |
| AP-09–AP-14 | Outside | n/a | AD/Entra/on-prem/network devices/VPN |

Correlated records appear in the report sheet *Attack Path Prerequisites* with per-key
status (VERIFIED, NOT_PRESENT, UNKNOWN, NOT_EVALUATED), blockers and supporting
evaluation IDs. AS-21/AS-22 cannot be linked (AUD-11).

## 6. Evidence collection requirements (priority order)
Supported adapters: ec2 DescribeInstances/DescribeSecurityGroups/DescribeNetworkInterfaces,
rds DescribeDBInstances, cloudtrail DescribeTrails, iam GetAccountAuthorizationDetails or
ListRoles, s3control GetPublicAccessBlock (+ Prowler 5.10 OCSF for two checks). Collect
full, unfiltered, paginated exports per account and Region with `request_parameters`
recorded; IAM/S3-account once per account. Interface evidence is required for any
security-group conclusion beyond UNKNOWN. Missing evidence by number of controls that
need it (private *Evidence Requirements* sheet): Organizations policy/target/account
exports 13 (management or delegated-admin account only; the collector VM may not have
this), `iam:GetCredentialReport` 10, `ec2:DescribeVpcs` 4, then 3 each for Access
Analyzer findings, route tables, ECS task definitions, Inspector findings, KMS rotation,
S3 bucket policy and Object Lock. Config/GuardDuty/Security Hub status are each needed by
one whole AWS-nn control (AWS-08/09/10). Lambda/ECS environment and EC2 user data must arrive as
collector-side redacted secret-scan results: raw values are rejected by the importer.

## Private audit workflow
```sh
.venv/bin/python -m offline_analyzer.methodology.audit data/private/<workbook>.xlsx artifacts/methodology-audit-YYYY-MM-DD
```
New ignored output directory only; prints counts. Outputs: `inventory.json`, `audit.json`,
`methodology-audit.xlsx` (Inventory, Inconsistencies, Control Evidence Matrix, STRIDE
Inventory, Attack Path Matrix, Adversary Scenarios, Evidence Requirements). Layout changes
fail closed (`LAYOUT_HEADER_MISMATCH:<table>`). A changed workbook hash fails the
reconciliation check until the specs are re-reviewed (`AUD-19`). Latest run:
`artifacts/methodology-audit-2026-10-10` (31 issues; AUD-19 and AUD-13 absent).

R1.2 adds IAM evaluation without changing the six partially implemented control counts.
All mappings remain PROPOSED; missing evidence and subset evaluations cannot establish
a control-level Pass. See docs/IAM_EVALUATION.md.

## 0.5.0 provider-aware visibility

The unchanged authoritative workbook was inspected locally and reconciles all 204 controls
with the pinned source hash. The GUI and JSON/Excel matrix retain original IDs, existing
AWS implementation classifications and separate GCP implementation records across nine
shared security domains. GCP source-clause mappings remain UNRESOLVED_PROVIDER_MAPPING;
no AWS-native source row was reused for an unrelated GCP condition. All 15 GCP rules are
additional technical criteria until a reviewed clause mapping is available (superseded in
0.7.0: see the shared cloud checklist section below). Domain
alignment, a parser or a resource count does not establish methodology coverage or PASS.
Original coverage_spec.py, methodology_links.py and source attack-path specs are unchanged.

## 0.7.0 shared cloud checklist (AWS and GCP)

The approved workbook is the single assessment checklist for both clouds
(`methodology/cloud_checklist.py`). It records, per control ID: an engineering paraphrase
of the control subject (source text stays in data/private), applicability (AWS, GCP, both,
or outside cloud evidence: directory, Entra ID, on-premises, network devices, active
scanning) and, for every GCP-applicable control, the GCP evidence operations and check
area an analyst uses.

Every executable rule (19 AWS, 15 GCP project, 10 GCP organization) now links to exactly
one checklist control (`rules/methodology_links.py`). Links added in 0.7.0 use
check-area criteria keys `<control>:CA.<topic>`: they classify a finding under the control
whose fail indicator it meets and never claim a source P/F clause or full coverage. The
private reconciliation (AUD-19) checks every link (AWS and GCP) against the workbook's
attack paths, STRIDE category and inherent severity. `SEC-EC2-SG-LATENT-EXPOSURE` maps
to 1.5.2, not AWS-15, because AWS-15 fails only on a public interface.

Control outcome per cloud (`matrix`): FAIL when any linked rule fails; MANUAL VALIDATION
when linked rules pass (remaining criteria are not automated) or no rule exists;
INSUFFICIENT EVIDENCE when linked rules lack evidence; NOT APPLICABLE outside the cloud's
evidence or when the service is verified not enabled; NOT ASSESSED when the run has no
evidence for that cloud. No control is ever reported PASS automatically.

Tests: tests/test_cloud_checklist.py (synthetic organization), tests/test_r1.py,
tests/test_methodology_audit.py (private reconciliation, local only).

## GCP configuration increment (2026-10-16)

The workbook supplied again by the owner matches the pinned SHA-256 and contains **204**
controls, not the 219 mentioned in the enhancement prompt. The source remains unchanged.
Coverage spec **1.4.0** adds separate `GCP_CONFIG_COVERAGE` records for 23 partial criteria
under 13 existing control IDs. Source AWS classifications and attack-path prerequisites
are retained. All new links are PROPOSED check-area mappings, never full clause coverage.
See [the explicit matrix](docs/GCP_CONFIGURATION_COVERAGE.md). The checklist JSON adds
implementation status and GCP evidence operations; UNKNOWN and manual results remain
visible and partial inapplicability cannot dismiss the broader mapped control.
