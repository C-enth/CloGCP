# AWS analysis readiness (read-only review, 2026-10-19)

Branch `feature/offline-security-analyzer`, working tree as found (uncommitted changes preserved).
Evidence: code reading plus synthetic runs in a scratch workspace outside the repository. No real
workspace or evidence was opened; no code, test, config or collector file was changed.
**VERIFIED** = read in code and/or reproduced on synthetic data; **INFERRED** = deduced from code,
not exercised. Synthetic results never count as real-export compatibility (AGENTS.md).

## 1. AWS rules (19)

Source: `rules/registry.py:ALL_RULES` (VERIFIED by enumerating it). "IAM eval" = uses
`iam/evaluator.py` via `EvaluationContext.iam`. Severity is the rule default; FAIL verdicts may
override class/severity (`rules/engine.py:risk_context`).

| Rule | Tests | Severity logic | Datasets (primary + context) | IAM eval |
|---|---|---|---|---|
| R0-EC2-IMDSV2 | HttpTokens=optional | MEDIUM, state note if not running (`configuration.py:instance_state_context`) | ec2:DescribeInstances | No |
| R0-RDS-ENCRYPTION | StorageEncrypted=false (Aurora → UNKNOWN) | MEDIUM | rds:DescribeDBInstances | No |
| R0-CLOUDTRAIL-VALIDATION | LogFileValidationEnabled=false | LOW | cloudtrail:DescribeTrails | No |
| R1-EC2-SG-SENSITIVE-INGRESS | 0.0.0.0/0 to listed port on in-use public ENI | HIGH with IGW route, MEDIUM route missing, LOW no route (`network.py:exposure_verdict`) | SGs + ENIs, route tables | No |
| R1-IAM-ROLE-TRUST-CONDITIONS | Cross-account trust without OrgID/ExternalId | Registry and RCP state; CRITICAL only with supported privilege (`iam_trust.py:classify_failure`) | GAAD / ListRoles / GetRole | Yes (privilege, RCP) |
| R1-S3-ACCOUNT-BPA | Account BPA flags off/absent | MEDIUM baseline | s3control:GetPublicAccessBlock | No |
| R1-S3-BUCKET-PUBLIC-ACCESS | Public policy/ACL not blocked by either BPA level | HIGH potential exposure | GetBucketPolicyStatus + bucket BPA, ACL, account BPA | No |
| R1-RDS-PUBLIC-ACCESS | PubliclyAccessible=true | HIGH/MEDIUM/LOW by SG + route (`r1.py:public_database_exposure`) | DescribeDBInstances + SGs, routes | No |
| R1-EC2-IMDS-HOP-LIMIT | Hop limit > 1 | LOW baseline | ec2:DescribeInstances | No |
| R1-IAM-INSTANCE-ROLE-PRIVILEGE | Instance role with Action:* or unguarded PassRole | HIGH supported gap / HIGH-MEDIUM potential / LOW (`iam_privilege.py:instance_role_privilege`) | GAAD + policy versions, profiles | Yes (PassRole) |
| SEC-IAM-ROLE-WILDCARD | Non-instance role with Allow Action:* | MEDIUM potential | GAAD + per-role IAM calls | Pattern only |
| SEC-KMS-WILDCARD-PRINCIPAL | Unconditioned Principal * on kms:* | HIGH potential | kms:GetKeyPolicy | Parser only |
| SEC-EC2-SG-LATENT-EXPOSURE | Sensitive port open, no in-use public ENI | MEDIUM baseline | SGs + ENIs | No |
| SEC-CLOUDTRAIL-LOGGING | IsLogging=false | HIGH | cloudtrail:GetTrailStatus | No |
| SEC-CLOUDTRAIL-MANAGEMENT-EVENTS | No management write selector | MEDIUM | cloudtrail:GetEventSelectors | No |
| SEC-GUARDDUTY-ENABLED | No ENABLED detector in Region | MEDIUM | ListDetectors + GetDetector | No |
| SEC-CONFIG-RECORDING | No recording recorder | MEDIUM | DescribeConfigurationRecorderStatus | No |
| SEC-SECURITYHUB-ENABLED | Hub absent (InvalidAccessException) | INFO | securityhub:DescribeHub | No |
| SEC-KMS-ROTATION | CMK rotation off | LOW | kms:DescribeKey + GetKeyRotationStatus | No |

Only the R0 rules are ungated; every other rule reports scope gaps only when its evidence family
was supplied (`engine.py:supplied_rules`; test `test_r1.py::test_global_scope_and_family_gating`).

## 2. IAM evaluator

| Policy type | Status | Evidence |
|---|---|---|
| Identity (managed + inline) | Evaluated, three-valued | `evaluator.py:evaluate_identity`; `test_iam.py::test_action_and_resource_semantics` VERIFIED |
| Permissions boundary | Evaluated; missing document → UNKNOWN | `evaluate_identity`; `test_iam.py::test_explicit_deny_and_boundary` VERIFIED |
| SCP | Evaluated along evidenced hierarchy; service-linked roles and management account → NOT_APPLICABLE | `organizations.py:OrganizationModel.evaluate`; `test_iam.py::test_scp_applicability_and_inheritance` VERIFIED |
| RCP | Cross-account AssumeRole target only; principal `*` only | `evaluator.py:evaluate_assume`, `rcp_principal` VERIFIED |
| Trust policy | Cross-account AssumeRole only; same-account excluded | `evaluate_trust`, `evaluate_assume` VERIFIED |
| Trust conditions (rule) | Binding = OrgID/ExternalId with positive operators | `iam_trust.py:conditions`; `test_r1.py::test_trust_condition_truth_table` VERIFIED |
| Session policies | Declared not evaluated (note on each decision) | `evaluator.py:SESSION_NOTE`; docs/IAM_EVALUATION.md VERIFIED |
| Resource-based (S3/KMS/Lambda) | Declared out of scope | docs/IAM_EVALUATION.md "Unsupported" VERIFIED |
| Users, groups | Not modelled (roles only) | `iam/model.py:KINDS` VERIFIED |
| Numeric/date/IP/set operators, variables, NotPrincipal | Never a supported Allow | `policy.py:evaluate_condition`; `test_iam.py::test_unsupported_semantics_never_become_allowed` VERIFIED |

## 3. Attack paths

30 specs (`attack_paths/specs.py:PATHS`); 6 are OUTSIDE_CURRENT_AWS_SCOPE (AP-09..14). **Only AP-04,
AP-05 and AP-06 produce records** (`prerequisites.py:path_records`) VERIFIED.

| Path | Builder / prerequisites set | Hop model | STRIDE | FP handling |
|---|---|---|---|---|
| AP-04 | SG-ingress FAIL (P1) + IMDSv2 (P2) + instance-role privilege (P4); P3 exploitation never set | 3 hops (`model.py:AWS_CHAINS`), PROVEN only with source records | From linked findings (Spoofing/EoP) + TS-01, TS-03 | Flagged and uncounted when a linked finding is excluded (VERIFIED §5) |
| AP-05 | Account BPA (P1); bucket FAIL sets P2+P3; P4 classification never | 2 hops | Information Disclosure; TS-02 | As AP-04 |
| AP-06 | PassRole investigations → P1, P4; **P2 never set** | 2 hops, hop 1 ANY(P1,P2) | **Empty**: records cite no findings | **Cannot be excluded through a finding**: no `finding_ids`; only path review |

- **AP-06 cannot reach FEASIBLE.** `aws_feasibility` requires every checkable prerequisite VERIFIED, and AP-06.P2 (CONFIG) is never populated by `prerequisites.py:iam_escalation`. VERIFIED (all AP-06 records INSUFFICIENT_EVIDENCE in every synthetic run). So AP-06 severity calibration never fires.
- **No AWS path can be SUPPORTED/PROVEN end-to-end.** Exploitation prerequisites are never verified, by design. VERIFIED: `test_r1.py::test_attack_path_records_never_claim_support`.
- **Hop rules.** No PROVEN hop without a cited record (`test_attack_path_hops.py::test_no_proven_hop_without_a_source_record`) and BLOCKED propagation (`::test_any_blocked_hop_blocks_the_path`) VERIFIED.

## 4. Platform-managed identities (synthetic)

Synthetic member account plus management account; DescribeOrganization collected, hierarchy not
(the typical member-account collection). Run with and without the registry and with and without an
exported AdministratorAccess document. All VERIFIED by synthetic run.

| Identity | Rules firing | Paths | Why |
|---|---|---|---|
| Service-linked role (synthetic AutoScaling-shaped policy with unconditioned PassRole) | none fail (wildcard PASS, trust N/A) | **AP-06 record**, P4 VERIFIED | SCP is NOT_APPLICABLE to SLRs (`organizations.py:applicability`), and `analysis.py:passrole` treats the SLR as an attacker-controllable principal |
| AWSReservedSSO_* (SAML trust, AdministratorAccess) | SEC-IAM-ROLE-WILDCARD FAIL MEDIUM if the doc is exported, else UNKNOWN | AP-06 if the doc is exported | Federated trust ignored by the trust rule (`iam_trust.py:aws_principals`); Action:* matched by `security_observations.py:role_wildcard` |
| OrganizationAccountAccessRole (management root, no condition) | Trust FAIL: **POTENTIAL_EXPOSURE HIGH** without registry, BASELINE MEDIUM with registry; wildcard FAIL/UNKNOWN as above | AP-06 if the doc is exported | `classify_failure` uses only the registry, **not** `OrganizationModel.management_accounts` |
| AWSControlTowerExecution | Identical to the row above | AP-06 if the doc is exported | Same |
| Customer roles trusting lambda / ec2 (admin) | SEC-IAM-ROLE-WILDCARD FAIL (lambda); R1-IAM-INSTANCE-ROLE-PRIVILEGE FAIL HIGH (ec2); UNKNOWN without the doc | AP-06; AP-04.P4 UNKNOWN | Expected; privilege stays POTENTIALLY_PRIVILEGED without SCP evidence |
| Service trust with aws:SourceAccount; SLR without PassRole | none (N/A) | none | Service-principal trust is outside AWS-04 |
| Mixed Service + management AWS principal | Trust FAIL MEDIUM (LOW with registry) | none | AWS principal part evaluated |

**Systemic effect.** Without SCP hierarchy evidence, no role reaches ADMIN_EQUIVALENT
(`analysis.py:privilege` needs ALLOWED). So every admin role becomes a PassRole principal with
POTENTIAL_ESCALATION records and an AP-06 record. In the admin-document variant that was 6 AP-06
records from 9 roles, all platform or admin roles. VERIFIED.

## 5. Shared fixes on AWS synthetic data

Two accounts × two Regions, three imports, enterprise snapshot, one AWS finding marked FALSE_POSITIVE.

| Check | Result | Evidence |
|---|---|---|
| Dashboard counts/severity | Removed (candidates 8→7, excluded 1, HIGH 2→1) | `reporting/cloud.py:dashboard` VERIFIED |
| Dashboard STRIDE | Path counts drop (3→1); dependent AP-04 flagged `excluded_dependency`. "Evaluations" counts unchanged by design | `cloud.py:dashboard`, `feasibility.py:attack_paths` VERIFIED |
| Tracker Staging | Finding ID removed; rows remain per control | `tracker.py:tracker_rows` VERIFIED |
| Overview | AWS-only overview = dashboard provider summary (correct). "Cloud Overview" sheet only built when GCP data exists | `excel.py:_export_excel`, `multicloud.py:sheets` VERIFIED |
| Findings/Review sheets | Removed; listed under "Excluded Findings" | VERIFIED |
| Enterprise Security Gaps | Issues with only excluded findings hidden | `queries.py:VISIBLE_ISSUE`; `test_phase3_defaults.py::test_enterprise_issues_with_only_excluded_findings_are_not_counted` VERIFIED |
| **Enterprise Account Summary "Findings"** | **Not reduced (4→4)** | `enterprise/queries.py:EnterpriseViews.accounts` has no exclusion filter. VERIFIED **gap** |
| Cross-Account Relationships / Shared Network / Evidence Gaps | Excluded finding ID still in "Related findings" | `reporting/enterprise.py:enterprise_sheets` VERIFIED (minor) |
| Report scope default | `confirmed` (model and API body) | `assessment_report.py:model`, `api/app.py` request model; `test_phase3_defaults.py::test_report_scope_defaults_to_confirmed_with_a_cover_notice` VERIFIED |
| Snapshot latest import, one account per import | Older import superseded | `snapshot.py:superseded_imports` VERIFIED |
| **Snapshot, multi-account or narrower re-collection** | **Stale data enters.** Key is partition+account+**Region** (`refresh.py:import_scope_key`) and whole runs are copied (`build_snapshot`). An old A+B import stayed a member for B, so A's stale snapshot conflicted with newer data and a resolved result became UNKNOWN ("Native snapshots disagree") | VERIFIED **gap** |
| Grouping, IAM | Role ARN (account-qualified) keeps same-named roles apart | `groups.py:group_key` VERIFIED |
| **Grouping, security groups** | Key is the bare `sg-…` ID (no account/Region): identical IDs in two accounts merged into one group | VERIFIED on colliding synthetic IDs; real collision INFERRED unlikely |

## 6. Collector contract (AWS 0.3.2)

| Item | Status | Evidence |
|---|---|---|
| Datasets | 131 (18 global, 77 regional, 36 dependent); 23 EVALUATED, 19 NORMALIZED only, 89 retained unparsed | `collectors/collector-analyzer-contract.json` VERIFIED |
| Services | 37 (IAM, EC2, S3, RDS, KMS, CloudTrail, Config, GuardDuty, Security Hub, Organizations, …) | Same |
| Regions | Operator `--regions` ⊆ config `approved_regions`, and each must be enabled, else abort | `collectors/aws/assessment.py:main` VERIFIED |
| Permissions | Read-only spoke role; README states SecurityAudit + ViewOnlyAccess | `collectors/aws/README.md` VERIFIED (permission sufficiency INFERRED) |
| Version acceptance | 0.3.0, 0.3.1, 0.3.2; otherwise `COLLECTOR_VERSION_PROFILE_UNSUPPORTED` | `collector_v030_native.py:VERSIONS`; `test_collector_v030_native.py::test_collector_contract_and_coverage_matrix_are_current` VERIFIED |
| Integrity | checksums.sha256 must list every file; tamper fails closed | `test_collector_v030_native.py::test_native_package_rejects_tampering` VERIFIED |
| Missing Region | Declared target with no source → UNKNOWN scope rows (supplied families plus R0) | synthetic run; `engine.py:scope_result` VERIFIED |
| Denied service | ACCESS_DENIED → coverage ERROR → COLLECTION_ERROR row, never PASS | synthetic run VERIFIED |
| Defined absence | NoSuchPublicAccessBlockConfiguration, InvalidAccessException, NoSuchBucketPolicy, AWSOrganizationsNotInUse → configuration state | `ingestion/coverage.py:DEFINED_ABSENCE` VERIFIED |
| Coverage reason codes | `ACCESS_DENIED_FOR_THIS_ATTEMPT_SERVICE_STATE_UNKNOWN`, `COLLECTOR_REPORTED_NOT_ENABLED_<code>`, `NOT_COLLECTED_<code>`, `AWS_DEFINED_CONFIGURATION_ABSENCE`, `EVENT_SELECTOR_COVERAGE_UNKNOWN_RECOLLECT_WITH_COLLECTOR_0_3_1`, `PROWLER_NONZERO_EXIT_…`, `COLLECTOR_OUTCOME_PRESERVED` | `collector_v030_native.py:interpretation` VERIFIED |
| **SCP/RCP collection** | SCP chain only (no RCP, no ListPolicies); **root-attached SCPs are listed but `describe_policy` is not called** | `assessment.py:organization_scope` VERIFIED by reading; effect INFERRED (root content → UNKNOWN unless also attached lower) |

## 7. Scale (synthetic, 100 accounts, this Mac, single process)

Standard workload: `tools/fixtures/scale.py:generate` (25 resources × 2 Regions, 16 accounts/shard).
Stress workload: 40 roles/account, org-bound wildcard trusts and broad PassRole.

| Stage | Standard | Stress | >30 s |
|---|---|---|---|
| Per-shard import / assess | 0.9–4.4 s / 3.0–18.3 s | 0.1–1.0 s / 3.1–9.7 s | no |
| Snapshot build | 2.8 s | 0.3 s | no |
| **Snapshot assess** | **≈200 s** (200.6, 196.3 on reruns) | 38.0 s | **yes** |
| Correlate | 6.6 s | 27.2 s | no |
| Attack paths / dashboard | 14.9 s / 21.6 s | 4.5 s / 7.5 s | no |
| **Excel export** | **61–63 s** | **62.1 s** | **yes** |
| Observations / findings / edges | 26,607 / 9,300 / 25,834 | 4,100 / 3,000 / 43,025 | |
| Peak RSS | ≈0.83 GB | ≈0.89 GB | |

- **Where assessment time goes.** Wall-clock instrumentation shows per-resource DB round trips dominate: `engine.py:evaluate_resource` 107 s (22,900 calls), `store.observations` 71 s (16,611 calls), `persist_result` 22 s, `calibrate` 15 s. The cost is superlinear: about 13 s per 16-account shard versus about 200 s for 100 accounts. VERIFIED. Unexplained: the same call under cProfile took 17.6 s. Do not cite that figure.
- **Silent truncation.** In the stress workload, `MAX_TRANSITIONS` and `MAX_PASSROLE` (20,000, `iam/analysis.py`) were both reached. The truncation is recorded in the enterprise graph and the Excel "IAM Evidence Gaps" sheet. But `feasibility.py:attack_paths` returned `truncated: false` with 976 AP-06 records for 1,000 PassRole principals, so the dashboard, path view and report omit 24 principals without notice. VERIFIED.
- **Caps that fail closed or are flagged.** Snapshot 250,000 observations and 2,048 members (`snapshot.py:build_snapshot`); 4,096 observations / 8 MiB per resource (`engine.py:assess`); `MAX_EDGES` 100,000 flagged (`correlate.py`); graph view flagged (`test_enterprise.py::test_graph_and_page_limits_are_explicit`). VERIFIED by code; only the IAM budgets were exercised. The real collector runs one account per import, so 100 accounts means 100 imports plus one snapshot. INFERRED.

## 8. Gaps and prioritised change list

| # | Priority | Change | Basis |
|---|---|---|---|
| 1 | P1 | Propagate `IamAnalysis.truncated` into `attack_paths()["truncated"]`, the dashboard and the report | §7 VERIFIED |
| 2 | P1 | Snapshot membership per scope: copy only the newest import's observations for each account+Region (or refuse partially superseded members), and warn on overlap | §5 VERIFIED |
| 3 | P1 | Apply `excluded_ids` to `EnterpriseViews.accounts` finding counts; consider filtering related findings in enterprise sheets | §5 VERIFIED |
| 4 | P1 | Platform-identity handling (rule-version bump plus methodology review): treat service-linked roles as non-attacker principals in `passrole`/AP-06; classify trusts from the evidenced management account like registered accounts; offer AWS FP presets (service-linked, AWSReservedSSO, OrganizationAccountAccessRole, ControlTower) | §4 VERIFIED |
| 5 | P1 | Assessment performance: batch per-resource queries (prefetch observations and refs per run) to remove the ≈200 s superlinear stage; then the Excel export (≈62 s) | §7 VERIFIED |
| 6 | P2 | AP-06: populate P2 from R1-IAM-ROLE-TRUST-CONDITIONS FAILs and link findings, so AP-06 can be FEASIBLE, STRIDE-mapped and FP-excludable | §3 VERIFIED |
| 7 | P2 | Collector (separate authorised change): call `describe_policy` for root SCPs; collect RCPs. Analyzer: report "SCP hierarchy unavailable" once per account rather than per role | §6 VERIFIED / INFERRED |
| 8 | P2 | Group security-group findings by account-qualified ARN | §5 VERIFIED |
| 9 | P3 | Records for AP-02/03/07/15/17–29 (specs only today); model IAM users/groups; AWS-shaped principal extraction for FP carry-over (`exclusions.py:PRINCIPAL` is GCP-shaped, INFERRED) | §2–3 VERIFIED |

**Confirmation.** No real workspace, evidence or collector output was opened. All runs used
synthetic data in a scratch directory outside the repository. This file is the only file written to
the repository. It is uncommitted.
