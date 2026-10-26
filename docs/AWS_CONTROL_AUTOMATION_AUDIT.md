# AWS control automation audit (2026-10-20, completed 2026-10-22)

Counterpart of docs/GCP_CONTROL_AUTOMATION_AUDIT.md for the 19 AWS rules
(`rules/registry.py:ALL_RULES`). First written read-only on 2026-10-20; completed after AWS
readiness phases 0-2, collector 0.3.3 and the Phase F tests. Evidence: code reading plus
synthetic collector output, now produced by the real collector (collectors/aws/assessment.py
0.3.3) on the in-process fake cloud (tools/fixtures/aws_fake_cloud.py). No real workspace,
evidence or package was opened. **VERIFIED** = read in code and reproduced by a named test;
**INFERRED** = read in code only.

Classes: **A** logic missing (evidence is collected, the analyzer does not use it), **B**
correlation missing (needs another account, the organization or a registry), **C** evidence not
collected, **D** business context (no offline rule can decide).

## 1. The four questions

| # | Question | Answer (current) | Evidence |
|---|---|---|---|
| a | Does import mark verified, successful AWS datasets as partial? | **No, with one deliberate exception.** A COMPLETE journal row with verified checksums is COMPLETE. Per-resource requests (`Bucket`, `KeyId`, trail name) are PARTIAL for their listing but complete for their resource; the scope decision uses the parent listing (b, d). R0 imports without request parameters stay PARTIAL (legacy rule). | `ingestion/coverage.py`, `rules/engine.py:dependent_scope`. VERIFIED: tests/test_aws_dependent_scope.py |
| b | Which rules can never emit PASS despite complete evidence? | **None**, at resource level or at scope level. On a complete, compliant synthetic account every one of the 19 rules emits PASS and no collection-scope row remains (the S3 bucket scope row is now decided by the bucket listing). | VERIFIED: tests/test_aws_rule_correctness.py::test_every_aws_rule_reaches_pass_on_complete_compliant_evidence |
| c | Omitted-field semantics | Conservative: absent or non-boolean fields give UNKNOWN with the field named. Absence is read only where AWS defines it (NoSuchPublicAccessBlockConfiguration, NoSuchBucketPolicy, InvalidAccessException for Security Hub, AWSOrganizationsNotInUseException); empty DetectorIds / ConfigurationRecordersStatus mean none exists; KMS `KeySpec` absent is SYMMETRIC_DEFAULT (CreateKey default). Unchanged. | `ingestion/coverage.py:DEFINED_ABSENCE`, `rules/security_observations.py`. VERIFIED by reading and tests/test_r1.py |
| d | Empty successful list gives N/A? | **Yes**, also for dependent datasets (fixed in readiness phase 0): an empty COMPLETE parent listing gives NOT_APPLICABLE, a failed parent COLLECTION_ERROR, never PASS. The GCP counterpart is tested alongside. | `rules/engine.py:dependent_scope`. VERIFIED: tests/test_aws_dependent_scope.py (incl. GCP) |

## 2. Per-rule table (current)

| Rule | PASS reachable | Remaining UNKNOWN / MANUAL sources | Class | Status |
|---|---|---|---|---|
| R0-EC2-IMDSV2 | Yes | State or MetadataOptions not applied | — | — |
| R0-RDS-ENCRYPTION | Yes (instances) | **Aurora always UNKNOWN**: `rds.describe_db_clusters` collected, not parsed | **A** | Open (decision 1) |
| R0-CLOUDTRAIL-VALIDATION | Yes | Shadow-trail-only Regions | — | — |
| R1-EC2-SG-SENSITIVE-INGRESS | Yes | Route tables or ENIs incomplete (severity only) | — | Workload pairing added (phase 2) |
| R1-IAM-ROLE-TRUST-CONDITIONS | Yes | Trusted business partners | D | B resolved: management account from DescribeOrganization (phase 2) |
| R1-S3-ACCOUNT-BPA | Yes | — | — | — |
| R1-S3-BUCKET-PUBLIC-ACCESS | Yes | MANUAL when IgnorePublicAcls is off at both levels: `s3.get_bucket_ownership_controls` collected, not parsed | **A** | Scope row fixed (phase 0); ACL item open (decision 2) |
| R1-RDS-PUBLIC-ACCESS | Yes | — | — | — |
| R1-EC2-IMDS-HOP-LIMIT | Yes | — | — | — |
| R1-IAM-INSTANCE-ROLE-PRIVILEGE | Yes | Member accounts: organization controls not assessed (Organizations access denied) | B / C | C resolved for authorized identities: collector 0.3.3 collects SCP and RCP content at every node including the root; member denial stated explicitly |
| SEC-IAM-ROLE-WILDCARD | Yes | Intended administrator roles | D | Platform role classes labelled (phase 2), severity kept |
| SEC-KMS-WILDCARD-PRINCIPAL | Yes | — | — | Dependent scope fixed (phase 0) |
| SEC-EC2-SG-LATENT-EXPOSURE | Yes | — | — | — |
| SEC-CLOUDTRAIL-LOGGING | Yes | Organization trails in another account | B | Dependent scope fixed (phase 0) |
| SEC-CLOUDTRAIL-MANAGEMENT-EVENTS | Yes | Advanced selectors without an eventCategory selector | — | Dependent scope fixed (phase 0) |
| SEC-GUARDDUTY-ENABLED | Yes | Delegated-administrator setups | B | — |
| SEC-CONFIG-RECORDING | Yes | — | — | — |
| SEC-SECURITYHUB-ENABLED | Yes | — | — | — |
| SEC-KMS-ROTATION | Yes | GetKeyRotationStatus missing for a key | — | Dependent scope fixed (phase 0) |

Counts: 19 rules reach PASS; open class A items 2 (decisions 1, 2); class B items are
organization-level correlations outside one account's evidence; class D is business context.

## 3. Phase F items, implementation and tests

| Item | Implementation | Tests |
|---|---|---|
| Platform-managed identity classifier: service-linked roles, AWSReservedSSO_*, OrganizationAccountAccessRole, AWSControlTowerExecution, service principals, management account from DescribeOrganization | `rules/aws_identity.py:classify`, `role_class`, `scope_from` | test_aws_readiness_phase2: test_trust_classes, test_role_classes, test_management_account_needs_organization_evidence, test_organization_access_role_reclassified_with_evidence, test_without_organization_evidence_nothing_is_lowered |
| Trust-policy condition rendering | `rules/aws_identity.py:render_conditions`, `chunks` | test_conditions_render_binding_keys_and_never_the_external_id, test_long_text_is_split_not_dropped, test_trust_conditions_and_service_principals_are_rendered |
| SCP awareness: absent SCP evidence = "organization controls not assessed"; admin roles keep base severity with the reason | `rules/aws_identity.py:organization_note`, `reporting/assessment_report.py:organization_notes`; collector 0.3.3 `collection_facts.organization` -> AWS_ORGANIZATION_ACCESS_MISSING | test_scp_awareness_keeps_severity_and_states_the_gap; test_aws_collector_033::test_missing_organization_access_is_explicit, test_organization_chain_with_scp_and_rcp_content |
| AP-06 prerequisite P2, hop and STRIDE mapping | `attack_paths/prerequisites.py:iam_escalation`, `attack_paths/model.py` | test_ap06_links_findings_maps_stride_and_honours_exclusion, test_ap06_p2_is_declared_unverifiable_without_trust_results |
| Instance profile x open security group x public interface pairing | `rules/aws_identity.py:workload_context` | test_privileged_instance_role_raises_exposure, test_least_privilege_instance_role_is_labelled_not_lowered, test_unresolved_instance_role_is_never_narrowed |
| Never lower severity silently | Reclassification only with evidence, stated as "Reclassified from <class>/<severity> to ..." in the exposure | tests/test_aws_rule_correctness.py::test_identity_enrichment_never_lowers_severity_silently (enrichment on versus off on one synthetic account: the only lower severity is the evidenced organization access role, stated explicitly) |

## 4. Shared-code issues fixed once (both providers)

| Issue | Fix | Proof for both providers |
|---|---|---|
| Dependent-dataset scope rows always UNKNOWN | Parent listing decides (phase 0) | tests/test_aws_dependent_scope.py includes the GCP empty-list and failure counterpart |
| Collection gaps without a reason for AWS sources | `reporting/coverage_reasons.py:source_category` (GCP: the collector's own category, unchanged) | GCP equality fingerprint identical to the baseline after phases B-F |
| Per-resource queries and linear scans in the engine context (837 s on 143 accounts) | Indexed lookups, batched writes (phase D) | Snapshot outputs byte-identical before/after; GCP equality fingerprint identical |
| Consolidated reporting across providers | Frozen GCP edition merged with a reconciliation gate (phase E) | tests/test_gcp_frozen_feed.py; GCP outputs unchanged when no edition is linked (fingerprint) |

## 5. Decisions needed

1. Parse `rds.describe_db_clusters` (Aurora `StorageEncrypted`) in R0-RDS-ENCRYPTION: changes
   outcomes for Aurora from UNKNOWN to PASS/FAIL; rule version bump and methodology review.
2. Parse `s3.get_bucket_ownership_controls` (BucketOwnerEnforced disables ACLs) in
   R1-S3-BUCKET-PUBLIC-ACCESS: settles the object-ACL MANUAL case; rule version bump.

## 6. Confirmation

Only synthetic data in scratch directories and pytest temporary directories was used.
