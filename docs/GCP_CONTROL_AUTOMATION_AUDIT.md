# GCP control automation audit (read-only, 2026-10-20)

Scope: all 48 GCP rules in `rules/registry.py` (38 `GCP_RULES`, 10 `ORG_RULES`). Sources: rule
code, tests, the committed synthetic outcome table `tests/gcp_rule_outcomes_baseline.json`, and
one synthetic probe (the `expanded22` fixture with a SUCCESS organization IAM search, built as in
`tests/test_cloud_checklist.py::org_run`, run in a scratch directory). No real workspace,
evidence or package was opened; no code, configuration or collector file was changed.

**VERIFIED** = read in code or reproduced on synthetic data. **INFERRED** = deduced (for example
how a Google API serialises unset fields); not proven offline.

## 0. Systemic finding (affects every project rule)

- **S1, class A.** Every source from a 2.2.x expanded package is declared `coverage="PARTIAL"`,
  with the limitation `COLLECTOR_PAGINATION_UNVERIFIED`, even when the dataset status is SUCCESS
  and checksums are verified (`ingestion/gcp_expanded.py`, Source construction in the dataset loop).
  Consequences (VERIFIED by the probe):
  - **Scope rows.** The per-project collection-scope row of each of the 38 project rules is
    UNKNOWN ("Missing or incomplete project evidence blocks scope assessment"), even when
    every resource was evaluated. This comes from `rules/gcp.py:assess_gcp`, which needs
    COMPLETE coverage both for "skip" and for NOT_APPLICABLE on an empty dataset. On a
    41-project run that is 38 × 41 = 1,558 UNKNOWN rows.
  - **Empty datasets.** An empty dataset (no keys, no SQL, no buckets) cannot become
    NOT_APPLICABLE; it stays UNKNOWN.
  - **Org scope PASS.** The organization-rule collection-scope PASS is unreachable: a SUCCESS
    organization search was PARTIAL in the probe, and all 6 no-match org rules stayed UNKNOWN
    with "search completeness unverified" (`rules/gcp_org.py:assess_org`).
- **S2, class A.** Every expanded source carries `provenance: "collector-unverified"` (same
  place). The API-key rules need `"collector-declared"` to interpret an omitted `restrictions`
  field (`rules/gcp.py:restrictions`). A key with no restrictions, which is the finding the rule
  exists for, therefore becomes UNKNOWN in every 2.2.x package. VERIFIED: in the committed
  baseline, 18 of 19 API-key results are UNKNOWN; the one FAIL is the legacy `gcp_fixture`.

## 1. Per-rule table

Outcomes are those the code can emit at resource level (scope rows are covered by S1). The
classes explain today's UNKNOWN or MANUAL results:
- **A**: evidence available, logic missing.
- **B**: evidence available, cross-resource correlation missing.
- **C**: evidence not collected or inaccessible.
- **D**: a genuine business-context requirement.

On quota projects, the repository documents only Cloud Asset lists, monitoring alert policies
and Discovery Engine as refused with user credentials and no quota project
(`docs/handoff/GCP_HANDOFF.md` §a, `collectors/gcp/README.md`; status `QUOTA_PROJECT_DENIED`).
Anything else stated about quota projects is INFERRED.

| # | Rule | Tests | Outcomes | Evidence datasets | Status | Why UNKNOWN/MANUAL today (class) | Code |
|---|---|---|---|---|---|---|---|
| 1 | GCP-STORAGE-PUBLIC | allUsers/allAuthenticatedUsers on a bucket, not blocked by PAP | PASS FAIL UNKNOWN N-A | bucket_iam, bucket_details, effective_policy (storage.publicAccessPrevention) | Automated | **B**: inherited PAP resolved only from a v1 `booleanPolicy` effective record; v2 `spec` or inconsistent records → UNKNOWN. Also A for custom/legacy roles ("Supported bucket-role permissions") and conditional bindings | `rules/gcp.py:public_storage` |
| 2 | GCP-API-APP | API key without an application restriction | PASS FAIL UNKNOWN N-A | api_keys / api_keys_rest, api_key_detail | Blocked for 2.2.x | **A** (S2): omitted `restrictions` needs collector-declared provenance | `rules/gcp.py:restrictions` |
| 3 | GCP-API-API | API key without API-target restriction | PASS FAIL UNKNOWN N-A | as above | Blocked for 2.2.x | **A** (S2) | `rules/gcp.py:restrictions` |
| 4 | GCP-API-BOTH | API key with neither restriction | PASS FAIL UNKNOWN N-A | as above | Blocked for 2.2.x | **A** (S2) | `rules/gcp.py:restrictions` |
| 5 | GCP-KEY-PERSISTENT | Enabled user-managed SA key exists | FAIL UNKNOWN N-A (no PASS by design) | sa_keys | Automated (presence rule) | **C**: malformed/absent `keyType` or a collection gap only; "zero keys" would be N-A but S1 blocks it | `rules/gcp.py:key_rule` |
| 6 | GCP-KEY-AGE | Key older than `max_key_age_days` (default 90) | PASS FAIL UNKNOWN N-A | sa_keys | Automated | **C**: missing `validAfterTime` or collection timestamp | `rules/gcp.py:key_rule` |
| 7 | GCP-KEY-PRIVILEGED | Key on an SA with an Owner/Editor binding | FAIL UNKNOWN N-A (never PASS) | sa_keys, service_accounts, project_iam | **Defect** | **B**: no correlated Owner/Editor binding → UNKNOWN instead of PASS; collected inherited bindings (parent_org_iam, parent_folder_iam, organization_iam) not correlated; conditional bindings A | `rules/gcp.py:key_rule`, `assess_gcp:key_context` |
| 8 | GCP-IAM-BASIC | Owner/Editor binding (agents excluded) | PASS FAIL UNKNOWN N-A | project_iam | Automated | **A**: any IAM Condition → UNKNOWN ("Evaluate IAM Conditions"); malformed members | `rules/gcp.py:binding_rule` |
| 9 | GCP-IAM-PUBLIC | Public principal on a sensitive project role | PASS FAIL UNKNOWN N-A | project_iam | Automated | **A**: public member on a role outside `SENSITIVE` → UNKNOWN; custom-role permissions (custom_role_detail) unused; predefined-role catalogue not collected (C) | `rules/gcp.py:binding_rule` |
| 10 | GCP-IAM-IMPERSONATION | Token Creator / SA User granted broadly | PASS FAIL UNKNOWN N-A | project_iam (sa_iam collected) | Automated for project subjects | **A**: non-`projects/` subjects (service-account policies from sa_iam) → UNKNOWN; conditions → UNKNOWN | `rules/gcp.py:binding_rule` |
| 11 | GCP-IAM-CROSSPROJECT | Owner/Editor held by an SA from another project | PASS FAIL UNKNOWN N-A | project_iam, org project index | Automated | **B**: SA home project unresolved (number-form email without an index) → UNKNOWN; the index needs IAM search (C when Cloud Asset is denied) | `rules/gcp.py:binding_rule`, `rules/gcp_identity.py` |
| 12 | GCP-GOV-KEYS | Effective key creation/upload constraints enforced | PASS FAIL UNKNOWN N-A | effective_policy (baseline constraints) | Automated | **A**: conditional or tag-based enforcement and v2 rule shapes → UNKNOWN; constraint without a record → scope UNKNOWN (C) | `rules/gcp.py:governance`, `assess_gcp` |
| 13 | GCP-LOG-AUDIT | Data Access audit-log exemptions | FAIL UNKNOWN (never PASS) | project_iam `auditConfigs` (parent_org_iam/parent_folder_iam collected) | **Defect** | **A**: no PASS branch; project-level DATA_READ+DATA_WRITE for `allServices` with no exemptions is decidable. B: inherited auditConfigs not merged | `rules/gcp.py:audit` |
| 14 | GCP-LOG-EXCLUSION | Enabled exclusion of security logs | FAIL UNKNOWN N-A (never PASS) | exclusions (logging) | Partial | **A**: only the exact `log_id("cloudaudit.googleapis.com/data_access")` filter FAILs; every other filter UNKNOWN; no PASS for filters that cannot match audit logs | `rules/gcp.py:exclusion` |
| 15 | GCP-SCC-OBSERVATION | Active SCC finding | FAIL UNKNOWN N-A (no PASS by design) | scc_findings / scc_findings_rest | Scanner observation | **C**: UNKNOWN only for missing state/category/resource, or SCC not available. FAIL always needs native confirmation (collector-analyzer contract rule) | `rules/gcp.py:scc` |
| 16 | GCP-NET-FW-ADMIN-INTERNET | Internet ingress to admin ports | PASS FAIL UNKNOWN N-A | firewall_rules, instances | Automated | **C**: malformed/absent `allowed`, `sourceRanges`, network or priority only. Collected hierarchical `firewall_policies` are a limitation, not evaluated (B, affects FAIL accuracy) | `rules/gcp_config.py:firewall` |
| 17 | GCP-NET-FW-DB-INTERNET | Internet ingress to DB ports | PASS FAIL UNKNOWN N-A | as above | Automated | **C** (as #16) | `rules/gcp_config.py:firewall` |
| 18 | GCP-NET-FW-ANY-INTERNET | Internet ingress on all ports | PASS FAIL UNKNOWN N-A | as above | Automated | **C** (as #16) | `rules/gcp_config.py:firewall` |
| 19 | GCP-NET-DEFAULT-NETWORK | Network named `default` | PASS FAIL UNKNOWN | vpcs | Automated | **C**: name missing only | `rules/gcp_config.py:default_network` |
| 20 | GCP-NET-FLOW-LOGS | Subnet flow logs disabled | PASS FAIL UNKNOWN N-A | subnets | Automated if field present | **A**: absent `logConfig`/`enableFlowLogs` → UNKNOWN (INFERRED: unset logging is often omitted) | `rules/gcp_config.py:flow_logs` |
| 21 | GCP-NET-PRIVATE-GOOGLE-ACCESS | Private Google Access off | PASS FAIL UNKNOWN N-A | subnets | Automated | **C**: field missing only | `rules/gcp_config.py:private_access` |
| 22 | GCP-VM-EXTERNAL-IP | Instance has an external address | PASS FAIL UNKNOWN | instances | Automated if keys present | **A**: interface without an `accessConfigs` key → UNKNOWN (INFERRED: omitted when no external access) | `rules/gcp_config.py:vm_external_ip` |
| 23 | GCP-VM-DEFAULT-SA | Default Compute SA attached | PASS FAIL UNKNOWN | instances | Automated if field present | **A**: `serviceAccounts` absent (no SA attached) → UNKNOWN | `rules/gcp_config.py:default_sa` |
| 24 | GCP-VM-FULL-API-SCOPE | Default SA with cloud-platform scope | PASS FAIL UNKNOWN | instances | Automated if field present | **A**: as #23 | `rules/gcp_config.py:full_scope` |
| 25 | GCP-VM-SERIAL-PORT | `serial-port-enable` true | PASS FAIL UNKNOWN | instances (effective_policy compute.disableSerialPortAccess collected) | Partial | **B**: instance key usually absent; the collected effective org policy is not consulted. Project `commonInstanceMetadata` not collected (C) | `rules/gcp_config.py:explicit_metadata` |
| 26 | GCP-VM-OSLOGIN | `enable-oslogin` false | PASS FAIL UNKNOWN | instances (effective_policy compute.requireOsLogin collected) | Partial | **B**: as #25 with compute.requireOsLogin | `rules/gcp_config.py:explicit_metadata` |
| 27 | GCP-VM-PROJECT-SSH-KEYS | Accepts project SSH keys without OS Login | PASS FAIL UNKNOWN | instances | Partial | **C**: project-wide `block-project-ssh-keys`/OS Login (compute.projects.get `commonInstanceMetadata`) is not in the dataset catalogue (`contracts/gcp_expanded_catalog.py`) | `rules/gcp_config.py:project_ssh_keys` |
| 28 | GCP-VM-SHIELDED | Secure Boot/vTPM/integrity monitoring | PASS FAIL UNKNOWN | instances | Automated if all three set | **A**: absent or partial `shieldedInstanceConfig` → UNKNOWN (images collected, not used) | `rules/gcp_config.py:shielded` |
| 29 | GCP-VM-IP-FORWARD | `canIpForward` true | PASS FAIL UNKNOWN | instances | Automated | **C**: field missing only | `rules/gcp_config.py:ip_forward` |
| 30 | GCP-STORAGE-UBLA | Uniform bucket-level access off | PASS FAIL UNKNOWN | buckets / bucket_details | Automated | **C**: field missing only | `rules/gcp_config.py:ubla` |
| 31 | GCP-STORAGE-PAP | Public access prevention not enforced | PASS FAIL UNKNOWN | buckets, effective_policy | Partial | **B**: `inherited` needs a v1 effective booleanPolicy; v2 `spec`/`rules` (project_org_policy_v2 collected) → UNKNOWN (`test_gcp_config.py::test_policy_inheritance_and_objectives_remain_unresolved`) | `rules/gcp_config.py:pap` |
| 32 | GCP-STORAGE-VERSIONING | Object versioning disabled | PASS FAIL UNKNOWN | buckets / bucket_details | Automated if field present | **A**: absent `versioning` → UNKNOWN (INFERRED: omitted when never enabled) | `rules/gcp_config.py:versioning` |
| 33 | GCP-SQL-OPEN-NETWORK | Authorized network 0.0.0.0/0 | PASS FAIL UNKNOWN | cloud_sql / sql_instances_rest | Automated if list present | **A**: `ipv4Enabled` true and `authorizedNetworks` absent → UNKNOWN (INFERRED: omitted when empty) | `rules/gcp_config.py:sql_open` |
| 34 | GCP-SQL-PUBLIC-IP | Public IPv4 enabled | PASS FAIL UNKNOWN | as above | Automated | **C**: field missing only | `rules/gcp_config.py:sql_public` |
| 35 | GCP-SQL-TLS | Unencrypted connections allowed | PASS FAIL UNKNOWN | as above | Automated if field present | **A**: neither `sslMode` nor `requireSsl` → UNKNOWN (INFERRED: `requireSsl` omitted when false) | `rules/gcp_config.py:sql_tls` |
| 36 | GCP-SQL-BACKUP | Automated backups disabled | PASS FAIL UNKNOWN N-A | as above | Automated | **C**: field missing only | `rules/gcp_config.py:sql_backup` |
| 37 | GCP-KMS-ROTATION | Rotation period > 90 days | PASS FAIL UNKNOWN N-A | kms_keys | **Defect (no FAIL for unrotated keys)** | **A**: absent `rotationPeriod` (no automatic rotation) → UNKNOWN, so the main failure case never FAILs | `rules/gcp_config.py:kms_rotation` |
| 38 | GCP-LOG-RETENTION | Retention vs objective | MANUAL UNKNOWN N-A (no PASS/FAIL) | logging buckets | Manual by design | **D**: approved retention objective required | `rules/gcp_config.py:log_retention` |
| 39 | GCP-ORG-PUBLIC-SERVERLESS | Public grant on serverless resources | FAIL; scope PASS/UNKNOWN | asset_iam_search (+ opt-in folder/organization search) | FAIL-only in practice | **C**: Cloud Asset refused without a quota project (documented for Cloud Asset list; search INFERRED same API) → no records, so no org rows; org/folder search opt-in (`-IncludeOrganizationSearch`). With records, scope PASS blocked by S1 (A) | `rules/gcp_org.py:assess_org`, `matches` |
| 40 | GCP-ORG-PUBLIC-DATA | Public grant on data resources | as #39 | as #39 | FAIL-only in practice | **C** (+ S1) | `rules/gcp_org.py:matches` |
| 41 | GCP-ORG-PUBLIC-OTHER | Public grant elsewhere | as #39 | as #39 | FAIL-only in practice | **C** (+ S1) | `rules/gcp_org.py:matches` |
| 42 | GCP-ORG-BASIC-ROLE | Owner/Editor on org/folder/project nodes | as #39 | as #39 | FAIL-only in practice | **C** (+ S1); conditional bindings skipped | `rules/gcp_org.py:matches` |
| 43 | GCP-ORG-SA-PRIVILEGED | Privileged default/user-managed SA | FAIL N-A UNKNOWN; scope | as #39 | FAIL-only in practice | **C** (+ S1); unresolved owner → UNKNOWN | `rules/gcp_org.py:matches`, `identity_result` |
| 44 | GCP-ORG-IMPERSONATION | Impersonation roles at org/folder | as #39 | as #39 | FAIL-only in practice | **C** (+ S1) | `rules/gcp_org.py:matches` |
| 45 | GCP-ORG-CROSSPROJECT-SA | SA privileged in another project | FAIL N-A UNKNOWN; scope | as #39 | FAIL-only in practice | **C** (+ S1) | `rules/gcp_org.py:matches`, `identity_result` |
| 46 | GCP-ORG-DELETED-PRINCIPAL | Bindings to deleted principals | as #39 | as #39 | FAIL-only in practice | **C** (+ S1) | `rules/gcp_org.py:matches` |
| 47 | GCP-ORG-EXTERNAL-DOMAIN | Principals from other domains | MANUAL only | as #39 | Manual by design | **D**: approved organization domain list | `rules/gcp_org.py:manual_reviews` |
| 48 | GCP-ORG-FEDERATION | Workload identity pool principals | MANUAL only | as #39 (workload_pool_providers collected) | Manual | **B**: provider configuration is collected, but its attribute condition and issuer are not evaluated ("Workload identity pool provider configuration" requested) | `rules/gcp_org.py:manual_reviews` |

## 2. Can a GCP rule emit PASS today?

Only at **resource level**. No project-wide PASS is ever asserted, by design (`rules/gcp.py:assess_gcp`,
`rules/engine.py`). A truncated source turns any PASS into UNKNOWN (`assess_gcp`).

**PASS reachable, VERIFIED by tests.** Each passes when the field is present and explicit:
- 21 configuration rules (`tests/test_gcp_config.py::test_explicit_positive_and_negative`): rows
  #16–30 and #32–37.
- GCP-STORAGE-PAP when enforced, or inherited with a consistent v1 effective policy
  (`test_pap_requires_project_effective_evidence`).
- GCP-STORAGE-PUBLIC: no public member, PAP enforced, or effective PAP enforced.
- GCP-IAM-BASIC, -PUBLIC, -IMPERSONATION, -CROSSPROJECT per unconditional binding (the probe
  shows CROSSPROJECT 3 PASS and PUBLIC 2 PASS).
- GCP-KEY-AGE within the threshold.
- GCP-GOV-KEYS when enforced, or the managed successor constraint is enforced.

**PASS reachable only for legacy (non-2.2.x) packages.** GCP-API-APP, -API and -BOTH: their
PASS needs either explicit restrictions or collector-declared provenance (S2).

**PASS unreachable.**

| Rule | Basis | Defect? |
|---|---|---|
| GCP-KEY-PERSISTENT, GCP-SCC-OBSERVATION | By design: presence / scanner rules | No |
| GCP-LOG-RETENTION, GCP-ORG-EXTERNAL-DOMAIN | By design (D) | No |
| GCP-KEY-PRIVILEGED | Complete project IAM showing no Owner/Editor for the SA still gives UNKNOWN | **Yes** |
| GCP-LOG-AUDIT | No PASS branch at all | **Yes** |
| GCP-LOG-EXCLUSION | No PASS for non-audit filters | **Yes** |
| GCP-ORG-FEDERATION | Manual although provider evidence is collected | **Yes** (B) |
| 8 ORG rules' scope PASS (#39–46) | Blocked by S1 even with a SUCCESS search (probe) | **Yes** |
| All 38 project rules' scope rows (UNKNOWN / N-A) | Blocked by S1 | **Yes** |

Related "never FAIL" defects (same root as S2):
- GCP-API-* never FAIL an unrestricted key in 2.2.x packages.
- GCP-KMS-ROTATION never FAILs a key without automatic rotation.

## 3. Counts

| Class | Count |
|---|---|
| A — evidence available, logic missing | 18 |
| B — evidence available, correlation missing | 7 |
| C — not collected or inaccessible | 21 |
| D — business context | 2 |
| **Total** | **48** |

The systemic S1/S2 issues are class A and come on top of each row's class.

| Domain (rule `domain`) | A | B | C | D | Total |
|---|---|---|---|---|---|
| Credentials and API Security | 3 | – | 2 | – | 5 |
| Data Protection | 3 | 2 | 3 | – | 8 |
| Governance | 1 | – | – | – | 1 |
| Identity and Access | 2 | 3 | 6 | 1 | 12 |
| Monitoring and Detection | 3 | – | – | 1 | 4 |
| Network and Exposure | 2 | – | 7 | – | 9 |
| Vulnerability and Risk | – | – | 1 | – | 1 |
| Workload Security | 4 | 2 | 2 | – | 8 |

## 4. Smallest change per class A/B rule, ranked by manual effort saved (41-project run)

Ranking uses result multiplicity: rows per project times 41. No real counts were used, so the
order is **INFERRED**. "Per resource" means every collected object of that kind.

| Rank | Rules | Smallest change | Effort saved |
|---|---|---|---|
| 1 | S1 (all 38 project rules; 8 org scope rows) | Declare `coverage="COMPLETE"` for SUCCESS/EMPTY datasets of checksum-verified 2.2.x packages (the collector records TRUNCATED/PARTIAL separately); keep PARTIAL otherwise (`ingestion/gcp_expanded.py`) | ~1,558 scope UNKNOWN rows; empty datasets become N-A |
| 2 | GCP-API-APP/-API/-BOTH | Treat SUCCESS datasets of checksum-verified 2.2.x packages as collector-declared, so an omitted `restrictions` means unrestricted (`ingestion/gcp_expanded.py` provenance) | 3 results per API key; unrestricted keys become FAIL |
| 3 | GCP-VM-DEFAULT-SA, -FULL-API-SCOPE, -EXTERNAL-IP | Absent `serviceAccounts` → no SA attached (PASS); interface without `accessConfigs` → no external IPv4 (needs S1 completeness) | 3 results per instance |
| 4 | GCP-VM-SERIAL-PORT, -OSLOGIN | Use the collected effective `compute.disableSerialPortAccess` / `compute.requireOsLogin` when the instance key is absent | 2 results per instance |
| 5 | GCP-IAM-BASIC, -IMPERSONATION, GCP-KEY-PRIVILEGED (conditions) | Evaluate the role and members of a conditional binding and report the condition text, instead of UNKNOWN (methodology decision on the outcome) | Per conditional binding |
| 6 | GCP-KEY-PRIVILEGED | PASS when project IAM and the collected parent org/folder IAM are COMPLETE and show no Owner/Editor for the SA | 1 per user-managed key |
| 7 | GCP-STORAGE-VERSIONING, GCP-STORAGE-PAP, GCP-STORAGE-PUBLIC | Absent `versioning` → disabled (FAIL); parse v2 effective policy `spec.rules` without conditions for PAP | Up to 3 per bucket |
| 8 | GCP-KMS-ROTATION | ENCRYPT_DECRYPT key without `rotationPeriod`/`nextRotationTime` → FAIL "no automatic rotation" | 1 per key |
| 9 | GCP-SQL-OPEN-NETWORK, GCP-SQL-TLS | Absent `authorizedNetworks` → none (PASS); absent `requireSsl` and `sslMode` → unencrypted allowed (FAIL) | 2 per SQL instance |
| 10 | GCP-NET-FLOW-LOGS | Absent `logConfig` and `enableFlowLogs` → disabled (FAIL) | 1 per subnet |
| 11 | GCP-LOG-AUDIT | PASS when project (merged with collected parent) `auditConfigs` enable DATA_READ/DATA_WRITE for `allServices` with no exemptions | 1 per project (41) |
| 12 | GCP-IAM-PUBLIC | Resolve custom-role permissions from custom_role_detail | Per public binding on a custom role |
| 13 | GCP-IAM-IMPERSONATION | Evaluate `serviceAccounts/` subjects from sa_iam like project subjects | Per SA policy binding |
| 14 | GCP-IAM-CROSSPROJECT | Resolve number-form SA homes from the collected project/folder/organization metadata | Per unresolved binding |
| 15 | GCP-GOV-KEYS | Parse v2 `spec.rules` with an unconditional `enforce` | 2 constraints per project (82) |
| 16 | GCP-LOG-EXCLUSION | PASS when the filter cannot select `cloudaudit.googleapis.com` logs (bounded parse of `log_id`/`logName` terms) | Per exclusion |
| 17 | GCP-VM-SHIELDED | Use the collected image `shieldedInstanceInitialState` when the instance config is partial | Per non-Shielded image instance |
| 18 | GCP-ORG-FEDERATION | Record the provider's `attributeCondition` and issuer; FAIL when absent, MANUAL otherwise | Per pool |

Rows 3, 7, 9 and 10 rely on Google APIs omitting unset fields (INFERRED). Each one needs
synthetic tests of the omitted-field case, and completeness from S1, before it can claim PASS
or FAIL; otherwise "missing evidence never yields PASS" would be broken.

## 5. Confirmation

Nothing real was opened. All analysis used rule code, tests, the committed synthetic outcome
table and one synthetic probe in a scratch directory outside the repository. Only this file was
written; it is uncommitted.
