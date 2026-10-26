# GCP configuration assessment increment

Implemented on `feature/offline-security-analyzer`; rule version 1.1.0.

The supplied workbook matches the pinned SHA-256 `a9d7ef1b075fa1eab9ea12cce654dc8ce65543bad810e8e233e7bb30761ae3cd`: 204 controls, 17 worksheets. The requested 219-control count does not match that source. No source requirements or IDs were changed.

This increment completes the previously unfinished 23 configuration evaluators across network, Compute Engine, Storage, Cloud SQL, KMS and Logging. The registry has 19 AWS and 48 GCP evaluators (67 total), including guided evaluations. These numbers are not control coverage. All check-area mappings remain PROPOSED and partial; automated sub-checks never produce a control-level PASS.

## Explicit rule matrix

Fields and expectations below are engineering guidance. Required evidence includes the primary operation plus any related observations cited by the result. Missing or malformed required fields return UNKNOWN, not a candidate finding. The existing whole-run checklist and generated collector matrix remain the control and dataset inventories.

| Rule | Control | Primary evidence operation | Fields | Criterion / expected configuration |
|---|---|---|---|---|
| GCP-NET-FW-ADMIN-INTERNET | 1.3.2 | `gcp:compute.firewalls.list` | `sourceRanges`, `allowed`, `ports`, `targetTags`, `priority`, `direction` | sourceRanges: approved administration networks, not 0.0.0.0/0 |
| GCP-NET-FW-DB-INTERNET | 1.5.2 | `gcp:compute.firewalls.list` | `sourceRanges`, `allowed`, `ports`, `targetTags`, `priority`, `direction` | sourceRanges: private networks only for database ports |
| GCP-NET-FW-ANY-INTERNET | 1.5.2 | `gcp:compute.firewalls.list` | `sourceRanges`, `allowed`, `IPProtocol`, `ports`, `targetTags`, `priority` | allowed: only required protocols and ports |
| GCP-NET-DEFAULT-NETWORK | 1.5.5 | `gcp:compute.networks.list` | `name`, `autoCreateSubnetworks` | name: no network named 'default' |
| GCP-NET-FLOW-LOGS | 1.5.7 | `gcp:expanded.subnets` | `logConfig`, `enable`, `enableFlowLogs` | enable: true |
| GCP-NET-PRIVATE-GOOGLE-ACCESS | 1.5.8 | `gcp:expanded.subnets` | `privateIpGoogleAccess` | privateIpGoogleAccess: true |
| GCP-VM-EXTERNAL-IP | 1.3.1 | `gcp:compute.instances.list` | `accessConfigs`, `natIP`, `networkInterfaces` | accessConfigs: absent (no external IP) |
| GCP-VM-DEFAULT-SA | 1.3.4 | `gcp:compute.instances.list` | `serviceAccounts`, `email` | email: dedicated least-privilege service account |
| GCP-VM-FULL-API-SCOPE | 1.3.4 | `gcp:compute.instances.list` | `serviceAccounts`, `email`, `scopes` | email: dedicated service account with reviewed least-privilege IAM grants |
| GCP-VM-SERIAL-PORT | 6.1.2 | `gcp:compute.instances.list` | `metadata`, `items`, `serial-port-enable` | serial-port-enable: false |
| GCP-VM-OSLOGIN | 6.1.2 | `gcp:compute.instances.list` | `metadata`, `items`, `enable-oslogin` | enable-oslogin: TRUE |
| GCP-VM-PROJECT-SSH-KEYS | 6.1.2 | `gcp:compute.instances.list` | `metadata`, `items`, `block-project-ssh-keys`, `enable-oslogin` | block-project-ssh-keys: true |
| GCP-VM-SHIELDED | 6.1.2 | `gcp:compute.instances.list` | `shieldedInstanceConfig`, `enableSecureBoot`, `enableVtpm`, `enableIntegrityMonitoring` | enableSecureBoot: true; enableVtpm: true; enableIntegrityMonitoring: true |
| GCP-VM-IP-FORWARD | 6.1.2 | `gcp:compute.instances.list` | `canIpForward` | canIpForward: false |
| GCP-STORAGE-UBLA | 6.1.2 | `gcp:storage.buckets.list` | `uniform_bucket_level_access`, `uniformBucketLevelAccess`, `enabled` | uniform_bucket_level_access: true |
| GCP-STORAGE-PAP | 1.4.1 | `gcp:storage.buckets.list` | `public_access_prevention`, `publicAccessPrevention` | public_access_prevention: enforced |
| GCP-STORAGE-VERSIONING | 1.4.5 | `gcp:storage.buckets.list` | `versioning_enabled`, `versioning`, `enabled` | versioning_enabled: true |
| GCP-SQL-OPEN-NETWORK | 1.5.2 | `gcp:expanded.cloud_sql` | `ipv4Enabled`, `authorizedNetworks`, `value` | authorizedNetworks: no 0.0.0.0/0 entry |
| GCP-SQL-PUBLIC-IP | 1.3.1 | `gcp:expanded.cloud_sql` | `ipv4Enabled`, `authorizedNetworks` | ipv4Enabled: false |
| GCP-SQL-TLS | 1.4.4 | `gcp:expanded.cloud_sql` | `sslMode`, `requireSsl` | sslMode: ENCRYPTED_ONLY |
| GCP-SQL-BACKUP | 6.1.2 | `gcp:expanded.cloud_sql` | `backupConfiguration`, `enabled` | enabled: true |
| GCP-KMS-ROTATION | 1.8.4 | `gcp:cloudkms.cryptoKeys.list` | `rotationPeriod`, `nextRotationTime`, `purpose` | rotationPeriod: 7776000s (90 days) or less |
| GCP-LOG-RETENTION | 8.4.1 | `gcp:logging.buckets.list` | `retentionDays`, `locked` | retentionDays: the organization's required period |

## Evaluation and severity boundaries

- Firewall checks use direction, disabled state, validated protocols/ports, public IPv4/IPv6 source families, exact project-qualified network references, priority, targets and all collected VM interfaces. An equal/higher-priority complete deny for the checked protocol/range and source family can block the clause. Narrow target denies remain limitations. All-ports allows are reported once rather than duplicated under admin and database rules.
- A matching assigned external IP gives POTENTIAL_EXPOSURE at HIGH for the firewall criterion. Without an established matching endpoint the candidate is a BASELINE_DEVIATION at MEDIUM, with exposure unresolved. Missing inventory is not proof of latent-only exposure. Hierarchical/network firewall policy, routes, listeners, effective reachability and exploitation are not resolved. External-IP candidates alone remain MEDIUM.
- Default service-account attachment is a MEDIUM identity baseline; cloud-platform scope on that default identity is LOW. Neither establishes Editor access or excessive effective privilege. Google recommends cloud-platform scope with least-privilege IAM roles; any finding needs owner context before confirmation.
- Instance metadata settings are evaluated only when explicit. Inherited project settings and unrecognized values remain UNKNOWN. Project SSH-key acceptance fails only when both key acceptance and disabled OS Login are explicit. Missing Shielded VM/image-support evidence remains UNKNOWN.
- Public Access Prevention inherited settings require consistent, project-effective v1 boolean-policy evidence. Ancestor inventories, conditions, v2 specifications, conflicting snapshots and missing effective policy remain UNKNOWN.
- SQL requires explicit IP, TLS and backup fields. Read-replica automated-backup checks are NOT_APPLICABLE, with primary backup validation separate. Authentication, public reachability and application requirements remain independent.
- KMS rotation uses a 90-day engineering baseline, compared without truncating fractional seconds. Asymmetric/MAC purposes are NOT_APPLICABLE; missing purpose or rotation evidence is UNKNOWN. Owner policy is still needed; no key material is accessed.
- Log retention reports observed days and asks for an approved objective; it does not create a retention finding merely because days are low. The service-managed _Required bucket is excluded from this configurable-retention criterion.
- The new Compute, SQL, KMS and GKE disabled-API shortcut from the unfinished draft was removed. Those collection errors remain UNKNOWN; complete empty inventory is a separate scoped absence result, never PASS. Existing historical API-key/Storage service handling is unchanged.

## Traceability and review

Per-verdict classification, suggested severity, exposure, supporting observations, evidence needs, compensating context and limitations pass through to stored results and candidates. Every new evaluator has GCP-specific remediation, read-only CLI verification and finding-detail fields. These are offline templates and never execute commands or fetch documentation. Reassessing unchanged evidence preserves the existing finding ID and analyst decision; changed fingerprints require the existing revalidation lifecycle. Confirmed-only Excel and Word/RTF exports are exercised with the new findings.

Coverage specification 1.4.0 adds separate GCP records without altering AWS classifications. Checklist JSON includes implementation status and the added operation requirements. MANUAL results stay manual; inapplicable partial criteria cannot mark an entire broader control inapplicable. Missing criteria remain visible.

## Remaining enhancement scope

This increment does not complete the entire enterprise enhancement request. Persisted guided-manual control decisions, per-project control dashboards, additional GKE/serverless/data/DevOps rules, richer effective network/IAM policy evaluation, and broader graph/cross-project scenarios remain follow-up work. Existing enterprise correlation, reviews and reporting are retained; no general reachability or exploitation engine is claimed. The authoritative catalogue remains 204 controls until a different reviewed source is supplied.

Actual collector-export compatibility and native Windows/Word/Excel execution are not established by synthetic tests. The collector, import format, canonical schemas and raw inputs were not redesigned.

## References reviewed

- [Google VPC firewall semantics](https://docs.cloud.google.com/firewall/docs/firewalls).
- [Compute service accounts and OAuth scopes](https://docs.cloud.google.com/compute/docs/access/service-accounts).
- [Service Usage enable/disable semantics](https://docs.cloud.google.com/service-usage/docs/enable-disable).

## Validation and handoff

[TEST_PLAN.md](../TEST_PLAN.md#gcp-configuration-increment-validation--2026-10-16)
records the full run (779 passed, 22 skipped), final focused suite (90 passed), four
actual browser workflows, schema/lint checks and the existing release-audit blockers.
Changes remain uncommitted on `feature/offline-security-analyzer`. No collector or
cloud configuration changed. Next assessment task: implement persisted guided-manual
control validation with project/resource evidence and review history, then expand GKE
and the remaining service rules against the same pinned catalogue.
