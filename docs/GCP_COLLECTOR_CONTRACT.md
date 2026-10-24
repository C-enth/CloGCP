# GCP collector contract

Generated from `contracts/gcp_expanded_catalog.py`; collector SHA256 `8980469b0088899901c597dde77af976b25de89a1348008f80065effa5dc5fcf`.

115 definitions: 90 fixed, 25 bounded dynamic families. The supplied collector is unchanged.
Supported versions: `closec-gcp-1`, `pilot-1.2.2`, `pilot-1.5`, `assessment-expanded-2.1`.
Unknown versions remain rejected. ZIP and browser-folder imports share the same adapter.

The table describes implementation support, not field acceptance. Expanded 2.1 actual exports
and real AWS packages remain unverified. Native observations retain original locators/hashes.
Cloud Asset search/list snapshots remain distinct from detailed service configurations.

## Transport and collection semantics

gcloud lists are arrays; describes and IAM policies are objects. REST outputs are flattened
arrays, including singleton GETs. Aggregated Compute items contain explicit scope maps.
Transport counts are checked before normalization; IAM binding expansion and nested scopes
can yield different observation counts. Malformed and unexpected shapes fail explicitly.
Indexed child names never identify a parent: canonical names or recorded read-only context do.
Zero collector page/detail limits mean unlimited collection; analyzer bounds still apply.

SUCCESS/EMPTY retain partial provenance: the collector declares no source hashes or provable
pagination completeness. EMPTY REST output cannot prove the source array field existed.
TRUNCATED retains partial observations and blocks positive conclusions from that source.
FAILED, API_DISABLED, ACCESS_DENIED, COMMAND_ERROR, AUTH_ERROR, RATE_LIMITED, NOT_FOUND,
HTTP_ERROR and SERVER_ERROR preserve failure metadata; failed output is never configuration.
API_DISABLED and ACCESS_DENIED never establish absence or a control PASS.

## Dataset support

All listed families are recognized and normalize typed metadata when their shape/identity is valid.
`NOT_EVALUATED` means no existing rule consumes that resource type. Evidence and coverage are
displayed/reportable; this does not imply a finding or report approval. Unknown families are
retained as unsupported observations. Read permission requirements must be reviewed for the
recorded source operation; exact permission mappings are not inferred from command success.

| Domain | Dataset / bounded pattern | Source | Resource type | Rule consumers |
|---|---|---|---|---|
| inventory | `project` | @('projects','describe',$ProjectId) | GCP::Project | NOT_EVALUATED |
| inventory | `assets` | @('asset','search-all-resources',"--scope=projects/$ProjectId") | GCP::Asset | NOT_EVALUATED |
| inventory | `asset_iam_search` | @('asset','search-all-iam-policies',"--scope=projects/$ProjectId") | GCP::AssetIAMSearchResult | NOT_EVALUATED |
| inventory | `asset_resource_list` | @('asset','list',"--project=$ProjectId",'--content-type=resource') | GCP::AssetResourceSnapshot | NOT_EVALUATED |
| inventory | `asset_iam_list` | @('asset','list',"--project=$ProjectId",'--content-type=iam-policy') | GCP::AssetIAMSnapshot | NOT_EVALUATED |
| api | `enabled_services` | @('services','list','--enabled',"--project=$ProjectId") | GCP::Service | NOT_EVALUATED |
| api | `api_keys` | @('services','api-keys','list',"--project=$ProjectId") | GCP::APIKey | GCP-API-APP, GCP-API-API, GCP-API-BOTH |
| identity | `project_iam` | @('projects','get-iam-policy',$ProjectId) | GCP::IAMPolicy | GCP-STORAGE-PUBLIC, GCP-IAM-BASIC, GCP-IAM-PUBLIC, GCP-IAM-IMPERSONATION, GCP-IAM-CROSSPROJECT, GCP-LOG-AUDIT, GCP-LOG-AUDIT-COVERAGE, GCP-IAM-CUSTOM-PUBLIC |
| identity | `service_accounts` | @('iam','service-accounts','list',"--project=$ProjectId") | GCP::ServiceAccount | NOT_EVALUATED |
| identity | `custom_roles` | @('iam','roles','list',"--project=$ProjectId") | GCP::CustomRole | NOT_EVALUATED |
| governance | `org_policies` | @('org-policies','list',"--project=$ProjectId") | GCP::OrgPolicyInventory | NOT_EVALUATED |
| logging | `sinks` | @('logging','sinks','list',"--project=$ProjectId") | GCP::LoggingSink | NOT_EVALUATED |
| logging | `buckets_global` | @('logging','buckets','list',"--project=$ProjectId",'--location=global') | GCP::LogBucket | GCP-LOG-RETENTION |
| monitoring | `alert_policies` | @('monitoring','policies','list',"--project=$ProjectId") | GCP::AlertPolicy | GCP-MONITOR-ALERT-DISABLED |
| network | `vpcs` | @('compute','networks','list',"--project=$ProjectId") | GCP::Network | GCP-NET-DEFAULT-NETWORK |
| network | `subnets` | @('compute','networks','subnets','list',"--project=$ProjectId") | GCP::Subnet | GCP-NET-FLOW-LOGS, GCP-NET-PRIVATE-GOOGLE-ACCESS |
| network | `firewall_rules` | @('compute','firewall-rules','list',"--project=$ProjectId") | GCP::Firewall | GCP-NET-FW-ADMIN-INTERNET, GCP-NET-FW-DB-INTERNET, GCP-NET-FW-ANY-INTERNET |
| network | `firewall_policies` | @('compute','network-firewall-policies','list',"--project=$ProjectId") | GCP::FirewallPolicy | GCP-NET-FIREWALL-POLICY |
| network | `routes` | @('compute','routes','list',"--project=$ProjectId") | GCP::Route | NOT_EVALUATED |
| network | `addresses` | @('compute','addresses','list',"--project=$ProjectId") | GCP::Address | NOT_EVALUATED |
| network | `routers` | @('compute','routers','list',"--project=$ProjectId") | GCP::Router | NOT_EVALUATED |
| network | `forwarding_rules` | @('compute','forwarding-rules','list',"--project=$ProjectId") | GCP::ForwardingRule | NOT_EVALUATED |
| network | `vpn_tunnels` | @('compute','vpn-tunnels','list',"--project=$ProjectId") | GCP::VPNTunnel | NOT_EVALUATED |
| compute | `instances` | @('compute','instances','list',"--project=$ProjectId") | GCP::ComputeInstance | GCP-VM-EXTERNAL-IP, GCP-VM-DEFAULT-SA, GCP-VM-FULL-API-SCOPE, GCP-VM-SERIAL-PORT, GCP-VM-OSLOGIN, GCP-VM-PROJECT-SSH-KEYS, GCP-VM-SHIELDED, GCP-VM-IP-FORWARD |
| compute | `disks` | @('compute','disks','list',"--project=$ProjectId") | GCP::Disk | NOT_EVALUATED |
| compute | `snapshots` | @('compute','snapshots','list',"--project=$ProjectId") | GCP::Snapshot | NOT_EVALUATED |
| compute | `gke_clusters` | @('container','clusters','list',"--project=$ProjectId") | GCP::GKECluster | GCP-GKE-LEGACY-ABAC, GCP-GKE-PRIVATE-NODES, GCP-GKE-SHIELDED-NODES, GCP-GKE-CLIENT-CERT, GCP-GKE-ENDPOINT, GCP-GKE-WORKLOAD-IDENTITY, GCP-GKE-NETWORK-POLICY, GCP-GKE-SECRETS-ENCRYPTION |
| serverless | `cloud_run` | @('run','services','list',"--project=$ProjectId") | GCP::RunService | GCP-RUN-PUBLIC, GCP-RUN-RUNTIME-PRIVILEGE |
| serverless | `functions` | @('functions','list',"--project=$ProjectId") | GCP::Function | GCP-FUNCTION-PUBLIC, GCP-FUNCTION-RUNTIME-PRIVILEGE |
| storage | `buckets` | @('storage','buckets','list',"--project=$ProjectId") | GCP::Bucket | GCP-STORAGE-UBLA, GCP-STORAGE-PAP, GCP-STORAGE-VERSIONING |
| data | `cloud_sql` | @('sql','instances','list',"--project=$ProjectId") | GCP::SQLInstance | GCP-SQL-OPEN-NETWORK, GCP-SQL-PUBLIC-IP, GCP-SQL-TLS, GCP-SQL-BACKUP, GCP-SQL-EXPLICIT-FLAGS |
| security | `secrets` | @('secrets','list',"--project=$ProjectId") | GCP::Secret | GCP-SECRET-LIFECYCLE |
| devops | `artifact_repositories` | @('artifacts','repositories','list',"--project=$ProjectId",'--location=all') | GCP::ArtifactRepository | GCP-ARTIFACT-TAGS |
| identity | `workload_identity_pools` | @('iam','workload-identity-pools','list',"--project=$ProjectId",'--location=global') | GCP::WorkloadIdentityPool | NOT_EVALUATED |
| security | `scc_findings` | @('scc','findings','list',"projects/$ProjectId") | GCP::SCCFinding | GCP-SCC-OBSERVATION |
| network | `dns_managed_zones` | @('dns','managed-zones','list',"--project=$ProjectId") | GCP::DNSZone | GCP-DNS-DNSSEC |
| compute | `mig_managed` | @('compute','instance-groups','managed','list',"--project=$ProjectId") | GCP::InstanceGroup | NOT_EVALUATED |
| serverless | `cloud_run_jobs` | @('run','jobs','list',"--project=$ProjectId") | GCP::RunJob | NOT_EVALUATED |
| messaging | `pubsub_topics` | @('pubsub','topics','list',"--project=$ProjectId") | GCP::PubSubTopic | NOT_EVALUATED |
| messaging | `pubsub_subscriptions` | @('pubsub','subscriptions','list',"--project=$ProjectId") | GCP::PubSubSubscription | GCP-PUBSUB-PUSH-AUTH |
| data | `spanner_instances` | @('spanner','instances','list',"--project=$ProjectId") | GCP::SpannerInstance | NOT_EVALUATED |
| devops | `cloudbuild_triggers` | @('builds','triggers','list',"--project=$ProjectId") | GCP::BuildTrigger | GCP-BUILD-APPROVAL |
| logging | `settings` | @('logging','settings','describe',"--project=$ProjectId") | GCP::LoggingSettings | NOT_EVALUATED |
| logging | `log_metrics` | @('logging','metrics','list',"--project=$ProjectId") | GCP::LogMetric | NOT_EVALUATED |
| logging | `buckets_us_central1` | @('logging','buckets','list',"--project=$ProjectId",'--location=us-central1') | GCP::LogBucket | GCP-LOG-RETENTION |
| logging | `buckets_europe_west1` | @('logging','buckets','list',"--project=$ProjectId",'--location=europe-west1') | GCP::LogBucket | GCP-LOG-RETENTION |
| network | `ssl_policies` | @('compute','ssl-policies','list',"--project=$ProjectId") | GCP::SSLPolicy | GCP-LB-TLS |
| network | `backend_services` | @('compute','backend-services','list',"--project=$ProjectId") | GCP::BackendService | GCP-LB-ARMOR, GCP-LB-LOGGING |
| network | `url_maps` | @('compute','url-maps','list',"--project=$ProjectId") | GCP::URLMap | NOT_EVALUATED |
| network | `security_policies` | @('compute','security-policies','list',"--project=$ProjectId") | GCP::SecurityPolicy | NOT_EVALUATED |
| compute | `instance_templates` | @('compute','instance-templates','list',"--project=$ProjectId") | GCP::InstanceTemplate | NOT_EVALUATED |
| compute | `images` | @('compute','images','list',"--project=$ProjectId") | GCP::Image | NOT_EVALUATED |
| governance | `parent_org_iam` | @('organizations','get-iam-policy',$parentId) | GCP::IAMPolicy | GCP-STORAGE-PUBLIC, GCP-IAM-BASIC, GCP-IAM-PUBLIC, GCP-IAM-IMPERSONATION, GCP-IAM-CROSSPROJECT, GCP-LOG-AUDIT, GCP-LOG-AUDIT-COVERAGE, GCP-IAM-CUSTOM-PUBLIC |
| governance | `parent_org_policies` | @('org-policies','list',"--organization=$parentId") | GCP::OrgPolicyInventory | NOT_EVALUATED |
| governance | `parent_folder_iam` | @('resource-manager','folders','get-iam-policy',$parentId) | GCP::IAMPolicy | GCP-STORAGE-PUBLIC, GCP-IAM-BASIC, GCP-IAM-PUBLIC, GCP-IAM-IMPERSONATION, GCP-IAM-CROSSPROJECT, GCP-LOG-AUDIT, GCP-LOG-AUDIT-COVERAGE, GCP-IAM-CUSTOM-PUBLIC |
| governance | `parent_folder_policies` | @('org-policies','list',"--folder=$parentId") | GCP::OrgPolicyInventory | NOT_EVALUATED |
| api | `api_key_detail_[1-9][0-9]{0,5}` | @('services','api-keys','describe',([string]$key.name),"--project=$ProjectId") | GCP::APIKey | GCP-API-APP, GCP-API-API, GCP-API-BOTH |
| identity | `sa_keys_[1-9][0-9]{0,5}` | @('iam','service-accounts','keys','list',"--iam-account=$email","--project=$ProjectId") | GCP::ServiceAccountKey | GCP-KEY-PERSISTENT, GCP-KEY-AGE, GCP-KEY-PRIVILEGED |
| identity | `sa_iam_[1-9][0-9]{0,5}` | @('iam','service-accounts','get-iam-policy',$email,"--project=$ProjectId") | GCP::IAMPolicy | GCP-STORAGE-PUBLIC, GCP-IAM-BASIC, GCP-IAM-PUBLIC, GCP-IAM-IMPERSONATION, GCP-IAM-CROSSPROJECT, GCP-LOG-AUDIT, GCP-LOG-AUDIT-COVERAGE, GCP-IAM-CUSTOM-PUBLIC |
| storage | `bucket_iam_[1-9][0-9]{0,5}` | @('storage','buckets','get-iam-policy',$uri) | GCP::IAMPolicy | GCP-STORAGE-PUBLIC, GCP-IAM-BASIC, GCP-IAM-PUBLIC, GCP-IAM-IMPERSONATION, GCP-IAM-CROSSPROJECT, GCP-LOG-AUDIT, GCP-LOG-AUDIT-COVERAGE, GCP-IAM-CUSTOM-PUBLIC |
| storage | `bucket_details_[1-9][0-9]{0,5}` | @('storage','buckets','describe',$uri) | GCP::Bucket | GCP-STORAGE-UBLA, GCP-STORAGE-PAP, GCP-STORAGE-VERSIONING |
| identity | `service_account_keys_inventory` | @('iam','service-accounts','list',"--project=$ProjectId") | GCP::ServiceAccount | NOT_EVALUATED |
| governance | `project_org_policy_v2` | @('org-policies','list',"--project=$ProjectId") | GCP::OrgPolicyInventory | NOT_EVALUATED |
| security | `kms_locations` | @('kms','locations','list',"--project=$ProjectId") | GCP::KMSLocation | NOT_EVALUATED |
| logging | `exclusions` | ($baseLogging+'/exclusions?pageSize=1000') | GCP::LoggingExclusion | GCP-LOG-EXCLUSION |
| logging | `log_buckets_locations` | ('https://logging.googleapis.com/v2/projects/'+[Uri]::EscapeDataString($ProjectId)+'/locations/-/buckets?pageSize=1000') | GCP::LogBucket | GCP-LOG-RETENTION |
| logging | `logging_settings_rest` | ($baseLogging+'/settings') | GCP::LoggingSettings | NOT_EVALUATED |
| api | `api_keys_rest` | ('https://apikeys.googleapis.com/v2/projects/'+[Uri]::EscapeDataString($ProjectId)+'/locations/global/keys?pageSize=1000') | GCP::APIKey | GCP-API-APP, GCP-API-API, GCP-API-BOTH |
| data | `bigquery_datasets_rest` | ('https://bigquery.googleapis.com/bigquery/v2/projects/'+[Uri]::EscapeDataString($ProjectId)+'/datasets?all=true&maxResults=1000') | GCP::BigQueryDataset | GCP-BQ-PUBLIC-DATA |
| data | `bq_dataset_[A-Za-z0-9_-]{1,200}_details` | $url | GCP::BigQueryDataset | GCP-BQ-PUBLIC-DATA |
| data | `bq_dataset_[A-Za-z0-9_-]{1,200}_tables` | ($url+'/tables?maxResults=1000') | GCP::BigQueryTable | NOT_EVALUATED |
| ai | `discovery_resource_[1-9][0-9]{0,5}` | ($host+$resourceName) | GCP::DiscoveryResource | NOT_EVALUATED |
| identity | `folder_[0-9]{1,20}_iam` | @('resource-manager','folders','get-iam-policy',$identifier) | GCP::IAMPolicy | GCP-STORAGE-PUBLIC, GCP-IAM-BASIC, GCP-IAM-PUBLIC, GCP-IAM-IMPERSONATION, GCP-IAM-CROSSPROJECT, GCP-LOG-AUDIT, GCP-LOG-AUDIT-COVERAGE, GCP-IAM-CUSTOM-PUBLIC |
| governance | `folder_[0-9]{1,20}_policies` | @('org-policies','list',"--folder=$identifier") | GCP::OrgPolicyInventory | NOT_EVALUATED |
| inventory | `folder_[0-9]{1,20}_iam_search` | @('asset','search-all-iam-policies',"--scope=$nodeName") | GCP::AssetIAMSearchResult | NOT_EVALUATED |
| inventory | `folder_[0-9]{1,20}_describe` | @('resource-manager','folders','describe',$identifier) | GCP::Folder | NOT_EVALUATED |
| identity | `organization_[0-9]{1,20}_iam` | @('organizations','get-iam-policy',([string]$node.id)) | GCP::IAMPolicy | GCP-STORAGE-PUBLIC, GCP-IAM-BASIC, GCP-IAM-PUBLIC, GCP-IAM-IMPERSONATION, GCP-IAM-CROSSPROJECT, GCP-LOG-AUDIT, GCP-LOG-AUDIT-COVERAGE, GCP-IAM-CUSTOM-PUBLIC |
| inventory | `organization_[0-9]{1,20}_iam_search` | @('asset','search-all-iam-policies',"--scope=$orgScope") | GCP::AssetIAMSearchResult | NOT_EVALUATED |
| governance | `organization_[0-9]{1,20}_policies` | @('org-policies','list',('--organization=' + $node.id)) | GCP::OrgPolicyInventory | NOT_EVALUATED |
| identity | `custom_role_detail_[1-9][0-9]{0,5}` | @('iam','roles','describe',([string]$role.name)) | GCP::CustomRole | NOT_EVALUATED |
| identity | `workload_pool_providers_[1-9][0-9]{0,5}` | @('iam','workload-identity-pools','providers','list',('--workload-identity-pool='+($poolName -split '/')[-1]),'--location=global',"--project=$ProjectId") | GCP::WorkloadIdentityProvider | GCP-WIF-SHARED-ISSUER |
| governance | `effective_policy_[1-9][0-9]{0,5}` | @('org-policies','describe',$constraint,'--effective',"--project=$ProjectId") | GCP::OrgPolicy | GCP-GOV-KEYS, GCP-GOV-GUARDRAIL |
| identity | `deny_policies_project` | ('https://iam.googleapis.com/v2/policies/cloudresourcemanager.googleapis.com%2Fprojects%2F'+$ProjectNumber+'/denypolicies?pageSize=1000') | GCP::IAMDenyPolicy | NOT_EVALUATED |
| identity | `principal_access_boundaries_project` | ('https://iam.googleapis.com/v3/projects/'+$P+'/locations/global/policyBindings?pageSize=1000') | GCP::PrincipalAccessBoundaryBinding | NOT_EVALUATED |
| identity | `workforce_pools` | ('https://iam.googleapis.com/v1/locations/global/workforcePools?pageSize=1000') | GCP::WorkforcePool | NOT_EVALUATED |
| identity | `iam_recommendations` | ('https://recommender.googleapis.com/v1/projects/'+$P+'/locations/global/recommenders/google.iam.policy.Recommender/recommendations?pageSize=1000') | GCP::IAMRecommendation | NOT_EVALUATED |
| security | `access_context_policies` | ('https://accesscontextmanager.googleapis.com/v1/accessPolicies?pageSize=1000') | GCP::AccessPolicy | NOT_EVALUATED |
| security | `scc_sources` | ('https://securitycenter.googleapis.com/v1/projects/'+$P+'/sources?pageSize=1000') | GCP::SCCSource | NOT_EVALUATED |
| security | `scc_findings_rest` | ('https://securitycenter.googleapis.com/v1/projects/'+$P+'/sources/-/findings?pageSize=1000') | GCP::SCCFinding | GCP-SCC-OBSERVATION |
| inventory | `compute_regions_rest` | ('https://compute.googleapis.com/compute/v1/projects/'+$P+'/regions?maxResults=500') | GCP::ComputeRegion | NOT_EVALUATED |
| inventory | `compute_zones_rest` | ('https://compute.googleapis.com/compute/v1/projects/'+$P+'/zones?maxResults=500') | GCP::ComputeZone | NOT_EVALUATED |
| security | `kms_locations_rest` | ('https://cloudkms.googleapis.com/v1/projects/'+$P+'/locations?pageSize=1000') | GCP::KMSLocation | NOT_EVALUATED |
| security | `secrets_rest` | ('https://secretmanager.googleapis.com/v1/projects/'+$P+'/secrets?pageSize=1000') | GCP::Secret | GCP-SECRET-LIFECYCLE |
| data | `sql_instances_rest` | ('https://sqladmin.googleapis.com/sql/v1beta4/projects/'+$P+'/instances?maxResults=500') | GCP::SQLInstance | GCP-SQL-OPEN-NETWORK, GCP-SQL-PUBLIC-IP, GCP-SQL-TLS, GCP-SQL-BACKUP, GCP-SQL-EXPLICIT-FLAGS |
| compute | `gke_clusters_rest` | ('https://container.googleapis.com/v1/projects/'+$P+'/locations/-/clusters') | GCP::GKECluster | GCP-GKE-LEGACY-ABAC, GCP-GKE-PRIVATE-NODES, GCP-GKE-SHIELDED-NODES, GCP-GKE-CLIENT-CERT, GCP-GKE-ENDPOINT, GCP-GKE-WORKLOAD-IDENTITY, GCP-GKE-NETWORK-POLICY, GCP-GKE-SECRETS-ENCRYPTION |
| serverless | `run_services_rest` | ('https://run.googleapis.com/v2/projects/'+$P+'/locations/-/services?pageSize=1000') | GCP::RunService | GCP-RUN-PUBLIC, GCP-RUN-RUNTIME-PRIVILEGE |
| serverless | `run_jobs_rest` | ('https://run.googleapis.com/v2/projects/'+$P+'/locations/-/jobs?pageSize=1000') | GCP::RunJob | NOT_EVALUATED |
| serverless | `functions_rest` | ('https://cloudfunctions.googleapis.com/v2/projects/'+$P+'/locations/-/functions?pageSize=1000') | GCP::Function | GCP-FUNCTION-PUBLIC, GCP-FUNCTION-RUNTIME-PRIVILEGE |
| monitoring | `notification_channels` | ('https://monitoring.googleapis.com/v3/projects/'+$P+'/notificationChannels?pageSize=1000') | GCP::NotificationChannel | NOT_EVALUATED |
| monitoring | `uptime_check_configs` | ('https://monitoring.googleapis.com/v3/projects/'+$P+'/uptimeCheckConfigs?pageSize=1000') | GCP::UptimeCheck | NOT_EVALUATED |
| network | `dns_policies` | ('https://dns.googleapis.com/dns/v1/projects/'+$P+'/policies?maxResults=500') | GCP::DNSPolicy | NOT_EVALUATED |
| network | `vpc_peerings` | ('https://compute.googleapis.com/compute/v1/projects/'+$P+'/global/networks?maxResults=500') | GCP::Network | GCP-NET-DEFAULT-NETWORK |
| network | `global_security_policies_rest` | ('https://compute.googleapis.com/compute/v1/projects/'+$P+'/global/securityPolicies?maxResults=500') | GCP::SecurityPolicy | NOT_EVALUATED |
| network | `interconnect_attachments` | ('https://compute.googleapis.com/compute/v1/projects/'+$P+'/aggregated/interconnectAttachments?maxResults=500') | GCP::InterconnectAttachment | NOT_EVALUATED |
| network | `psc_forwarding_rules` | ('https://compute.googleapis.com/compute/v1/projects/'+$P+'/aggregated/forwardingRules?maxResults=500') | GCP::ForwardingRule | NOT_EVALUATED |
| data | `bigquery_connections` | ('https://bigqueryconnection.googleapis.com/v1/projects/'+$P+'/locations/-/connections?pageSize=1000') | GCP::BigQueryConnection | NOT_EVALUATED |
| devops | `artifact_repositories_rest` | ('https://artifactregistry.googleapis.com/v1/projects/'+$P+'/locations/-/repositories?pageSize=1000') | GCP::ArtifactRepository | GCP-ARTIFACT-TAGS |
| devops | `cloudbuild_triggers_rest` | ('https://cloudbuild.googleapis.com/v1/projects/'+$P+'/triggers?pageSize=1000') | GCP::BuildTrigger | GCP-BUILD-APPROVAL |
| security | `kms_keyrings_[1-9][0-9]{0,5}` | ($locUrl+'/keyRings?pageSize=1000') | GCP::KMSKeyRing | NOT_EVALUATED |
| security | `kms_keys_[1-9][0-9]{0,5}_[1-9][0-9]{0,5}` | ('https://cloudkms.googleapis.com/v1/'+[string]$ring.name+'/cryptoKeys?pageSize=1000') | GCP::KMSKey | GCP-KMS-ROTATION |
| security | `kms_versions_[1-9][0-9]{0,5}_[1-9][0-9]{0,5}_[1-9][0-9]{0,5}` | ($keyUrl+'/cryptoKeyVersions?pageSize=1000') | GCP::KMSKeyVersion | NOT_EVALUATED |
| security | `secret_versions_[1-9][0-9]{0,5}` | ('https://secretmanager.googleapis.com/v1/'+[string]$secret.name+'/versions?pageSize=1000') | GCP::SecretVersion | NOT_EVALUATED |
| compute | `gke_node_pools_[1-9][0-9]{0,5}` | ('https://container.googleapis.com/v1/'+$path+'/nodePools') | GCP::GKENodePool | GCP-GKE-NODE-PRIVILEGE |
| serverless | `run_iam_[1-9][0-9]{0,5}` | @('run','services','get-iam-policy',$parts[-1],'--region='+$parts[3],'--project='+$ProjectId) | GCP::IAMPolicy | GCP-STORAGE-PUBLIC, GCP-IAM-BASIC, GCP-IAM-PUBLIC, GCP-IAM-IMPERSONATION, GCP-IAM-CROSSPROJECT, GCP-LOG-AUDIT, GCP-LOG-AUDIT-COVERAGE, GCP-IAM-CUSTOM-PUBLIC |
| serverless | `function_iam_[1-9][0-9]{0,5}` | @('functions','get-iam-policy',$parts[-1],'--region='+$parts[3],'--project='+$ProjectId) | GCP::IAMPolicy | GCP-STORAGE-PUBLIC, GCP-IAM-BASIC, GCP-IAM-PUBLIC, GCP-IAM-IMPERSONATION, GCP-IAM-CROSSPROJECT, GCP-LOG-AUDIT, GCP-LOG-AUDIT-COVERAGE, GCP-IAM-CUSTOM-PUBLIC |

## Application consumers and limitations

Each definition exposes `COLLECTED → RECOGNIZED → NORMALIZED → EVALUATED → DISPLAYED → REPORTABLE`
states in the machine-readable inventory. Account Explorer uses project scope; IAM Intelligence
shows observed identities/policies and qualified structural relationships. Evidence Explorer
retains unsupported observations and collection outcomes. Network Analysis shows only collected
network metadata; missing datasets and unsupported controls are coverage limitations.
Dashboard coverage denominators are declared operations and actual persisted evaluations,
never inferred cloud-resource totals or a security score. Reports use the selected run.

## Collector reliability review

The 2.1 script had an unbounded gcloud WaitForExit(), no pagination-token cycle guard,
no source integrity hashes, and could turn a missing REST array field into EMPTY.
Collector 2.2.0 (`collectors/gcp/`, schema `assessment-expanded-2.2`) bounds commands,
retries REST calls, guards pagination, records UNEXPECTED_SCHEMA/PARTIAL/TIMEOUT/
QUOTA_PROJECT_DENIED/UNSUPPORTED_ENDPOINT gaps and writes verified checksums. 2.1 packages
remain accepted with their limitations; the analyzer cannot recover uncollected records.

Regenerate: `PYTHONPATH=src python -m tools.gcp_collector_contract --doc docs/GCP_COLLECTOR_CONTRACT.md`.
Machine inventory: add `--json <local-output.json>`; tests import the same authoritative definitions.
