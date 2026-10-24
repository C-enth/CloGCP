"""Cloud-neutral view of the approved checklist: one control list for AWS and GCP.

The approved workbook (pinned by REVIEWED_METHODOLOGY_SHA256) is the single assessment
checklist for both clouds. This module holds control IDs, engineering paraphrases of
control titles (never source requirement text), per-provider applicability and the GCP
evidence/check areas an analyst uses for each GCP-applicable control. Control-level
outcomes are derived from rule results and never yield a control-level PASS, because no
rule evaluates every source criterion of a control.
"""

from collections import Counter

from offline_analyzer.methodology.coverage_spec import BY_CONTROL, COVERAGE, GCP_CONFIG_COVERAGE

AWS, GCP = "AWS", "GCP"
BOTH, NON_CLOUD = (AWS, GCP), ()

DOMAINS = {
    "1": "Cloud security (AWS and GCP)",
    "2": "Identity and access management",
    "3": "On-premises infrastructure",
    "4": "Network and security devices",
    "5": "Vulnerability assessment",
    "6": "Configuration and hardening",
    "7": "Access control and privilege review",
    "8": "Logging, monitoring and detection",
    "AWS": "AWS-specific control areas",
}

AREAS = {
    "1.1": "Account and project structure",
    "1.2": "Organization guardrails",
    "1.3": "Compute security",
    "1.4": "Storage security",
    "1.5": "Network security",
    "1.6": "Cloud-native IAM",
    "1.7": "Cloud logging and monitoring",
    "1.8": "Secrets and key management",
    "1.9": "Containers and serverless",
    "2.1": "Identity inventory",
    "2.2": "Privileged access",
    "2.3": "Active Directory",
    "2.4": "Entra ID",
    "2.5": "Federation and SSO",
    "2.6": "Authentication and MFA",
    "2.7": "Conditional access",
    "2.8": "Service-account governance",
    "3.1": "Windows servers",
    "3.2": "Linux servers",
    "3.3": "Directory integration",
    "3.4": "Virtualization",
    "3.5": "Server vulnerabilities",
    "3.6": "Lateral movement",
    "3.7": "Backup and recovery",
    "4.1": "Network architecture",
    "4.2": "Firewall rulebase",
    "4.3": "Routers and switches",
    "4.4": "Load balancers",
    "4.5": "Web application firewall",
    "4.6": "DDoS protection",
    "4.7": "Traffic flows",
    "4.8": "VPN and remote access",
    "5.1": "External attack surface",
    "5.2": "Internal scanning",
    "5.3": "Cloud vulnerability assessment",
    "5.4": "Attack-surface discovery",
    "6.1": "Cloud CIS benchmarks",
    "6.2": "OS CIS benchmarks",
    "6.3": "Cloud default configuration",
    "6.4": "Certificates and TLS",
    "6.5": "Misconfiguration summary",
    "7.1": "Access cross-mapping",
    "7.2": "Orphaned and dormant accounts",
    "7.3": "Privileged access paths",
    "7.4": "Third-party access",
    "7.5": "Access recertification",
    "8.1": "Logging coverage",
    "8.2": "SIEM integration",
    "8.3": "Detection capability",
    "8.4": "Log retention and integrity",
    "8.5": "Alert tuning",
    "8.6": "Incident response readiness",
}

# Engineering paraphrases of each control's subject (not the source requirement text).
TITLES = {
    "1.1.2": "Project, folder and organization hierarchy",
    "1.1.3": "Root / management account usage",
    "1.1.4": "Production and non-production separation",
    "1.1.5": "Billing and cost-anomaly alerting",
    "1.1.6": "Resource labelling and ownership",
    "1.1.7": "Shared-services account misuse",
    "1.1.8": "Isolated logging account or project",
    "1.2.1": "Service control policy coverage",
    "1.2.2": "Organization policy constraint coverage",
    "1.2.3": "Preventive versus detective guardrails",
    "1.2.4": "Guardrail exceptions and bypasses",
    "1.2.5": "Guardrails for high-risk actions",
    "1.2.6": "Ability to disable guardrails",
    "1.3.1": "Internet-exposed instances",
    "1.3.2": "SSH / RDP open to the internet",
    "1.3.3": "Instance metadata (IMDSv2) enforcement",
    "1.3.4": "Instance identity permissions",
    "1.3.5": "Image age and OS patching",
    "1.3.6": "Secrets in instance startup data",
    "1.3.7": "Session Manager access",
    "1.4.1": "Storage public-access prevention",
    "1.4.2": "Public or cross-account bucket access",
    "1.4.3": "Storage encryption at rest",
    "1.4.4": "Storage encryption in transit",
    "1.4.5": "Object versioning and lock",
    "1.4.6": "Sensitive data in storage",
    "1.4.7": "Storage lifecycle and retention",
    "1.4.8": "Replication security",
    "1.5.1": "Network and subnet segmentation",
    "1.5.2": "Inbound firewall / security-group exposure",
    "1.5.3": "Unrestricted outbound rules",
    "1.5.4": "Peering and transit connectivity",
    "1.5.5": "Default network and default rules",
    "1.5.6": "Network ACL effectiveness",
    "1.5.7": "Flow logs enabled",
    "1.5.8": "Private endpoints and service connections",
    "1.6.1": "Users with console and programmatic access",
    "1.6.2": "Access-key age and rotation",
    "1.6.3": "Wildcard and public-principal permissions",
    "1.6.4": "GCP basic roles (Owner / Editor / Viewer)",
    "1.6.5": "Cross-account and cross-project trust",
    "1.6.6": "Unused roles and permissions",
    "1.6.7": "IAM privilege-escalation paths",
    "1.7.1": "CloudTrail in all regions",
    "1.7.2": "GCP Admin Activity and Data Access audit logs",
    "1.7.3": "CloudTrail log integrity",
    "1.7.4": "Log storage protection",
    "1.7.5": "Alerts on critical API calls",
    "1.7.6": "Forwarding to a central SIEM",
    "1.7.7": "Ability to disable logging",
    "1.8.1": "Hard-coded secrets in repositories",
    "1.8.2": "Managed secret store versus environment variables",
    "1.8.3": "Key policies and key access",
    "1.8.4": "Key rotation",
    "1.8.5": "API key and token lifecycle",
    "1.8.6": "Secret-access logging",
    "1.9.1": "Container image scanning",
    "1.9.2": "Task / pod identity permissions",
    "1.9.3": "Serverless function permissions and exposure",
    "1.9.4": "Public container registries",
    "1.9.5": "Secrets in function environment",
    "1.9.6": "Privileged containers and host mounts",
    "2.1.1": "Inventory of human and service identities",
    "2.1.2": "Shared and generic accounts",
    "2.2.1": "Administrative and privileged roles",
    "2.2.2": "Effective (not just assigned) permissions",
    "2.2.3": "Privileged-access tooling",
    "2.2.4": "Just-in-time access",
    "2.3.1": "Forest and domain structure",
    "2.3.2": "Privileged directory groups",
    "2.3.3": "Kerberos attack surface",
    "2.3.4": "Directory delegation",
    "2.3.5": "Group policy security",
    "2.4.1": "Tenant configuration",
    "2.4.2": "App registrations and service principals",
    "2.4.3": "Privileged identity management",
    "2.5.1": "SAML / OIDC / workload federation trust",
    "2.5.2": "SSO scope and entitlements",
    "2.6.1": "MFA enforcement",
    "2.6.2": "MFA method strength",
    "2.6.3": "Password policy",
    "2.7.1": "Conditional access coverage",
    "2.7.2": "Named locations and trusted IPs",
    "2.7.3": "Device compliance",
    "2.8.1": "Service-account inventory and ownership",
    "2.8.2": "Service-account privilege",
    "2.8.3": "Service-account key rotation",
    "3.1.1": "Windows patching",
    "3.1.2": "Local administrator accounts",
    "3.1.3": "Host firewall",
    "3.1.4": "Windows hardening baseline",
    "3.2.1": "Linux patching",
    "3.2.2": "SSH daemon configuration",
    "3.2.3": "Sudo and SUID",
    "3.2.4": "Linux hardening baseline",
    "3.3.1": "Domain join and OU placement",
    "3.3.2": "Privileged groups on servers",
    "3.4.1": "Hypervisor access",
    "3.4.2": "VM isolation",
    "3.4.3": "Hypervisor patching",
    "3.5.1": "Internal vulnerability scanning",
    "3.5.2": "Unnecessary services and ports",
    "3.6.1": "SMB signing",
    "3.6.2": "LLMNR / NBT-NS poisoning",
    "3.6.3": "Credential reuse",
    "3.6.4": "RDP and NLA",
    "3.7.1": "Backup system access",
    "3.7.2": "Backup storage exposure",
    "3.7.3": "Backup restore testing",
    "4.1.1": "Topology and segmentation",
    "4.1.2": "Inter-zone controls",
    "4.1.3": "Management network isolation",
    "4.2.1": "Any-any firewall rules",
    "4.2.2": "Broad inbound firewall rules",
    "4.2.3": "Unused and shadowed rules",
    "4.2.4": "Firewall administration",
    "4.2.5": "Firewall firmware",
    "4.3.1": "Network device authentication",
    "4.3.2": "Management protocols",
    "4.3.3": "Unused device ports",
    "4.4.1": "Load-balancer TLS policy",
    "4.4.2": "Load-balancer access and admin exposure",
    "4.5.1": "WAF coverage",
    "4.5.2": "WAF blocking mode",
    "4.5.3": "WAF rule tuning",
    "4.6.1": "DDoS protection coverage",
    "4.6.2": "DDoS runbook",
    "4.7.1": "Critical traffic-flow validation",
    "4.7.2": "Egress filtering",
    "4.8.1": "VPN authentication",
    "4.8.2": "Split tunnelling",
    "5.1.1": "External asset discovery",
    "5.1.2": "External vulnerability scanning",
    "5.1.3": "Exposed login panels and endpoints",
    "5.1.4": "External TLS configuration",
    "5.2.1": "Internal network scanning",
    "5.2.2": "Exploitability-based prioritization",
    "5.2.3": "False-positive validation",
    "5.3.1": "Cloud-native vulnerability service (Inspector / SCC)",
    "5.3.2": "Container image vulnerabilities",
    "5.4.1": "Shadow and undocumented assets",
    "5.4.2": "Third-party and supply-chain exposure",
    "6.1.1": "AWS CIS benchmark",
    "6.1.2": "GCP CIS benchmark",
    "6.2.1": "Windows CIS benchmark",
    "6.2.2": "Linux CIS benchmark",
    "6.3.1": "Insecure service defaults",
    "6.3.2": "Unused services and regions",
    "6.4.1": "Certificate expiry",
    "6.4.2": "TLS versions and ciphers",
    "6.5.1": "Top misconfiguration summary",
    "7.1.1": "User-to-system access matrix",
    "7.1.2": "Duplicate and overlapping roles",
    "7.1.3": "Privilege creep",
    "7.2.1": "Orphaned accounts",
    "7.2.2": "Dormant accounts",
    "7.2.3": "Deprovisioning process",
    "7.3.1": "Bastion and jump hosts",
    "7.3.2": "Privileged session monitoring",
    "7.4.1": "Third-party access inventory",
    "7.4.2": "Vendor access recertification",
    "7.5.1": "Periodic access review",
    "8.1.1": "Cloud audit-log coverage",
    "8.1.2": "Infrastructure log coverage",
    "8.1.3": "Application and database logs",
    "8.2.1": "SIEM source coverage",
    "8.2.2": "Log parsing quality",
    "8.2.3": "SIEM retention",
    "8.3.1": "Detection use cases",
    "8.3.2": "Alert quality",
    "8.3.3": "Threat-scenario detection tests",
    "8.4.1": "Log retention policy",
    "8.4.2": "Log tamper protection",
    "8.5.1": "Alert thresholds",
    "8.6.1": "IR playbooks",
    "8.6.2": "Detection-to-response time",
    "AWS-01": "Organizations OUs and SCP coverage",
    "AWS-02": "Control Tower guardrails and drift",
    "AWS-03": "Identity Center permission sets",
    "AWS-04": "Assume-role trust conditions",
    "AWS-05": "IAM Access Analyzer coverage",
    "AWS-06": "Root user hardening",
    "AWS-07": "Organization CloudTrail",
    "AWS-08": "AWS Config coverage",
    "AWS-09": "GuardDuty enablement",
    "AWS-10": "Security Hub standards",
    "AWS-11": "S3 Block Public Access",
    "AWS-12": "KMS key policy, rotation and grants",
    "AWS-13": "Secrets Manager adoption",
    "AWS-14": "VPC design and flow logs",
    "AWS-15": "Sensitive-port ingress and NACLs",
    "AWS-16": "Transit Gateway and peering",
    "AWS-17": "Network Firewall coverage",
    "AWS-18": "WAF web ACL mode and rules",
    "AWS-19": "IMDSv2 and instance roles",
    "AWS-20": "ECS / ECR security",
    "AWS-21": "Lambda security",
    "AWS-22": "RDS security",
    "AWS-23": "DynamoDB security",
    "AWS-24": "OpenSearch security",
    "AWS-25": "MSK security",
    "AWS-26": "AWS Backup and Vault Lock",
    "AWS-27": "CI/CD OIDC trust and IaC state",
    "AWS-28": "Vendor cross-account roles",
}

AWS_ONLY = {"1.2.1", "1.3.3", "1.3.7", "1.5.6", "1.7.1", "1.7.3", "6.1.1"}
GCP_ONLY = {"1.1.2", "1.2.2", "1.6.4", "1.7.2", "6.1.2"}
CLOUD_SECTIONS_4 = {"4.4", "4.5", "4.6.1", "4.7.2"}


def applies(control_id: str) -> tuple[str, ...]:
    """Clouds whose collected evidence can address the control; () = outside cloud."""
    if control_id.startswith("AWS-") or control_id in AWS_ONLY:
        return (AWS,)
    if control_id in GCP_ONLY:
        return (GCP,)
    section = control_id.split(".")[0]
    area = control_id.rsplit(".", 1)[0]
    if section == "1" or section in {"7", "8"}:
        return BOTH
    if section == "2":
        return NON_CLOUD if area in {"2.3", "2.4", "2.7"} else BOTH
    if section == "4":
        return BOTH if area in CLOUD_SECTIONS_4 or control_id in CLOUD_SECTIONS_4 else NON_CLOUD
    if section == "5":
        return BOTH if area in {"5.3", "5.4"} else NON_CLOUD
    if section == "6":
        return NON_CLOUD if area == "6.2" else BOTH
    return NON_CLOUD


IAM = ("gcp:projects.getIamPolicy", "gcp:cloudasset.organizationIamSearch")
SA = ("gcp:iam.serviceAccounts.list", "gcp:iam.serviceAccountKeys.list")
LOGS = ("gcp:logging.sinks.list", "gcp:logging.buckets.list", "gcp:expanded.logging_settings_rest")
NET = ("gcp:compute.firewalls.list", "gcp:compute.networks.list", "gcp:expanded.subnets")
ORGPOL = ("gcp:orgpolicy.policies.list", "gcp:orgpolicy.organizationPolicies.list")
LB = ("gcp:expanded.forwarding_rules", "gcp:expanded.backend_services", "gcp:expanded.url_maps")

# GCP check areas for each GCP-applicable control: (evidence operations, what to check).
GCP_CHECKS: dict[str, tuple[tuple[str, ...], str]] = {
    "1.1.2": (("gcp:projects.get", "gcp:folders.get"), "Folder/project placement under the org"),
    "1.1.3": (IAM, "Organization Admin and super-admin style bindings and their use"),
    "1.1.4": (
        ("gcp:projects.get", *IAM),
        "Prod/non-prod projects in separate folders; no shared admins",
    ),
    "1.1.5": (("gcp:cloudasset.searchAllResources",), "Billing budgets and alerts (manual)"),
    "1.1.6": (("gcp:cloudasset.searchAllResources",), "Owner/environment labels on projects"),
    "1.1.7": (IAM, "Shared VPC host and shared-service project admin bindings"),
    "1.1.8": (LOGS, "Aggregated sinks into a dedicated logging project"),
    "1.2.2": (ORGPOL, "Key org policy constraints enforced at org/folder level"),
    "1.2.3": (ORGPOL, "Mix of org policy constraints and SCC detectors"),
    "1.2.4": (ORGPOL, "Project-level overrides that relax inherited constraints"),
    "1.2.5": (ORGPOL, "Constraints for SA keys, public IPs, public access prevention, domains"),
    "1.2.6": (IAM, "Who holds roles/orgpolicy.policyAdmin"),
    "1.3.1": (("gcp:compute.instances.list", "gcp:expanded.addresses"), "External IPs on VMs"),
    "1.3.2": (NET, "Firewall rules allowing 22/3389 from 0.0.0.0/0"),
    "1.3.4": (("gcp:compute.instances.list", *IAM), "VM service account and access scopes"),
    "1.3.5": (("gcp:expanded.images", "gcp:compute.instances.list"), "Image age (manual patching)"),
    "1.3.6": (("gcp:compute.instances.list",), "Secrets in startup-script metadata (manual)"),
    "1.4.1": (("gcp:storage.buckets.list", *ORGPOL), "Public access prevention enforced"),
    "1.4.2": (
        ("gcp:storage.buckets.getIamPolicy", *IAM),
        "allUsers/allAuthenticatedUsers bindings",
    ),
    "1.4.3": (("gcp:storage.buckets.list",), "CMEK where required by data classification"),
    "1.4.4": (("gcp:storage.buckets.list",), "TLS-only access (manual)"),
    "1.4.5": (("gcp:storage.buckets.list",), "Object versioning / retention lock"),
    "1.4.6": (("gcp:storage.buckets.list",), "DLP / sensitive-data discovery (manual)"),
    "1.4.7": (("gcp:storage.buckets.list",), "Lifecycle and retention policies"),
    "1.4.8": (("gcp:storage.buckets.list",), "Dual/multi-region and turbo replication posture"),
    "1.5.1": (NET, "Subnet tiering and segmentation per environment"),
    "1.5.2": (NET, "Ingress rules from 0.0.0.0/0 on sensitive ports"),
    "1.5.3": (NET, "Egress allow-all rules"),
    "1.5.4": (("gcp:expanded.vpc_peerings", "gcp:expanded.vpn_tunnels"), "Peering and VPN routes"),
    "1.5.5": (NET, "Default network and default-allow rules"),
    "1.5.7": (("gcp:expanded.subnets",), "VPC Flow Logs on subnets"),
    "1.5.8": (
        ("gcp:expanded.psc_forwarding_rules",),
        "Private Service Connect and Private Google Access",
    ),
    "1.6.1": (IAM, "Human users with direct project bindings plus SA keys"),
    "1.6.2": (SA, "User-managed SA keys and their age"),
    "1.6.3": (IAM, "allUsers/allAuthenticatedUsers and wildcard-equivalent roles"),
    "1.6.4": (IAM, "Owner/Editor bindings to users, groups and service accounts"),
    "1.6.5": (IAM, "Service accounts of one project privileged in another"),
    "1.6.6": (("gcp:expanded.iam_recommendations",), "IAM recommender excess-permission findings"),
    "1.6.7": (IAM, "Token Creator / SA User / actAs grants enabling impersonation"),
    "1.7.2": (("gcp:projects.getIamPolicy",), "auditConfigs for Data Access logs and exemptions"),
    "1.7.4": (LOGS, "Locked retention on log buckets"),
    "1.7.5": (
        ("gcp:monitoring.alertPolicies.list", "gcp:expanded.log_metrics"),
        "Alerts on IAM/audit changes",
    ),
    "1.7.6": (LOGS, "Sinks to the SIEM destination"),
    "1.7.7": (("gcp:logging.exclusions.list", *IAM), "Exclusions and logging.admin holders"),
    "1.8.1": (("gcp:expanded.cloudbuild_triggers",), "Repository secret scanning (manual)"),
    "1.8.2": (
        ("gcp:expanded.secrets", "gcp:expanded.functions"),
        "Secret Manager use versus env vars",
    ),
    "1.8.3": (("gcp:cloudkms.cryptoKeys.list", *IAM), "KMS key IAM bindings"),
    "1.8.4": (("gcp:cloudkms.cryptoKeys.list",), "rotationPeriod on CMEKs"),
    "1.8.5": (("gcp:apikeys.keys.list",), "API key restrictions and age"),
    "1.8.6": (LOGS, "Data Access logs for Secret Manager"),
    "1.9.1": (("gcp:expanded.artifact_repositories",), "Artifact Analysis scanning enabled"),
    "1.9.2": (("gcp:expanded.gke_clusters",), "Workload Identity and node SA scopes"),
    "1.9.3": (
        ("gcp:run.services.list", "gcp:run.services.getIamPolicy", *IAM),
        "Unauthenticated invokers and runtime SA",
    ),
    "1.9.4": (
        ("gcp:expanded.artifact_repositories", *IAM),
        "Public Artifact Registry repositories",
    ),
    "1.9.5": (
        ("gcp:expanded.functions", "gcp:run.services.list"),
        "Secrets in environment variables",
    ),
    "1.9.6": (
        ("gcp:expanded.gke_clusters",),
        "Privileged pods / host mounts (manual, cluster access)",
    ),
    "2.1.1": (("gcp:iam.serviceAccounts.list", *IAM), "All principals bound across the org"),
    "2.1.2": (IAM, "Shared or generic user principals"),
    "2.2.1": (IAM, "Owner, org admin, security admin and IAM admin holders"),
    "2.2.2": (
        ("gcp:expanded.deny_policies_project", "gcp:expanded.principal_access_boundaries_project"),
        "Deny policies and PABs for effective access",
    ),
    "2.2.3": ((), "PAM tooling (interview)"),
    "2.2.4": (IAM, "Conditional / time-bound privileged bindings"),
    "2.5.1": (
        ("gcp:expanded.workload_identity_pools", "gcp:expanded.workforce_pools"),
        "Pool providers and attribute conditions",
    ),
    "2.5.2": (("gcp:expanded.workforce_pools", *IAM), "Workforce pool group entitlements"),
    "2.6.1": ((), "2-step verification in Cloud Identity/Workspace (admin export)"),
    "2.6.2": ((), "Security-key enforcement (admin export)"),
    "2.6.3": ((), "Password policy (admin export)"),
    "2.8.1": (SA, "Service accounts with owners/descriptions"),
    "2.8.2": (IAM, "Service accounts with Owner/Editor/admin roles"),
    "2.8.3": (SA, "User-managed SA keys and rotation"),
    "4.4.1": (("gcp:expanded.ssl_policies", *LB), "SSL policy minimum TLS and profile"),
    "4.4.2": (LB, "Internet-facing load balancers and backends"),
    "4.5.1": (("gcp:expanded.security_policies", *LB), "Cloud Armor attached to external backends"),
    "4.5.2": (("gcp:expanded.security_policies",), "Cloud Armor rules in deny/preview mode"),
    "4.5.3": (("gcp:expanded.security_policies",), "Preconfigured WAF rules coverage"),
    "4.6.1": (("gcp:expanded.security_policies",), "Cloud Armor / Adaptive Protection"),
    "4.7.2": (NET, "Egress deny rules and Cloud NAT scope"),
    "5.3.1": (
        ("gcp:securitycenter.findings.list", "gcp:expanded.scc_sources"),
        "SCC enabled and active findings",
    ),
    "5.3.2": (("gcp:expanded.artifact_repositories",), "Image vulnerability findings"),
    "5.4.1": (
        ("gcp:cloudasset.searchAllResources", "gcp:serviceusage.services.list"),
        "Assets and enabled APIs not in inventory",
    ),
    "5.4.2": (IAM, "External domains and federated identities with access"),
    "6.1.2": (("gcp:cloudasset.searchAllResources",), "Map CIS GCP controls to this checklist"),
    "6.3.1": (
        ("gcp:storage.buckets.list", *NET),
        "Default network, default SA, uniform bucket access",
    ),
    "6.3.2": (("gcp:serviceusage.services.list",), "Enabled but unused APIs"),
    "6.4.1": (LB, "Managed certificate expiry"),
    "6.4.2": (("gcp:expanded.ssl_policies",), "TLS 1.2+ and restricted profile"),
    "6.5.1": ((), "Summarize top failures from this assessment"),
    "7.1.1": (IAM, "Principal to project/resource access matrix"),
    "7.1.2": (("gcp:iam.roles.list",), "Overlapping custom roles"),
    "7.1.3": (("gcp:expanded.iam_recommendations",), "Recommender unused-permission findings"),
    "7.2.1": (IAM, "deleted: principals still bound"),
    "7.2.2": (("gcp:expanded.iam_recommendations",), "Inactive principals (recommender)"),
    "7.2.3": ((), "Leaver process (interview)"),
    "7.3.1": (("gcp:compute.instances.list", *NET), "IAP / bastion path to VMs"),
    "7.3.2": (LOGS, "Data Access logs for privileged sessions"),
    "7.4.1": (IAM, "Principals from external domains"),
    "7.4.2": ((), "Vendor recertification evidence (interview)"),
    "7.5.1": ((), "Access review records (interview)"),
    "8.1.1": (("gcp:projects.getIamPolicy", *LOGS), "Audit logs, exclusions and sinks"),
    "8.1.2": (LOGS, "VPC flow, firewall and DNS logs"),
    "8.1.3": (LOGS, "Cloud SQL / application logs routed"),
    "8.2.1": (LOGS, "Sinks covering the SIEM sources"),
    "8.2.2": ((), "SIEM parsing (interview)"),
    "8.2.3": (("gcp:logging.buckets.list",), "Log bucket retention days"),
    "8.3.1": (("gcp:monitoring.alertPolicies.list",), "Alert/detection coverage"),
    "8.3.2": ((), "Alert quality (interview)"),
    "8.3.3": ((), "Detection tests (interview)"),
    "8.4.1": (("gcp:logging.buckets.list",), "Retention versus policy"),
    "8.4.2": (("gcp:logging.buckets.list", *IAM), "Bucket lock and logging.admin holders"),
    "8.5.1": (("gcp:monitoring.alertPolicies.list",), "Alert thresholds"),
    "8.6.1": (("gcp:expanded.notification_channels",), "Notification channels and playbooks"),
    "8.6.2": ((), "Response metrics (interview)"),
}

LABEL = {
    "PASS": "PASS",
    "FAIL": "FAIL",
    "NOT_APPLICABLE": "NOT APPLICABLE",
    "UNKNOWN": "INSUFFICIENT EVIDENCE",
    "COLLECTION_ERROR": "INSUFFICIENT EVIDENCE",
    "MANUAL_VALIDATION_REQUIRED": "MANUAL VALIDATION",
}


def control_ids() -> list[str]:
    return [entry.control_id for entry in COVERAGE]


def describe(control_id: str | None) -> dict:
    """Checklist classification for a control ID (empty values when unmapped)."""
    if not control_id or control_id not in BY_CONTROL:
        return {"checklist_domain": "", "checklist_area": "", "checklist_title": ""}
    if control_id.startswith("AWS-"):
        domain, area = DOMAINS["AWS"], TITLES[control_id]
    else:
        domain = DOMAINS[control_id.split(".")[0]]
        area = AREAS.get(control_id.rsplit(".", 1)[0], "")
    return {
        "checklist_domain": domain,
        "checklist_area": area,
        "checklist_title": TITLES.get(control_id, ""),
    }


def rules_for(control_id: str, provider: str) -> tuple[str, ...]:
    from offline_analyzer.rules.gcp import GCP_RULES
    from offline_analyzer.rules.gcp_org import ORG_RULES
    from offline_analyzer.rules.registry import ALL_RULES

    found = [
        r.rule_id
        for r in (*ALL_RULES, *GCP_RULES, *ORG_RULES)
        if r.methodology and r.methodology.control_id == control_id and r.provider == provider
    ]
    if provider == AWS:
        found += [r for r in BY_CONTROL[control_id].rules if r not in found]
    return tuple(found)


def control_outcome(control_id: str, provider: str, counts: Counter) -> tuple[str, str]:
    """(outcome label, basis) for one control and provider from rule-result label counts."""
    if provider not in applies(control_id):
        return "NOT APPLICABLE", f"Outside {provider} cloud evidence; assess in its own workstream"
    rules = rules_for(control_id, provider)
    if counts.get("FAIL"):
        return "FAIL", f"{counts['FAIL']} failed rule result(s)"
    if rules and counts.get("PASS") and not counts.get("INSUFFICIENT EVIDENCE"):
        return (
            "MANUAL VALIDATION",
            "Automated criteria passed; remaining criteria need analyst review",
        )
    if counts.get("MANUAL VALIDATION") and not counts.get("INSUFFICIENT EVIDENCE"):
        return (
            "MANUAL VALIDATION",
            "Observed criteria require an approved objective or analyst context",
        )
    if rules and counts.get("NOT APPLICABLE") and not counts.get("INSUFFICIENT EVIDENCE"):
        if provider == GCP and any(c.control_id == control_id for c in GCP_CONFIG_COVERAGE):
            return (
                "MANUAL VALIDATION",
                "Observed criteria not applicable; remaining criteria need review",
            )
        return "NOT APPLICABLE", "Evaluated resources absent or service not enabled"
    if rules or (
        provider == AWS and BY_CONTROL[control_id].status == "BLOCKED_BY_MISSING_EVIDENCE"
    ):
        return "INSUFFICIENT EVIDENCE", "Required evidence missing, failed or incomplete"
    return "MANUAL VALIDATION", "No automated rule; validate with the listed check area"


def matrix(results, providers=(AWS, GCP), assessed=None) -> list[dict]:
    """One row per checklist control with per-provider outcome; results are r0 Results.

    `assessed` lists clouds with imported evidence; others report NOT ASSESSED.
    """
    by_rule: dict[tuple[str, str], Counter] = {}
    for result in results:
        provider = getattr(result, "provider", None) or AWS
        key = (provider, result.rule_id)
        by_rule.setdefault(key, Counter())[
            LABEL.get(str(result.outcome), "INSUFFICIENT EVIDENCE")
        ] += 1
    rows = []
    for control in control_ids():
        row = {"control_id": control, **describe(control), "applies": list(applies(control))}
        for provider in providers:
            counts = Counter()
            for rule in rules_for(control, provider):
                counts.update(by_rule.get((provider, rule), Counter()))
            outcome, basis = control_outcome(control, provider, counts)
            if assessed is not None and provider not in assessed and outcome != "NOT APPLICABLE":
                outcome, basis = "NOT ASSESSED", f"No {provider} evidence imported in this run"
            row[provider.lower()] = {
                "outcome": outcome,
                "basis": basis,
                "rules": list(rules_for(control, provider)),
                "results": dict(counts),
                "implementation_status": (
                    "NOT APPLICABLE"
                    if outcome == "NOT APPLICABLE"
                    else "EVIDENCE UNAVAILABLE"
                    if outcome in {"INSUFFICIENT EVIDENCE", "NOT ASSESSED"}
                    else "PARTIALLY AUTOMATED"
                    if rules_for(control, provider)
                    else "GUIDED MANUAL"
                ),
            }
        check = GCP_CHECKS.get(control)
        row["gcp_check"] = check[1] if check else ""
        row["gcp_evidence"] = list(check[0]) if check else []
        additions = next((c for c in GCP_CONFIG_COVERAGE if c.control_id == control), None)
        if additions:
            row["gcp_evidence"] = list(dict.fromkeys([*row["gcp_evidence"], *additions.evidence]))
        rows.append(row)
    return rows
