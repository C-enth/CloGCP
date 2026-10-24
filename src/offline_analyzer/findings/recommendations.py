"""Versioned, offline corrective guidance reviewed against authoritative AWS documentation."""

from dataclasses import asdict, dataclass, replace

VERSION = "recommendations-1.0.0"
AWS = "https://docs.aws.amazon.com/"


@dataclass(frozen=True)
class Recommendation:
    expected_posture: str
    recommended_action: str
    immediate_mitigation: str
    permanent_remediation: str
    implementation_guidance: str
    operational_considerations: str
    compensating_controls: str
    validation_procedure: str
    references: tuple[str, ...]
    version: str = VERSION


IMDS = Recommendation(
    "Metadata requests require IMDSv2 tokens on workloads that use the metadata endpoint.",
    "Require IMDSv2 after validating every workload's metadata clients.",
    (
        "Restrict untrusted entry points and reduce the attached role's permissions "
        "while migrating clients."
    ),
    "Set HttpTokens to required in instance metadata options and launch templates.",
    (
        "Inventory SDKs, agents and bootstrap scripts; upgrade token-incompatible "
        "clients; test on a canary instance; apply metadata options and verify the "
        "applied state."
    ),
    (
        "Legacy SDKs and bootstrap scripts may lose credentials. Container metadata "
        "access depends on network hops. Schedule a rollback-capable rollout with the"
        " workload owner."
    ),
    (
        "Disable the metadata endpoint only if the workload does not need it; a host "
        "firewall restriction needs workload testing and does not replace token "
        "enforcement."
    ),
    (
        "Have the authorized owner test token-based access and denial of tokenless "
        "requests without recording credentials; recollect DescribeInstances and "
        "verify applied HttpTokens=required."
    ),
    (AWS + "AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",),
)
HOP = Recommendation(
    "The metadata response hop limit matches the workload's validated networking needs.",
    "Reduce unnecessary metadata response hops without breaking container credentials.",
    (
        "Require IMDSv2 and restrict untrusted application entry points while "
        "validating the hop limit."
    ),
    "Use the lowest tested hop limit in instance settings and launch templates.",
    (
        "Identify container networking and credential consumers; test a lower "
        "HttpPutResponseHopLimit on a representative canary; document justified "
        "exceptions and update launch templates."
    ),
    (
        "A hop limit of one can prevent containers from obtaining metadata responses."
        " Do not force it on EKS/ECS hosts before compatibility testing."
    ),
    (
        "Where extra hops are required, use workload-specific identities where "
        "supported and validate host-level metadata restrictions; these do not prove "
        "SSRF prevention."
    ),
    (
        "Recollect applied metadata options and test the approved container/agent "
        "credential flow; retain evidence supporting any exception."
    ),
    IMDS.references,
)
ENCRYPTION = Recommendation(
    "Supported RDS databases use encryption at rest with an approved, available KMS key.",
    "Migrate the unencrypted database to an encrypted deployment.",
    (
        "Restrict access and protect backup handling while scheduling migration; "
        "network restrictions do not supply encryption at rest."
    ),
    (
        "Create an encrypted snapshot copy and restore an encrypted database, then "
        "perform an approved application cutover where supported by the engine."
    ),
    (
        "Confirm engine-specific migration support, KMS key permissions, "
        "replica/backup dependencies and recovery objectives; test restore, "
        "consistency and cutover before production execution."
    ),
    (
        "This is a migration, not an in-place encryption toggle. Plan downtime or a "
        "tested replication approach, endpoint changes, rollback and key "
        "availability."
    ),
    (
        "No network or IAM control is equivalent to database encryption at rest. "
        "Application encryption may protect selected fields but requires separate "
        "validation."
    ),
    (
        "Recollect the target database's StorageEncrypted and key identity; test "
        "restore and application access. Aurora needs cluster-level evidence and is "
        "excluded from this instance-only conclusion."
    ),
    (AWS + "AmazonRDS/latest/UserGuide/Overview.Encryption.html",),
)
TRAIL = Recommendation(
    "CloudTrail produces signed integrity digest files for the required trail scope.",
    (
        "Enable log-file validation on the affected trail and establish an integrity "
        "verification procedure."
    ),
    "Protect the logging bucket and preserve existing logs/digests during the change.",
    (
        "Enable LogFileValidationEnabled on the trail; retain digests and "
        "periodically verify the digest chain using an authorized validation process."
    ),
    (
        "Coordinate with the organization trail owner and logging account; verify "
        "destination permissions, retention and the trail's home Region before "
        "changing centrally managed settings."
    ),
    (
        "Enabling the setting produces digests; it does not verify historical logs or"
        " repair a prior missing digest interval."
    ),
    (
        "Restricted logging-bucket writes and retention protection help preserve "
        "evidence but do not replace signed digest validation."
    ),
    (
        "Recollect DescribeTrails and inspect digest delivery and an authorized "
        "validation result. This analyzer never executes CloudTrail validation "
        "commands or proves event-selector coverage."
    ),
    (AWS + "awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",),
)
SG = Recommendation(
    "Administrative ingress is limited to approved management sources and required ports.",
    "Remove broad administrative ingress from the affected security groups.",
    "Narrow ingress to approved management addresses or a validated private management path.",
    (
        "Replace world-accessible administrative rules with least-required sources, "
        "protocols and ports; codify them in deployment configuration."
    ),
    (
        "Identify every attached workload and legitimate administrator; stage "
        "replacement rules, test the approved access path, then remove broad IPv4 and"
        " IPv6 rules."
    ),
    (
        "A change affects all resources attached to the group. Preserve emergency "
        "access and coordinate application, bastion and shared-VPC owners."
    ),
    (
        "A validated VPN, private management path or host firewall may reduce "
        "exposure; do not assume a WAF protects SSH/RDP or that a NACL blocks traffic"
        " without evidence."
    ),
    (
        "Recollect groups, interfaces and routes; verify the approved source can "
        "connect and unapproved sources are rejected through an authorized network "
        "test. Configuration alone is not application reachability proof."
    ),
    (AWS + "AWSEC2/latest/UserGuide/security-group-rules-reference.html",),
)
S3 = Recommendation(
    "Public bucket access is prevented unless a documented public use is explicitly approved.",
    "Remove unnecessary public policies/ACLs and enable applicable Block Public Access controls.",
    (
        "Restrict the affected public grant after identifying legitimate readers and "
        "service dependencies."
    ),
    (
        "Apply account and bucket public-access controls, scoped bucket policies and "
        "an approved ownership/ACL model."
    ),
    (
        "Review policy principals, ACL grants, account/bucket access-block settings "
        "and delivery services; test a scoped replacement before enabling controls "
        "that could deny an intended public workload."
    ),
    (
        "Public websites, cross-account integrations and log delivery require "
        "validation. No sensitive-data exposure is claimed without data "
        "classification and access evidence."
    ),
    (
        "An approved distribution with restricted origin access may support an "
        "intended publication use case; validate the actual architecture rather than "
        "assuming it exists."
    ),
    (
        "Recollect account/bucket access-block, policy status and ACL evidence; an "
        "authorized owner verifies intended access and denied anonymous access. "
        "Classify data separately."
    ),
    (AWS + "AmazonS3/latest/userguide/access-control-block-public-access.html",),
)
TRUST = Recommendation(
    (
        "Role trust identifies intended callers and enforces conditions justified by "
        "the authentication flow."
    ),
    "Constrain unsafe role trust after validating every legitimate caller.",
    (
        "Remove unintended external principals or suspend their trust grant through "
        "an approved change."
    ),
    (
        "Use specific approved principals and appropriate trust conditions; validate "
        "source identity permissions, boundaries and organization restrictions "
        "separately."
    ),
    (
        "Inventory callers and federation/service integration requirements; stage the"
        " revised trust policy; test legitimate and denied callers with the "
        "authorized owner. Use ExternalId or federation claim restrictions only where"
        " relevant to the flow."
    ),
    (
        "Trust changes can break automation or federation. A trust Allow alone does "
        "not establish AssumeRole permission; retain caller-policy and request-"
        "context dependencies."
    ),
    (
        "Supported organization restrictions or explicit denies may restrict access; "
        "confirm applicability. MFA conditions are not universally suitable for "
        "service principals."
    ),
    (
        "Recollect role trust, source identity policies and applicable restrictions; "
        "review supported/blocked/unknown IAM transitions and authorized "
        "positive/negative authentication tests."
    ),
    (AWS + "IAM/latest/UserGuide/id_roles_update-role-trust-policy.html",),
)
PRIVILEGE = Recommendation(
    (
        "Workload role policies grant only required actions and scoped resources; "
        "PassRole targets and service context are constrained."
    ),
    "Replace broad role permissions and restrict PassRole to required role/service combinations.",
    (
        "Reduce unnecessary permissions only after identifying active application and"
        " automation dependencies."
    ),
    (
        "Maintain scoped identity policies and supported permissions "
        "boundaries/organization restrictions; remove unrestricted administrative "
        "action patterns."
    ),
    (
        "Identify required calls from approved activity evidence; test a scoped "
        "policy on a representative workload; constrain PassRole resources and "
        "iam:PassedToService where applicable."
    ),
    (
        "Removing permissions can interrupt deployments, recovery and workloads. "
        "Validate service launch permissions and target-role trust; configuration "
        "never proves attacker control or successful escalation."
    ),
    (
        "A validated boundary or SCP can limit permissions, but its complete document"
        " and applicability must be available; do not assume a missing restriction "
        "protects the workload."
    ),
    (
        "Recollect resolved policy versions, boundaries, profile membership and "
        "organization evidence; rerun IAM prerequisites and have the owner test "
        "intended operations and rejected unauthorized combinations."
    ),
    (
        AWS + "IAM/latest/UserGuide/id_roles_use_passrole.html",
        AWS + "IAM/latest/UserGuide/access_policies_boundaries.html",
    ),
)
RDS_PUBLIC = Recommendation(
    "Database ingress and public-address configuration match approved client connectivity.",
    "Remove unnecessary public database addressing and narrow ingress.",
    (
        "Restrict database security groups to validated application clients while "
        "planning private connectivity."
    ),
    (
        "Use an approved private database placement and required client routes; "
        "disable PubliclyAccessible after connectivity validation."
    ),
    (
        "Identify clients, DNS behavior, subnet groups and management paths; test "
        "private connectivity and endpoint resolution, then apply the approved "
        "addressing/security-group changes."
    ),
    (
        "Public clients and administrative integrations may lose connectivity; "
        "coordinate DNS, routing, failover and maintenance windows."
    ),
    (
        "Restrictive groups and verified routing/filter controls can reduce network "
        "exposure; neither proves application authentication or removes the public-"
        "address configuration."
    ),
    (
        "Recollect RDS addressing, attached groups, interfaces and subnet routes; "
        "perform authorized client connectivity tests. Retain NACL/inspection "
        "dependencies where unverified."
    ),
    (AWS + "AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",),
)

ROLE_WILDCARD = replace(
    PRIVILEGE,
    expected_posture="Role actions and resources match verified workload requirements.",
    recommended_action=(
        "Replace wildcard action grants with verified workload actions and resource scope."
    ),
    immediate_mitigation=(
        "Review applicable boundaries and explicit denies; restrict untrusted role entry points."
    ),
    permanent_remediation=(
        "Deploy a tested least-privilege role policy with explicit workload scope."
    ),
    implementation_guidance="Inventory workload API use and dependencies; "
    "create a scoped policy; test it "
    "with representative authorized workloads; roll out in stages and retain a rollback policy.",
    validation_procedure="Recollect role, attached and inline policy documents and versions; "
    "verify "
    "the wildcard pattern is absent and required workloads work. Assess effective permissions "
    "separately with boundaries, request context, explicit denies and SCP/RCP.",
)
KMS_WILDCARD = Recommendation(
    "Key-policy principals, KMS operations and conditions match approved consumers.",
    "Remove unconditional wildcard-principal grants after verifying legitimate key consumers.",
    (
        "Restrict the principal or apply verified caller-context conditions; retain "
        "key recovery access."
    ),
    "Use approved principal ARNs and minimum KMS operations with appropriate tested conditions.",
    "Identify applications, AWS services, cross-account consumers and key administrators; "
    "stage a restricted policy; verify expected cryptographic operations and administration "
    "before applying it to production. Do not bypass the key-policy lockout safety check.",
    "Incorrect key policies can stop database, storage or application cryptographic operations "
    "and lock out administrators. Validate grants, service integrations and recovery access "
    "with the workload and key owners before rollout.",
    "Applicable explicit denies and verified service-context conditions may reduce exposure; "
    "their applicability requires validation and they do not justify unexplained broad principals.",
    "Recollect GetKeyPolicy and ListGrants; confirm no unconditional wildcard-principal Allow "
    "remains; test approved operations and rejected unapproved callers in an authorized "
    "test scope. Verify cross-account IAM dependencies independently.",
    (
        AWS + "kms/latest/developerguide/key-policy-overview.html",
        AWS + "kms/latest/developerguide/key-policy-modifying-external-accounts.html",
    ),
)

TRAIL_LOGGING = Recommendation(
    "Every trail relied on for audit evidence is logging and delivering to its destination.",
    "Start logging on the trail, or retire it and document the trail that supersedes it.",
    "Confirm another account or organization trail records the same events in the meantime.",
    "Keep required trails logging; alert on StopLogging and DeleteTrail API calls.",
    "Identify why logging stopped (change record, failed delivery permissions or bucket "
    "policy); fix delivery prerequisites before restarting so logs are not lost again.",
    "Restarting logging increases S3 storage and any downstream SIEM ingestion volume.",
    "An organization trail or another trail capturing the same events limits the gap; "
    "verify its coverage rather than assuming it.",
    "Recollect GetTrailStatus and confirm IsLogging is true and no delivery error is reported; "
    "verify a recent log file exists in the destination.",
    (AWS + "awscloudtrail/latest/userguide/cloudtrail-turning-off-logging.html",),
)
MANAGEMENT_EVENTS = Recommendation(
    "Trails relied on for audit evidence capture management write events.",
    "Include management write events in the trail's event selectors.",
    "Confirm another trail records management events for the account in the meantime.",
    "Configure basic selectors with IncludeManagementEvents=true and ReadWriteType All "
    "or WriteOnly, or an advanced selector on eventCategory Management.",
    "Review advanced selectors for intentional exclusions with the logging owner before "
    "changing them; document approved exclusions.",
    "Additional management events increase log volume modestly; data events are separate.",
    "An organization trail capturing management events limits the gap; verify its scope.",
    "Recollect GetEventSelectors and confirm management write events are captured.",
    (AWS + "awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html",),
)
GUARDDUTY = Recommendation(
    "GuardDuty is enabled in every in-scope Region, ideally organization-wide.",
    "Enable GuardDuty in the Region, preferably through the delegated administrator.",
    "Prioritize Regions with production workloads while organization enablement is planned.",
    "Use a delegated administrator with auto-enable for new accounts and Regions.",
    "Agree finding routing and triage ownership before enabling, so findings are acted on.",
    "GuardDuty has usage-based cost; protection plans can be scoped deliberately.",
    "Other detective controls may partially cover threats; they do not replace GuardDuty "
    "findings without a documented decision.",
    "Recollect ListDetectors and GetDetector and confirm a detector with Status ENABLED.",
    (
        AWS + "guardduty/latest/ug/guardduty_settingup.html",
        AWS + "guardduty/latest/ug/guardduty_organizations.html",
    ),
)
CONFIG_RECORDING = Recommendation(
    "An AWS Config recorder is recording in every in-scope Region with a delivery channel.",
    "Create or start a configuration recorder with a delivery channel in the Region.",
    "Retain CloudTrail evidence for configuration changes while recording is restored.",
    "Manage recorders centrally (for example through organization conformance tooling).",
    "Confirm the delivery channel bucket and role permissions before starting the recorder.",
    "Recording incurs per-configuration-item cost; scope resource types deliberately.",
    "CloudTrail records API activity but not resource configuration history.",
    "Recollect DescribeConfigurationRecorderStatus and confirm recording=true with no "
    "FAILURE last status.",
    (AWS + "config/latest/developerguide/stop-start-recorder.html",),
)
SECURITY_HUB = Recommendation(
    "Security Hub is enabled in in-scope Regions with agreed standards.",
    "Enable Security Hub through the organization's delegated administrator.",
    "Review individual service findings (for example GuardDuty) directly in the meantime.",
    "Enable centrally with cross-Region aggregation and agreed security standards.",
    "Decide standards, finding routing and suppression governance before enabling.",
    "Security Hub and its controls have usage-based cost and depend on AWS Config.",
    "Native service consoles still provide findings, without aggregation or standards checks.",
    "Recollect DescribeHub and confirm a HubArn is returned in the Region.",
    (AWS + "securityhub/latest/userguide/securityhub-settingup.html",),
)
KMS_ROTATION = Recommendation(
    "Customer-managed symmetric keys rotate automatically unless an approved exception exists.",
    "Enable automatic rotation for the key, or document the approved manual process.",
    "None required for existing ciphertext; rotation keeps prior key material for decryption.",
    "Enable automatic rotation with an appropriate rotation period.",
    "Confirm the key is a symmetric AWS_KMS key; imported or asymmetric keys rotate manually.",
    "Rotation does not re-encrypt existing data and does not change the key ID or ARN.",
    "A documented manual rotation process may be an acceptable alternative.",
    "Recollect GetKeyRotationStatus and confirm KeyRotationEnabled is true.",
    (AWS + "kms/latest/developerguide/rotate-keys.html",),
)

LATENT_INGRESS = Recommendation(
    "Sensitive ports are reachable only from approved administrative sources.",
    "Remove 0.0.0.0/0 and ::/0 sources for sensitive ports from the security group.",
    "Confirm no public resource is planned to use the group until the rule is restricted.",
    "Use approved CIDRs or prefix lists, or replace SSH/RDP with Session Manager.",
    "Identify the owner and purpose of the rule; check launch templates and automation that "
    "attach the group before changing it.",
    "Restricting sources can interrupt administrators or integrations relying on the rule.",
    "Network ACLs or the absence of public addresses limit current reachability but do not "
    "remove the latent configuration risk.",
    "Recollect DescribeSecurityGroups and confirm no sensitive port allows 0.0.0.0/0 or ::/0.",
    (AWS + "vpc/latest/userguide/security-group-rules.html",),
)

TEMPLATES = {
    "R0-EC2-IMDSV2": IMDS,
    "R1-EC2-IMDS-HOP-LIMIT": HOP,
    "R0-RDS-ENCRYPTION": ENCRYPTION,
    "R0-CLOUDTRAIL-VALIDATION": TRAIL,
    "R1-EC2-SG-SENSITIVE-INGRESS": SG,
    "R1-IAM-ROLE-TRUST-CONDITIONS": TRUST,
    "R1-S3-ACCOUNT-BPA": S3,
    "R1-S3-BUCKET-PUBLIC-ACCESS": S3,
    "R1-RDS-PUBLIC-ACCESS": RDS_PUBLIC,
    "R1-IAM-INSTANCE-ROLE-PRIVILEGE": PRIVILEGE,
    "SEC-IAM-ROLE-WILDCARD": ROLE_WILDCARD,
    "SEC-KMS-WILDCARD-PRINCIPAL": KMS_WILDCARD,
    "SEC-CLOUDTRAIL-LOGGING": TRAIL_LOGGING,
    "SEC-CLOUDTRAIL-MANAGEMENT-EVENTS": MANAGEMENT_EVENTS,
    "SEC-GUARDDUTY-ENABLED": GUARDDUTY,
    "SEC-CONFIG-RECORDING": CONFIG_RECORDING,
    "SEC-SECURITYHUB-ENABLED": SECURITY_HUB,
    "SEC-KMS-ROTATION": KMS_ROTATION,
    "SEC-EC2-SG-LATENT-EXPOSURE": LATENT_INGRESS,
}


def recommendation(rule_id: str) -> dict:
    if rule_id.startswith("GCP-"):
        from offline_analyzer.findings.gcp_recommendations import template_for

        template = template_for(rule_id)
    else:
        template = TEMPLATES.get(rule_id)
    return (
        {"status": "TEMPLATE_REQUIRES_ANALYST_APPROVAL", **asdict(template)}
        if template
        else {
            "status": "ANALYST_AUTHORED_REMEDIATION_REQUIRED",
            "version": VERSION,
            "references": (),
        }
    )
