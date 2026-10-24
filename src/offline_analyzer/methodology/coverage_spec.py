"""Analyst-authored coverage classification keyed by original methodology control IDs.

Contains identifiers, implementation status, evidence operations and reason codes only.
No source requirement text is stored here; the private audit joins this specification
with the locally held workbook. Every entry is a proposal pending methodology-owner review.
"""

from dataclasses import dataclass

# Workbook version against which this classification was reviewed (SHA-256, not content).
REVIEWED_METHODOLOGY_SHA256 = "a9d7ef1b075fa1eab9ea12cce654dc8ce65543bad810e8e233e7bb30761ae3cd"
SPEC_VERSION = "1.4.0"

STATUSES = (
    "IMPLEMENTED_AND_VERIFIED",
    "IMPLEMENTED_REQUIRES_VALIDATION",
    "PARTIALLY_IMPLEMENTED",
    "NOT_IMPLEMENTED",
    "BLOCKED_BY_MISSING_EVIDENCE",
    "REQUIRES_METHODOLOGY_CLARIFICATION",
    "MANUAL_VALIDATION_REQUIRED",
    "OUTSIDE_CURRENT_AWS_SCOPE",
)
REASONS = {
    "TEMPLATE_CRITERIA": "Pass/fail criteria are a shared category template, not control-specific",
    "CRITERIA_TOPIC_MISMATCH": "Assigned template criteria address a different topic",
    "NON_AWS_PLATFORM": "Requirement concerns GCP, Entra ID, AD, on-premises or network devices",
    "ORG_ADMIN_EVIDENCE": "Needs Organizations/Control Tower/IAM Identity Center admin exports",
    "CREDENTIAL_GUARD_CONFLICT": "Raw evidence would contain secret values; needs redacted "
    "collector-side scan output",
    "PROCESS_OR_INTERVIEW": "Process, interview, SIEM-side or architecture judgement",
    "ACTIVE_TESTING": "Needs active scanning or exploitation testing outside offline analysis",
    "IAM_ENGINE": "Needs effective-permission/privilege-escalation analysis (not implemented)",
    "REACHABILITY_ENGINE": "Needs route/NACL/reachability analysis (not implemented)",
    "CLASSIFICATION_INPUT": "Needs approved environment/data/vendor classification input",
    "CONJUNCTIVE_PASS": "Source PASS clause combines automated and non-automated criteria",
    "ADAPTER_MISSING": "AWS evidence is collectable but no analyzer adapter/rule exists yet",
}

IVR, PART, NI, BME, RMC, MVR, OOS = (
    "IMPLEMENTED_REQUIRES_VALIDATION",
    "PARTIALLY_IMPLEMENTED",
    "NOT_IMPLEMENTED",
    "BLOCKED_BY_MISSING_EVIDENCE",
    "REQUIRES_METHODOLOGY_CLARIFICATION",
    "MANUAL_VALIDATION_REQUIRED",
    "OUTSIDE_CURRENT_AWS_SCOPE",
)


@dataclass(frozen=True)
class ControlCoverage:
    control_id: str
    status: str
    evidence: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    related: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()


def c(control_id, status, evidence=(), rules=(), related=(), reasons=()):
    return ControlCoverage(control_id, status, evidence, rules, related, reasons)


T, M = "TEMPLATE_CRITERIA", "CRITERIA_TOPIC_MISMATCH"
GAAD = "iam:GetAccountAuthorizationDetails"
CRED = "iam:GetCredentialReport"
SG, ENI = "ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces"
ORG = "organizations:ListPolicies+ListTargetsForPolicy+ListAccounts"

COVERAGE: tuple[ControlCoverage, ...] = (
    # 1.x Cloud security: AWS-relevant topics, but template criteria block automation.
    c("1.1.2", OOS, reasons=("NON_AWS_PLATFORM",)),
    c("1.1.3", RMC, (CRED, "cloudtrail:LookupEvents"), related=("AWS-06",), reasons=(T, M)),
    c("1.1.4", RMC, (ORG,), related=("AWS-01",), reasons=(T, "ORG_ADMIN_EVIDENCE")),
    c("1.1.5", RMC, ("ce:GetAnomalyMonitors", "budgets:DescribeBudgets"), reasons=(T,)),
    c("1.1.6", RMC, (ORG, "tag:GetResources"), reasons=(T, "ORG_ADMIN_EVIDENCE")),
    c("1.1.7", MVR, (ORG,), related=("AWS-01",), reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("1.1.8", RMC, (ORG, "cloudtrail:DescribeTrails"), related=("AWS-07",), reasons=(T,)),
    c("1.2.1", RMC, (ORG,), related=("AWS-01",), reasons=(T, "ORG_ADMIN_EVIDENCE")),
    c("1.2.2", OOS, reasons=("NON_AWS_PLATFORM",)),
    c("1.2.3", MVR, (ORG,), related=("AWS-01",), reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("1.2.4", RMC, (ORG,), related=("AWS-01",), reasons=(T, "ORG_ADMIN_EVIDENCE")),
    c("1.2.5", RMC, (ORG,), related=("AWS-01", "AWS-07"), reasons=(T, "ORG_ADMIN_EVIDENCE")),
    c("1.2.6", RMC, (GAAD, ORG), related=("AWS-01",), reasons=(T, "IAM_ENGINE")),
    c("1.3.1", RMC, ("ec2:DescribeInstances", ENI, SG), related=("AWS-15",), reasons=(T,)),
    c("1.3.2", RMC, (SG, ENI), ("R1-EC2-SG-SENSITIVE-INGRESS",), ("AWS-15",), (T,)),
    c("1.3.3", RMC, ("ec2:DescribeInstances",), ("R0-EC2-IMDSV2",), ("AWS-19",), (T, M)),
    c(
        "1.3.4",
        RMC,
        (GAAD, "ec2:DescribeIamInstanceProfileAssociations"),
        (),
        ("AWS-19",),
        (T, "IAM_ENGINE"),
    ),
    c(
        "1.3.5",
        RMC,
        ("ssm:DescribeInstancePatchStates", "ec2:DescribeImages", "inspector2:ListFindings"),
        reasons=(T, M),
    ),
    c(
        "1.3.6",
        BME,
        ("collector-side user-data secret scan",),
        related=("AWS-13",),
        reasons=(T, "CREDENTIAL_GUARD_CONFLICT"),
    ),
    c("1.3.7", RMC, ("ssm:DescribeInstanceInformation", GAAD), reasons=(T, M)),
    c(
        "1.4.1",
        RMC,
        ("s3control:GetPublicAccessBlock", "s3api:GetPublicAccessBlock"),
        ("R1-S3-ACCOUNT-BPA",),
        ("AWS-11",),
        (T, M),
    ),
    c(
        "1.4.2",
        RMC,
        ("s3api:GetBucketPolicyStatus", "s3api:GetBucketAcl", "s3api:GetBucketPolicy"),
        related=("AWS-11",),
        reasons=(T, M),
    ),
    c("1.4.3", RMC, ("s3api:GetBucketEncryption", "kms:GetKeyRotationStatus"), reasons=(T,)),
    c("1.4.4", RMC, ("s3api:GetBucketPolicy",), reasons=(T,)),
    c(
        "1.4.5",
        RMC,
        ("s3api:GetBucketVersioning", "s3api:GetObjectLockConfiguration"),
        reasons=(T,),
    ),
    c("1.4.6", MVR, ("macie2:ListFindings",), reasons=(T, "ACTIVE_TESTING")),
    c("1.4.7", RMC, ("s3api:GetBucketLifecycleConfiguration",), reasons=(T, M)),
    c("1.4.8", RMC, ("s3api:GetBucketReplication",), reasons=(T,)),
    c(
        "1.5.1",
        RMC,
        ("ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:DescribeRouteTables"),
        related=("AWS-14",),
        reasons=(T, "REACHABILITY_ENGINE"),
    ),
    c(
        "1.5.2",
        RMC,
        (SG, ENI),
        ("R1-EC2-SG-SENSITIVE-INGRESS", "SEC-EC2-SG-LATENT-EXPOSURE"),
        ("AWS-15",),
        (T,),
    ),
    c("1.5.3", RMC, (SG,), reasons=(T, M)),
    c(
        "1.5.4",
        RMC,
        ("ec2:DescribeVpcPeeringConnections", "ec2:SearchTransitGatewayRoutes"),
        related=("AWS-16",),
        reasons=(T, "REACHABILITY_ENGINE"),
    ),
    c("1.5.5", RMC, ("ec2:DescribeVpcs", SG, ENI), related=("AWS-14",), reasons=(T, M)),
    c("1.5.6", RMC, ("ec2:DescribeNetworkAcls",), related=("AWS-15",), reasons=(T, M)),
    c(
        "1.5.7",
        RMC,
        ("ec2:DescribeFlowLogs", "ec2:DescribeVpcs"),
        related=("AWS-14",),
        reasons=(T,),
    ),
    c("1.5.8", RMC, ("ec2:DescribeVpcEndpoints",), reasons=(T,)),
    c("1.6.1", RMC, (CRED,), reasons=(T,)),
    c("1.6.2", RMC, (CRED,), reasons=(T,)),
    c("1.6.3", RMC, (GAAD,), ("SEC-IAM-ROLE-WILDCARD",), reasons=(T, "IAM_ENGINE")),
    c("1.6.4", OOS, reasons=("NON_AWS_PLATFORM",)),
    c("1.6.5", RMC, (GAAD,), ("R1-IAM-ROLE-TRUST-CONDITIONS",), ("AWS-04",), (T, M)),
    c("1.6.6", RMC, ("accessanalyzer:ListFindingsV2",), related=("AWS-05",), reasons=(T, M)),
    c("1.6.7", RMC, (GAAD, "cloudsplaining export"), reasons=(T, "IAM_ENGINE")),
    c(
        "1.7.1",
        RMC,
        ("cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"),
        ("SEC-CLOUDTRAIL-LOGGING", "SEC-CLOUDTRAIL-MANAGEMENT-EVENTS"),
        related=("AWS-07",),
        reasons=(T,),
    ),
    c("1.7.2", OOS, reasons=("NON_AWS_PLATFORM",)),
    c(
        "1.7.3",
        RMC,
        ("cloudtrail:DescribeTrails",),
        ("R0-CLOUDTRAIL-VALIDATION",),
        ("AWS-07",),
        (T, M),
    ),
    c(
        "1.7.4",
        RMC,
        ("s3api:GetObjectLockConfiguration", "s3api:GetBucketPolicy"),
        related=("AWS-07",),
        reasons=(T, M),
    ),
    c(
        "1.7.5",
        RMC,
        ("cloudwatch:DescribeAlarms", "logs:DescribeMetricFilters"),
        related=("AWS-06",),
        reasons=(T,),
    ),
    c("1.7.6", MVR, reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("1.7.7", RMC, (GAAD, ORG), related=("AWS-07",), reasons=(T, "IAM_ENGINE")),
    c("1.8.1", OOS, ("repository secret scan",), reasons=("NON_AWS_PLATFORM",)),
    c(
        "1.8.2",
        BME,
        ("collector-side Lambda/ECS environment secret scan",),
        related=("AWS-13", "AWS-21"),
        reasons=(T, "CREDENTIAL_GUARD_CONFLICT"),
    ),
    c("1.8.3", RMC, ("kms:GetKeyPolicy",), related=("AWS-12",), reasons=(T, M)),
    c("1.8.4", RMC, ("kms:GetKeyRotationStatus",), related=("AWS-12",), reasons=(T,)),
    c("1.8.5", RMC, (CRED,), reasons=(T,)),
    c("1.8.6", RMC, ("cloudtrail:GetEventSelectors",), related=("AWS-07",), reasons=(T,)),
    c(
        "1.9.1",
        RMC,
        ("ecr:DescribeImageScanFindings", "inspector2:ListFindings"),
        related=("AWS-20",),
        reasons=(T, M),
    ),
    c(
        "1.9.2",
        RMC,
        ("ecs:DescribeTaskDefinition", GAAD),
        related=("AWS-20",),
        reasons=(T, "IAM_ENGINE"),
    ),
    c(
        "1.9.3",
        RMC,
        ("lambda:ListFunctions", "lambda:GetPolicy", GAAD),
        related=("AWS-21",),
        reasons=(T, "IAM_ENGINE"),
    ),
    c("1.9.4", RMC, ("ecr:GetRepositoryPolicy",), related=("AWS-20",), reasons=(T, M)),
    c(
        "1.9.5",
        BME,
        ("collector-side Lambda environment secret scan",),
        related=("AWS-21",),
        reasons=(T, "CREDENTIAL_GUARD_CONFLICT"),
    ),
    c("1.9.6", RMC, ("ecs:DescribeTaskDefinition",), related=("AWS-20",), reasons=(T, M)),
    # 2.x Identity: AWS-relevant subset only.
    c("2.1.1", MVR, (GAAD, "identitystore:ListUsers"), reasons=(T, "NON_AWS_PLATFORM")),
    c("2.1.2", MVR, (CRED,), reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("2.2.1", RMC, (GAAD,), related=("AWS-03",), reasons=(T, "IAM_ENGINE")),
    c("2.2.2", RMC, (GAAD,), reasons=(T, "IAM_ENGINE")),
    c("2.2.3", MVR, reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("2.2.4", MVR, related=("AWS-03",), reasons=(T, "PROCESS_OR_INTERVIEW")),
    *(
        c(i, OOS, reasons=("NON_AWS_PLATFORM",))
        for i in (
            "2.3.1",
            "2.3.2",
            "2.3.3",
            "2.3.4",
            "2.3.5",
            "2.4.1",
            "2.4.2",
            "2.4.3",
            "2.7.1",
            "2.7.2",
            "2.7.3",
        )
    ),
    c(
        "2.5.1",
        RMC,
        ("iam:ListSAMLProviders", "iam:ListOpenIDConnectProviders"),
        related=("AWS-27",),
        reasons=(T, "NON_AWS_PLATFORM"),
    ),
    c(
        "2.5.2",
        BME,
        ("sso-admin:ListAccountAssignments",),
        related=("AWS-03",),
        reasons=(T, "ORG_ADMIN_EVIDENCE"),
    ),
    c("2.6.1", RMC, (CRED,), related=("AWS-06",), reasons=(T, "NON_AWS_PLATFORM")),
    c("2.6.2", RMC, ("iam:ListMFADevices",), reasons=(T, "NON_AWS_PLATFORM")),
    c("2.6.3", RMC, ("iam:GetAccountPasswordPolicy",), reasons=(T,)),
    c("2.8.1", MVR, reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("2.8.2", RMC, (GAAD,), reasons=(T, "IAM_ENGINE")),
    c("2.8.3", RMC, (CRED,), reasons=(T,)),
    # 3.x On-premises infrastructure.
    *(
        c(i, OOS, reasons=("NON_AWS_PLATFORM",))
        for i in (
            "3.1.1",
            "3.1.2",
            "3.1.3",
            "3.1.4",
            "3.2.1",
            "3.2.2",
            "3.2.3",
            "3.2.4",
            "3.3.1",
            "3.3.2",
            "3.4.1",
            "3.4.2",
            "3.4.3",
            "3.5.1",
            "3.5.2",
            "3.6.1",
            "3.6.2",
            "3.6.3",
            "3.6.4",
            "3.7.1",
            "3.7.2",
            "3.7.3",
        )
    ),
    # 4.x Network devices: AWS-native subsets only.
    c("4.1.1", MVR, reasons=(T, "PROCESS_OR_INTERVIEW")),
    *(
        c(i, OOS, reasons=("NON_AWS_PLATFORM",))
        for i in (
            "4.1.2",
            "4.1.3",
            "4.2.1",
            "4.2.2",
            "4.2.3",
            "4.2.4",
            "4.2.5",
            "4.3.1",
            "4.3.2",
            "4.3.3",
            "4.8.1",
            "4.8.2",
        )
    ),
    c("4.4.1", RMC, ("elbv2:DescribeListeners", "elbv2:DescribeSSLPolicies"), reasons=(T,)),
    c("4.4.2", RMC, ("elbv2:DescribeLoadBalancers", SG), reasons=(T,)),
    c(
        "4.5.1",
        RMC,
        ("wafv2:ListWebACLs", "wafv2:ListResourcesForWebACL"),
        related=("AWS-18",),
        reasons=(T,),
    ),
    c("4.5.2", RMC, ("wafv2:GetWebACL",), related=("AWS-18",), reasons=(T,)),
    c("4.5.3", MVR, related=("AWS-18",), reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("4.6.1", RMC, ("shield:ListProtections",), reasons=(T,)),
    c("4.6.2", MVR, reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("4.7.1", MVR, reasons=(T, "REACHABILITY_ENGINE")),
    c(
        "4.7.2",
        RMC,
        (SG, "network-firewall:DescribeFirewallPolicy"),
        related=("AWS-17",),
        reasons=(T, "REACHABILITY_ENGINE"),
    ),
    # 5.x Vulnerability assessment.
    *(c(i, MVR, reasons=(T, "ACTIVE_TESTING")) for i in ("5.1.1", "5.1.2", "5.1.3", "5.1.4")),
    *(c(i, OOS, reasons=("NON_AWS_PLATFORM",)) for i in ("5.2.1", "5.2.2", "5.2.3")),
    c("5.3.1", RMC, ("inspector2:ListFindings", "inspector2:ListCoverage"), reasons=(T,)),
    c("5.3.2", RMC, ("ecr:DescribeImageScanFindings",), related=("AWS-20",), reasons=(T,)),
    c("5.4.1", MVR, reasons=(T, "ACTIVE_TESTING")),
    c("5.4.2", MVR, related=("AWS-28",), reasons=(T, "CLASSIFICATION_INPUT")),
    # 6.x Configuration and hardening.
    c("6.1.1", RMC, ("prowler CIS compliance export",), reasons=(T,)),
    c("6.1.2", OOS, reasons=("NON_AWS_PLATFORM",)),
    *(c(i, OOS, reasons=("NON_AWS_PLATFORM",)) for i in ("6.2.1", "6.2.2")),
    c("6.3.1", RMC, reasons=(T,)),
    c("6.3.2", RMC, ("account:ListRegions", ORG), reasons=(T,)),
    c("6.4.1", RMC, ("acm:ListCertificates", "acm:DescribeCertificate"), reasons=(T,)),
    c("6.4.2", RMC, ("elbv2:DescribeListeners", "cloudfront:ListDistributions"), reasons=(T,)),
    c("6.5.1", MVR, reasons=(T, "PROCESS_OR_INTERVIEW")),
    # 7.x Access control and privilege review.
    c("7.1.1", MVR, reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("7.1.2", RMC, (GAAD,), reasons=(T, "IAM_ENGINE")),
    c(
        "7.1.3",
        RMC,
        (GAAD, "iam:GenerateServiceLastAccessedDetails"),
        related=("AWS-05",),
        reasons=(T, "IAM_ENGINE"),
    ),
    c("7.2.1", RMC, (CRED,), reasons=(T, "CLASSIFICATION_INPUT")),
    c("7.2.2", RMC, (CRED,), reasons=(T,)),
    c("7.2.3", MVR, reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("7.3.1", MVR, reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("7.3.2", MVR, reasons=(T, "PROCESS_OR_INTERVIEW")),
    c(
        "7.4.1",
        RMC,
        (GAAD,),
        ("R1-IAM-ROLE-TRUST-CONDITIONS",),
        ("AWS-28",),
        (T, "CLASSIFICATION_INPUT"),
    ),
    c("7.4.2", MVR, related=("AWS-28",), reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("7.5.1", MVR, reasons=(T, "PROCESS_OR_INTERVIEW")),
    # 8.x Logging, monitoring and detection.
    c(
        "8.1.1",
        RMC,
        ("cloudtrail:DescribeTrails", "cloudtrail:GetEventSelectors"),
        related=("AWS-07",),
        reasons=(T,),
    ),
    c("8.1.2", MVR, reasons=(T, "PROCESS_OR_INTERVIEW")),
    c("8.1.3", RMC, ("rds:DescribeDBInstances",), reasons=(T, "PROCESS_OR_INTERVIEW")),
    *(
        c(i, MVR, reasons=(T, "PROCESS_OR_INTERVIEW"))
        for i in (
            "8.2.1",
            "8.2.2",
            "8.2.3",
            "8.3.1",
            "8.3.2",
            "8.3.3",
            "8.5.1",
            "8.6.1",
            "8.6.2",
        )
    ),
    c(
        "8.4.1",
        RMC,
        ("logs:DescribeLogGroups", "s3api:GetBucketLifecycleConfiguration"),
        reasons=(T,),
    ),
    c("8.4.2", RMC, ("s3api:GetObjectLockConfiguration",), related=("AWS-07",), reasons=(T,)),
    # AWS-nn controls carry control-specific criteria and are the primary automation target.
    c(
        "AWS-01",
        BME,
        (ORG, "organizations:ListOrganizationalUnitsForParent"),
        reasons=("ORG_ADMIN_EVIDENCE",),
    ),
    c(
        "AWS-02",
        BME,
        ("controltower:ListEnabledControls", "controltower:GetLandingZone"),
        reasons=("ORG_ADMIN_EVIDENCE", "PROCESS_OR_INTERVIEW"),
    ),
    c(
        "AWS-03",
        BME,
        (
            "sso-admin:ListPermissionSets",
            "sso-admin:DescribePermissionSet",
            "sso-admin:ListAccountAssignments",
        ),
        reasons=("ORG_ADMIN_EVIDENCE",),
    ),
    c(
        "AWS-04",
        PART,
        (GAAD, "iam:ListRoles", "accessanalyzer:ListFindingsV2"),
        ("R1-IAM-ROLE-TRUST-CONDITIONS",),
        reasons=("CONJUNCTIVE_PASS", "CLASSIFICATION_INPUT"),
    ),
    c(
        "AWS-05",
        NI,
        ("accessanalyzer:ListAnalyzers", "accessanalyzer:ListFindingsV2"),
        reasons=("ADAPTER_MISSING",),
    ),
    c(
        "AWS-06",
        NI,
        ("iam:GetAccountSummary", CRED, "cloudwatch:DescribeAlarms"),
        reasons=("ADAPTER_MISSING",),
    ),
    c(
        "AWS-07",
        PART,
        ("cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", ORG),
        ("R0-CLOUDTRAIL-VALIDATION",),
        reasons=("CONJUNCTIVE_PASS", "ORG_ADMIN_EVIDENCE"),
    ),
    c(
        "AWS-08",
        PART,
        ("config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus"),
        ("SEC-CONFIG-RECORDING",),
        reasons=("CONJUNCTIVE_PASS", "ORG_ADMIN_EVIDENCE"),
    ),
    c(
        "AWS-09",
        PART,
        ("guardduty:ListDetectors", "guardduty:GetDetector"),
        ("SEC-GUARDDUTY-ENABLED",),
        reasons=("CONJUNCTIVE_PASS", "ORG_ADMIN_EVIDENCE"),
    ),
    c(
        "AWS-10",
        PART,
        ("securityhub:DescribeHub", "securityhub:GetEnabledStandards"),
        ("SEC-SECURITYHUB-ENABLED",),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "AWS-11",
        PART,
        (
            "s3control:GetPublicAccessBlock",
            "s3api:GetPublicAccessBlock",
            "s3api:GetBucketPolicyStatus",
            "s3api:GetBucketAcl",
        ),
        ("R1-S3-ACCOUNT-BPA", "R1-S3-BUCKET-PUBLIC-ACCESS"),
        reasons=("CONJUNCTIVE_PASS", "CLASSIFICATION_INPUT"),
    ),
    c(
        "AWS-12",
        PART,
        ("kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListGrants"),
        ("SEC-KMS-WILDCARD-PRINCIPAL", "SEC-KMS-ROTATION"),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "AWS-13",
        NI,
        ("secretsmanager:ListSecrets", "ssm:DescribeParameters"),
        reasons=("ADAPTER_MISSING", "CREDENTIAL_GUARD_CONFLICT"),
    ),
    c(
        "AWS-14",
        NI,
        ("ec2:DescribeVpcs", "ec2:DescribeFlowLogs", "ec2:DescribeRouteTables"),
        reasons=("ADAPTER_MISSING",),
    ),
    c(
        "AWS-15",
        PART,
        (SG, ENI, "ec2:DescribeRouteTables", "ec2:DescribeNetworkAcls"),
        ("R1-EC2-SG-SENSITIVE-INGRESS",),
        reasons=("CONJUNCTIVE_PASS", "REACHABILITY_ENGINE"),
    ),
    c(
        "AWS-16",
        BME,
        ("ec2:SearchTransitGatewayRoutes", "ec2:DescribeVpcPeeringConnections"),
        reasons=("CLASSIFICATION_INPUT", "REACHABILITY_ENGINE"),
    ),
    c(
        "AWS-17",
        MVR,
        ("network-firewall:DescribeFirewall", "ec2:DescribeRouteTables"),
        reasons=("PROCESS_OR_INTERVIEW", "REACHABILITY_ENGINE"),
    ),
    c(
        "AWS-18",
        NI,
        ("wafv2:GetWebACL", "wafv2:ListResourcesForWebACL"),
        reasons=("ADAPTER_MISSING",),
    ),
    c(
        "AWS-19",
        PART,
        ("ec2:DescribeInstances", GAAD),
        ("R0-EC2-IMDSV2", "R1-EC2-IMDS-HOP-LIMIT", "R1-IAM-INSTANCE-ROLE-PRIVILEGE"),
        reasons=("CONJUNCTIVE_PASS", "IAM_ENGINE"),
    ),
    c(
        "AWS-20",
        NI,
        ("ecs:DescribeTaskDefinition", "ecr:GetRepositoryPolicy"),
        reasons=("ADAPTER_MISSING",),
    ),
    c(
        "AWS-21",
        BME,
        ("lambda:ListFunctions", "lambda:GetPolicy"),
        reasons=("CREDENTIAL_GUARD_CONFLICT", "IAM_ENGINE"),
    ),
    c(
        "AWS-22",
        PART,
        (
            "rds:DescribeDBInstances",
            SG,
            "ec2:DescribeRouteTables",
            "rds:DescribeDBSnapshotAttributes",
        ),
        ("R0-RDS-ENCRYPTION", "R1-RDS-PUBLIC-ACCESS"),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "AWS-23",
        NI,
        ("dynamodb:DescribeTable", "dynamodb:DescribeContinuousBackups"),
        reasons=("ADAPTER_MISSING", "CLASSIFICATION_INPUT"),
    ),
    c("AWS-24", NI, ("opensearch:DescribeDomains",), reasons=("ADAPTER_MISSING",)),
    c("AWS-25", NI, ("kafka:DescribeClusterV2",), reasons=("ADAPTER_MISSING",)),
    c(
        "AWS-26",
        NI,
        ("backup:DescribeBackupVault", "backup:GetBackupVaultAccessPolicy"),
        reasons=("ADAPTER_MISSING", "CLASSIFICATION_INPUT"),
    ),
    c(
        "AWS-27",
        NI,
        ("iam:ListOpenIDConnectProviders", GAAD),
        reasons=("ADAPTER_MISSING", "PROCESS_OR_INTERVIEW"),
    ),
    c(
        "AWS-28",
        MVR,
        (GAAD,),
        ("R1-IAM-ROLE-TRUST-CONDITIONS",),
        reasons=("CLASSIFICATION_INPUT", "PROCESS_OR_INTERVIEW"),
    ),
)
BY_CONTROL = {entry.control_id: entry for entry in COVERAGE}

# Hand-reviewed methodology issues that structural checks cannot detect. IDs only.
REVIEW_ITEMS = (
    (
        "MR-H01",
        "CRITERIA_TOPIC_MISMATCH",
        tuple(e.control_id for e in COVERAGE if "CRITERIA_TOPIC_MISMATCH" in e.reasons),
    ),
    ("MR-H02", "SENSITIVE_PORT_LIST_OPEN_ENDED", ("AWS-15",)),
    ("MR-H03", "HTTP_PORTS_TREATED_AS_NON_SENSITIVE_ASSUMPTION", ("AWS-15",)),
    ("MR-H04", "APPROVED_CIDR_LIST_NOT_SUPPLIED", ("AWS-15",)),
    ("MR-H05", "TRUST_CONDITION_SET_AMBIGUOUS_MFA_ORGPATHS", ("AWS-04",)),
    ("MR-H06", "THIRD_PARTY_DETERMINATION_NEEDS_ORG_ACCOUNT_LIST", ("AWS-04", "AWS-28")),
    ("MR-H07", "STRONG_AUTH_UNDEFINED", ("AWS-22",)),
    (
        "MR-H08",
        "CONJUNCTIVE_PASS_CLAUSES",
        tuple(e.control_id for e in COVERAGE if "CONJUNCTIVE_PASS" in e.reasons),
    ),
    ("MR-H09", "ORG_WIDE_CLAIMS_NEED_ALL_ACCOUNT_EVIDENCE", ("AWS-01", "AWS-07", "AWS-11")),
    ("MR-H10", "TRACKER_GRANULARITY_AND_SCANNER_COLUMNS_AMBIGUOUS", ()),
    ("MR-H11", "ACCOUNT_KEYS_ARE_PLACEHOLDERS", ()),
    ("MR-H12", "THREAT_NOTATION_HASH_N_ASSUMED_EQUAL_TS_NN", ()),
    ("MR-H13", "SCENARIO_TO_THREAT_LINK_BY_ORDINAL_REF", ()),
    ("MR-H14", "UNGUARDED_PASSROLE_INTERPRETATION", ("AWS-19",)),
)


# Provider-specific additions do not alter the source AWS classification above.
# These are check-area implementations, not complete source-clause automation.
GCP_CONFIG_COVERAGE: tuple[ControlCoverage, ...] = (
    c(
        "1.3.1",
        PART,
        ("gcp:compute.instances.list", "gcp:expanded.cloud_sql"),
        ("GCP-VM-EXTERNAL-IP", "GCP-SQL-PUBLIC-IP"),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "1.3.2",
        PART,
        ("gcp:compute.firewalls.list", "gcp:compute.instances.list"),
        ("GCP-NET-FW-ADMIN-INTERNET",),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "1.3.4",
        PART,
        ("gcp:compute.instances.list",),
        ("GCP-VM-DEFAULT-SA", "GCP-VM-FULL-API-SCOPE"),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "1.4.1",
        PART,
        ("gcp:storage.buckets.list",),
        ("GCP-STORAGE-PAP",),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c("1.4.4", PART, ("gcp:expanded.cloud_sql",), ("GCP-SQL-TLS",), reasons=("CONJUNCTIVE_PASS",)),
    c(
        "1.4.5",
        PART,
        ("gcp:storage.buckets.list",),
        ("GCP-STORAGE-VERSIONING",),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "1.5.2",
        PART,
        ("gcp:compute.firewalls.list", "gcp:expanded.cloud_sql"),
        ("GCP-NET-FW-DB-INTERNET", "GCP-NET-FW-ANY-INTERNET", "GCP-SQL-OPEN-NETWORK"),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "1.5.5",
        PART,
        ("gcp:compute.networks.list",),
        ("GCP-NET-DEFAULT-NETWORK",),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "1.5.7",
        PART,
        ("gcp:expanded.subnets",),
        ("GCP-NET-FLOW-LOGS",),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "1.5.8",
        PART,
        ("gcp:expanded.subnets",),
        ("GCP-NET-PRIVATE-GOOGLE-ACCESS",),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "1.8.4",
        PART,
        ("gcp:cloudkms.cryptoKeys.list",),
        ("GCP-KMS-ROTATION",),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "6.1.2",
        PART,
        ("gcp:compute.instances.list", "gcp:storage.buckets.list", "gcp:expanded.cloud_sql"),
        (
            "GCP-VM-SERIAL-PORT",
            "GCP-VM-OSLOGIN",
            "GCP-VM-PROJECT-SSH-KEYS",
            "GCP-VM-SHIELDED",
            "GCP-VM-IP-FORWARD",
            "GCP-STORAGE-UBLA",
            "GCP-SQL-BACKUP",
        ),
        reasons=("CONJUNCTIVE_PASS",),
    ),
    c(
        "8.4.1",
        PART,
        ("gcp:logging.buckets.list",),
        ("GCP-LOG-RETENTION",),
        reasons=("CLASSIFICATION_INPUT", "CONJUNCTIVE_PASS"),
    ),
)
