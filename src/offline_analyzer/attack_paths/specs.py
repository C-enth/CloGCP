"""Typed prerequisite specifications for the methodology attack paths (AP-01..AP-30).

Analyst-authored and keyed by source IDs; no source narrative text is stored. Kinds:
CONFIG (configuration evidence; `rules` names implemented rules), IAM_ENGINE,
REACHABILITY, ORG_EVIDENCE, CLASSIFICATION, DETECTION, MANUAL and EXPLOITATION.
EXPLOITATION prerequisites are hypotheses; no automated result may mark them verified,
so no path in this specification can reach SUPPORTED from configuration alone.
"""

from dataclasses import dataclass

SPEC_VERSION = "1.2.0"  # 1.2.0: AP-06 P1/P2 are alternatives (ALTERNATIVES)
KINDS = (
    "CONFIG",
    "IAM_ENGINE",
    "REACHABILITY",
    "ORG_EVIDENCE",
    "CLASSIFICATION",
    "DETECTION",
    "MANUAL",
    "EXPLOITATION",
)


@dataclass(frozen=True)
class Prerequisite:
    key: str
    kind: str
    summary: str
    evidence: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()


@dataclass(frozen=True)
class PathSpec:
    path_id: str
    scope: str  # AWS | PARTIAL_AWS | OUTSIDE_CURRENT_AWS_SCOPE
    threats: tuple[str, ...]  # source "#N" links normalized to TS-NN (review item MR-H12)
    prerequisites: tuple[Prerequisite, ...] = ()
    blockers: tuple[str, ...] = ()


P = Prerequisite
SG_ENI = ("ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces")
GAAD = ("iam:GetAccountAuthorizationDetails",)
ORG = ("organizations:ListPolicies", "organizations:ListTargetsForPolicy")
OUTSIDE = "OUTSIDE_CURRENT_AWS_SCOPE"

PATHS = (
    PathSpec(
        "AP-01",
        "AWS",
        (),
        (
            P("AP-01.P1", "ORG_EVIDENCE", "Accounts outside environment-segregated OUs", ORG),
            P("AP-01.P2", "ORG_EVIDENCE", "Tag policy enforcement absent", ORG),
            P("AP-01.P3", "ORG_EVIDENCE", "No deny-based guardrail SCPs", ORG),
        ),
        ("Deny-based SCPs attached to every workload OU",),
    ),
    PathSpec(
        "AP-02",
        "AWS",
        ("TS-03", "TS-05"),
        (
            P("AP-02.P1", "ORG_EVIDENCE", "SCP exception or account excluded from guardrails", ORG),
            P(
                "AP-02.P2",
                "IAM_ENGINE",
                "Identity able to modify or detach organization policies",
                GAAD + ORG,
            ),
            P("AP-02.P3", "EXPLOITATION", "Compromise of that identity"),
            P(
                "AP-02.P4",
                "CONFIG",
                "Unconditioned cross-account trust enabling pivot",
                GAAD,
                ("R1-IAM-ROLE-TRUST-CONDITIONS",),
            ),
        ),
        ("Organization policy changes restricted to management-account break-glass roles",),
    ),
    PathSpec(
        "AP-03",
        "AWS",
        ("TS-04", "TS-15"),
        (
            P(
                "AP-03.P1",
                "IAM_ENGINE",
                "Non-break-glass identity allowed StopLogging/DeleteTrail",
                GAAD,
            ),
            P("AP-03.P2", "ORG_EVIDENCE", "No SCP denying trail modification", ORG),
            P(
                "AP-03.P3",
                "DETECTION",
                "No alert on trail changes and no SIEM ingestion",
                ("cloudwatch:DescribeAlarms",),
            ),
            P("AP-03.P4", "EXPLOITATION", "Compromise of an identity holding P1 permissions"),
        ),
        ("Organization trail owned by management account", "SCP deny on trail changes"),
    ),
    PathSpec(
        "AP-04",
        "AWS",
        ("TS-01", "TS-03"),
        (
            P(
                "AP-04.P1",
                "CONFIG",
                "Instance interface with public IPv4 whose security group "
                "allows 0.0.0.0/0 to a sensitive port",
                SG_ENI,
                ("R1-EC2-SG-SENSITIVE-INGRESS",),
            ),
            P(
                "AP-04.P2",
                "CONFIG",
                "Same instance permits IMDSv1 (token optional)",
                ("ec2:DescribeInstances",),
                ("R0-EC2-IMDSV2",),
            ),
            P(
                "AP-04.P3",
                "EXPLOITATION",
                "Exploitable service, SSRF or credential compromise on the exposed workload",
            ),
            P(
                "AP-04.P4",
                "IAM_ENGINE",
                "Instance role permissions enable escalation or broad access",
                GAAD + ("ec2:DescribeIamInstanceProfileAssociations",),
            ),
        ),
        (
            "IMDSv2 required blocks the SSRF-to-IMDSv1 variant only",
            "NACL/route/host firewall restrictions (not evaluated)",
        ),
    ),
    PathSpec(
        "AP-05",
        "AWS",
        ("TS-02",),
        (
            P(
                "AP-05.P1",
                "CONFIG",
                "Account-level Block Public Access not fully enabled",
                ("s3control:GetPublicAccessBlock",),
                ("R1-S3-ACCOUNT-BPA",),
            ),
            P(
                "AP-05.P2",
                "CONFIG",
                "Bucket-level Block Public Access not fully enabled",
                ("s3api:GetPublicAccessBlock",),
            ),
            P(
                "AP-05.P3",
                "CONFIG",
                "Bucket policy or ACL grants public access",
                ("s3api:GetBucketPolicyStatus", "s3api:GetBucketAcl"),
            ),
            P("AP-05.P4", "CLASSIFICATION", "Bucket holds sensitive data"),
        ),
        ("All four account-level Block Public Access settings enabled",),
    ),
    PathSpec(
        "AP-06",
        "AWS",
        ("TS-03", "TS-08", "TS-10"),
        (
            P(
                "AP-06.P1",
                "IAM_ENGINE",
                "Principal holds escalation-capable permissions "
                "(for example unconstrained iam:PassRole or wildcards)",
                GAAD,
            ),
            P(
                "AP-06.P2",
                "CONFIG",
                "Cross-account trust without binding conditions",
                GAAD,
                ("R1-IAM-ROLE-TRUST-CONDITIONS",),
            ),
            P("AP-06.P3", "EXPLOITATION", "Attacker controls a principal with P1 or P2 access"),
            P(
                "AP-06.P4",
                "ORG_EVIDENCE",
                "No SCP or permission boundary blocks the escalation",
                ORG,
            ),
        ),
    ),
    PathSpec(
        "AP-07",
        "PARTIAL_AWS",
        ("TS-10",),
        (
            P("AP-07.P1", "MANUAL", "Secret present in repository or environment variable"),
            P("AP-07.P2", "CONFIG", "Long-lived valid access key", ("iam:GetCredentialReport",)),
            P("AP-07.P3", "IAM_ENGINE", "Credential grants access to further services", GAAD),
        ),
    ),
    PathSpec(
        "AP-08",
        "AWS",
        (),
        (
            P(
                "AP-08.P1",
                "CONFIG",
                "Vulnerable image deployed",
                ("ecr:DescribeImageScanFindings",),
            ),
            P(
                "AP-08.P2",
                "CONFIG",
                "Privileged container or host mount",
                ("ecs:DescribeTaskDefinition",),
            ),
            P("AP-08.P3", "EXPLOITATION", "Remote code execution and container escape"),
            P("AP-08.P4", "IAM_ENGINE", "Node/task role over-privileged", GAAD),
        ),
    ),
    *(
        PathSpec(path, OUTSIDE, threats)
        for path, threats in (
            ("AP-09", ("TS-06",)),
            ("AP-10", ("TS-07",)),
            ("AP-11", ("TS-16", "TS-17", "TS-19")),
            ("AP-12", ("TS-18", "TS-20")),
            ("AP-13", ("TS-11", "TS-13")),
            ("AP-14", ("TS-12", "TS-14")),
        )
    ),
    PathSpec(
        "AP-15",
        "PARTIAL_AWS",
        ("TS-09",),
        (
            P(
                "AP-15.P1",
                "CLASSIFICATION",
                "Privileged IAM user or vendor role without owner",
                ("iam:GetCredentialReport",) + GAAD,
            ),
            P("AP-15.P2", "DETECTION", "No monitoring of that identity's activity"),
            P("AP-15.P3", "EXPLOITATION", "Attacker activates the orphaned identity"),
        ),
    ),
    PathSpec(
        "AP-16",
        "AWS",
        (),
        (
            P(
                "AP-16.P1",
                "ORG_EVIDENCE",
                "Account not enrolled or landing zone drifted",
                ("controltower:ListEnabledControls",),
            ),
            P(
                "AP-16.P2",
                "ORG_EVIDENCE",
                "Mandatory guardrails disabled for an OU",
                ("controltower:ListEnabledControls",),
            ),
        ),
    ),
    PathSpec(
        "AP-17",
        "AWS",
        (),
        (
            P(
                "AP-17.P1",
                "ORG_EVIDENCE",
                "Administrator permission set assigned broadly",
                ("sso-admin:ListAccountAssignments",),
            ),
            P("AP-17.P2", "EXPLOITATION", "Compromise of an assigned SSO identity"),
        ),
    ),
    PathSpec(
        "AP-18",
        "AWS",
        (),
        (
            P(
                "AP-18.P1",
                "CONFIG",
                "Key policy permits broad or cross-account decrypt",
                ("kms:GetKeyPolicy",),
            ),
            P(
                "AP-18.P2",
                "CONFIG",
                "Ciphertext/snapshots reachable by the trusted account",
                ("rds:DescribeDBSnapshotAttributes", "ec2:DescribeSnapshotAttribute"),
            ),
            P("AP-18.P3", "EXPLOITATION", "Attacker operates in the trusted account"),
        ),
    ),
    PathSpec(
        "AP-19",
        "AWS",
        (),
        (
            P(
                "AP-19.P1",
                "CONFIG",
                "RDS instance PubliclyAccessible=true",
                ("rds:DescribeDBInstances",),
                ("R1-RDS-PUBLIC-ACCESS",),
            ),
            P(
                "AP-19.P2",
                "REACHABILITY",
                "Security group and subnet route admit internet clients",
                SG_ENI + ("ec2:DescribeRouteTables",),
            ),
            P("AP-19.P3", "MANUAL", "Database authentication weak or credentials exposed"),
            P(
                "AP-19.P4",
                "CONFIG",
                "Alternative: snapshot shared publicly",
                ("rds:DescribeDBSnapshotAttributes",),
            ),
        ),
        ("PubliclyAccessible=false (blocks the direct-endpoint variant)",),
    ),
    PathSpec(
        "AP-20",
        "AWS",
        (),
        (
            P("AP-20.P1", "MANUAL", "Secret in Lambda environment (needs redacted collector scan)"),
            P("AP-20.P2", "IAM_ENGINE", "Execution role reaches downstream services", GAAD),
            P("AP-20.P3", "EXPLOITATION", "Function compromise or configuration read access"),
        ),
    ),
    PathSpec(
        "AP-21",
        "AWS",
        (),
        (
            P(
                "AP-21.P1",
                "CONFIG",
                "Repository writable/public or image unscanned",
                ("ecr:GetRepositoryPolicy", "ecr:DescribeRepositories"),
            ),
            P("AP-21.P2", "IAM_ENGINE", "Task role over-privileged", GAAD),
            P("AP-21.P3", "EXPLOITATION", "Malicious image deployed"),
        ),
    ),
    PathSpec(
        "AP-22",
        "AWS",
        (),
        (
            P(
                "AP-22.P1",
                "REACHABILITY",
                "Transit gateway routes connect non-production to production",
                ("ec2:SearchTransitGatewayRoutes",),
            ),
            P("AP-22.P2", "CLASSIFICATION", "Account/VPC environment classification"),
            P("AP-22.P3", "EXPLOITATION", "Compromise of a workload in the source VPC"),
        ),
    ),
    PathSpec(
        "AP-23",
        "AWS",
        (),
        (
            P(
                "AP-23.P1",
                "REACHABILITY",
                "Route tables bypass the inspection VPC",
                ("ec2:DescribeRouteTables", "network-firewall:DescribeFirewall"),
            ),
        ),
    ),
    PathSpec(
        "AP-24",
        "AWS",
        (),
        (
            P(
                "AP-24.P1",
                "CONFIG",
                "Public endpoint or open access policy",
                ("opensearch:DescribeDomains",),
            ),
        ),
    ),
    PathSpec(
        "AP-25",
        "AWS",
        (),
        (
            P(
                "AP-25.P1",
                "CONFIG",
                "Plaintext listener or unauthenticated access",
                ("kafka:DescribeClusterV2",),
            ),
            P("AP-25.P2", "REACHABILITY", "Brokers reachable from untrusted networks", SG_ENI),
        ),
    ),
    PathSpec(
        "AP-26",
        "AWS",
        (),
        (
            P(
                "AP-26.P1",
                "CONFIG",
                "Vault without compliance-mode lock",
                ("backup:DescribeBackupVault",),
            ),
            P("AP-26.P2", "IAM_ENGINE", "Identity can delete recovery points", GAAD),
            P("AP-26.P3", "EXPLOITATION", "Compromise of that identity"),
        ),
    ),
    PathSpec(
        "AP-27",
        "AWS",
        (),
        (
            P("AP-27.P1", "CONFIG", "OIDC role trust with wildcard subject/audience", GAAD),
            P("AP-27.P2", "EXPLOITATION", "Attacker controls a matching repository/branch"),
        ),
    ),
    PathSpec(
        "AP-28",
        "AWS",
        (),
        (
            P(
                "AP-28.P1",
                "CONFIG",
                "GuardDuty/Security Hub disabled or not auto-enabled",
                ("guardduty:ListDetectors", "securityhub:DescribeHub"),
            ),
        ),
    ),
    PathSpec(
        "AP-29",
        "AWS",
        (),
        (
            P(
                "AP-29.P1",
                "CONFIG",
                "Resource policy with Principal:* or broad account",
                ("s3api:GetBucketPolicy", "kms:GetKeyPolicy", "lambda:GetPolicy"),
            ),
            P(
                "AP-29.P2",
                "CONFIG",
                "Role trust without binding conditions",
                GAAD,
                ("R1-IAM-ROLE-TRUST-CONDITIONS",),
            ),
            P(
                "AP-29.P3",
                "CONFIG",
                "Access Analyzer external-access finding",
                ("accessanalyzer:ListFindingsV2",),
            ),
        ),
    ),
    PathSpec(
        "AP-30",
        "PARTIAL_AWS",
        (),
        (
            P(
                "AP-30.P1",
                "REACHABILITY",
                "Hybrid routes reach on-premises segments",
                ("ec2:DescribeRouteTables", "directconnect:DescribeVirtualInterfaces"),
            ),
            P("AP-30.P2", "EXPLOITATION", "Compromise of a cloud workload"),
        ),
    ),
)
BY_PATH = {path.path_id: path for path in PATHS}
# Prerequisites of which any one suffices (the path's ANY hop): a group is met when one member
# is VERIFIED and is absent only when every member is verified absent.
ALTERNATIVES = {"AP-06": (("AP-06.P1", "AP-06.P2"),)}

# STRIDE scenario AWS applicability; prerequisites are expressed via the linked paths.
THREAT_SCOPE = {
    "TS-01": ("AWS", ("AP-04.P1", "AP-04.P2")),
    "TS-02": ("AWS", ("AP-05.P1", "AP-05.P2", "AP-05.P3", "AP-05.P4")),
    "TS-03": ("AWS", ("AP-04.P2", "AP-06.P1", "AP-06.P4")),
    "TS-04": ("AWS", ("AP-03.P1", "AP-03.P2", "AP-03.P3")),
    "TS-05": ("AWS", ("AP-22.P1", "AP-22.P2")),
    "TS-06": (OUTSIDE, ()),
    "TS-07": (OUTSIDE, ()),
    "TS-08": ("AWS", ("AP-06.P2", "AP-06.P1")),
    "TS-09": (OUTSIDE, ()),
    "TS-10": ("PARTIAL_AWS", ("AP-07.P1", "AP-07.P2", "AP-07.P3")),
    "TS-11": (OUTSIDE, ()),
    "TS-12": (OUTSIDE, ()),
    "TS-13": (OUTSIDE, ()),
    "TS-14": ("PARTIAL_AWS", ()),
    "TS-15": ("PARTIAL_AWS", ("AP-03.P3",)),
    "TS-16": (OUTSIDE, ()),
    "TS-17": (OUTSIDE, ()),
    "TS-18": (OUTSIDE, ()),
    "TS-19": (OUTSIDE, ()),
    "TS-20": (OUTSIDE, ()),
}
