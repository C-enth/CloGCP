"""Single registry of executable rules used by the engine, findings and reporting."""

from dataclasses import replace

from offline_analyzer.rules.configuration import RULES as R0_RULES
from offline_analyzer.rules.gcp import GCP_RULES
from offline_analyzer.rules.gcp_org import ORG_RULES
from offline_analyzer.rules.iam_privilege import IAM_RULES
from offline_analyzer.rules.r1 import R1_RULES
from offline_analyzer.rules.security_observations import ADDITIONAL_RULES

# AWS datasets collected per resource of a parent listing: collector 0.3.x calls the dependent
# API only after a COMPLETE parent, so the parent's journal outcome decides the collection
# scope (rules/engine.py:dependent_scope). Unparsed parents are read from the stored
# collection summary.
DEPENDENT_PARENTS = {
    "kms:DescribeKey": "kms:ListKeys",
    "kms:GetKeyPolicy": "kms:ListKeys",
    "cloudtrail:GetTrailStatus": "cloudtrail:DescribeTrails",
    "cloudtrail:GetEventSelectors": "cloudtrail:DescribeTrails",
    "s3api:GetBucketPolicyStatus": "s3api:ListBuckets",
}
# Phase 0 (AWS readiness): scope rows from the parent listing; resource predicates unchanged.
DEPENDENT_SCOPE_VERSIONS = {
    "R1-S3-BUCKET-PUBLIC-ACCESS": "1.2.0",
    "SEC-KMS-WILDCARD-PRINCIPAL": "1.2.0",
    "SEC-KMS-ROTATION": "1.2.0",
    "SEC-CLOUDTRAIL-LOGGING": "1.2.0",
    "SEC-CLOUDTRAIL-MANAGEMENT-EVENTS": "1.2.0",
}
ALL_RULES = tuple(
    replace(rule, version=DEPENDENT_SCOPE_VERSIONS.get(rule.rule_id, rule.version))
    for rule in R0_RULES + R1_RULES + IAM_RULES + ADDITIONAL_RULES
)
PROVIDER_RULES = ALL_RULES + GCP_RULES + ORG_RULES
BY_ID = {rule.rule_id: rule for rule in PROVIDER_RULES}
# Opt-in service-account identity resolution (rules/gcp_identity.py, E1/E2). Only these
# rules and attack-path kinds use it; hygiene rules get no identity enrichment.
IDENTITY_ENRICHED = frozenset(
    {
        "GCP-IAM-CROSSPROJECT",
        "GCP-IAM-BASIC",
        "GCP-IAM-IMPERSONATION",
        "GCP-ORG-SA-PRIVILEGED",
        "GCP-ORG-CROSSPROJECT-SA",
        "XP-01",
        "XP-02",
    }
)
# Root-cause group key per rule (findings/groups.py). Default: the rule ID alone. "principal":
# rule ID + canonical principal(s) named by the finding; "resource": rule ID + the rule's own
# resource (firewall / security-group rule); "org_node": rule ID + the organization or folder
# node the grant is inherited from (other resources fall back to the rule ID).
GROUP_KEYS = {
    **{
        rule: "principal"
        for rule in (
            "GCP-IAM-BASIC",
            "GCP-IAM-IMPERSONATION",
            "GCP-IAM-CROSSPROJECT",
            "GCP-KEY-PERSISTENT",
            "GCP-KEY-AGE",
            "GCP-KEY-PRIVILEGED",
            "GCP-ORG-SA-PRIVILEGED",
            "GCP-ORG-CROSSPROJECT-SA",
            "R1-IAM-INSTANCE-ROLE-PRIVILEGE",
            "R1-IAM-ROLE-TRUST-CONDITIONS",
        )
    },
    **{
        rule: "resource"
        for rule in (
            "GCP-NET-FW-ADMIN-INTERNET",
            "GCP-NET-FW-DB-INTERNET",
            "GCP-NET-FW-ANY-INTERNET",
            "R1-EC2-SG-SENSITIVE-INGRESS",
            "SEC-EC2-SG-LATENT-EXPOSURE",
        )
    },
    **{
        rule: "org_node"
        for rule in (
            "GCP-ORG-BASIC-ROLE",
            "GCP-ORG-IMPERSONATION",
            "GCP-ORG-DELETED-PRINCIPAL",
            "GCP-ORG-PUBLIC-DATA",
            "GCP-ORG-PUBLIC-OTHER",
            "GCP-ORG-PUBLIC-SERVERLESS",
        )
    },
}
# Opt-in attached service-account privilege context (rules/gcp_principal_context.py, E5).
PRINCIPAL_CONTEXT_RULES = frozenset(
    {
        "GCP-VM-DEFAULT-SA",
        "GCP-VM-FULL-API-SCOPE",
        "GCP-NET-FW-ADMIN-INTERNET",
        "GCP-NET-FW-DB-INTERNET",
        "GCP-NET-FW-ANY-INTERNET",
    }
)
# Opt-in AWS principal/role identity classification (rules/aws_identity.py). Only these rules
# get trust-class, role-class and organization-control context.
AWS_IDENTITY_ENRICHED = frozenset(
    {"R1-IAM-ROLE-TRUST-CONDITIONS", "R1-IAM-INSTANCE-ROLE-PRIVILEGE", "SEC-IAM-ROLE-WILDCARD"}
)
# Opt-in AWS workload-identity context (instance-profile role x open security group x public
# interface; rules/aws_identity.py:workload_context), the AWS analogue of GCP E5.
AWS_PRINCIPAL_CONTEXT_RULES = frozenset({"R1-EC2-SG-SENSITIVE-INGRESS"})
# iam:ListRoles carries the same trust document as GetAccountAuthorizationDetails.
EQUIVALENT_OPERATIONS = {
    "iam:ListRoles": "iam:GetAccountAuthorizationDetails",
    "iam:GetRole": "iam:GetAccountAuthorizationDetails",
}


def rule_operations(rule) -> set[str]:
    primary = {rule.operation} | {
        alias for alias, target in EQUIVALENT_OPERATIONS.items() if target == rule.operation
    }
    return primary | set(rule.context_operations)


def primary_operations(rule) -> set[str]:
    return rule_operations(rule) - set(rule.context_operations)
