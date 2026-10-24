"""Single registry of executable rules used by the engine, findings and reporting."""

from offline_analyzer.rules.configuration import RULES as R0_RULES
from offline_analyzer.rules.gcp import GCP_RULES
from offline_analyzer.rules.gcp_org import ORG_RULES
from offline_analyzer.rules.iam_privilege import IAM_RULES
from offline_analyzer.rules.r1 import R1_RULES
from offline_analyzer.rules.security_observations import ADDITIONAL_RULES

ALL_RULES = R0_RULES + R1_RULES + IAM_RULES + ADDITIONAL_RULES
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
