"""Proposed rule-to-methodology mappings, pinned to a reviewed workbook fingerprint.

Criterion keys name individual clauses of a control's source PASS (P) / FAIL (F)
criteria; their analyst-authored meaning is documented in METHODOLOGY_COVERAGE.md.
Attack paths, STRIDE category and inherent severity are copied source metadata used
for traceability only: they never set technical severity or a confirmed conclusion.
A rule that evaluates a subset of clauses can never produce a control-level Pass.
"""

from dataclasses import dataclass

from offline_analyzer.methodology.coverage_spec import REVIEWED_METHODOLOGY_SHA256


@dataclass(frozen=True)
class MethodologyLink:
    control_id: str
    criteria: tuple[str, ...]
    not_evaluated: tuple[str, ...]
    attack_paths: tuple[str, ...]
    stride_category: str
    inherent_severity: str
    status: str = "PROPOSED"
    full_coverage: bool = False
    methodology_sha256: str = REVIEWED_METHODOLOGY_SHA256


AWS_04 = dict(
    control_id="AWS-04",
    not_evaluated=("AWS-04:P2", "AWS-04:F2"),
    attack_paths=("AP-06", "AP-27", "AP-29"),
    stride_category="Elevation of Privilege",
    inherent_severity="Critical",
)
AWS_07 = dict(
    control_id="AWS-07",
    not_evaluated=(
        "AWS-07:P1.org-multi-region",
        "AWS-07:P2",
        "AWS-07:P3",
        "AWS-07:P4",
        "AWS-07:F1",
        "AWS-07:F3",
        "AWS-07:F4",
    ),
    attack_paths=("AP-03", "AP-28"),
    stride_category="Repudiation",
    inherent_severity="Critical",
)
AWS_11 = dict(
    control_id="AWS-11",
    not_evaluated=("AWS-11:P2", "AWS-11:P3", "AWS-11:F2", "AWS-11:F3", "AWS-11:F4"),
    attack_paths=("AP-05", "AP-29"),
    stride_category="Information Disclosure",
    inherent_severity="Critical",
)
AWS_15 = dict(
    control_id="AWS-15",
    not_evaluated=("AWS-15:P2", "AWS-15:V-NACL"),
    attack_paths=("AP-04", "AP-15"),
    stride_category="Spoofing / Elevation of Privilege",
    inherent_severity="Critical",
)
AWS_19 = dict(
    control_id="AWS-19",
    attack_paths=("AP-04", "AP-06"),
    stride_category="Spoofing / Elevation of Privilege",
    inherent_severity="Critical",
)
AWS_22 = dict(
    control_id="AWS-22",
    attack_paths=("AP-19",),
    stride_category="Information Disclosure / Spoofing",
    inherent_severity="Critical",
)

LINKS = {
    "R0-EC2-IMDSV2": MethodologyLink(
        criteria=("AWS-19:P1", "AWS-19:F1"),
        not_evaluated=("AWS-19:P2", "AWS-19:P3", "AWS-19:P4", "AWS-19:F2", "AWS-19:F3"),
        **AWS_19,
    ),
    "R1-EC2-IMDS-HOP-LIMIT": MethodologyLink(
        criteria=("AWS-19:P2", "AWS-19:F2"),
        not_evaluated=("AWS-19:P1", "AWS-19:P3", "AWS-19:P4", "AWS-19:F1", "AWS-19:F3"),
        **AWS_19,
    ),
    "R0-RDS-ENCRYPTION": MethodologyLink(
        criteria=("AWS-22:P2", "AWS-22:F2"),
        not_evaluated=(
            "AWS-22:P1",
            "AWS-22:P3",
            "AWS-22:P4",
            "AWS-22:F1",
            "AWS-22:F3",
            "AWS-22:F4",
        ),
        **AWS_22,
    ),
    "R1-RDS-PUBLIC-ACCESS": MethodologyLink(
        criteria=("AWS-22:P1", "AWS-22:F1"),
        not_evaluated=(
            "AWS-22:P2",
            "AWS-22:P3",
            "AWS-22:P4",
            "AWS-22:F2",
            "AWS-22:F3",
            "AWS-22:F4",
        ),
        **AWS_22,
    ),
    "R0-CLOUDTRAIL-VALIDATION": MethodologyLink(
        criteria=("AWS-07:P1.validation", "AWS-07:F2"), **AWS_07
    ),
    "R1-EC2-SG-SENSITIVE-INGRESS": MethodologyLink(criteria=("AWS-15:P1", "AWS-15:F1"), **AWS_15),
    "R1-IAM-ROLE-TRUST-CONDITIONS": MethodologyLink(criteria=("AWS-04:P1", "AWS-04:F1"), **AWS_04),
    "R1-S3-ACCOUNT-BPA": MethodologyLink(criteria=("AWS-11:P1", "AWS-11:F1"), **AWS_11),
    "R1-S3-BUCKET-PUBLIC-ACCESS": MethodologyLink(
        criteria=("AWS-11:P2", "AWS-11:F2"),
        **{
            **AWS_11,
            "not_evaluated": ("AWS-11:P1", "AWS-11:P3", "AWS-11:F1", "AWS-11:F3", "AWS-11:F4"),
        },
    ),
    "R1-IAM-INSTANCE-ROLE-PRIVILEGE": MethodologyLink(
        criteria=("AWS-19:P4", "AWS-19:F3"),
        not_evaluated=("AWS-19:P1", "AWS-19:P2", "AWS-19:P3", "AWS-19:F1", "AWS-19:F2"),
        **AWS_19,
    ),
}


def mapping_fields(rule) -> dict:
    """Result/finding mapping fields for a rule's proposed checklist link."""
    link = rule.methodology
    if not link:
        return {}
    return {
        "methodology_id": link.control_id,
        "mapping_status": link.status,
        "methodology_criteria": link.criteria,
        "methodology_sha256": link.methodology_sha256,
    }


# Source metadata (attack paths, STRIDE, inherent severity) for checklist controls used
# by AWS additional-observation rules and GCP rules. Criteria keys of the form
# "<control>:CA.<topic>" name an engineering check area (METHODOLOGY_COVERAGE.md), not a
# source PASS/FAIL clause; these links never claim control-level coverage.
CONTROL_META = {
    "1.2.2": (("AP-02",), "Tampering / Elevation of Privilege", "High"),
    "1.4.2": (("AP-05",), "Information Disclosure", "Critical"),
    "1.5.2": (("AP-04",), "Spoofing / Elevation of Privilege", "Critical"),
    "1.6.3": (("AP-06",), "Elevation of Privilege", "Critical"),
    "1.6.4": (("AP-06",), "Elevation of Privilege", "High"),
    "1.6.5": (("AP-06",), "Elevation of Privilege", "Critical"),
    "1.6.7": (("AP-06",), "Elevation of Privilege", "Critical"),
    "1.7.1": (("AP-03",), "Repudiation", "Critical"),
    "1.7.2": (("AP-03",), "Repudiation", "Critical"),
    "1.8.5": (("AP-07",), "Information Disclosure", "High"),
    "1.9.3": (("AP-08",), "Elevation of Privilege / Tampering", "Critical"),
    "2.5.1": (("AP-10",), "Spoofing / Elevation of Privilege", "Critical"),
    "2.8.2": (("AP-06",), "Elevation of Privilege", "Critical"),
    "2.8.3": (("AP-06",), "Elevation of Privilege", "High"),
    "5.3.1": (("AP-04",), "Spoofing / Elevation of Privilege", "High"),
    "7.2.1": (("AP-15",), "Spoofing / Repudiation", "Critical"),
    "7.4.1": (("AP-15",), "Spoofing / Repudiation", "Critical"),
    "8.1.1": (("AP-03",), "Repudiation", "Critical"),
    "AWS-08": (("AP-01", "AP-03"), "Repudiation / Tampering", "High"),
    "AWS-09": (("AP-03", "AP-04", "AP-28"), "Repudiation / Information Disclosure", "High"),
    "AWS-10": (("AP-28",), "Repudiation", "High"),
    "AWS-12": (("AP-18", "AP-29"), "Information Disclosure", "High"),
    # Derived from the reviewed workbook (Linked Attack Path, STRIDE, Inherent Severity) for
    # the GCP configuration rules (rules/gcp_config.py).
    "1.3.1": (("AP-04",), "Spoofing / Elevation of Privilege", "Critical"),
    "1.3.2": (("AP-04",), "Spoofing / Elevation of Privilege", "Critical"),
    "1.3.4": (("AP-04",), "Spoofing / Elevation of Privilege", "Critical"),
    "1.4.1": (("AP-05",), "Information Disclosure", "Critical"),
    "1.4.4": (("AP-05",), "Information Disclosure", "Medium"),
    "1.4.5": (("AP-05",), "Information Disclosure", "High"),
    "1.5.5": (("AP-01",), "Information Disclosure / Tampering", "Medium"),
    "1.5.7": (("AP-03",), "Repudiation", "High"),
    "1.5.8": (("AP-02",), "Tampering / Elevation of Privilege", "High"),
    "1.8.4": (("AP-07",), "Information Disclosure", "High"),
    "6.1.2": (("AP-01",), "Information Disclosure / Tampering", "High"),
    "8.4.1": (("AP-03",), "Repudiation", "High"),
}


def check_area(control_id: str, *topics: str) -> MethodologyLink:
    paths, stride, severity = CONTROL_META[control_id]
    return MethodologyLink(
        control_id=control_id,
        criteria=tuple(f"{control_id}:CA.{topic}" for topic in topics),
        not_evaluated=(),
        attack_paths=paths,
        stride_category=stride,
        inherent_severity=severity,
    )


LINKS.update(
    {
        # AWS additional observations, classified under the shared checklist.
        "SEC-IAM-ROLE-WILDCARD": check_area("1.6.3", "role-wildcard-action"),
        "SEC-KMS-WILDCARD-PRINCIPAL": check_area("AWS-12", "key-policy-wildcard-principal"),
        # AWS-15 fails only on a public ENI; latent (unattached/private) exposure is the
        # broader 1.5.2 inbound-exposure control.
        "SEC-EC2-SG-LATENT-EXPOSURE": check_area("1.5.2", "latent-sensitive-ingress"),
        "SEC-CLOUDTRAIL-LOGGING": check_area("1.7.1", "trail-logging"),
        "SEC-CLOUDTRAIL-MANAGEMENT-EVENTS": check_area("1.7.1", "management-events"),
        "SEC-GUARDDUTY-ENABLED": check_area("AWS-09", "detector-enabled"),
        "SEC-CONFIG-RECORDING": check_area("AWS-08", "recorder-recording"),
        "SEC-SECURITYHUB-ENABLED": check_area("AWS-10", "hub-enabled"),
        "SEC-KMS-ROTATION": check_area("AWS-12", "cmk-rotation"),
        # GCP project rules.
        "GCP-STORAGE-PUBLIC": check_area("1.4.2", "public-bucket-binding"),
        "GCP-API-APP": check_area("1.8.5", "api-key-application-restriction"),
        "GCP-API-API": check_area("1.8.5", "api-key-api-restriction"),
        "GCP-API-BOTH": check_area("1.8.5", "api-key-unrestricted"),
        "GCP-KEY-PERSISTENT": check_area("2.8.3", "user-managed-key"),
        "GCP-KEY-AGE": check_area("2.8.3", "key-age"),
        "GCP-KEY-PRIVILEGED": check_area("2.8.2", "privileged-sa-key"),
        "GCP-IAM-BASIC": check_area("1.6.4", "basic-role-binding"),
        "GCP-IAM-PUBLIC": check_area("1.6.3", "public-principal-binding"),
        "GCP-IAM-IMPERSONATION": check_area("1.6.7", "broad-impersonation"),
        "GCP-IAM-CROSSPROJECT": check_area("1.6.5", "cross-project-privileged-sa"),
        "GCP-GOV-KEYS": check_area("1.2.2", "sa-key-constraints"),
        "GCP-LOG-AUDIT": check_area("1.7.2", "data-access-exemption"),
        "GCP-LOG-EXCLUSION": check_area("8.1.1", "logging-exclusion"),
        "GCP-SCC-OBSERVATION": check_area("5.3.1", "scc-active-finding"),
        # GCP organization-wide (cross-project) rules.
        "GCP-ORG-PUBLIC-SERVERLESS": check_area("1.9.3", "public-invoker"),
        "GCP-ORG-PUBLIC-DATA": check_area("1.4.2", "public-data-binding"),
        "GCP-ORG-PUBLIC-OTHER": check_area("1.6.3", "public-principal-binding"),
        "GCP-ORG-BASIC-ROLE": check_area("1.6.4", "org-basic-role-human"),
        "GCP-ORG-SA-PRIVILEGED": check_area("2.8.2", "org-sa-basic-role"),
        "GCP-ORG-IMPERSONATION": check_area("1.6.7", "inherited-impersonation"),
        "GCP-ORG-CROSSPROJECT-SA": check_area("1.6.5", "foreign-sa-privileged"),
        "GCP-ORG-DELETED-PRINCIPAL": check_area("7.2.1", "deleted-principal-binding"),
        "GCP-ORG-EXTERNAL-DOMAIN": check_area("7.4.1", "external-domain-principal"),
        "GCP-ORG-FEDERATION": check_area("2.5.1", "workload-identity-trust"),
        # GCP configuration rules (network, Compute Engine, storage, Cloud SQL, KMS, logging).
        "GCP-NET-FW-ADMIN-INTERNET": check_area("1.3.2", "firewall-admin-ports-internet"),
        "GCP-NET-FW-DB-INTERNET": check_area("1.5.2", "firewall-database-ports-internet"),
        "GCP-NET-FW-ANY-INTERNET": check_area("1.5.2", "firewall-all-ports-internet"),
        "GCP-NET-DEFAULT-NETWORK": check_area("1.5.5", "default-network"),
        "GCP-NET-FLOW-LOGS": check_area("1.5.7", "subnet-flow-logs"),
        "GCP-NET-PRIVATE-GOOGLE-ACCESS": check_area("1.5.8", "private-google-access"),
        "GCP-VM-EXTERNAL-IP": check_area("1.3.1", "instance-external-ip"),
        "GCP-VM-DEFAULT-SA": check_area("1.3.4", "default-service-account"),
        "GCP-VM-FULL-API-SCOPE": check_area("1.3.4", "default-sa-full-scope"),
        "GCP-VM-SERIAL-PORT": check_area("6.1.2", "serial-port"),
        "GCP-VM-OSLOGIN": check_area("6.1.2", "os-login"),
        "GCP-VM-PROJECT-SSH-KEYS": check_area("6.1.2", "project-ssh-keys"),
        "GCP-VM-SHIELDED": check_area("6.1.2", "shielded-vm"),
        "GCP-VM-IP-FORWARD": check_area("6.1.2", "ip-forwarding"),
        "GCP-STORAGE-UBLA": check_area("6.1.2", "uniform-bucket-level-access"),
        "GCP-STORAGE-PAP": check_area("1.4.1", "public-access-prevention"),
        "GCP-STORAGE-VERSIONING": check_area("1.4.5", "object-versioning"),
        "GCP-SQL-OPEN-NETWORK": check_area("1.5.2", "sql-authorized-internet"),
        "GCP-SQL-PUBLIC-IP": check_area("1.3.1", "sql-public-ip"),
        "GCP-SQL-TLS": check_area("1.4.4", "sql-tls"),
        "GCP-SQL-BACKUP": check_area("6.1.2", "sql-backups"),
        "GCP-KMS-ROTATION": check_area("1.8.4", "kms-rotation"),
        "GCP-LOG-RETENTION": check_area("8.4.1", "log-bucket-retention"),
    }
)
