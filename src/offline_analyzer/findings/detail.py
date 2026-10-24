"""Detailed, evidence-backed analysis of one finding (ADR-009).

Every statement is either read from stored analyzer data (candidate, evaluation, sources,
raw collected files) or taken from versioned guidance and labelled as security analysis.
The evidence snippet is the collected JSON at the finding's evidence locator, with
credentials and secret values masked. Commands are text for review; nothing is executed.
"""

import json
import re

from offline_analyzer.contracts.r0 import Candidate
from offline_analyzer.findings.explanations import explain
from offline_analyzer.findings.generate import validation_status
from offline_analyzer.findings.recommendations import recommendation
from offline_analyzer.findings.sre import STAGES, VERDICTS, latest_sre, stage
from offline_analyzer.ingestion.json_input import SECRET_KEYS, SECRET_VALUE, InputError
from offline_analyzer.ingestion.safety import resolve_under, sha256_file
from offline_analyzer.reporting.coverage_reasons import reason_text

VERSION = "finding-detail-1.0.0"
SNIPPET_LIMIT = 12000
MASK = "***MASKED***"
SECRETISH = ("secret", "password", "privatekey", "token", "credential", "apikey", "keystring")

LEAST = "Least privilege"
EXPOSURE = "Minimal exposure / secure defaults"
AUDIT = "Accountability: complete, tamper-evident audit logging"
DATA = "Data protection at rest"
CREDS = "Credential lifecycle hygiene"
TRUST = "Explicit trust boundaries"

# rule: (weakness, principle, fields to highlight, (field, expected secure value),
#        remediation command for review, read-only verification command)
RULES = {
    "R0-EC2-IMDSV2": (
        "Weak access restriction (metadata service)",
        EXPOSURE,
        ("HttpTokens", "MetadataOptions"),
        (("HttpTokens", "required"),),
        "aws ec2 modify-instance-metadata-options --instance-id <instance-id> "
        "--http-tokens required --http-endpoint enabled",
        "aws ec2 describe-instances --instance-ids <instance-id> "
        "--query 'Reservations[].Instances[].MetadataOptions'",
    ),
    "R1-EC2-IMDS-HOP-LIMIT": (
        "Weak access restriction (metadata service)",
        EXPOSURE,
        ("HttpPutResponseHopLimit", "MetadataOptions"),
        (("HttpPutResponseHopLimit", "1"),),
        "aws ec2 modify-instance-metadata-options --instance-id <instance-id> "
        "--http-put-response-hop-limit 1",
        "aws ec2 describe-instances --instance-ids <instance-id> "
        "--query 'Reservations[].Instances[].MetadataOptions.HttpPutResponseHopLimit'",
    ),
    "R0-RDS-ENCRYPTION": (
        "Missing encryption",
        DATA,
        ("StorageEncrypted", "KmsKeyId"),
        (("StorageEncrypted", "true"),),
        "",  # No in-place change: snapshot, copy with --kms-key-id, restore, cut over.
        "aws rds describe-db-instances --db-instance-identifier <db-instance> "
        "--query 'DBInstances[].StorageEncrypted'",
    ),
    "R0-CLOUDTRAIL-VALIDATION": (
        "Integrity control missing (audit logs)",
        AUDIT,
        ("LogFileValidationEnabled",),
        (("LogFileValidationEnabled", "true"),),
        "aws cloudtrail update-trail --name <trail-name> --enable-log-file-validation",
        "aws cloudtrail describe-trails --trail-name-list <trail-name> "
        "--query 'trailList[].LogFileValidationEnabled'",
    ),
    "R1-EC2-SG-SENSITIVE-INGRESS": (
        "Public exposure (network)",
        EXPOSURE,
        ("IpPermissions", "IpRanges", "CidrIp", "FromPort", "ToPort", "Ipv6Ranges"),
        (("CidrIp", "not 0.0.0.0/0 on administrative or database ports"),),
        "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp "
        "--port <port> --cidr 0.0.0.0/0",
        "aws ec2 describe-security-groups --group-ids <sg-id> "
        "--query 'SecurityGroups[].IpPermissions'",
    ),
    "SEC-EC2-SG-LATENT-EXPOSURE": (
        "Public exposure (network, latent)",
        EXPOSURE,
        ("IpPermissions", "IpRanges", "CidrIp", "FromPort", "ToPort"),
        (("CidrIp", "not 0.0.0.0/0 on administrative or database ports"),),
        "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp "
        "--port <port> --cidr 0.0.0.0/0",
        "aws ec2 describe-security-groups --group-ids <sg-id> "
        "--query 'SecurityGroups[].IpPermissions'",
    ),
    "R1-IAM-ROLE-TRUST-CONDITIONS": (
        "Weak access restriction (cross-account trust)",
        TRUST,
        ("AssumeRolePolicyDocument", "Principal", "Condition", "Action"),
        (("Condition", "aws:PrincipalOrgID or sts:ExternalId binding present"),),
        "",  # Policy edit: add a Condition block; reviewed per trusted party.
        "aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'",
    ),
    "R1-S3-ACCOUNT-BPA": (
        "Public exposure guardrail missing",
        EXPOSURE,
        ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"),
        tuple(
            (k, "true")
            for k in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        ),
        "aws s3control put-public-access-block --account-id <account-id> "
        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
        "BlockPublicPolicy=true,RestrictPublicBuckets=true",
        "aws s3control get-public-access-block --account-id <account-id>",
    ),
    "R1-S3-BUCKET-PUBLIC-ACCESS": (
        "Public exposure (data)",
        EXPOSURE,
        ("IsPublic", "PolicyStatus", "Grants", "URI"),
        (("IsPublic", "false"),),
        "aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration "
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        "aws s3api get-bucket-policy-status --bucket <bucket>",
    ),
    "R1-RDS-PUBLIC-ACCESS": (
        "Public exposure (database)",
        EXPOSURE,
        ("PubliclyAccessible", "Endpoint"),
        (("PubliclyAccessible", "false"),),
        "aws rds modify-db-instance --db-instance-identifier <db-instance> "
        "--no-publicly-accessible  # add --apply-immediately only in an approved window",
        "aws rds describe-db-instances --db-instance-identifier <db-instance> "
        "--query 'DBInstances[].PubliclyAccessible'",
    ),
    "R1-IAM-INSTANCE-ROLE-PRIVILEGE": (
        "Excessive permissions",
        LEAST,
        ("Action", "Resource", "Effect", "PolicyDocument"),
        (("Action", "specific actions; no '*' and no unconstrained iam:PassRole"),),
        "",
        "aws iam list-attached-role-policies --role-name <role-name>",
    ),
    "SEC-IAM-ROLE-WILDCARD": (
        "Excessive permissions",
        LEAST,
        ("Action", "Resource", "Effect", "PolicyDocument"),
        (("Action", "specific service actions, not wildcards"),),
        "",
        "aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>",
    ),
    "SEC-KMS-WILDCARD-PRINCIPAL": (
        "Excessive permissions (key policy)",
        LEAST,
        ("Principal", "Condition", "Action"),
        (("Principal", "named principals or a binding Condition, not '*'"),),
        "",
        "aws kms get-key-policy --key-id <key-id> --policy-name default",
    ),
    "SEC-CLOUDTRAIL-LOGGING": (
        "Insufficient logging",
        AUDIT,
        ("IsLogging",),
        (("IsLogging", "true"),),
        "aws cloudtrail start-logging --name <trail-name>",
        "aws cloudtrail get-trail-status --name <trail-name> --query IsLogging",
    ),
    "SEC-CLOUDTRAIL-MANAGEMENT-EVENTS": (
        "Insufficient logging",
        AUDIT,
        ("IncludeManagementEvents", "ReadWriteType"),
        (("IncludeManagementEvents", "true"), ("ReadWriteType", "All or WriteOnly")),
        "",
        "aws cloudtrail get-event-selectors --trail-name <trail-name>",
    ),
    "SEC-GUARDDUTY-ENABLED": (
        "Insufficient threat detection",
        AUDIT,
        ("Status", "DetectorIds"),
        (("Status", "ENABLED"),),
        "aws guardduty create-detector --enable --region <region>",
        "aws guardduty list-detectors --region <region>",
    ),
    "SEC-CONFIG-RECORDING": (
        "Insufficient configuration monitoring",
        AUDIT,
        ("recording", "lastStatus"),
        (("recording", "true"),),
        "aws configservice start-configuration-recorder --configuration-recorder-name <recorder>",
        "aws configservice describe-configuration-recorder-status --region <region>",
    ),
    "SEC-SECURITYHUB-ENABLED": (
        "Insufficient security monitoring",
        AUDIT,
        ("HubArn",),
        (("HubArn", "present"),),
        "aws securityhub enable-security-hub --region <region>",
        "aws securityhub describe-hub --region <region>",
    ),
    "SEC-KMS-ROTATION": (
        "Key management weakness",
        CREDS,
        ("KeyRotationEnabled",),
        (("KeyRotationEnabled", "true"),),
        "aws kms enable-key-rotation --key-id <key-id>",
        "aws kms get-key-rotation-status --key-id <key-id>",
    ),
    "GCP-STORAGE-PUBLIC": (
        "Public exposure (data)",
        EXPOSURE,
        ("members", "role", "publicAccessPrevention"),
        (("members", "no allUsers / allAuthenticatedUsers"),),
        "gcloud storage buckets update gs://<bucket> --public-access-prevention",
        "gcloud storage buckets get-iam-policy gs://<bucket>",
    ),
    "GCP-API-APP": (
        "Weak access restriction (API key)",
        CREDS,
        ("restrictions",),
        (("restrictions", "application restrictions set"),),
        "",
        "gcloud services api-keys describe <key-id> --format='value(restrictions)'",
    ),
    "GCP-API-API": (
        "Weak access restriction (API key)",
        CREDS,
        ("restrictions", "apiTargets"),
        (("apiTargets", "only the APIs the application needs"),),
        "gcloud services api-keys update <key-id> --api-target=service=<service>.googleapis.com",
        "gcloud services api-keys describe <key-id> --format='value(restrictions.apiTargets)'",
    ),
    "GCP-API-BOTH": (
        "Weak access restriction (API key)",
        CREDS,
        ("restrictions",),
        (("restrictions", "application and API restrictions set"),),
        "",
        "gcloud services api-keys describe <key-id> --format='value(restrictions)'",
    ),
    "GCP-KEY-PERSISTENT": (
        "Credential management weakness",
        CREDS,
        ("keyType", "validAfterTime", "disabled"),
        (("keyType", "SYSTEM_MANAGED (no user-managed keys)"),),
        "gcloud iam service-accounts keys delete <key-id> --iam-account=<service-account>",
        "gcloud iam service-accounts keys list --iam-account=<service-account> --managed-by=user",
    ),
    "GCP-KEY-AGE": (
        "Credential management weakness",
        CREDS,
        ("keyType", "validAfterTime"),
        (("validAfterTime", "within the rotation policy"),),
        "gcloud iam service-accounts keys delete <key-id> --iam-account=<service-account>",
        "gcloud iam service-accounts keys list --iam-account=<service-account> --managed-by=user",
    ),
    "GCP-KEY-PRIVILEGED": (
        "Credential management weakness (privileged)",
        CREDS,
        ("keyType", "role", "members"),
        (("keyType", "SYSTEM_MANAGED (no user-managed keys)"),),
        "gcloud iam service-accounts keys delete <key-id> --iam-account=<service-account>",
        "gcloud iam service-accounts keys list --iam-account=<service-account> --managed-by=user",
    ),
    "GCP-IAM-BASIC": (
        "Excessive permissions",
        LEAST,
        ("role", "members"),
        (("role", "task-specific roles, not roles/owner or roles/editor"),),
        "gcloud projects remove-iam-policy-binding <project> --member=<member> --role=<role>",
        "gcloud projects get-iam-policy <project> --flatten=bindings "
        "--filter='bindings.role:(roles/owner roles/editor)'",
    ),
    "GCP-IAM-PUBLIC": (
        "Public exposure (IAM)",
        EXPOSURE,
        ("role", "members"),
        (("members", "no allUsers / allAuthenticatedUsers"),),
        "gcloud projects remove-iam-policy-binding <project> --member=allUsers --role=<role>",
        "gcloud projects get-iam-policy <project>",
    ),
    "GCP-IAM-IMPERSONATION": (
        "Excessive permissions (impersonation)",
        LEAST,
        ("role", "members"),
        (("role", "token creator / user granted on specific service accounts only"),),
        "",
        "gcloud projects get-iam-policy <project> --flatten=bindings "
        "--filter='bindings.role:(roles/iam.serviceAccountTokenCreator "
        "roles/iam.serviceAccountUser)'",
    ),
    "GCP-IAM-CROSSPROJECT": (
        "Excessive permissions (cross-project)",
        TRUST,
        ("role", "members"),
        (("role", "narrow role for approved cross-project use"),),
        "",
        "gcloud projects get-iam-policy <project>",
    ),
    "GCP-GOV-KEYS": (
        "Credential governance missing",
        CREDS,
        ("constraint", "enforce", "enforced", "booleanPolicy"),
        (("enforce", "true (unconditional) for the record's own constraint"),),
        "",
        "gcloud org-policies describe <constraint> --effective --project=<project>",
    ),
    "GCP-LOG-AUDIT": (
        "Insufficient logging",
        AUDIT,
        ("auditConfigs", "exemptedMembers", "logType"),
        (("exemptedMembers", "empty for security-relevant services"),),
        "",
        "gcloud projects get-iam-policy <project> --format='json(auditConfigs)'",
    ),
    "GCP-LOG-EXCLUSION": (
        "Insufficient logging",
        AUDIT,
        ("filter", "disabled", "exclusions"),
        (("filter", "does not drop security-relevant events"),),
        "",
        "gcloud logging sinks list --project=<project>",
    ),
    "GCP-SCC-OBSERVATION": (
        "Detector-reported weakness",
        EXPOSURE,
        ("category", "state", "severity"),
        (("state", "INACTIVE after remediation"),),
        "",
        "gcloud scc findings list <organization-or-project> --filter='state=\"ACTIVE\"'",
    ),
}


def _config_details() -> dict:
    from offline_analyzer.rules.gcp_config import DETAIL

    return DETAIL


ORG_RULES = {
    "GCP-ORG-PUBLIC-SERVERLESS": ("Public exposure (serverless)", EXPOSURE),
    "GCP-ORG-PUBLIC-DATA": ("Public exposure (data)", EXPOSURE),
    "GCP-ORG-PUBLIC-OTHER": ("Public exposure (IAM)", EXPOSURE),
    "GCP-ORG-BASIC-ROLE": ("Excessive permissions", LEAST),
    "GCP-ORG-SA-PRIVILEGED": ("Excessive permissions", LEAST),
    "GCP-ORG-IMPERSONATION": ("Excessive permissions (impersonation)", LEAST),
    "GCP-ORG-CROSSPROJECT-SA": ("Excessive permissions (cross-project)", TRUST),
    "GCP-ORG-DELETED-PRINCIPAL": ("Stale access", LEAST),
    "GCP-ORG-EXTERNAL-DOMAIN": ("Third-party access", TRUST),
    "GCP-ORG-FEDERATION": ("Weak access restriction (federation)", TRUST),
}
CLASS_MEANING = {
    "BASELINE_DEVIATION": "Confirmed misconfiguration against the secure baseline.",
    "POTENTIAL_EXPOSURE": (
        "Potential risk: the configuration is confirmed; exposure or exploitability needs "
        "additional validation."
    ),
    "SUPPORTED_SECURITY_GAP": "Security gap supported by the collected evidence.",
}


def _masked(value, depth=0):
    if depth > 40:
        return "[depth limited]"
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            norm = re.sub(r"[^a-z]", "", str(key).lower())
            secret = norm in SECRET_KEYS or any(s in norm for s in SECRETISH)
            out[key] = (
                MASK if secret and item not in (None, "", [], {}) else _masked(item, depth + 1)
            )
        return out
    if isinstance(value, list):
        return [_masked(item, depth + 1) for item in value]
    if isinstance(value, str) and SECRET_VALUE.search(value):
        return MASK
    return value


def _pointer(document, locator: str):
    if not locator.startswith("/"):
        return None
    node = document
    for raw in locator.split("/")[1:]:
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        elif isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _decoded(value):
    """URL-encoded or string JSON policy documents become objects so fields are visible."""
    if isinstance(value, str) and value[:3] in {"%7B", "%7b"}:
        from urllib.parse import unquote

        value = unquote(value)
    if isinstance(value, str) and value.lstrip().startswith("{"):
        try:
            return json.loads(value)
        except ValueError:
            return value
    if isinstance(value, dict):
        return {k: _decoded(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decoded(v) for v in value]
    return value


def _find(value, keys: set[str], path="", found=None):
    found = [] if found is None else found
    if len(found) >= 20:
        return found
    if isinstance(value, dict):
        for key, item in value.items():
            here = f"{path}/{key}"
            if key.lower() in keys:
                found.append({"path": here, "field": key, "value": item})
            _find(item, keys, here, found)
    elif isinstance(value, list):
        for i, item in enumerate(value[:200]):
            _find(item, keys, f"{path}/{i}", found)
    return found


def _short(value) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return text if len(text) <= 300 else text[:297] + "..."


def finding_detail(store, run: str, finding_id: str) -> dict:
    store.require_run(run)
    row = store.db.execute(
        "SELECT data FROM findings WHERE run_id=? AND finding_id=?", [run, finding_id]
    ).fetchone()
    if not row:
        raise InputError("FINDING_NOT_FOUND_IN_RUN")
    finding = Candidate.model_validate_json(row[0])
    from offline_analyzer.findings.generate import fingerprint
    from offline_analyzer.methodology.cloud_checklist import describe

    status, decision = validation_status(store, finding)
    sre = latest_sre(store, run).get(finding_id)
    current_stage = stage(status, sre, fingerprint(finding))
    explanation = explain(finding)
    advice = recommendation(finding.rule_id)
    evaluation = next(
        (
            json.loads(data)
            for (data,) in store.rows(
                "SELECT data FROM evaluations WHERE run_id=? AND resource_id=? AND "
                "json_extract_string(data,'$.rule_id')=? ORDER BY evaluation_id LIMIT 1",
                [run, finding.resource_id, finding.rule_id],
            )
        ),
        {},
    )
    weakness, principle, highlight, expected, fix_cli, verify_cli = {
        **RULES,
        **_config_details(),
    }.get(
        finding.rule_id,
        (*ORG_RULES.get(finding.rule_id, ("Security weakness", EXPOSURE)), (), (), "", ""),
    )
    keys = {k.lower() for k in highlight} | {f.lower() for f, _ in expected}
    sources = {s["artifact_id"]: s for s in store.source_data(run) if s.get("artifact_id")}
    hashes = dict(store.rows("SELECT artifact_id,sha256 FROM artifacts WHERE run_id=?", [run]))
    evidence, actual = [], []
    for ref in finding.evidence[:10]:
        source = sources.get(ref.artifact_id, {})
        sha = hashes.get(ref.artifact_id)
        snippet, note, intact = None, "", False
        if sha:
            path = resolve_under(store.workspace, f"raw/{sha}.json")
            if path.is_file():
                intact = sha256_file(path) == sha
                node = _pointer(json.loads(path.read_text(encoding="utf-8")), ref.locator)
                if node is None:
                    note = "The evidence locator could not be resolved in the stored file."
                else:
                    snippet = _decoded(_masked(node))
            else:
                note = "The stored evidence file is not available in this workspace."
        text = json.dumps(snippet, indent=2, sort_keys=True) if snippet is not None else ""
        if len(text) > SNIPPET_LIMIT:
            text, note = text[:SNIPPET_LIMIT], "Snippet truncated for display; see the file."
        matches = _find(snippet, keys) if snippet is not None else []
        if finding.rule_id != "R1-IAM-ROLE-TRUST-CONDITIONS":
            # Permission rules: the role's trust policy is context, not the failing setting.
            matches = [m for m in matches if "/AssumeRolePolicyDocument" not in m["path"]]
        actual.extend(matches)
        metadata = source.get("gcp_metadata") or {}
        evidence.append(
            {
                "operation": source.get("operation", "unrecorded"),
                "file": metadata.get("original_file") or source.get("path", "unrecorded"),
                "locator": ref.locator,
                "collected_at": metadata.get("completed_at") or source.get("collected_at"),
                "coverage": source.get("effective_coverage"),
                "collection_errors": source.get("errors") or [],
                "coverage_reason": reason_text(
                    metadata.get("error_category"), metadata.get("completeness_limitations")
                ),
                "artifact_sha256": sha,
                "integrity_verified": intact,
                "snippet": text,
                "highlight": sorted({m["field"] for m in matches}),
                "note": note,
            }
        )
    parameters = []
    for field, secure in expected:
        values = [m for m in actual if m["field"].lower() == field.lower()]
        parameters.append(
            {
                "field": field,
                "actual": "; ".join(f"{m['path']} = {_short(m['value'])}" for m in values[:5])
                or "Absent in the collected configuration",
                "expected": secure,
            }
        )
    if finding.rule_id in IDENTITY_RULES:
        parameters = identity_parameters(store, run, finding, evaluation, expected) or parameters
    elif finding.rule_id == "GCP-GOV-KEYS":
        parameters, verify_cli = key_governance_parameters(store, run, finding, evaluation)
    sre_dump = sre.model_dump(mode="json") if sre else None
    checklist = describe(finding.methodology_id)
    service = (evidence[0]["operation"] if evidence else "").split(":")[-1].split(".")[0]
    detail = {
        "version": VERSION,
        "overview": {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "provider": finding.provider or "AWS",
            "service": service or "unrecorded",
            "account_or_project": finding.project_id or finding.account_id,
            "region": finding.region,
            "resource_name": finding.native_id.rstrip("/").split("/")[-1].split(":")[-1],
            "resource_id": finding.native_id,
            "severity": finding.suggested_severity,
            "confidence": finding.evidence_confidence,
            "analyst_status": status,
            "stage": STAGES[current_stage],
            "control": finding.methodology_id or "Not mapped",
            "control_subject": checklist["checklist_title"],
            "domain": finding.security_domain,
            "rule": f"{finding.rule_id} {finding.rule_version}",
            "summary": f"{finding.title}. {explanation['why_flagged']}",
        },
        "observed": {
            "observation": finding.technical_observation,
            "exposure": finding.exposure_status,
            "parameters": parameters,
            "expected_posture": advice.get("expected_posture")
            or "Secure baseline for this control (see recommendation).",
        },
        "gap": {
            "weakness": weakness,
            "principle_violated": principle,
            "what_is_wrong": evaluation.get("reasoning") or finding.technical_observation,
            "why_insecure": explanation["impact"],
            "classification": CLASS_MEANING.get(finding.finding_class, finding.finding_class),
        },
        "evidence": evidence,
        "misuse": {
            "scenario": explanation["misuse"],
            "confirmed_by_evidence": [finding.technical_observation, finding.exposure_status],
            "unverified_prerequisites": list(finding.missing_evidence),
            "attack_paths": list(finding.attack_paths),
        },
        "impact": {
            "technical": explanation["impact"],
            "severity": finding.suggested_severity,
            "severity_rationale": finding.severity_rationale,
            "business": "Business context not provided; confirm asset criticality with the owner.",
        },
        "remediation": {
            "recommended_action": explanation["recommendation"],
            "immediate_mitigation": advice.get("immediate_mitigation", ""),
            "permanent_remediation": advice.get("permanent_remediation") or finding.remediation,
            "implementation_guidance": advice.get("implementation_guidance", ""),
            "operational_considerations": advice.get("operational_considerations", ""),
            "compensating_controls": advice.get("compensating_controls", ""),
            "command": fix_cli,
            "command_note": "For review only. CloSec never runs commands; replace <placeholders>, "
            "test outside production and follow change approval."
            if fix_cli
            else "No single verified command; follow the implementation guidance.",
            "references": list(advice.get("references", ())),
        },
        "validation": {
            "procedure": advice.get("validation_procedure")
            or "Recollect the configuration and confirm the expected values below.",
            "command": verify_cli,
            "expected_state": [f"{p['field']}: {p['expected']}" for p in parameters]
            or [advice.get("expected_posture", "Secure baseline restored")],
            "closure": "Mark remediated when a fresh collection shows the expected values and "
            "CloSec no longer raises this finding.",
        },
        "completeness": {
            "confirmed_observations": len(evaluation.get("supporting_observations", [])),
            "contradictory_observations": list(finding.contradictory_observations),
            "missing_information": list(finding.missing_evidence),
            "collection_errors": [
                f"{e['operation']}: {e['coverage']}"
                for e in evidence
                if e["coverage"] not in (None, "COMPLETE") or e["collection_errors"]
            ],
            "false_positive_conditions": list(evaluation.get("limitations", [])),
            "additional_validation": list(finding.validation_requirements),
            "needs_analyst_validation": finding.evidence_confidence != "HIGH"
            or bool(finding.missing_evidence),
        },
        "review": {
            "analyst_status": status,
            "analyst": decision.analyst if decision else "",
            "remark": decision.note if decision else "",
            "sre": sre_dump,
            "sre_verdict": VERDICTS.get(sre.verdict, "") if sre else "",
        },
    }
    detail["technical_finding"] = technical_finding(detail)
    detail["principals"] = principal_links(store, run, finding, evaluation)
    return detail


IDENTITY_RULES = {
    "GCP-IAM-CROSSPROJECT",
    "GCP-IAM-BASIC",
    "GCP-IAM-IMPERSONATION",
    "GCP-ORG-SA-PRIVILEGED",
    "GCP-ORG-CROSSPROJECT-SA",
}


def _supporting(store, run: str, evaluation: dict) -> list:
    found = []
    for oid in list(evaluation.get("supporting_observations") or [])[:50]:
        found.extend(store.observations(run, observation_id=oid))
    return found


def identity_parameters(store, run, finding: Candidate, evaluation: dict, expected) -> list:
    """Actual configuration for the identity rules: member, account class, owner project,
    role and condition (or "none"), from the finding's own binding records."""
    from offline_analyzer.rules.gcp_identity import account_class, scope_from
    from offline_analyzer.rules.gcp_org import org_records, project_index

    observations = _supporting(store, run, evaluation)
    sources = [s for s in store.source_data(run) if s.get("format") == "gcp-json-v1"]
    org = [
        obs
        for obs in store.observations(run, provider="GCP")
        if obs.resource_type == "GCP::AssetIAMSearchResult"
    ]
    scope = scope_from(sources, project_index(org_records(org))).for_project(
        finding.project_id, finding.project_number
    )
    reasoning = evaluation.get("reasoning") or ""
    target = expected[0][1] if expected else "least-privilege binding"
    rows = []
    for obs in observations:
        config = obs.configuration or {}
        if obs.resource_type == "GCP::IAMBinding":
            bindings = [(config.get("role"), config.get("members") or [], config.get("condition"))]
            org_level = False
        elif obs.resource_type == "GCP::AssetIAMSearchResult":
            policy = config.get("policy") or {}
            bindings = [
                (b.get("role"), b.get("members") or [], b.get("condition"))
                for b in (policy.get("bindings", []) if isinstance(policy, dict) else [])
                if isinstance(b, dict)
            ]
            org_level = True
        else:
            continue
        for role, members, condition in bindings:
            for member in members:
                if not isinstance(member, str):
                    continue
                member = member.split("?", 1)[0]
                if org_level and member not in reasoning:
                    continue
                account = account_class(member, scope)
                cls = (
                    account.account_class
                    if account
                    else f"{member.split(':', 1)[0]} principal (not a service account)"
                )
                owner = account.owner if account else "n/a"
                rule_condition = (
                    (condition.get("title") or condition.get("expression") or "conditional")
                    if isinstance(condition, dict) and condition
                    else "none"
                )
                rows.append(
                    {
                        "field": f"Member {len(rows) + 1}",
                        "actual": f"{member}; account class {cls}; owner project {owner}; "
                        f"role {role}; condition {rule_condition}",
                        "expected": target,
                    }
                )
    return rows[:50]


def key_governance_parameters(store, run, finding: Candidate, evaluation: dict):
    """Constraint, observed value and verification command from the finding's own record."""
    from offline_analyzer.rules.gcp import constraint_name, observed_policy

    record = next(
        (o for o in _supporting(store, run, evaluation) if o.resource_type == "GCP::OrgPolicy"),
        None,
    )
    if record is None:
        return [
            {
                "field": "effective policy record",
                "actual": "not collected (UNKNOWN)",
                "expected": "an effective record with unconditional enforce: true",
            }
        ], ""
    name = constraint_name(record.configuration) or "unrecorded constraint"
    project = finding.project_id or "<project>"
    rows = [
        {"field": "constraint", "actual": name, "expected": name},
        {
            "field": "effective enforcement",
            "actual": observed_policy(record.configuration),
            "expected": f"enforce: true (unconditional) for {name}",
        },
    ]
    managed = "iam.managed." + name.removeprefix("iam.")
    limitations = " ".join(evaluation.get("limitations") or [])
    rows.append(
        {
            "field": "managed constraint",
            "actual": "not observed"
            if "Managed constraint not observed" in limitations
            else "observed (see related evidence)",
            "expected": f"{managed} enforced, or the legacy constraint enforced",
        }
    )
    return rows, f"gcloud org-policies describe {name} --effective --project={project}"


def principal_links(store, run: str, finding: Candidate, evaluation: dict) -> list[dict]:
    """GCP members and attached service accounts named by the finding's evidence; each links to
    the per-principal role view (iam/gcp_principals.py). Never inferred beyond the evidence."""
    if finding.provider != "GCP":
        return []
    ids = list(evaluation.get("supporting_observations") or [])[:50]
    found: dict[str, str] = {}
    text = " ".join([finding.technical_observation or "", evaluation.get("reasoning") or ""])
    for oid in ids:
        for obs in store.observations(run, observation_id=oid):
            config = obs.configuration or {}
            if obs.resource_type == "GCP::IAMBinding":
                for member in config.get("members") or []:
                    if isinstance(member, str) and ":" in member:
                        found.setdefault(member.split("?", 1)[0], "binding member")
            elif obs.resource_type == "GCP::ComputeInstance":
                for account in config.get("serviceAccounts") or []:
                    if isinstance(account, dict) and isinstance(account.get("email"), str):
                        found.setdefault(
                            "serviceAccount:" + account["email"], "attached service account"
                        )
            elif obs.resource_type == "GCP::ServiceAccount" and isinstance(
                config.get("email"), str
            ):
                found.setdefault("serviceAccount:" + config["email"], "service account")
            elif obs.resource_type == "GCP::AssetIAMSearchResult":
                policy = config.get("policy") or {}
                for binding in policy.get("bindings", []) if isinstance(policy, dict) else []:
                    for member in (binding or {}).get("members") or []:
                        if isinstance(member, str) and member.split("?", 1)[0] in text:
                            found.setdefault(member.split("?", 1)[0], "binding member")
    if "/serviceAccounts/" in (finding.native_id or ""):
        email = finding.native_id.split("/serviceAccounts/", 1)[1].split("/", 1)[0]
        if "@" in email:
            found.setdefault("serviceAccount:" + email, "service account")
    return [
        {"principal": member, "relation": relation}
        for member, relation in sorted(found.items())
        if not member.startswith(("allUsers", "allAuthenticatedUsers"))
    ][:20]


def technical_finding(d: dict) -> str:
    """Plain-text report entry for the technical assessment report (analyst reviews it)."""
    o, ob, g, i, r, v = (
        d["overview"],
        d["observed"],
        d["gap"],
        d["impact"],
        d["remediation"],
        d["validation"],
    )
    params = "\n".join(
        f"  - {p['field']}: actual {p['actual']}; expected {p['expected']}"
        for p in ob["parameters"]
    )
    refs = "\n".join(
        f"  - {e['operation']} ({e['file']}, {e['locator']}, collected {e['collected_at']})"
        for e in d["evidence"]
    )
    lines = [
        f"Title: {o['title']}",
        f"Finding ID: {o['finding_id']}",
        f"Severity: {o['severity']} (confidence {o['confidence']})",
        f"Affected resource: {o['provider']} {o['account_or_project']}, {o['region']}, "
        f"{o['resource_id']}",
        f"Control: {o['control']} {o['control_subject']}",
        "",
        f"Observation: {ob['observation']}",
        "Actual configuration:" + (f"\n{params}" if params else " see supporting evidence"),
        f"Expected configuration: {ob['expected_posture']}",
        "",
        f"Security gap: {g['weakness']}; {g['what_is_wrong']} "
        f"(principle: {g['principle_violated']}). {g['classification']}",
        f"Risk and potential impact: {i['technical']}",
        f"How it can be misused: {d['misuse']['scenario']}",
        f"Severity rationale: {i['severity_rationale']}",
        "",
        "Supporting evidence:" + (f"\n{refs}" if refs else " none recorded"),
        "",
        f"Recommended remediation: {r['recommended_action']}",
        *(
            [f"Permanent remediation: {r['permanent_remediation']}"]
            if r["permanent_remediation"]
            else []
        ),
        *([f"Command for review (not executed): {r['command']}"] if r["command"] else []),
        f"Validation: {v['procedure']}",
        *([f"Verification command (read-only): {v['command']}"] if v["command"] else []),
        "",
        "Draft generated by CloSec from collected evidence; subject to analyst review and "
        "approval.",
    ]
    return "\n".join(lines)
