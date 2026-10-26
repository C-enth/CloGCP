"""Deterministic reporting templates. No scanner or authorization evaluation."""

import json
import re

from .evidence import Focus

TEMPLATES = {
    "IAM": (
        (
            "A party controlling the named principal could attempt the granted "
            "operation on the recorded scope. actAs requires a separate workload "
            "execution mechanism; a binding does not establish token possession or "
            "effective access."
        ),
        (
            "A documented delegation requirement with narrowly scoped permissions, "
            "evaluated conditions and effective deny/boundary controls could justify "
            "this design. No exception approval is "
            "inferred."
        ),
        (
            "Limit the identified grant to required principals and resources; "
            "evaluate conditions and effective restrictions before accepting "
            "delegation."
        ),
        (
            "Provide the relevant allow binding, inherited scopes, custom-role "
            "permissions, conditions, deny policies and principal boundary "
            "context."
        ),
    ),
    "Network": (
        (
            "Traffic could reach an affected workload only if routes, applicable "
            "firewall priorities, hierarchical policies and an active listener "
            "permit the same flow. An allow rule alone does not prove reachability "
            "or compromise."
        ),
        (
            "A documented public service requirement and effective source, port and "
            "application controls could justify the rule. Demonstrate the actual "
            "flow and blocking controls."
        ),
        (
            "Restrict the recorded source ranges and protocols to the intended "
            "workload and approved clients; verify higher-priority and hierarchical "
            "rules."
        ),
        (
            "Provide matching routes, target tags/service accounts, firewall "
            "priority, deny rules and listener/application authorization "
            "evidence."
        ),
    ),
    "GKE": (
        (
            "A reachable control plane or compromised workload could expose cluster "
            "or runtime permissions only when endpoint authorization, Kubernetes "
            "RBAC and workload identity mappings permit it. Standard and Autopilot "
            "settings must be evaluated in their own "
            "modes."
        ),
        (
            "An approved endpoint or workload design with restricted networks, RBAC "
            "and mapped workload identities could justify the configuration. Mode "
            "defaults are not exception evidence."
        ),
        (
            "Validate the cluster mode, control-plane access configuration, RBAC and "
            "each workload identity mapping before changing the affected "
            "setting."
        ),
        (
            "Provide cluster mode and endpoint settings, node/workload identity "
            "configuration, namespace/service-account mappings and relevant "
            "RBAC."
        ),
    ),
    "Serverless": (
        (
            "A public invoker binding permits a potential invocation route only when "
            "ingress and frontend controls admit the request. Invocation does not "
            "give the caller the runtime service account or establish application "
            "compromise."
        ),
        (
            "An approved public endpoint with application authorization and "
            "appropriate ingress controls could be intentional. Internal-only "
            "ingress may block the direct internet "
            "variant."
        ),
        (
            "Restrict invocation and ingress to the intended clients and minimize "
            "runtime identity permissions; verify any approved external "
            "frontend."
        ),
        (
            "Provide invoker IAM, ingress settings, frontend routing, application "
            "authorization and the runtime identity's effective "
            "permissions."
        ),
    ),
    "Storage": (
        (
            "A public or broad data grant could expose objects only if public access "
            "prevention, uniform bucket access, applicable IAM conditions and "
            "perimeter controls allow that route. Data sensitivity and actual reads "
            "are not established by a policy alone."
        ),
        (
            "A documented public dataset or delivery requirement with reviewed "
            "object scope and sensitivity could justify access. Supply the approval "
            "and effective access controls."
        ),
        (
            "Remove unnecessary public/broad grants and enforce the intended "
            "public-access restrictions after validating required delivery "
            "paths."
        ),
        (
            "Provide bucket IAM, public-access prevention, uniform access settings, "
            "conditions, relevant perimeter controls and data "
            "classification."
        ),
    ),
    "SQL": (
        (
            "The recorded database settings could allow network access or weaken "
            "transport protection only if address assignment, authorized networks, "
            "connector behavior and database authentication permit the route. "
            "Omitted fields are not proof of a secure "
            "default."
        ),
        (
            "An approved connector/private connectivity design with verified "
            "effective settings may explain the observation. Demonstrate effective "
            "configuration rather than assumed defaults."
        ),
        (
            "Verify the instance's effective network and transport settings, then "
            "restrict unnecessary public access and enforce the intended secure "
            "connection method."
        ),
        (
            "Provide full instance settings, authorized networks, private "
            "connectivity, connector configuration and transport/authentication "
            "evidence."
        ),
    ),
    "Organization policy": (
        (
            "The project may inherit an effective organization constraint that "
            "changes the local setting. A local policy or omitted value alone does "
            "not establish the effective restriction."
        ),
        (
            "An approved organization/folder exception with effective inherited "
            "policy evidence may explain the setting. An exception is not assumed "
            "from a missing local policy."
        ),
        (
            "Resolve the effective policy across the actual ancestor chain and "
            "review any inherited exception before changing the local "
            "constraint."
        ),
        (
            "Provide the effective constraint, organization/folder inheritance, "
            "exception conditions and applicable project "
            "scope."
        ),
    ),
    "Logging": (
        (
            "Security-relevant events may be unavailable if audit categories, "
            "exemptions, exclusions or routing omit them. Central sinks can provide "
            "coverage, but a sink reference alone does not establish delivery or "
            "retention."
        ),
        (
            "A central logging design may satisfy the requirement when routing, "
            "destination permissions, retention and sample event delivery are "
            "demonstrated."
        ),
        (
            "Verify audit categories, exemptions, exclusions and central sink "
            "delivery, then close the specific coverage gap identified in the source "
            "observation."
        ),
        (
            "Provide effective audit configuration, sink filters/destinations, "
            "exclusions, retention and authorized sample delivery "
            "metadata."
        ),
    ),
    "Other": (
        (
            "The source observation describes a potential configuration gap. The "
            "exported data does not establish successful misuse or the complete "
            "authorization context."
        ),
        (
            "A client may provide a documented requirement and effective "
            "compensating-control evidence. No exception or safety conclusion is "
            "inferred."
        ),
        (
            "Resolve the source observation's specific expected configuration and "
            "evidence gaps before approving a technical "
            "change."
        ),
        (
            "Provide the exact resource configuration, source requirement and "
            "applicable conditions or controls for assessor "
            "review."
        ),
    ),
}

# Read-only command references pinned to existing CloGCP DETAIL/RULES definitions.
# Parameters come only from explicitly selected verification guidance, never free text.
COMMANDS = {
    "GCP-IAM-IMPERSONATION": ("project", "gcloud projects get-iam-policy {project} --format=json"),
    "GCP-NET-FW-ADMIN-INTERNET": (
        "project rule",
        "gcloud compute firewall-rules describe {rule} --project={project} --format=json",
    ),
    "GCP-STORAGE-PUBLIC": (
        "project bucket",
        "gcloud storage buckets get-iam-policy gs://{bucket} --project={project} --format=json",
    ),
    "GCP-SQL-PUBLIC-IP": (
        "project instance",
        "gcloud sql instances describe {instance} --project={project} --format=json",
    ),
    "GCP-LOG-AUDIT": (
        "project",
        "gcloud projects get-iam-policy {project} --format='json(auditConfigs)'",
    ),
}


def domain(row: dict, evidence: Focus) -> str:
    text = " ".join(
        str(row.get(k) or "")
        for k in ("Domain / tool", "Observation / gap", "Affected objects / services")
    ).lower()
    text += " " + " ".join(e.get("operation", "") for e in evidence.entries).lower()
    for category, tokens in (
        ("GKE", ("gke", "kubernetes", "autopilot")),
        ("Serverless", ("serverless", "gcp:run.", "cloudfunctions", "cloud run")),
        ("Storage", ("storage", "bucket")),
        ("SQL", ("sql", "database")),
        ("Organization policy", ("orgpolicy", "organization policy", "constraint")),
        ("Logging", ("logging", "audit", "sink")),
        ("Network", ("firewall", "network")),
        ("IAM", ("iam", "identity", "delegation")),
    ):
        if any(token in text for token in tokens):
            return category
    return "Other"


def verification(guidance: dict) -> str:
    control = guidance.get("control_id", "")
    if control not in COMMANDS:
        return "Verification procedure required: no supported control/parameter mapping exported."
    required, template = COMMANDS[control]
    parameters = guidance.get("parameters") or {}
    if not isinstance(parameters, dict) or any(
        not isinstance(parameters.get(p), str)
        or not re.fullmatch(
            r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
            if p == "project"
            else r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]",
            parameters[p],
        )
        for p in required.split()
    ):
        return "Verification procedure required: safe resource parameters unavailable."
    return template.format(**{k: parameters[k] for k in required.split()})


def narrative(row: dict, focused: Focus) -> dict:
    category = domain(row, focused)
    scenario, exception, remediation, challenge = TEMPLATES[category]
    expected = (
        row.get("Expected control / requirement")
        or "Expected source requirement unavailable; assessor review required."
    )
    observed = (
        json.dumps([e["selected"] for e in focused.entries], ensure_ascii=True, sort_keys=True)
        if focused.entries
        else "Evidence detail unavailable"
    )
    from .schema import COLUMNS

    command_context = focused.context
    control = command_context.get("control_id", "")
    project = (command_context.get("parameters") or {}).get("project", "")
    if (
        not control
        or control not in str(row.get(COLUMNS[19]) or "")
        or project != row.get(COLUMNS[2])
    ):
        command_context = {}
    return {
        "domain": category,
        "observed": observed,
        "why": str(
            row.get("Assessor conclusion / evidence basis")
            or "Source technical rationale unavailable; assessor review required."
        ),
        "expected": str(expected),
        "scenario": scenario,
        "exception": exception,
        "remediation": str(row.get("Recommended action") or remediation),
        "verification": verification(command_context),
        "supports": (
            "Support requires the collected value and scope to match the source observation's "
            "stated condition. Compare the focused excerpt with the original requirement; "
            "this tool does not rerun the control."
        ),
        "contradicts": (
            "A different effective value, applicable blocking control, incorrect "
            "resource attribution or a supported exception requires assessor review "
            "in CloGCP; do not edit the security conclusion "
            "here."
        ),
        "challenge": challenge,
        "unresolved": "; ".join(focused.limitations)
        or (
            "Execution and complete effective access remain unverified; review the "
            "recorded qualifying controls."
        ),
    }
