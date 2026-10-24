"""E5: attached service-account privilege context for VM and firewall exposure rules.

Opt-in only (`registry.PRINCIPAL_CONTEXT_RULES`): GCP-VM-DEFAULT-SA, GCP-VM-FULL-API-SCOPE,
GCP-NET-FW-ADMIN-INTERNET, GCP-NET-FW-DB-INTERNET, GCP-NET-FW-ANY-INTERNET. The base rule
decides FAIL/PASS/UNKNOWN as before; this step only adds context to a FAIL and may raise its
severity, never lower it and never turn missing evidence into PASS.

The attached accounts' roles come from the per-principal resolver (iam/gcp_principals.py),
built over the run being assessed only, so a rule result never depends on other imports.

| Privilege | GCP-VM-DEFAULT-SA (MEDIUM) | GCP-VM-FULL-API-SCOPE (LOW) | GCP-NET-FW-*-INTERNET |
|---|---|---|---|
| PRIVILEGED | HIGH | MEDIUM; HIGH with an external IP | severity kept; context added |
| NARROW | kept; "attached service account holds only narrow roles (...)" | same | same |
| NONE_OBSERVED | kept; label "no role binding observed" | same | same |
| UNRESOLVED | kept; "privileges unresolved: <reason>" | same | same |
"""

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.rules.configuration import Verdict

RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
BASE = {
    "GCP-VM-DEFAULT-SA": "MEDIUM",
    "GCP-VM-FULL-API-SCOPE": "LOW",
    "GCP-NET-FW-ADMIN-INTERNET": "HIGH",
    "GCP-NET-FW-DB-INTERNET": "HIGH",
    "GCP-NET-FW-ANY-INTERNET": "HIGH",
}
FULL_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


def higher(current: str | None, proposed: str) -> str:
    current = current or "INFO"
    return proposed if RANK.get(proposed, 0) > RANK.get(current, 0) else current


def attached(instance_config: dict) -> list[dict]:
    return [
        a
        for a in instance_config.get("serviceAccounts") or []
        if isinstance(a, dict) and isinstance(a.get("email"), str)
    ]


def account_context(index, email: str) -> dict:
    """Resolved roles of one attached account, with the IAM finding references."""
    result = index.lookup("serviceAccount:" + email)
    roles = sorted({b["role"] for b in result["bindings"]})
    privileged = sorted({b["role"] for b in result["bindings"] if b["privileged"] is True})
    references = sorted(
        {
            stable_id("finding", ["GCP-IAM-BASIC", b["binding_resource_id"]])
            for b in result["bindings"]
            if b.get("binding_resource_id")
            and b["role"] in {"roles/owner", "roles/editor"}
            and b["scope"] == "project"
            and not b["conditional"]
            and b.get("account_class") != "PLATFORM_AGENT"
        }
    )
    reason = next(
        (p["reason"] for p in result["projects"] if p["status"] != "RESOLVED"),
        "; ".join(sorted({b["role"] for b in result["bindings"] if b["role_status"] != "RESOLVED"}))
        or "resolution incomplete",
    )
    return {
        "email": email,
        "privilege": result["privilege"],
        "roles": roles,
        "privileged_roles": privileged,
        "reason": reason,
        "findings": references,
    }


def describe(context: dict, scopes: list[str]) -> str:
    roles = ", ".join(context["roles"][:8]) or "none observed"
    text = f"Attached service account {context['email']} (scopes: {', '.join(scopes) or 'none'}): "
    if context["privilege"] == "PRIVILEGED":
        text += "privileged role(s) " + ", ".join(context["privileged_roles"][:8])
    elif context["privilege"] == "NARROW":
        text += f"attached service account holds only narrow roles ({roles})"
    elif context["privilege"] == "NONE_OBSERVED":
        text += "no role binding observed (resolved)"
    else:
        text += f"privileges unresolved: {context['reason']}"
    if context["findings"]:
        text += "; see its finding(s) GCP-IAM-BASIC " + ", ".join(context["findings"][:3])
    return text


def enrich(rule_id: str, verdict: Verdict, instances: list, index) -> Verdict:
    """Add attached-account context to a FAIL; raise severity per the table above."""
    if verdict.outcome != Outcome.FAIL or index is None:
        return verdict
    severity = verdict.severity or BASE[rule_id]
    notes, unresolved = [], []
    for instance in instances:
        config = instance.configuration or {}
        external = any(
            access.get("natIP") or access.get("type") == "ONE_TO_ONE_NAT"
            for nic in config.get("networkInterfaces") or []
            if isinstance(nic, dict)
            for access in nic.get("accessConfigs") or []
            if isinstance(access, dict)
        )
        for account in attached(config):
            if rule_id in {"GCP-VM-DEFAULT-SA", "GCP-VM-FULL-API-SCOPE"} and not account[
                "email"
            ].endswith("-compute@developer.gserviceaccount.com"):
                continue
            context = account_context(index, account["email"])
            scopes = [s for s in account.get("scopes") or [] if isinstance(s, str)]
            notes.append(describe(context, scopes))
            if context["privilege"] == "PRIVILEGED":
                if rule_id == "GCP-VM-DEFAULT-SA":
                    severity = higher(severity, "HIGH")
                elif rule_id == "GCP-VM-FULL-API-SCOPE" and FULL_SCOPE in scopes:
                    severity = higher(severity, "HIGH" if external else "MEDIUM")
            elif context["privilege"] not in {"NARROW", "NONE_OBSERVED"}:
                unresolved.append(f"Attached service account privileges ({context['reason']})")
    if not notes:
        return verdict
    # The base text says "privileges unresolved"; the context below states them instead.
    base = verdict.reasoning.replace("; privileges unresolved.", ".")
    return Verdict(
        verdict.outcome,
        base + " " + " ".join(sorted(set(notes))[:6]),
        verdict.missing,
        verdict.related,
        verdict.limitations,
        verdict.finding_class,
        severity if RANK[severity] > RANK[BASE[rule_id]] or verdict.severity else None,
        verdict.exposure,
        tuple(dict.fromkeys(verdict.evidence_needed + tuple(unresolved))),
        verdict.compensating,
    )
