"""Instance-role privilege (methodology AWS-19 clauses P4/F3).

F3 is literal: an instance role whose resolved identity policies contain an Allow with
Action "*" or an unguarded iam:PassRole (any role resource, no iam:PassedToService
condition; engineering interpretation MR-H14). The finding class comes from the PassRole
escalation investigation, never from the permission alone: escalation also needs
service-operation permission, a service-trusted privileged target and attacker control
of the instance, which configuration cannot prove.
"""

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.rules.configuration import Rule, Verdict
from offline_analyzer.rules.methodology_links import LINKS

GAAD = "iam:GetAccountAuthorizationDetails"


def instance_role_privilege(obs, context) -> Verdict:
    analysis = context.iam
    role = analysis.inventory.roles.get((obs.account_id, (obs.native_id or "").rsplit("/", 1)[-1]))
    if role is None:
        return Verdict(Outcome.UNKNOWN, "Role identity unresolved.", ("role ARN",))
    if role.instance_profiles is None:
        return Verdict(
            Outcome.UNKNOWN,
            "Instance-profile membership of this role was not collected.",
            ("GetAccountAuthorizationDetails or ListInstanceProfilesForRole for the role",),
        )
    if not role.instance_profiles:
        return Verdict(Outcome.NOT_APPLICABLE, "Role is not in any instance profile.")
    documents, unresolved = analysis.inventory.identity_documents(role)
    wildcard = [
        s.origin
        for d in documents
        for s in d.statements
        if s.effect == "Allow" and s.actions and {"*", "*:*"} & set(s.actions)
    ]
    broad = analysis.broad_passrole(role)
    instances = sorted(
        i.native_id
        for i in analysis.instances
        if role.arn in analysis.inventory.profiles.get(i.configuration["InstanceProfileArn"], ())
    )
    used = (
        f"used by instances {', '.join(instances)}"
        if instances
        else "no collected instance uses it"
    )
    if not wildcard and not broad:
        if unresolved or any(s.unsupported for d in documents for s in d.statements):
            return Verdict(
                Outcome.UNKNOWN,
                "Instance role identity policies are incomplete or contain unsupported "
                "statements; Action:* and unguarded PassRole cannot be excluded.",
                tuple(unresolved) or ("supported policy statements",),
            )
        return Verdict(
            Outcome.PASS,
            f"Instance role ({used}) has no Allow Action:* and no unguarded iam:PassRole "
            "in its resolved identity policies.",
            limitations=("Least privilege beyond these two patterns (P3) is not evaluated",),
        )
    records = [r for r in analysis.passrole() if r.principal == role.arn]
    by_class = {}
    for record in records:
        by_class.setdefault(record.classification, []).append(record)
    observed = []
    if wildcard:
        observed.append(f"Allow Action:* ({', '.join(wildcard)})")
    if broad:
        observed.append(f"unguarded iam:PassRole ({', '.join(broad)})")
    summary = ", ".join(f"{k}={len(v)}" for k, v in sorted(by_class.items())) or "none"
    needed = sorted({m for r in records for m in r.missing})
    preconditions = "control of the instance or its application (SSRF/RCE) not evaluated"
    if "SUPPORTED_ESCALATION_PREREQUISITES" in by_class:
        finding_class, severity = "SUPPORTED_SECURITY_GAP", "HIGH"
        exposure = (
            "PassRole escalation prerequisites supported by evidence (permission, service "
            f"trust, service operation, privileged target); {preconditions}"
        )
    elif wildcard or {"POTENTIAL_ESCALATION", "UNKNOWN_MISSING_EVIDENCE"} & set(by_class):
        finding_class = "POTENTIAL_EXPOSURE"
        severity = "HIGH" if wildcard else "MEDIUM"
        exposure = (
            "Escalation prerequisites incomplete or unresolved; " + preconditions
            if not wildcard
            else "Instance role policy contains Allow Action:*; effective permissions can be "
            "restricted by conditions, boundaries, explicit denies and SCP/RCP. Instance "
            "compromise and effective broad access are not established (" + preconditions + ")"
        )
    else:
        finding_class, severity = "BASELINE_DEVIATION", "LOW"
        exposure = "Every evaluated PassRole combination is blocked or not an escalation"
    return Verdict(
        Outcome.FAIL,
        f"Instance role ({used}) policies contain " + "; ".join(observed) + ".",
        limitations=(f"PassRole investigations: {summary}",),
        finding_class=finding_class,
        severity=severity,
        exposure=exposure,
        evidence_needed=tuple(needed),
        compensating=tuple(sorted({b for r in records for b in r.blocking}))[:10],
    )


IAM_RULES = (
    Rule(
        "R1-IAM-INSTANCE-ROLE-PRIVILEGE",
        "1.0.2",
        "AWS::IAM::Role",
        GAAD,
        "Instance role allows Action:* or unguarded iam:PassRole",
        "Identity and access",
        ("resolved identity policies", "instance-profile membership"),
        instance_role_privilege,
        "Resolved identity policies contain broad Allow statements. The permissions a workload "
        "can actually use depend on conditions, boundaries, explicit denies and SCP/RCP. "
        "Escalation also requires service permissions, target role trust and workload control; "
        "see the separate PassRole investigations for supported and missing prerequisites.",
        "Scope iam:PassRole to specific role ARNs with an iam:PassedToService condition and "
        "replace Action:* with least-privilege actions; recollect configuration.",
        "MEDIUM",
        "Instance-role privilege enabling escalation if the workload is compromised.",
        follow_up=(
            "Confirm whether the instance workload is exposed to SSRF/RCE",
            "Review PassRole investigation records for blocked and missing prerequisites",
            "Approve proposed methodology mapping and business severity context",
        ),
        methodology=LINKS["R1-IAM-INSTANCE-ROLE-PRIVILEGE"],
        scope="GLOBAL",
        family_gated=True,
        contextual=True,
        context_operations=("iam:ListInstanceProfilesForRole", "iam:GetPolicyVersion"),
        finding_class="POTENTIAL_EXPOSURE",
    ),
)
