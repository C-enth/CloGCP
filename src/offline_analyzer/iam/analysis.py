"""IAM investigations: privilege levels, cross-account transitions, PassRole prerequisites.

Derived deterministically from a run's observations. Observed relationships (policy
attachments, trusts, instance usage, candidate permissions) are kept separate from
evaluated ones (supported AssumeRole transitions, blocking policies). Work is bounded and
truncation is reported, never silently treated as "no further paths".
"""

import re
from dataclasses import dataclass, field

from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.iam.evaluator import (
    ALLOWED,
    DENIED,
    POTENTIAL,
    UNKNOWN_DECISION,
    Decision,
    Request,
    evaluate_assume,
    evaluate_documents,
    evaluate_identity,
)
from offline_analyzer.iam.model import KINDS, IamInventory
from offline_analyzer.iam.organizations import OrganizationModel
from offline_analyzer.iam.policy import FALSE, TRUE, match_action, match_resource

MAX_TRANSITIONS = 20000
MAX_PASSROLE = 20000
ESCALATION_PROBES = (
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:AttachUserPolicy",
    "iam:CreateAccessKey",
)
# Bounded PassRole service scenarios: (service principal, launch operations, run/access op).
SERVICES = {
    "ec2.amazonaws.com": ("ec2:RunInstances",),
    "lambda.amazonaws.com": ("lambda:CreateFunction", "lambda:InvokeFunction"),
}
ORG_KINDS = (
    "AWS::Organizations::Organization",
    "AWS::Organizations::Membership",
    "AWS::Organizations::Root",
    "AWS::Organizations::OrganizationalUnit",
    "AWS::Organizations::Account",
    "AWS::Organizations::ParentLink",
    "AWS::Organizations::Policy",
    "AWS::Organizations::PolicyTargetList",
    "AWS::Organizations::TargetPolicyList",
)
ARN_ACCOUNT = re.compile(r"^arn:[^:]+:iam::([0-9]{12}):(root|role/.+)$")


@dataclass
class Investigation:
    kind: str  # ASSUME_ROLE | PASS_ROLE
    principal: str
    target: str
    service: str | None
    state: str
    classification: str
    reasoning: str
    supporting: list[str] = field(default_factory=list)
    blocking: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Relationship:
    kind: str
    source: str
    target: str
    basis: str  # OBSERVED | EVALUATED
    detail: str
    evidence: tuple[str, ...] = ()


def load(store, run_id, kinds, partition=None) -> list[Normalized]:
    marks = ",".join("?" for _ in kinds)
    partition_clause = (
        "AND resource_id IS NOT NULL AND json_extract_string(data,'$.partition')=? "
        if partition
        else ""
    )
    return [
        Normalized.model_validate_json(row[0])
        for row in store.rows(
            f"SELECT data FROM observations WHERE run_id=? AND tool='aws' AND kind IN ({marks}) "
            + partition_clause
            + "ORDER BY observation_id",
            [run_id, *kinds, *([partition] if partition else [])],
        )
    ]


class IamAnalysis:
    def __init__(self, store, run_id, sources, registry=None, partition=None):
        self.inventory = IamInventory(load(store, run_id, KINDS, partition))
        self.org = OrganizationModel(load(store, run_id, ORG_KINDS, partition), sources)
        self.instances = [
            o
            for o in load(store, run_id, ("AWS::EC2::Instance",), partition)
            if isinstance(o.configuration.get("InstanceProfileArn"), str)
        ]
        self.registry = registry
        self._privilege: dict[str, tuple[str, list[str]]] = {}
        self._privilege_missing: dict[str, list[str]] = {}
        self._transitions = None
        self._passrole = None
        self.truncated: list[str] = []
        self.truncation: list[dict] = []  # provenance/truncation.py records

    def _budget(self, budget: str, shown: int, total: int, effect: str, basis: str) -> None:
        from offline_analyzer.provenance.truncation import record, text

        entry = record(budget, "run", shown, total, effect, basis, provider="AWS")
        self.truncation.append(entry)
        self.truncated.append(text(entry))

    def identity(self, role, action, resource=None, context=None) -> Decision:
        context = {
            "aws:principalarn": (role.arn,),
            "aws:principalaccount": (role.account,),
            **(context or {}),
        }
        return evaluate_identity(self.inventory, self.org, role, Request(action, resource, context))

    def privilege(self, role) -> tuple[str, list[str]]:
        """ADMIN_EQUIVALENT / ESCALATION_CAPABLE (supported), POTENTIALLY_PRIVILEGED,
        NOT_SHOWN_PRIVILEGED (all probes denied by evidence) or UNRESOLVED."""
        if role.arn in self._privilege:
            return self._privilege[role.arn]
        decisions = {probe: self.identity(role, probe) for probe in ESCALATION_PROBES}
        states = {d.state for d in decisions.values()}
        documents, _ = self.inventory.identity_documents(role)
        wildcard = any(
            s.effect == "Allow"
            and not s.conditions
            and s.actions
            and {"*", "*:*"} & set(s.actions)
            and s.resources == ("*",)
            for d in documents
            for s in d.statements
        )
        notes = [f"{p}: {d.state}" for p, d in decisions.items()]
        self._privilege_missing[role.arn] = sorted(
            {m for d in decisions.values() for m in d.missing}
        )
        if ALLOWED in states:
            level = (
                "ADMIN_EQUIVALENT"
                if wildcard and decisions["iam:AttachRolePolicy"].state == ALLOWED
                else "ESCALATION_CAPABLE"
            )
        elif POTENTIAL in states:
            level = "POTENTIALLY_PRIVILEGED"
        elif states == {DENIED}:
            level = "NOT_SHOWN_PRIVILEGED"
        else:
            level = "UNRESOLVED"
        if level == "POTENTIALLY_PRIVILEGED" and self.identity_admin(role):
            notes.append(
                "Identity policies grant Action:* on Resource:* with no boundary or explicit "
                "deny; administrator-equivalent is not established only because organization "
                "controls (SCP) are not assessed"
            )
        indicated = [a for a in role.attached or () if a.endswith(":policy/AdministratorAccess")]
        if indicated and self.inventory.managed_document(indicated[0]) is None:
            notes.append(
                "AWS-managed AdministratorAccess attached; document not exported "
                "(indicated, not resolved)"
            )
        self._privilege[role.arn] = (level, notes)
        return self._privilege[role.arn]

    def identity_admin(self, role) -> bool:
        """Complete identity policies with an unconditioned Allow Action:* on Resource:*, no
        boundary and no Deny statement: administrator by identity policy, whatever the
        (unassessed) organization controls allow. Such a principal gains nothing by passing
        a role: every SCP that limits it also limits the role it passes."""
        documents, unresolved = self.inventory.identity_documents(role)
        if unresolved or role.boundary_arn:
            return False
        statements = [s for d in documents for s in d.statements]
        if any(d.unsupported for d in documents) or any(s.unsupported for s in statements):
            return False
        if any(s.effect == "Deny" for s in statements):
            return False
        return any(
            s.effect == "Allow"
            and not s.conditions
            and s.actions
            and {"*", "*:*"} & set(s.actions)
            and s.resources == ("*",)
            for s in statements
        )

    def privilege_missing(self, role) -> list[str]:
        self.privilege(role)
        return self._privilege_missing.get(role.arn, [])

    def trusted_accounts(self, role) -> set[str]:
        accounts = set()
        for statement in role.trust.statements if role.trust else ():
            if statement.effect != "Allow" or match_action(statement, "sts:AssumeRole") != TRUE:
                continue
            for value in (statement.principals or {}).get("AWS", ()):
                match = ARN_ACCOUNT.match(value)
                account = value if value.isdigit() else match.group(1) if match else value
                if account != role.account:
                    accounts.add(account)
        return accounts

    def transitions(self) -> list[Investigation]:
        """Cross-account AssumeRole candidates from trust principals to collected roles."""
        if self._transitions is not None:
            return self._transitions
        records = []
        dropped = 0  # candidate (source, target) pairs beyond the budget, counted not evaluated
        by_account: dict[str, list] = {}
        for role in self.inventory.roles.values():
            by_account.setdefault(role.account, []).append(role)
        for target in sorted(self.inventory.roles.values(), key=lambda r: r.arn):
            for account in sorted(self.trusted_accounts(target)):
                sources = (
                    [r for a, roles in by_account.items() if a != target.account for r in roles]
                    if account == "*"
                    else by_account.get(account, [])
                )
                if len(records) >= MAX_TRANSITIONS:
                    dropped += len(sources) or 1
                    continue
                if not sources:
                    records.append(
                        Investigation(
                            "ASSUME_ROLE",
                            f"account {account}",
                            target.arn,
                            None,
                            UNKNOWN_DECISION,
                            "UNKNOWN_MISSING_EVIDENCE",
                            "Trusted account has no collected IAM evidence; source principals and "
                            "their permissions are unknown. Trust alone does not establish access.",
                            missing=[f"IAM evidence for account {account}"],
                        )
                    )
                    continue
                for source in sorted(sources, key=lambda r: r.arn):
                    if len(records) >= MAX_TRANSITIONS:
                        dropped += 1
                        continue
                    decision = evaluate_assume(self.inventory, self.org, source, target)
                    records.append(self._assume_record(source, target, decision))
        if dropped:
            self._budget(
                "AssumeRole investigation budget",
                len(records),
                len(records) + dropped,
                "cross-account (source, target) role pairs beyond the budget were not "
                "evaluated; trust-finding transition counts and the enterprise graph omit them",
                "exact count of candidate pairs; the pairs beyond the budget were not evaluated",
            )
        self._transitions = records
        return records

    @staticmethod
    def _assume_record(source, target, decision: Decision) -> Investigation:
        classification = {
            ALLOWED: "SUPPORTED_TRANSITION",
            DENIED: "BLOCKED",
            POTENTIAL: "POTENTIAL_TRANSITION",
            UNKNOWN_DECISION: "UNKNOWN_MISSING_EVIDENCE",
        }[decision.state]
        reasoning = {
            ALLOWED: "Source identity policies, target trust and applicable organization "
            "policies all allow sts:AssumeRole with the supported request context.",
            DENIED: "Evidence blocks the transition: " + "; ".join(decision.blocking),
            POTENTIAL: "Allowed by the evaluated policies, but required evidence or "
            "request context is missing.",
            UNKNOWN_DECISION: "Authorization cannot be determined from the collected evidence.",
        }[decision.state]
        return Investigation(
            "ASSUME_ROLE",
            source.arn,
            target.arn,
            None,
            decision.state,
            classification,
            reasoning,
            decision.supporting,
            decision.blocking,
            sorted(set(decision.missing)),
            ["Attacker control of the source principal (not evaluated)"] + decision.notes,
        )

    def broad_passrole(self, role) -> list[str]:
        """Allow statements granting iam:PassRole on any role without a service condition."""
        probe = f"arn:{role.partition or 'aws'}:iam::{role.account}:role/zz-any-role-probe"
        documents, _ = self.inventory.identity_documents(role)
        found = []
        for document in documents:
            for statement in document.statements:
                if statement.effect != "Allow" or statement.unsupported:
                    continue
                if match_action(statement, "iam:PassRole") != TRUE:
                    continue
                if match_resource(statement, probe)[0] != TRUE:
                    continue
                if any(c.key.lower() == "iam:passedtoservice" for c in statement.conditions):
                    continue
                found.append(statement.origin)
        return found

    def passrole(self) -> list[Investigation]:
        if self._passrole is not None:
            return self._passrole
        records = []
        roles = sorted(self.inventory.roles.values(), key=lambda r: r.arn)
        trusted = {t.arn: any(self._service_trusted(t, s) for s in SERVICES) for t in roles}

        def remaining(principal, targets) -> int:
            """Service-trusted same-account target roles of `principal` not evaluated."""
            return sum(
                trusted[t.arn]
                for t in targets
                if t.account == principal.account and t.arn != principal.arn
            )

        exhausted, pending, principals_left = False, 0, 0
        for principal in roles:
            documents, unresolved = self.inventory.identity_documents(principal)
            candidate = any(
                match_action(s, "iam:PassRole") == TRUE and s.effect == "Allow"
                for d in documents
                for s in d.statements
            )
            if exhausted:
                if candidate:
                    pending += remaining(principal, roles)
                    principals_left += 1
                continue
            if not candidate:
                if unresolved and not principal.service_linked:
                    records.append(
                        Investigation(
                            "PASS_ROLE",
                            principal.arn,
                            "(any role in account)",
                            None,
                            UNKNOWN_DECISION,
                            "UNKNOWN_MISSING_EVIDENCE",
                            "Identity policies are incomplete; iam:PassRole permissions unknown.",
                            missing=unresolved,
                        )
                    )
                continue
            excluded, unprivileged = [], []
            if principal.service_linked:
                # Platform-managed: only the AWS service can assume the role, so no customer
                # principal controls it (rules/aws_identity.py role class SERVICE_LINKED).
                records.append(
                    Investigation(
                        "PASS_ROLE",
                        principal.arn,
                        "(any role in account)",
                        None,
                        self.identity(principal, "iam:PassRole").state,
                        "NOT_AN_ESCALATION",
                        "Service-linked role: its trust admits only the AWS service, so no "
                        "customer principal can act as it; its iam:PassRole is the service's "
                        "own behaviour, not an attacker-controllable escalation.",
                    )
                )
                continue
            admin = self.privilege(principal)[0] == "ADMIN_EQUIVALENT"
            if admin or self.identity_admin(principal):
                records.append(
                    Investigation(
                        "PASS_ROLE",
                        principal.arn,
                        "(any role in account)",
                        None,
                        self.identity(principal, "iam:PassRole").state,
                        "NOT_AN_ESCALATION",
                        "Principal already holds administrator-equivalent permissions; passing "
                        "a role cannot add privilege."
                        if admin
                        else "Principal's identity policies already grant Action:* on "
                        "Resource:* (no boundary or deny); passing a role cannot add privilege. "
                        "Organization controls (SCP) are not assessed and limit both equally.",
                    )
                )
                continue
            for position, target in enumerate(roles):
                if target.account != principal.account or target.arn == principal.arn:
                    continue
                named = self._names_target(documents, target.arn)
                scope = self.identity(principal, "iam:PassRole", target.arn)
                if scope.state == DENIED and not scope.blocking[0].startswith(
                    ("inline:", "managed:")
                ):
                    # Implicitly outside the principal's PassRole scope: summarized below.
                    if any(self._service_trusted(target, s) for s in SERVICES):
                        excluded.append(target.arn)
                    continue
                if not named and self.privilege(target)[0] == "NOT_SHOWN_PRIVILEGED":
                    if any(self._service_trusted(target, s) for s in SERVICES):
                        unprivileged.append(target.arn)
                    continue
                for service, operations in SERVICES.items():
                    if not self._service_trusted(target, service):
                        if named:
                            records.append(self._incompatible(principal, target, service, named))
                        continue
                    if len(records) >= MAX_PASSROLE:
                        exhausted = True
                        break
                    records.append(self._passrole_record(principal, target, service, operations))
                if exhausted:
                    pending += remaining(principal, roles[position:])
                    principals_left += 1
                    break
            if exhausted:
                continue  # the partly evaluated principal gets no summary records
            if unprivileged:
                records.append(
                    Investigation(
                        "PASS_ROLE",
                        principal.arn,
                        f"{len(unprivileged)} non-privileged roles",
                        None,
                        POTENTIAL,
                        "NOT_AN_ESCALATION",
                        "Passable, but these roles are not shown to hold escalation-capable "
                        "permissions: " + ", ".join(sorted(unprivileged)),
                    )
                )
            if excluded:
                records.append(
                    Investigation(
                        "PASS_ROLE",
                        principal.arn,
                        f"{len(excluded)} other service-trusted roles",
                        None,
                        DENIED,
                        "BLOCKED_COMBINATION",
                        "These roles are outside the principal's iam:PassRole scope: "
                        + ", ".join(sorted(excluded)),
                        blocking=["iam:PassRole statement resources exclude these roles"],
                    )
                )
        if exhausted:
            self._budget(
                "PassRole investigation budget",
                len(records),
                len(records) + pending,
                f"{principals_left} principal(s) with iam:PassRole were not or only partly "
                "evaluated; their AP-06 path records and PassRole investigations are missing",
                "records evaluated plus service-trusted target roles not evaluated (an "
                "estimate: each such role yields up to one record per trusting service)",
            )
        self._passrole = records
        return records

    @staticmethod
    def _names_target(documents, arn) -> list[str]:
        """Allow iam:PassRole statements that name this exact role ARN."""
        return [
            s.origin
            for d in documents
            for s in d.statements
            if s.effect == "Allow"
            and match_action(s, "iam:PassRole") == TRUE
            and arn in (s.resources or ())
        ]

    @staticmethod
    def _incompatible(principal, target, service, named) -> Investigation:
        return Investigation(
            "PASS_ROLE",
            principal.arn,
            target.arn,
            service,
            DENIED,
            "BLOCKED_COMBINATION",
            f"{principal.arn} may pass {target.arn}, but its trust policy does not admit "
            f"{service}; the service cannot assume it.",
            supporting=named,
            blocking=[f"trust of {target.arn} does not admit {service}"],
        )

    @staticmethod
    def _service_trusted(target, service) -> bool:
        """Candidate filter only: any Allow trust statement naming the service principal."""
        return any(
            s.effect == "Allow" and service in (s.principals or {}).get("Service", ())
            for s in (target.trust.statements if target.trust else ())
        )

    def _service_trust(self, target, service) -> Decision:
        def match(statement):
            return TRUE if service in (statement.principals or {}).get("Service", ()) else FALSE

        request = Request("sts:AssumeRole", target.arn, {"aws:principalisawsservice": ("true",)})
        result = evaluate_documents([target.trust], request, match)
        if result["deny_true"]:
            return Decision(DENIED, blocking=result["deny_true"])
        if result["allow_true"] and not result["deny_unknown"]:
            return Decision(ALLOWED, supporting=result["allow_true"])
        if result["allow_true"] or result["allow_unknown"]:
            return Decision(POTENTIAL, supporting=result["allow_true"], missing=result["reasons"])
        if result["allow_unsupported"]:
            return Decision(UNKNOWN_DECISION, missing=result["reasons"])
        return Decision(DENIED, blocking=[f"trust of {target.arn} does not admit {service}"])

    def _passrole_record(self, principal, target, service, operations) -> Investigation:
        components = {
            "iam:PassRole": self.identity(
                principal, "iam:PassRole", target.arn, {"iam:passedtoservice": (service,)}
            ),
            f"trust({service})": self._service_trust(target, service),
            **{op: self.identity(principal, op) for op in operations},
        }
        preconditions = ["Attacker control of the principal (not evaluated)"]
        if service == "ec2.amazonaws.com":
            if target.instance_profiles:
                components["instance profile"] = Decision(
                    ALLOWED, supporting=list(target.instance_profiles)
                )
            elif target.instance_profiles is None:
                components["instance profile"] = Decision(
                    UNKNOWN_DECISION, missing=[f"instance profile membership of {target.arn}"]
                )
            else:
                for op in ("iam:CreateInstanceProfile", "iam:AddRoleToInstanceProfile"):
                    components[op] = self.identity(principal, op)
            preconditions.append("Ability to retrieve role credentials from the launched instance")
        else:
            preconditions.append("Ability to run code in and observe output of the function")
        target_level, target_notes = self.privilege(target)
        principal_level, _ = self.privilege(principal)
        states = {name: d.state for name, d in components.items()}
        supporting = [f"{n}: {s}" for n, d in components.items() for s in d.supporting]
        blocking = [f"{n}: {b}" for n, d in components.items() for b in d.blocking]
        missing = sorted({m for d in components.values() for m in d.missing})
        if DENIED in states.values():
            classification, state = "BLOCKED_COMBINATION", DENIED
        elif principal_level == "ADMIN_EQUIVALENT":
            classification, state = "NOT_AN_ESCALATION", states["iam:PassRole"]
            blocking.append("principal already has administrator-equivalent permissions")
        elif target_level == "NOT_SHOWN_PRIVILEGED":
            classification, state = "NOT_AN_ESCALATION", states["iam:PassRole"]
            blocking.append("target role not shown to hold escalation-capable permissions")
        elif UNKNOWN_DECISION in states.values():
            classification, state = "UNKNOWN_MISSING_EVIDENCE", UNKNOWN_DECISION
        elif set(states.values()) == {ALLOWED} and target_level in {
            "ADMIN_EQUIVALENT",
            "ESCALATION_CAPABLE",
        }:
            classification, state = "SUPPORTED_ESCALATION_PREREQUISITES", ALLOWED
        else:
            classification, state = "POTENTIAL_ESCALATION", POTENTIAL
            if target_level in {"POTENTIALLY_PRIVILEGED", "UNRESOLVED"}:
                missing.append(f"resolved privileges of {target.arn} ({target_level})")
        reasoning = (
            f"{principal.arn} -> pass {target.arn} to {service}: "
            + ", ".join(f"{n}={s}" for n, s in states.items())
            + f"; target privilege {target_level}; principal privilege {principal_level}."
        )
        return Investigation(
            "PASS_ROLE",
            principal.arn,
            target.arn,
            service,
            state,
            classification,
            reasoning,
            supporting,
            blocking,
            missing,
            preconditions + target_notes,
        )

    def relationships(self) -> list[Relationship]:
        found = []
        for role in sorted(self.inventory.roles.values(), key=lambda r: r.arn):
            evidence = role.observations
            for arn in role.attached or ():
                resolved = (
                    "resolved" if self.inventory.managed_document(arn) else "document not collected"
                )
                found.append(
                    Relationship("ROLE_HAS_POLICY", role.arn, arn, "OBSERVED", resolved, evidence)
                )
            for name, document in role.inline.items():
                found.append(
                    Relationship(
                        "ROLE_HAS_POLICY",
                        role.arn,
                        f"inline:{name}",
                        "OBSERVED",
                        "resolved" if document else "document not collected",
                        evidence,
                    )
                )
            if role.boundary_arn:
                found.append(
                    Relationship(
                        "ROLE_HAS_BOUNDARY",
                        role.arn,
                        role.boundary_arn,
                        "OBSERVED",
                        "resolved"
                        if self.inventory.managed_document(role.boundary_arn)
                        else "document not collected",
                        evidence,
                    )
                )
            for statement in role.trust.statements if role.trust else ():
                for kind, values in (statement.principals or {}).items():
                    for value in values:
                        detail = f"{statement.effect} {kind}; conditions: " + (
                            ", ".join(f"{c.operator}:{c.key}" for c in statement.conditions)
                            or "none"
                        )
                        found.append(
                            Relationship(
                                "ROLE_TRUSTS_PRINCIPAL",
                                role.arn,
                                value,
                                "OBSERVED",
                                detail,
                                evidence,
                            )
                        )
            documents, _ = self.inventory.identity_documents(role)
            for document in documents:
                for statement in document.statements:
                    if statement.effect != "Allow":
                        continue
                    for action in ("iam:PassRole", "sts:AssumeRole", "*"):
                        if action != "*" and match_action(statement, action) != TRUE:
                            continue
                        if action == "*" and not {"*", "*:*"} & set(statement.actions or ()):
                            continue
                        found.append(
                            Relationship(
                                "ROLE_PERMITS_ACTION_CANDIDATE",
                                role.arn,
                                action,
                                "OBSERVED",
                                f"statement {statement.origin} (not an authorization decision)",
                                evidence,
                            )
                        )
                        break
        for instance in self.instances:
            profile = instance.configuration["InstanceProfileArn"]
            for role_arn in self.inventory.profiles.get(profile, ()):
                found.append(
                    Relationship(
                        "INSTANCE_USES_ROLE",
                        instance.native_id,
                        role_arn,
                        "OBSERVED",
                        f"via {profile}",
                        (instance.observation_id,),
                    )
                )
        for record in self.transitions():
            if record.state == ALLOWED:
                found.append(
                    Relationship(
                        "PRINCIPAL_CAN_ASSUME_ROLE_SUPPORTED",
                        record.principal,
                        record.target,
                        "EVALUATED",
                        "; ".join(record.supporting),
                    )
                )
            for blocker in record.blocking:
                found.append(
                    Relationship(
                        "POLICY_BLOCKS_ACTION",
                        blocker,
                        f"sts:AssumeRole {record.target}",
                        "EVALUATED",
                        f"for {record.principal}",
                    )
                )
        for record in self.passrole():
            if record.classification == "BLOCKED_COMBINATION":
                for blocker in record.blocking:
                    found.append(
                        Relationship(
                            "POLICY_BLOCKS_ACTION",
                            blocker,
                            f"iam:PassRole {record.target}",
                            "EVALUATED",
                            f"for {record.principal} to {record.service}",
                        )
                    )
        return found

    def evidence_gaps(self) -> list[tuple[str, str, str]]:
        gaps = set()
        for role in self.inventory.roles.values():
            _, missing = self.inventory.identity_documents(role)
            for item in missing:
                gaps.add(("IAM policy evidence", role.arn, item))
            if role.boundary_arn and not self.inventory.managed_document(role.boundary_arn):
                gaps.add(("Permissions boundary", role.arn, role.boundary_arn))
            layer = self.org.applicability(
                role.account, "SERVICE_CONTROL_POLICY", role.service_linked
            )
            if layer == "NOT_COLLECTED":
                gaps.add(("SCP evidence", role.account, "Organizations/SCP exports not supplied"))
        for item in self.truncated:
            gaps.add(("Analysis budget", "run", item))
        return sorted(gaps)
