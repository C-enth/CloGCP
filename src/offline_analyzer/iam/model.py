"""Canonical IAM inventory assembled from every supported IAM source in a run.

A role may be described by GetAccountAuthorizationDetails, ListRoles/GetRole and per-role
listing calls. Facts are merged per (account, role name); disagreeing sources, truncated
listings or missing documents leave that fact unknown (None) with a recorded reason.
An attachment reference is never treated as a resolved policy document.
"""

import json
from dataclasses import dataclass, field

from offline_analyzer.iam.policy import PolicyDocument, parse_policy

ROLE = "AWS::IAM::Role"
KINDS = (
    ROLE,
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::ManagedPolicyVersion",
    "AWS::IAM::InstanceProfile",
    "AWS::IAM::RoleAttachmentList",
    "AWS::IAM::RoleInlinePolicyList",
    "AWS::IAM::RoleInlinePolicy",
    "AWS::IAM::RoleInstanceProfileList",
)


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def merge(values: list, label: str, reasons: list):
    """Single agreed value, or None with a reason when absent or conflicting."""
    distinct = {canonical(v): v for v in values if v is not None}
    if len(distinct) == 1:
        return next(iter(distinct.values()))
    reasons.append(f"{label} {'conflicting across sources' if distinct else 'not collected'}")
    return None


@dataclass
class Role:
    arn: str
    account: str
    name: str
    partition: str | None
    trust_raw: dict | None
    trust: PolicyDocument | None
    boundary_arn: str | None
    attached: tuple[str, ...] | None
    inline_names: tuple[str, ...] | None
    inline: dict[str, PolicyDocument | None]
    instance_profiles: tuple[str, ...] | None
    observations: tuple[str, ...]
    reasons: list[str] = field(default_factory=list)

    @property
    def service_linked(self) -> bool:
        return ":role/aws-service-role/" in self.arn


@dataclass
class ManagedPolicy:
    arn: str
    default_version: str | None
    document: PolicyDocument | None
    reason: str | None
    observations: tuple[str, ...]


class IamInventory:
    def __init__(self, observations):
        by_kind: dict[str, list] = {kind: [] for kind in KINDS}
        for obs in observations:
            if obs.resource_type in by_kind:
                by_kind[obs.resource_type].append(obs)
        self.policies = self._policies(by_kind)
        self.profiles: dict[str, tuple[str, ...]] = {}
        for obs in by_kind["AWS::IAM::InstanceProfile"]:
            arns = obs.configuration.get("RoleArns")
            if obs.native_id and isinstance(arns, list):
                self.profiles[obs.native_id] = tuple(a for a in arns if isinstance(a, str))
        self.roles = self._roles(by_kind)
        self.by_arn = {role.arn: role for role in self.roles.values()}
        for role in self.roles.values():  # membership from authorization details/listings
            for profile in role.instance_profiles or ():
                members = set(self.profiles.get(profile, ())) | {role.arn}
                self.profiles[profile] = tuple(sorted(members))

    def _policies(self, by_kind) -> dict[str, ManagedPolicy]:
        grouped: dict[str, list] = {}
        for obs in by_kind["AWS::IAM::ManagedPolicy"]:
            grouped.setdefault(obs.native_id, []).append(obs)
        versions: dict[str, list] = {}
        for obs in by_kind["AWS::IAM::ManagedPolicyVersion"]:
            arn = obs.configuration.get("PolicyArn")
            versions.setdefault(arn, []).append(obs)
            grouped.setdefault(arn, [])
        policies = {}
        for arn, items in grouped.items():
            if not isinstance(arn, str):
                continue
            reasons: list[str] = []
            default = merge(
                [o.configuration.get("DefaultVersionId") for o in items], "default version", []
            )
            candidates = [
                (o.configuration.get("DefaultVersionId"), o.configuration.get("DefaultDocument"))
                for o in items
                if o.configuration.get("DefaultDocument") is not None
            ]
            for obs in versions.get(arn, []):
                config = obs.configuration
                if config.get("Document") is None:
                    continue
                if (default and config.get("VersionId") == default) or (
                    not default and config.get("IsDefaultVersion") is True
                ):
                    candidates.append((config.get("VersionId"), config.get("Document")))
            raw = merge([doc for _, doc in candidates], "default policy document", reasons)
            policies[arn] = ManagedPolicy(
                arn=arn,
                default_version=default or (candidates[0][0] if raw is not None else None),
                document=parse_policy(raw, f"managed:{arn}") if raw is not None else None,
                reason=reasons[0] if raw is None else None,
                observations=tuple(o.observation_id for o in items + versions.get(arn, [])),
            )
        return policies

    def _roles(self, by_kind) -> dict[tuple[str, str], Role]:
        grouped: dict[tuple[str, str], list] = {}
        for obs in by_kind[ROLE]:
            if obs.native_id and obs.account_id:
                grouped.setdefault((obs.account_id, obs.native_id.rsplit("/", 1)[-1]), []).append(
                    obs
                )
        fragments: dict[tuple[str, str, str], list] = {}
        for kind in (
            "AWS::IAM::RoleAttachmentList",
            "AWS::IAM::RoleInlinePolicyList",
            "AWS::IAM::RoleInstanceProfileList",
            "AWS::IAM::RoleInlinePolicy",
        ):
            for obs in by_kind[kind]:
                name = (obs.native_id or "").split("/", 1)[0]
                fragments.setdefault((kind, obs.account_id, name), []).append(obs)
        roles = {}
        for (account, name), items in grouped.items():
            reasons: list[str] = []
            arn = merge([o.native_id for o in items], "role ARN", reasons)
            if arn is None:
                continue
            trust_raw = merge(
                [o.configuration.get("AssumeRolePolicyDocument") for o in items],
                "trust policy",
                reasons,
            )
            boundary = merge(
                [
                    o.configuration.get("PermissionsBoundaryArn")
                    for o in items
                    if o.configuration.get("PermissionsEvidence") or o.operation == "iam:GetRole"
                ],
                "permissions boundary",
                [],
            )
            attached = self._listing(
                [
                    o.configuration.get("AttachedPolicyArns")
                    for o in items
                    if o.configuration.get("PermissionsEvidence")
                ],
                fragments.get(("AWS::IAM::RoleAttachmentList", account, name), []),
                "PolicyArns",
                "attached policies",
                reasons,
            )
            inline_names = self._listing(
                [
                    o.configuration.get("InlinePolicyNames")
                    for o in items
                    if o.configuration.get("PermissionsEvidence")
                ],
                fragments.get(("AWS::IAM::RoleInlinePolicyList", account, name), []),
                "PolicyNames",
                "inline policy names",
                reasons,
            )
            profiles = self._listing(
                [
                    o.configuration.get("InstanceProfileArns")
                    for o in items
                    if o.configuration.get("PermissionsEvidence")
                ],
                fragments.get(("AWS::IAM::RoleInstanceProfileList", account, name), []),
                "ProfileArns",
                "instance profiles",
                [],
            )
            inline = {}
            documents: dict[str, list] = {}
            for obs in items:
                config = obs.configuration
                if config.get("PermissionsEvidence") and isinstance(
                    config.get("InlinePolicyNames"), list
                ):
                    for key, doc in zip(
                        config["InlinePolicyNames"],
                        config.get("InlinePolicies") or [],
                        strict=False,
                    ):
                        documents.setdefault(key, []).append(doc)
            for obs in fragments.get(("AWS::IAM::RoleInlinePolicy", account, name), []):
                documents.setdefault(obs.configuration.get("PolicyName"), []).append(
                    obs.configuration.get("Document")
                )
            for policy_name in inline_names or ():
                doc_reasons: list[str] = []
                raw = merge(
                    documents.get(policy_name, []), f"inline policy {policy_name}", doc_reasons
                )
                inline[policy_name] = (
                    parse_policy(raw, f"inline:{arn}/{policy_name}") if raw else None
                )
            if profiles is None:
                derived = tuple(p for p, roles in self.profiles.items() if arn in roles)
                profiles = derived or None  # profile objects alone cannot prove "none"
            frag_ids = [
                o.observation_id
                for key, obs_list in fragments.items()
                if key[1:] == (account, name)
                for o in obs_list
            ]
            roles[(account, name)] = Role(
                arn=arn,
                account=account,
                name=name,
                partition=items[0].partition,
                trust_raw=trust_raw if isinstance(trust_raw, dict) else None,
                trust=parse_policy(trust_raw, f"trust:{arn}")
                if isinstance(trust_raw, dict)
                else None,
                boundary_arn=boundary,
                attached=attached,
                inline_names=inline_names,
                inline=inline,
                instance_profiles=profiles,
                observations=tuple(sorted({o.observation_id for o in items} | set(frag_ids))),
                reasons=reasons,
            )
        return roles

    @staticmethod
    def _listing(embedded, fragments, key, label, reasons):
        """Complete list from authorization details and/or non-truncated per-role calls."""
        values = [tuple(v) for v in embedded if isinstance(v, list)]
        for obs in fragments:
            listed = obs.configuration.get(key)
            if obs.configuration.get("Truncated") or not isinstance(listed, list):
                reasons.append(f"{label} listing truncated or unreadable")
                return None
            values.append(tuple(listed))
        merged = merge([tuple(sorted(v)) for v in values], label, reasons)
        return merged

    def identity_documents(self, role: Role) -> tuple[list[PolicyDocument], list[str]]:
        """Resolved identity policies plus reasons the set may be incomplete."""
        documents, missing = [], [f"{role.arn}: {reason}" for reason in role.reasons]
        if role.attached is None:
            missing.append(f"attached managed policies for {role.arn}")
        for arn in role.attached or ():
            policy = self.policies.get(arn)
            if policy and policy.document:
                documents.append(policy.document)
            else:
                missing.append(f"managed policy document {arn}")
        if role.inline_names is None:
            missing.append(f"inline policies for {role.arn}")
        for name, document in role.inline.items():
            if document:
                documents.append(document)
            else:
                missing.append(f"inline policy document {role.arn}/{name}")
        return documents, sorted(set(missing))

    def managed_document(self, arn: str) -> PolicyDocument | None:
        policy = self.policies.get(arn)
        return policy.document if policy else None
