"""Organizations hierarchy and SCP/RCP applicability from approved exports.

Never infers that SCPs are absent: no Organizations evidence gives NOT_COLLECTED, and
incomplete attachment listings give UNKNOWN for that level. Management-account
principals, service-linked roles, disabled policy types and accounts proven outside an
organization are NOT_APPLICABLE. Hierarchy edges come only from parent references in
the evidence.
"""

from dataclasses import dataclass, field

from offline_analyzer.iam.policy import FALSE, TRUE, UNKNOWN, parse_policy

SCP, RCP = "SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"
NOT_COLLECTED, NOT_APPLICABLE = "NOT_COLLECTED", "NOT_APPLICABLE"


@dataclass
class PolicyLayer:
    """Result of evaluating one policy type along an account's hierarchy path."""

    state: str  # TRUE (allows), FALSE (blocks), UNKNOWN, NOT_COLLECTED, NOT_APPLICABLE
    blocking: list[str] = field(default_factory=list)
    supporting: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    reason: str = ""


class OrganizationModel:
    def __init__(self, observations, sources):
        self.organizations, self.outside = {}, set()
        self.roots, self.parents, self.policies = {}, {}, {}
        self.policy_targets, self.target_policies = {}, {}
        self.evidence = False
        self.listed_policy_types = {
            (s.get("request_parameters") or {}).get("Filter")
            for s in sources
            if s["operation"] == "organizations:ListPolicies"
            and s["effective_coverage"] == "COMPLETE"
        }
        for obs in observations:
            kind, config, native = obs.resource_type, obs.configuration, obs.native_id
            if not (kind or "").startswith("AWS::Organizations::") or not native:
                continue
            self.evidence = True
            if kind == "AWS::Organizations::Organization":
                self.organizations[native] = config
            elif (
                kind == "AWS::Organizations::Membership" and config.get("in_organization") is False
            ):
                self.outside.add(native)
            elif kind == "AWS::Organizations::Root":
                self.roots[native] = config.get("PolicyTypes")
            elif kind in {"AWS::Organizations::OrganizationalUnit", "AWS::Organizations::Account"}:
                if config.get("ParentId"):
                    self.parents.setdefault(native, set()).add(config["ParentId"])
            elif kind == "AWS::Organizations::ParentLink" and config.get("ParentId"):
                self.parents.setdefault(native, set()).add(config["ParentId"])
            elif kind == "AWS::Organizations::Policy":
                merged = self.policies.setdefault(native, {})
                merged.update({k: v for k, v in config.items() if v is not None})
            elif kind == "AWS::Organizations::PolicyTargetList":
                self.policy_targets.setdefault(native, []).append(config)
            elif kind == "AWS::Organizations::TargetPolicyList":
                target = native.split("#", 1)[0]
                self.target_policies.setdefault((target, config.get("Filter")), []).append(config)

    @property
    def management_accounts(self) -> set[str]:
        return {
            o.get("MasterAccountId")
            for o in self.organizations.values()
            if o.get("MasterAccountId")
        }

    @property
    def organization_id(self) -> str | None:
        return next(iter(self.organizations)) if len(self.organizations) == 1 else None

    def path(self, account: str) -> tuple[list[str] | None, str]:
        """Root -> OUs -> account from evidenced parent edges only."""
        nodes, current = [account], account
        for _ in range(16):
            parents = self.parents.get(current)
            if not parents:
                return None, f"parent of {current} not collected"
            if len(parents) > 1:
                return None, f"conflicting parents for {current}"
            current = next(iter(parents))
            nodes.append(current)
            if current.startswith("r-"):
                return list(reversed(nodes)), ""
        return None, "hierarchy depth limit exceeded"

    def attached(self, node: str, policy_type: str) -> tuple[list[str] | None, str]:
        listings = self.target_policies.get((node, policy_type), [])
        if listings:
            if any(entry.get("Truncated") for entry in listings):
                return None, f"{policy_type} attachments for {node} truncated"
            ids = {
                tuple(sorted(i for i in entry.get("PolicyIds") or [] if i)) for entry in listings
            }
            if len(ids) != 1:
                return None, f"{policy_type} attachments for {node} conflict"
            return list(next(iter(ids))), ""
        if policy_type not in self.listed_policy_types:
            return None, f"{policy_type} attachments for {node} not collected"
        typed = [p for p, c in self.policies.items() if c.get("Type") == policy_type]
        found = []
        for policy in typed:
            lists = self.policy_targets.get(policy, [])
            if not lists or any(entry.get("Truncated") for entry in lists):
                return None, f"targets of {policy} not collected"
            if any(node in (entry.get("TargetIds") or []) for entry in lists):
                found.append(policy)
        return found, ""

    def applicability(self, account: str, policy_type: str, service_linked: bool) -> str | None:
        if not self.evidence:
            return NOT_COLLECTED
        if account in self.outside:
            return NOT_APPLICABLE
        if account in self.management_accounts:
            return NOT_APPLICABLE
        if service_linked and policy_type == SCP:
            return NOT_APPLICABLE
        return None

    def evaluate(
        self, account, policy_type, request, evaluate_documents, service_linked=False
    ) -> PolicyLayer:
        """Every hierarchy level must allow; any applicable deny blocks."""
        exempt = self.applicability(account, policy_type, service_linked)
        if exempt == NOT_COLLECTED:
            return PolicyLayer(
                NOT_COLLECTED, missing=[f"{policy_type} evidence for account {account}"]
            )
        if exempt == NOT_APPLICABLE:
            return PolicyLayer(
                NOT_APPLICABLE, reason=f"{policy_type} not applicable to this principal/account"
            )
        nodes, why = self.path(account)
        if nodes is None:
            return PolicyLayer(UNKNOWN, missing=[f"organization hierarchy: {why}"])
        types = self.roots.get(nodes[0])
        if not isinstance(types, list):
            return PolicyLayer(UNKNOWN, missing=[f"policy types enabled on {nodes[0]}"])
        if not any(
            t.get("Type") == policy_type and t.get("Status") == "ENABLED"
            for t in types
            if isinstance(t, dict)
        ):
            return PolicyLayer(NOT_APPLICABLE, reason=f"{policy_type} not enabled on {nodes[0]}")
        layer = PolicyLayer(TRUE)
        for node in nodes:
            ids, why = self.attached(node, policy_type)
            if ids is None:
                layer.state, layer.missing = UNKNOWN, layer.missing + [why]
                continue
            documents = []
            for policy_id in ids:
                content = self.policies.get(policy_id, {}).get("Content")
                document = (
                    parse_policy(content, f"{policy_type}:{policy_id}@{node}") if content else None
                )
                if document is None:
                    layer.state = UNKNOWN
                    layer.missing.append(f"content of {policy_id}")
                else:
                    documents.append(document)
            result = evaluate_documents(documents, request)
            if result["deny_true"]:
                return PolicyLayer(FALSE, blocking=result["deny_true"], missing=layer.missing)
            if result["allow_true"]:
                layer.supporting += result["allow_true"]
            elif (
                result["allow_unknown"]
                or result["allow_unsupported"]
                or result["deny_unknown"]
                or layer.state == UNKNOWN
            ):
                layer.state = UNKNOWN
                layer.missing += result["reasons"]
            elif ids is not None and len(documents) == len(ids):
                return PolicyLayer(
                    FALSE, blocking=[f"no {policy_type} at {node} allows the action"]
                )
            if result["deny_unknown"]:
                layer.state = UNKNOWN
        return layer
