"""Root-cause groups of findings (owner brief 2a). The key per rule is declared in
`rules/registry.py:GROUP_KEYS`; the group ID depends only on that key, so a group is the same
in every run and snapshot. Grouping is a view: finding IDs, evaluations and decisions are
unchanged, and bulk actions on a group act on its member findings (at most MAX_BULK)."""

import re
from collections import Counter

from offline_analyzer.contracts.r0 import Candidate, stable_id

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
# AWS resource-keyed rules whose native IDs are not account-qualified.
ACCOUNT_QUALIFIED = frozenset({"R1-EC2-SG-SENSITIVE-INGRESS", "SEC-EC2-SG-LATENT-EXPOSURE"})
ORG_NODE = re.compile(r"(?:^|/)((?:organizations|folders)/\d+)(?:$|/)")


def group_key(finding: Candidate) -> tuple[str, str, str]:
    """(rule ID, key kind, key value) for a finding."""
    from offline_analyzer.findings.exclusions import principals
    from offline_analyzer.rules.registry import GROUP_KEYS

    kind = GROUP_KEYS.get(finding.rule_id, "rule")
    value = ""
    if kind == "principal":
        value = ", ".join(principals(finding))
        if not value and finding.rule_id.startswith("R1-IAM-"):
            value = finding.native_id  # the IAM role itself
    elif kind == "resource":
        value = finding.native_id or ""
        if value and finding.rule_id in ACCOUNT_QUALIFIED:
            # Security-group IDs are only Region-unique: qualify by account and Region so the
            # same ID in two accounts never forms one group.
            value = f"{finding.account_id or 'account?'}/{finding.region or 'region?'}/{value}"
    elif kind == "org_node":
        match = ORG_NODE.search(finding.native_id or "")
        value = match[1] if match else ""
    if not value:
        kind = "rule"
    return finding.rule_id, kind, value


def group_id(finding: Candidate) -> str:
    return stable_id("finding-group", list(group_key(finding)))


def highest(severities) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, -1), default="INFO")


def groups(store, run: str) -> list[dict]:
    """Groups of the run's findings; excluded findings are counted, never members."""
    from offline_analyzer.findings.exclusions import excluded
    from offline_analyzer.findings.sre import latest_sre, review_state

    hidden = excluded(store, run)
    decisions, sre = store.latest_decisions(run), latest_sre(store, run)
    found: dict[str, dict] = {}
    for finding in store.candidates(run):
        rule, kind, value = group_key(finding)
        entry = found.setdefault(
            stable_id("finding-group", [rule, kind, value]),
            {
                "group_id": stable_id("finding-group", [rule, kind, value]),
                "rule_id": rule,
                "title": finding.title,
                "key_kind": kind,
                "key": value or rule,
                "members": [],
                "excluded": 0,
                "resources": set(),
                "scopes": set(),
                "severities": [],
                "stages": Counter(),
            },
        )
        if finding.finding_id in hidden:
            entry["excluded"] += 1
            continue
        _status, stage = review_state(store, finding, decisions, sre)
        entry["members"].append(finding.finding_id)
        entry["resources"].add(finding.native_id)
        entry["scopes"].add(finding.project_id or finding.account_id)
        entry["severities"].append(finding.suggested_severity)
        entry["stages"][stage] += 1
    result = []
    for entry in found.values():
        if not entry["members"]:
            continue
        result.append(
            {
                **{k: entry[k] for k in ("group_id", "rule_id", "title", "key_kind", "key")},
                "members": sorted(entry["members"]),
                "member_count": len(entry["members"]),
                "excluded_members": entry["excluded"],
                "affected_resources": len(entry["resources"]),
                "affected_scopes": len(entry["scopes"]),
                "severity": highest(entry["severities"]),
                "status_mix": dict(sorted(entry["stages"].items())),
            }
        )
    result.sort(
        key=lambda g: (-SEVERITY_ORDER.get(g["severity"], -1), -g["member_count"], g["title"])
    )
    return result
