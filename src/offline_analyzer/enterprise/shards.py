"""Business-group shards when one enterprise snapshot cannot hold every selected import.

A single snapshot is limited to MAX_OBSERVATIONS observations and MAX_MEMBERS imports
(enterprise/snapshot.py, fail closed). When a selection exceeds either cap, `plan` groups the
imports by business group (from the AWS collector manifest, `business_group`; GCP imports
form group "GCP"; imports without a group form "Unassigned") and every group becomes its own
snapshot. A shard set is recorded in `enterprise_shards` so the split is never silent:

* the combined view (`combined`) lists every shard with its counts and the summed totals;
* every report of a shard snapshot carries a SHARDED_ENTERPRISE_ASSESSMENT coverage note
  naming its group and the other groups;
* relationships between groups (cross-account edges, attack paths) are not correlated
  across shards, and every view says so.
"""

import json
from collections import Counter

from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.ingestion.json_input import InputError

UNASSIGNED = "Unassigned"


def group_of(store, run: str) -> str:
    from offline_analyzer.ingestion.collector import stored_summary

    summary = stored_summary(store.workspace, run) or {}
    if summary.get("business_group"):
        return str(summary["business_group"])
    gcp = store.db.execute(
        "SELECT 1 FROM sources WHERE run_id=? AND json_extract_string(data,'$.format')="
        "'gcp-json-v1' LIMIT 1",
        [run],
    ).fetchone()
    return "GCP" if gcp else UNASSIGNED


def observation_counts(store, runs: list[str]) -> dict[str, int]:
    if not runs:
        return {}
    marks = ",".join("?" for _ in runs)
    return dict(
        store.rows(
            f"SELECT run_id, count(*) FROM observations WHERE run_id IN ({marks}) GROUP BY 1",
            runs,
        )
    )


def plan(store, selected: list[str] | None = None, *, force: bool = False) -> dict:
    """Whether the selection fits one snapshot, and the business-group shards otherwise."""
    from offline_analyzer.enterprise.snapshot import MAX_MEMBERS, MAX_OBSERVATIONS, members

    selected = sorted(set(selected if selected is not None else members(store)))
    counts = observation_counts(store, selected)
    total = sum(counts.values())
    fits = total <= MAX_OBSERVATIONS and len(selected) <= MAX_MEMBERS
    groups: dict[str, list[str]] = {}
    for run in selected:
        groups.setdefault(group_of(store, run), []).append(run)
    shards = [
        {
            "group": name,
            "members": runs,
            "observations": sum(counts.get(r, 0) for r in runs),
            "fits": sum(counts.get(r, 0) for r in runs) <= MAX_OBSERVATIONS
            and len(runs) <= MAX_MEMBERS,
        }
        for name, runs in sorted(groups.items())
    ]
    return {
        "members": len(selected),
        "observations": total,
        "limits": {"observations": MAX_OBSERVATIONS, "members": MAX_MEMBERS},
        "single_snapshot_fits": fits,
        "sharded": force or not fits,
        "shards": shards,
    }


def assess_sharded(store, selected: list[str] | None = None, *, force: bool = False) -> dict:
    """One assessed snapshot per business group; returns the recorded shard set."""
    from offline_analyzer.enterprise.snapshot import assess_enterprise

    layout = plan(store, selected, force=force)
    if not layout["sharded"]:
        run = assess_enterprise(store, selected)
        return {"shard_set": None, "runs": [run], "plan": layout}
    too_large = [s["group"] for s in layout["shards"] if not s["fits"]]
    if too_large:
        raise InputError("SHARD_EXCEEDS_SNAPSHOT_LIMIT")
    runs = [(s["group"], assess_enterprise(store, s["members"]), s) for s in layout["shards"]]
    shard_set = stable_id("shard-set", sorted(r for _g, r, _s in runs))
    with store.transaction():
        for group, run, shard in runs:
            store.db.execute(
                "INSERT INTO enterprise_shards VALUES (?,?,?,?) ON CONFLICT DO NOTHING",
                [
                    shard_set,
                    run,
                    group,
                    json.dumps(
                        {
                            "members": shard["members"],
                            "observations": shard["observations"],
                            "groups": [g for g, _r, _s in runs],
                        }
                    ),
                ],
            )
    return {"shard_set": shard_set, "runs": [r for _g, r, _s in runs], "plan": layout}


def shard_of(store, run: str) -> dict | None:
    row = store.db.execute(
        "SELECT shard_set, group_name, data FROM enterprise_shards WHERE run_id=? "
        "ORDER BY shard_set LIMIT 1",
        [run],
    ).fetchone()
    if not row:
        return None
    data = json.loads(row[2])
    return {"shard_set": row[0], "group": row[1], "groups": data["groups"]}


def combined(store, shard_set: str) -> dict:
    """Combined enterprise view of a shard set: per-shard counts and summed totals."""
    rows = store.db.execute(
        "SELECT run_id, group_name, data FROM enterprise_shards WHERE shard_set=? "
        "ORDER BY group_name",
        [shard_set],
    ).fetchall()
    if not rows:
        raise InputError("SHARD_SET_NOT_FOUND")
    from offline_analyzer.findings.exclusions import excluded

    shards, totals = [], Counter()
    for run, group, raw in rows:
        data = json.loads(raw)
        hidden = excluded(store, run)
        severities = Counter(
            sev
            for fid, sev in store.rows(
                "SELECT finding_id, json_extract_string(data,'$.suggested_severity') FROM "
                "findings WHERE run_id=?",
                [run],
            )
            if fid not in hidden
        )
        accounts = store.db.execute(
            "SELECT count(DISTINCT account_id) FROM observations WHERE run_id=? AND "
            "account_id IS NOT NULL",
            [run],
        ).fetchone()[0]
        entry = {
            "group": group,
            "run_id": run,
            "imports": len(data["members"]),
            "accounts": accounts,
            "observations": data["observations"],
            "findings": sum(severities.values()),
            "excluded_findings": len(hidden),
            "severity": dict(sorted(severities.items())),
        }
        shards.append(entry)
        for key in ("imports", "accounts", "observations", "findings", "excluded_findings"):
            totals[key] += entry[key]
        for severity, count in severities.items():
            totals["severity:" + severity] += count
    return {
        "shard_set": shard_set,
        "shards": shards,
        "totals": dict(sorted(totals.items())),
        "cross_group_correlation": "NOT_ASSESSED",
        "notice": (
            f"This enterprise view combines {len(shards)} business-group snapshots because one "
            "snapshot cannot hold every import. Relationships between business groups "
            "(cross-account access, network paths, attack paths) are not correlated across "
            "shards."
        ),
    }


def coverage_note(store, run: str) -> dict | None:
    """Report coverage note for a shard snapshot (Word and Excel)."""
    shard = shard_of(store, run)
    if not shard:
        return None
    others = [g for g in shard["groups"] if g != shard["group"]]
    return {
        "provider": "Enterprise",
        "scope": shard["group"],
        "name": "",
        "code": "SHARDED_ENTERPRISE_ASSESSMENT",
        "reason": (
            f"This edition covers business group {shard['group']}, one of "
            f"{len(shard['groups'])} snapshots of one assessment (other groups: "
            f"{', '.join(others) or 'none'}). Relationships with other business groups are "
            "not correlated in this edition."
        ),
        "datasets": len(shard["groups"]),
    }
