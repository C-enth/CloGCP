"""Persisted enterprise projections, bounded graph selection and evidence-bound review."""

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import UTC, datetime

from offline_analyzer.contracts.r0 import Decision, stable_id
from offline_analyzer.enterprise.snapshot import members, superseded_imports
from offline_analyzer.findings.exclusions import excluded_ids
from offline_analyzer.ingestion.json_input import SECRET_VALUE, InputError
from offline_analyzer.inventory.accounts import workspace_registry

# Configuration references (containment, attachment, trust text). They are evidence of
# structure, not authorization or exposure; reported separately so totals do not mislead.
STRUCTURAL_KINDS = frozenset(
    {
        "RESOURCE_IN_VPC",
        "INSTANCE_USES_ROLE",
        "INSTANCE_USES_PROFILE",
        "ROLE_HAS_POLICY",
        "ROLE_HAS_BOUNDARY",
        "TRUST_POLICY_ALLOW_REFERENCE",
    }
)
# An issue whose linked findings are all excluded (any reason) is not counted or listed.
VISIBLE_ISSUE = (
    "(coalesce(json_array_length(json_extract(data,'$.finding_ids')),0)=0 OR EXISTS "
    "(SELECT 1 FROM json_each(data,'$.finding_ids') j "
    "WHERE json_extract_string(j.value,'$') NOT IN (SELECT unnest(?))))"
)
# Evidence older than the snapshot's newest collection by more than this is flagged stale.
STALE_AFTER_DAYS = 7


def parse_time(value: str):
    from datetime import UTC, datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def scope_collections(store, run: str) -> list[dict]:
    """Collection times per scope: AWS account or GCP project ID (labels as before)."""
    from offline_analyzer.enterprise.refresh import scope_key

    times: dict[str, list[str]] = defaultdict(list)
    for source in store.source_data(run):
        key = (scope_key(source) or "").split(":", 1)[-1]
        if key and source.get("collected_at"):
            times[key].append(source["collected_at"])
    return [{"account": key, "collected_at": value} for key, value in sorted(times.items())]


def collection_window(accounts: list[dict]) -> dict:
    """Spread of collection times across accounts; relative, so results are reproducible."""
    latest = {
        a["account"]: max(parse_time(t) for t in a["collected_at"])
        for a in accounts
        if a["collected_at"]
    }
    if not latest:
        return {"earliest": None, "latest": None, "spread_hours": None, "stale_accounts": []}
    newest, oldest = max(latest.values()), min(latest.values())
    stale = sorted(
        account
        for account, when in latest.items()
        if (newest - when).total_seconds() > STALE_AFTER_DAYS * 86400
    )
    return {
        "earliest": oldest.isoformat(),
        "latest": newest.isoformat(),
        "spread_hours": round((newest - oldest).total_seconds() / 3600, 2),
        "stale_after_days": STALE_AFTER_DAYS,
        "stale_accounts": stale,
    }


class EnterpriseViews:
    def accounts(self, store, run: str) -> list[dict]:
        store.require_run(run)
        registry = workspace_registry(store.workspace)
        sources = defaultdict(list)
        for s in store.source_data(run):
            if s["account_id"]:
                sources[s["account_id"]].append(s)
        counts = dict(
            store.rows(
                (
                    "SELECT account_id,count(DISTINCT resource_id) FROM "
                    "observations WHERE run_id=? AND account_id IS NOT NULL GROUP BY account_id"
                ),
                [run],
            )
        )
        findings = defaultdict(Counter)
        for account, severity, n in store.rows(
            (
                "SELECT account_id,"
                "json_extract_string(f.data,'$.suggested_severity'),count(*) FROM "
                "findings f JOIN finding_resources r USING(run_id,finding_id) "
                "WHERE run_id=? GROUP BY ALL"
            ),
            [run],
        ):
            findings[account][severity] = n
        referenced = {
            a
            for row in store.rows(
                "SELECT source_account,destination_account FROM enterprise_edges WHERE run_id=?",
                [run],
            )
            for a in row
            if a
        }
        ids = set(sources) | set(counts) | referenced | set(registry.in_scope if registry else ())
        hierarchy = defaultdict(set)
        for (data,) in store.rows(
            (
                "SELECT data FROM enterprise_edges WHERE "
                "run_id=? AND kind='ORGANIZATION_PARENT_REFERENCE'"
            ),
            [run],
        ):
            e = json.loads(data)
            hierarchy[e["source"]].add(e["destination"])
        assessed_accounts = {
            a
            for (a,) in store.rows(
                "SELECT DISTINCT json_extract_string(data,'$.account_id') "
                "FROM evaluations WHERE run_id=?",
                [run],
            )
            if a
        }
        result = []
        for account in sorted(ids):
            entry = registry.accounts.get(account) if registry else None
            groups = set(entry.groups if entry else ())
            node, seen = account, set()
            for _ in range(16):
                parents = hierarchy.get(node, set())
                if len(parents) != 1 or node in seen:
                    break
                seen.add(node)
                node = next(iter(parents))
                groups.add(node)
            collected = sources.get(account, [])
            result.append(
                {
                    "account": account,
                    "alias": entry.alias if entry else None,
                    "groups": sorted(groups),
                    "resources": counts.get(account, 0),
                    "severity": dict(findings[account]),
                    "findings": sum(findings[account].values()),
                    "sources": len(collected),
                    "regions": sorted({s["region"] for s in collected if s["region"]}),
                    "coverage": sorted({s["effective_coverage"] for s in collected})
                    or ["NOT_COLLECTED"],
                    "collected_at": sorted({s["collected_at"] for s in collected}),
                    "represented": bool(collected or counts.get(account)),
                    "assessed": account in assessed_accounts,
                    "identity_basis": "APPROVED_REGISTRY"
                    if entry
                    else "COLLECTED_EVIDENCE"
                    if collected or counts.get(account)
                    else "REFERENCED_ONLY",
                    "registry": entry.tracker_key if entry else None,
                    "outside_registry": not bool(entry) if registry else None,
                }
            )
        return result

    def dashboard(self, store, run: str) -> dict:
        accounts = self.accounts(store, run)
        states = dict(
            store.rows(
                "SELECT status,count(*) FROM enterprise_edges WHERE run_id=? GROUP BY status", [run]
            )
        )
        cross = store.db.execute(
            (
                "SELECT count(*) FROM enterprise_edges WHERE "
                "run_id=? AND source_account<>destination_account"
            ),
            [run],
        ).fetchone()[0]
        issues = store.db.execute(
            "SELECT count(*) FROM enterprise_issues WHERE run_id=? AND " + VISIBLE_ISSUE,
            [run, excluded_ids(store, run)],
        ).fetchone()[0]
        snapshot = store.db.execute(
            "SELECT members FROM enterprise_snapshots WHERE run_id=?", [run]
        ).fetchone()
        selected = json.loads(snapshot[0]) if snapshot else [run]
        sources = list(store.source_data(run))
        projection = store.db.execute(
            "SELECT data FROM enterprise_projection WHERE run_id=?", [run]
        ).fetchone()
        kinds = dict(
            store.rows(
                "SELECT kind,count(*) FROM enterprise_edges WHERE run_id=? GROUP BY kind", [run]
            )
        )
        structural = sum(n for k, n in kinds.items() if k in STRUCTURAL_KINDS)
        return {
            "relationship_categories": {
                "structural_configuration_references": structural,
                "authorization_or_exposure": sum(kinds.values()) - structural,
            },
            "collection_window": collection_window(scope_collections(store, run)),
            "projection": json.loads(projection[0])
            if projection
            else {"truncation": [], "not_correlated": True},
            "represented_accounts": sum(a["represented"] for a in accounts),
            "assessed_accounts": sum(a["assessed"] for a in accounts),
            "referenced_accounts": sum(not a["represented"] for a in accounts),
            "missing_registry_accounts": sum(
                a["identity_basis"] == "APPROVED_REGISTRY" and not a["represented"]
                for a in accounts
            ),
            "relationships": sum(states.values()),
            "cross_account_relationships": cross,
            "relationship_status": states,
            "systemic_investigations": issues,
            "collections": dict(Counter(s["effective_coverage"] for s in sources)),
            "member_runs": selected,
            "available_imports": members(store),
            "additional_imports": sorted(set(members(store)) - set(selected)),
            # Older imports of a scope: not included by default, selectable explicitly.
            "superseded_imports": superseded_imports(store),
            "groups": sorted({g for a in accounts for g in a["groups"]}),
            "repeated_control_observations": [
                {
                    "rule_id": r,
                    "distinct_accounts": a,
                    "independent_resources": n,
                    "qualification": "Repeated control failures; no shared root inferred",
                }
                for r, a, n in store.rows(
                    "SELECT json_extract_string(data,'$.rule_id'),count(DISTINCT "
                    "json_extract_string(data,'$.account_id')),count(*) FROM findings "
                    "WHERE run_id=? AND finding_id NOT IN (SELECT unnest(?)) "
                    "GROUP BY 1 HAVING count(DISTINCT "
                    "json_extract_string(data,'$.account_id'))>1",
                    [run, excluded_ids(store, run)],
                )
            ],
            "high_risk_groups": dict(
                Counter(
                    g
                    for a in accounts
                    if a["severity"].get("HIGH") or a["severity"].get("CRITICAL")
                    for g in a["groups"]
                )
            ),
        }

    def relationships(
        self,
        store,
        run: str,
        *,
        source="",
        destination="",
        account="",
        kind="",
        domain="",
        status="",
        q="",
        group="",
        outside=False,
        missing_only=False,
        privileged=False,
        offset=0,
        limit=50,
    ):
        store.require_run(run)
        if not 1 <= limit <= 200 or not 0 <= offset <= 1000000 or len(q) > 200:
            raise InputError("INVALID_PAGE")
        where, params = ["run_id=?"], [run]
        for field, value in [
            ("source_account", source),
            ("destination_account", destination),
            ("kind", kind),
            ("domain", domain),
            ("status", status),
        ]:
            if value:
                where.append(f"{field}=?")
                params.append(value)
        if account:
            ids = account.split(",")
            if len(ids) > 512 or any(not re.fullmatch(r"[0-9]{12}", a) for a in ids):
                raise InputError("INVALID_ACCOUNT_SELECTION")
            marks = ",".join("?" for _ in ids)
            where.append(f"(source_account IN ({marks}) OR destination_account IN ({marks}))")
            params.extend([*ids, *ids])
        if group:
            ids = [a["account"] for a in self.accounts(store, run) if group in a["groups"]]
            if not ids:
                return {"items": [], "total": 0, "offset": offset, "limit": limit}
            marks = ",".join("?" for _ in ids)
            where.append(f"(source_account IN ({marks}) OR destination_account IN ({marks}))")
            params.extend([*ids, *ids])
        if outside:
            where.append("json_extract_string(data,'$.outside_registry')='true'")
        if missing_only:
            where.append("json_array_length(json_extract(data,'$.missing')) > 0")
        if privileged:
            where.append(
                "json_extract_string(data,'$.target_privilege') IN "
                "('ADMIN_EQUIVALENT','ESCALATION_CAPABLE','POTENTIALLY_PRIVILEGED')"
            )
        if q:
            where.append("lower(data) LIKE ?")
            params.append("%" + q.lower() + "%")
        predicate = " AND ".join(where)
        total = store.db.execute(
            "SELECT count(*) FROM enterprise_edges WHERE " + predicate, params
        ).fetchone()[0]
        data = [
            json.loads(d)
            for (d,) in store.rows(
                "SELECT data FROM enterprise_edges WHERE "
                + predicate
                + " ORDER BY relationship_id LIMIT ? OFFSET ?",
                [*params, limit, offset],
            )
        ]
        return {"items": data, "total": total, "offset": offset, "limit": limit}

    def graph(
        self, store, run: str, *, node_limit=80, edge_limit=150, depth=2, focus="", **filters
    ):
        import networkx as nx

        if not 1 <= node_limit <= 150 or not 1 <= edge_limit <= 200 or not 0 <= depth <= 4:
            raise InputError("INVALID_GRAPH_BUDGET")
        result = self.relationships(store, run, limit=edge_limit, **filters)
        graph = nx.MultiDiGraph()
        truncated = result["total"] > edge_limit
        for e in result["items"]:
            src = stable_id("node", [e["source_partition"], e["source_account"], e["source"]])
            dst = stable_id(
                "node", [e["destination_partition"], e["destination_account"], e["destination"]]
            )
            new = {src, dst} - set(graph)
            if len(graph) + len(new) > node_limit:
                truncated = True
                continue
            graph.add_node(
                src,
                identity=e["source"],
                account=e["source_account"],
                partition=e["source_partition"],
            )
            graph.add_node(
                dst,
                identity=e["destination"],
                account=e["destination_account"],
                partition=e["destination_partition"],
            )
            graph.add_edge(
                src,
                dst,
                key=e["relationship_id"],
                record={**e, "graph_source": src, "graph_destination": dst},
            )
        if focus:
            if focus in graph:
                kept = set(
                    nx.single_source_shortest_path_length(
                        graph.to_undirected(), focus, cutoff=depth
                    )
                )
                graph = graph.subgraph(kept).copy()
            else:
                graph = nx.MultiDiGraph()
        return {
            "nodes": [{"id": n, **d} for n, d in graph.nodes(data=True)],
            "edges": [d["record"] for *_, d in graph.edges(data=True)],
            "truncated": truncated,
            "selection_total": result["total"],
            "limits": {"nodes": node_limit, "edges": edge_limit, "depth": depth},
            "limitation": (
                "Filtered reference/predicate graph; not a "
                "complete reachability or exploitation path"
            ),
        }

    def issues(self, store, run: str, offset=0, limit=50, multi=True):
        store.require_run(run)
        if not 1 <= limit <= 100 or not 0 <= offset <= 1000000:
            raise InputError("INVALID_PAGE")
        where = (
            "run_id=? AND "
            + VISIBLE_ISSUE
            + (
                " AND CAST(json_extract_string(data,'$.affected_account_count') AS INTEGER)>1"
                if multi
                else ""
            )
        )
        hidden = excluded_ids(store, run)
        total = store.db.execute(
            "SELECT count(*) FROM enterprise_issues WHERE " + where, [run, hidden]
        ).fetchone()[0]
        items = [
            self.review_state(store, json.loads(d))
            for (d,) in store.rows(
                "SELECT data FROM enterprise_issues WHERE "
                + where
                + " ORDER BY investigation_id LIMIT ? OFFSET ?",
                [run, hidden, limit, offset],
            )
        ]
        return {"items": items, "total": total, "offset": offset, "limit": limit}

    @staticmethod
    def review_state(store, item):
        fingerprint = hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest()
        decision = store.latest_decision(item["investigation_id"])
        item["analyst_status"] = (
            "CANDIDATE"
            if not decision
            else decision.status
            if decision.evidence_fingerprint == fingerprint
            else "NEEDS_REVALIDATION"
        )
        item["decision"] = decision.model_dump(mode="json") if decision else None
        return item

    def review(self, store, run, issue, status, analyst, note):
        row = store.db.execute(
            "SELECT data FROM enterprise_issues WHERE run_id=? AND investigation_id=?", [run, issue]
        ).fetchone()
        if not row:
            raise InputError("INVESTIGATION_NOT_FOUND")
        if SECRET_VALUE.search(analyst) or SECRET_VALUE.search(note):
            raise InputError("CREDENTIAL_MATERIAL_REJECTED")
        item = json.loads(row[0])
        decision = Decision(
            finding_id=issue,
            status=status,
            analyst=analyst,
            note=note,
            decided_at=datetime.now(UTC),
            run_id=run,
            evidence_fingerprint=hashlib.sha256(
                json.dumps(item, sort_keys=True).encode()
            ).hexdigest(),
        )
        did = stable_id("decision", decision.model_dump(mode="json"))
        with store.transaction():
            store.db.execute(
                "INSERT INTO decisions VALUES (?,?,?,?)",
                [did, issue, decision.decided_at.isoformat(), decision.model_dump_json()],
            )
        return did
