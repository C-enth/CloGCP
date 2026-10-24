"""Bounded bulk enrichment for a findings page; no repeated enterprise-edge scans."""

import json
from collections import defaultdict

from offline_analyzer.storage.store import Store


def page_context(store: Store, run: str, items: list[dict]) -> tuple[dict, dict, dict]:
    if not items:
        return {}, {}, {}
    ids = [f["finding_id"] for f in items]
    resources = list({f["resource_id"] for f in items})
    evaluations = {}
    for resource, raw in store.rows(
        "SELECT resource_id,data FROM evaluations WHERE run_id=? AND "
        "resource_id IN (SELECT unnest(?)) ORDER BY evaluation_id",
        [run, resources],
    ):
        result = json.loads(raw)
        evaluations.setdefault((resource, result["rule_id"]), result)
    observation_ids = list(
        {
            oid
            for item in items
            for oid in evaluations.get((item["resource_id"], item["rule_id"]), {}).get(
                "supporting_observations", []
            )[:100]
        }
    )
    timestamps = {
        oid: {"observation_id": oid, "collected_at": stamp, "operation": operation}
        for oid, stamp, operation in store.rows(
            "SELECT observation_id,json_extract_string(data,'$.collected_at'),"
            "json_extract_string(data,'$.operation') FROM observations WHERE run_id=? "
            "AND observation_id IN (SELECT unnest(?))",
            [run, observation_ids],
        )
    }
    linked = defaultdict(list)
    for fid, raw in store.rows(
        "SELECT json_extract_string(f.value,'$') AS fid,e.data FROM enterprise_edges e, "
        "json_each(e.data,'$.related_findings') f WHERE e.run_id=? AND "
        "json_extract_string(f.value,'$') IN (SELECT unnest(?)) QUALIFY "
        "row_number() OVER(PARTITION BY fid ORDER BY e.relationship_id)<=100 "
        "ORDER BY fid,e.relationship_id",
        [run, ids],
    ):
        linked[fid].append(json.loads(raw))
    return evaluations, timestamps, linked
