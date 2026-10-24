"""Exact SCC/native condition correlation; no fuzzy merging of different resources."""

from datetime import datetime


def timestamp(value: object) -> datetime | None:
    try:
        parsed = (
            datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else None
        )
        return parsed if parsed and parsed.tzinfo else None
    except ValueError:
        return None


def scc_correlations(store, run: str) -> list[dict]:
    """Only the reviewed 90-day key-rotation category is eligible for exact deduplication."""
    store.require_run(run)
    native = {}
    observations = {}
    sources = {s["artifact_id"]: s for s in store.source_data(run) if s["artifact_id"]}
    for obs in store.observations(run, provider="GCP"):
        if obs.provider != "GCP":
            continue
        observations[obs.observation_id] = obs
    from offline_analyzer.contracts.r0 import Result

    # Use the writer connection so correlation sees evaluations in the current transaction.
    rows = store.db.execute(
        "SELECT data FROM evaluations WHERE run_id=? AND "
        "json_extract_string(data,'$.rule_id')='GCP-KEY-AGE'",
        [run],
    ).fetchall()
    for (data,) in rows:
        result = Result.model_validate_json(data)
        if result.rule_id == "GCP-KEY-AGE" and result.evaluation_scope == "RESOURCE":
            native[(result.project_id, result.native_id)] = result
    rows = []
    for obs in observations.values():
        if obs.resource_type != "GCP::SCCFinding":
            continue
        c = obs.configuration
        resource = c.get("resourceName", "")
        resource = resource.removeprefix("//iam.googleapis.com/")
        result = native.get((obs.project_id, resource))
        event = timestamp(c.get("eventTime"))
        related = (
            [observations[oid] for oid in result.supporting_observations if oid in observations]
            if result
            else []
        )
        same_policy = bool(related) and all(
            o.configuration.get("_collection", {}).get("max_key_age_days") == 90 for o in related
        )
        fresh = bool(event and related) and all(
            o.collected_at and abs((o.collected_at - event).total_seconds()) <= 86400
            for o in related
        )
        source = sources.get(obs.evidence.artifact_id, {})
        usable = source.get("effective_coverage") in {"COMPLETE", "PARTIAL"} and not source.get(
            "errors"
        )
        reviewed = (
            usable
            and c.get("category") == "SERVICE_ACCOUNT_KEY_NOT_ROTATED"
            and c.get("state") == "ACTIVE"
            and same_policy
        )
        equivalent = reviewed and fresh and result and result.outcome == "FAIL"
        rows.append(
            {
                "provider": "GCP",
                "project_id": obs.project_id,
                "scc_observation_id": obs.observation_id,
                "source_finding_id": obs.source_finding_id,
                "category": c.get("category"),
                "original_severity": c.get("severity"),
                "state": c.get("state"),
                "event_time": c.get("eventTime"),
                "resource": c.get("resourceName"),
                "native_evaluation_id": result.evaluation_id if result else None,
                "status": "EQUIVALENT_NATIVE_CONDITION"
                if equivalent
                else "COLLECTION_UNUSABLE"
                if not usable
                else "CONTRADICTORY_NATIVE_SNAPSHOT"
                if reviewed and result and fresh and result.outcome == "PASS"
                else "STALE_OR_UNRESOLVED_TIME"
                if reviewed and result and not fresh
                else "SUPPLEMENTARY_UNCORRELATED",
                "evidence": [r.model_dump() for r in store.refs(run, [obs.observation_id])],
                "qualification": (
                    "Deduplication requires exact project, key resource, reviewed issue, "
                    "policy threshold and 24-hour event context. Original observations "
                    "remain retained."
                ),
            }
        )
    return rows


def deduplicate(store, run: str) -> None:
    """During assessment, keep the native candidate and attach equivalent SCC provenance."""

    from offline_analyzer.contracts.models import EvidenceRef
    from offline_analyzer.contracts.r0 import Candidate, stable_id

    for correlation in scc_correlations(store, run):
        if correlation["status"] != "EQUIVALENT_NATIVE_CONDITION":
            continue
        native_result = store.db.execute(
            "SELECT resource_id FROM evaluations WHERE run_id=? AND evaluation_id=?",
            [run, correlation["native_evaluation_id"]],
        ).fetchone()
        native_finding = stable_id("finding", ["GCP-KEY-AGE", native_result[0]])
        row = store.db.execute(
            "SELECT data FROM findings WHERE run_id=? AND finding_id=?", [run, native_finding]
        ).fetchone()
        if not row:
            continue
        finding = Candidate.model_validate_json(row[0])
        refs = {
            *finding.evidence,
            *[EvidenceRef.model_validate(r) for r in correlation["evidence"]],
        }
        updated = finding.model_copy(
            update={"evidence": tuple(sorted(refs, key=lambda r: (r.artifact_id, r.locator)))}
        )
        store.db.execute(
            "UPDATE findings SET data=? WHERE run_id=? AND finding_id=?",
            [updated.model_dump_json(), run, native_finding],
        )
        resource = store.db.execute(
            "SELECT resource_id FROM observations WHERE run_id=? AND observation_id=?",
            [run, correlation["scc_observation_id"]],
        ).fetchone()[0]
        duplicate = stable_id("finding", ["GCP-SCC-OBSERVATION", resource])
        store.db.execute(
            "DELETE FROM finding_resources WHERE run_id=? AND finding_id=?", [run, duplicate]
        )
        store.db.execute("DELETE FROM findings WHERE run_id=? AND finding_id=?", [run, duplicate])
