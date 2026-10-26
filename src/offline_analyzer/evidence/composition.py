"""Reference base + supplementary imports in a new analysis; never rewrite source runs."""

import hashlib
import json
from datetime import UTC, datetime

from clogcp_delta.collector import semantic
from offline_analyzer.contracts.evidence_composition import EvidenceComposition
from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.findings.generate import fingerprint, validation_status
from offline_analyzer.iam.gcp_permissions import canonical
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.rules.engine import assess, verify_raw

VERSION = "gcp-evidence-composition-1"
MAX_OBSERVATIONS = 250000


def _subject(obs, numbers: dict) -> str:
    config = obs.configuration
    if obs.resource_type == "GCP::IAMBinding":
        value = config.get("subject", "")
    elif obs.resource_type == "GCP::AssetIAMSearchResult":
        value = config.get("resource", "")
    else:
        value = obs.native_id or ""
    return canonical(value, numbers)


def _scope(source: dict, numbers: dict) -> tuple[str, str, str]:
    params = source.get("request_parameters") or {}
    subject = canonical(params.get("subject") or params.get("parent") or "", numbers)
    operation = source["operation"]
    family = "IAM" if "getIamPolicy" in operation else operation
    return source.get("project_id") or "", family, subject


def _time(value) -> datetime:
    if not value:
        raise InputError("COMPOSITION_COLLECTION_TIMESTAMP_REQUIRED")
    result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise InputError("COMPOSITION_AWARE_TIMESTAMP_REQUIRED")
    return result.astimezone(UTC)


def compose(store, base: str, delta: str) -> str:
    """Idempotent materialization of references, with conservative scoped precedence.

    Shared/global IAM context requires the existing evaluator to assess the new run.
    This fallback never calls enterprise rebuilding, reimports, or changes old results.
    """
    if base == delta:
        raise InputError("DISTINCT_BASE_AND_DELTA_REQUIRED")
    for member in (base, delta):
        store.require_run(member)
        verify_raw(store, member)
    sources = {r: list(store.source_data(r)) for r in (base, delta)}
    if not sources[delta] or any(
        (s.get("gcp_metadata") or {}).get("contract_version") != "gcp-delta-1"
        for s in sources[delta]
    ):
        raise InputError("SUPPLEMENTARY_IMPORT_REQUIRED")
    origins = {
        (s.get("gcp_metadata") or {}).get("dataset_origin")
        for member in (base, delta)
        for s in sources[member]
        if s.get("format") == "gcp-json-v1"
    } - {None}
    if len(origins) != 1:
        raise InputError("COMPOSITION_ORIGIN_MISMATCH")
    run = stable_id("run", [VERSION, base, delta])
    if store.db.execute("SELECT 1 FROM runs WHERE run_id=?", [run]).fetchone():
        verify_raw(store, run)
        if not description(store, run).get("materialized_sha256"):
            return _finish(store, run, base, origins)
        return run
    numbers = {
        str(s["project_number"]): s["project_id"]
        for items in sources.values()
        for s in items
        if s.get("project_number")
    }
    observations = {r: list(store.observations(r)) for r in (base, delta)}
    if sum(map(len, observations.values())) > MAX_OBSERVATIONS:
        raise InputError("COMPOSITION_OBSERVATION_LIMIT")
    # Requests are per resource, including failed collection attempts. A fresh failure
    # suppresses stale successful policy bytes rather than pretending those remain current.
    delta_by_scope = {_scope(s, numbers): s for s in sources[delta]}
    base_by_artifact = {s.get("artifact_id"): s for s in sources[base]}

    def policy_key(obs):
        if obs.resource_type not in {"GCP::IAMPolicy", "GCP::AssetIAMSearchResult"}:
            return None
        config = obs.configuration.get("policy", obs.configuration)
        policy = {
            k: v for k, v in config.items() if k not in {"etag", "_parameters", "_collection"}
        }
        return json.dumps(semantic(policy), sort_keys=True)

    fresh_policies = {
        (o.project_id, "IAM", _subject(o, numbers)): policy_key(o)
        for o in observations[delta]
        if policy_key(o) is not None
    }
    equivalent = {
        (o.project_id, "IAM", _subject(o, numbers))
        for o in observations[base]
        if policy_key(o) is not None
        and policy_key(o) == fresh_policies.get((o.project_id, "IAM", _subject(o, numbers)))
    }
    dropped, rejected_delta, events, touched = set(), set(), [], set()
    for obs in observations[base]:
        subject = _subject(obs, numbers)
        family = (
            "IAM"
            if obs.resource_type
            in {"GCP::IAMPolicy", "GCP::IAMBinding", "GCP::AssetIAMSearchResult"}
            else obs.operation
        )
        key = (obs.project_id or "", family, subject)
        incoming = delta_by_scope.get(key)
        if not incoming:
            continue
        old = base_by_artifact.get(obs.evidence.artifact_id, {})
        old_time, new_time = _time(obs.collected_at), _time(incoming["collected_at"])
        status = (
            "SUPERSEDED_BY_LATER_ATTEMPT"
            if new_time > old_time
            else (
                "SAME_TIME_CONFLICT_REQUIRES_REVIEW"
                if new_time == old_time
                else "OLDER_DELTA_RETAINED_AS_HISTORY"
            )
        )
        if key in equivalent:
            status = "SEMANTICALLY_EQUIVALENT_BASIS_RETAINED"
            rejected_delta.add(key)
        if key not in equivalent and new_time >= old_time:
            dropped.add(obs.observation_id)
            touched.add(obs.evidence.artifact_id)
        if new_time <= old_time:
            # Equal-time divergent evidence has no safe precedence: neither is active.
            rejected_delta.add(key)
        events.append(
            {
                "resource_scope": list(key),
                "previous_observation": obs.observation_id,
                "previous_artifact": obs.evidence.artifact_id,
                "new_artifact": incoming.get("artifact_id"),
                "previous_collected_at": old.get("collected_at"),
                "new_collected_at": incoming.get("collected_at"),
                "status": status,
                "new_coverage": incoming["effective_coverage"],
            }
        )
    # Compare collection timestamps, never label the combined records one simultaneous state.
    dates = sorted({str(s.get("collected_at")) for items in sources.values() for s in items})
    metadata = {
        "schema_version": VERSION,
        "base_run": base,
        "delta_run": delta,
        "source_runs": [base, delta],
        "events": events,
        "collection_timestamps": dates,
        "simultaneous_state_established": False,
        "temporally_mixed": len(dates) > 1,
        "baseline_modified": False,
        "analysis_strategy": "EXISTING_EVALUATORS_IN_NEW_RUN",
        "broader_analysis_reason": (
            "IAM policies affect shared context across controls; existing evaluators "
            "run only in this new version."
        ),
        "affected_scopes": [list(k) for k in sorted(delta_by_scope)],
        "security_reviews_copied": False,
    }
    metadata = EvidenceComposition.model_validate(metadata).model_dump(mode="json")
    base_package = json.loads(
        store.db.execute("SELECT package FROM runs WHERE run_id=?", [base]).fetchone()[0]
    )
    package = {
        "sources": [],
        "targets": base_package.get("targets", []),
        "evidence_composition": metadata,
    }
    with store.transaction():
        store.db.execute(
            "INSERT INTO runs VALUES (?,?,?)",
            [run, datetime.now(UTC).isoformat(), json.dumps(package)],
        )
        for member in (base, delta):
            for sid, raw in store.db.execute(
                "SELECT source_id,data FROM sources WHERE run_id=?", [member]
            ).fetchall():
                source = json.loads(raw)
                meta = dict(source.get("gcp_metadata") or {})
                meta["composition"] = {
                    "version": VERSION,
                    "source_run": member,
                    "original_source_id": sid,
                    "temporally_mixed": len(dates) > 1,
                }
                source["gcp_metadata"] = meta
                if member == base and source.get("artifact_id") in touched:
                    source["effective_coverage"] = "PARTIAL"
                    source["limitations"] = [
                        *source.get("limitations", []),
                        (
                            "Historical resource records superseded by supplementary collection; "
                            "original descriptor retained in source "
                            "run."
                        ),
                    ]
                if member == delta and _scope(source, numbers) in rejected_delta:
                    source["effective_coverage"] = "NOT_COLLECTED"
                    source["limitations"] = [
                        *source.get("limitations", []),
                        "Older or same-time conflicting supplementary evidence is not active.",
                    ]
                store.db.execute(
                    "INSERT INTO sources VALUES (?,?,?) ON CONFLICT DO NOTHING",
                    [run, stable_id("source-ref", [member, sid]), json.dumps(source)],
                )
            store.db.execute(
                (
                    "INSERT INTO artifacts SELECT ?,artifact_id,sha256,size_bytes FROM "
                    "artifacts WHERE run_id=? ON CONFLICT DO "
                    "NOTHING"
                ),
                [run, member],
            )
            selected = []
            for obs in observations[member]:
                if member == base and obs.observation_id in dropped:
                    continue
                family = (
                    "IAM"
                    if obs.resource_type
                    in {"GCP::IAMPolicy", "GCP::IAMBinding", "GCP::AssetIAMSearchResult"}
                    else obs.operation
                )
                key = (obs.project_id or "", family, _subject(obs, numbers))
                if member == delta and key in rejected_delta:
                    continue
                selected.append(obs)
                if len(selected) >= 128:
                    store.put_observations(run, selected)
                    selected = []
            store.put_observations(run, selected)
        # Every locator for retained observations survives, including equivalent facts
        # from multiple original files. Superseded refs remain in the immutable base run.
        for member in (base, delta):
            store.db.execute(
                (
                    "INSERT INTO evidence_refs SELECT ?,e.observation_id,e.artifact_id,e.loca"
                    "tor FROM evidence_refs e WHERE e.run_id=? AND EXISTS (SELECT 1 FROM "
                    "observations o WHERE o.run_id=? AND o.observation_id=e.observation_id) "
                    "ON CONFLICT DO NOTHING"
                ),
                [run, member, run],
            )
    return _finish(store, run, base, origins)


def _finish(store, run: str, base: str, origins: set[str]) -> str:
    package = json.loads(
        store.db.execute("SELECT package FROM runs WHERE run_id=?", [run]).fetchone()[0]
    )
    metadata = package["evidence_composition"]
    assess(store, run)
    before = {f.finding_id: f for f in store.candidates(base)}
    after = {f.finding_id: f for f in store.candidates(run)}
    reconciliation = []
    for fid in sorted(set(before) | set(after)):
        old, new = before.get(fid), after.get(fid)
        state = (
            "UNCHANGED"
            if old and new and fingerprint(old) == fingerprint(new)
            else (
                "CHANGED_REQUIRES_REVIEW"
                if old and new
                else "NEW"
                if new
                else "NOT_REPRODUCED_REVIEW_REQUIRED"
            )
        )
        reconciliation.append(
            {
                "finding_id": fid,
                "state": state,
                "prior_validation": validation_status(store, old)[0] if old else "CANDIDATE",
                "current_validation": validation_status(store, new)[0] if new else "HISTORICAL",
                "approval_copied": False,
            }
        )
    metadata["reconciliation"] = reconciliation
    metadata["materialized_sha256"] = materialized_digest(store, run)
    metadata = EvidenceComposition.model_validate(metadata).model_dump(mode="json")
    package["evidence_composition"] = metadata
    with store.transaction():
        store.db.execute("UPDATE runs SET package=? WHERE run_id=?", [json.dumps(package), run])
    from offline_analyzer.inventory.environment import record_run_origin

    record_run_origin(store.workspace, run, next(iter(origins)))
    return run


def materialized_digest(store, run: str) -> str:
    digest = hashlib.sha256()
    for table in ("sources", "artifacts", "observations", "evidence_refs"):
        # Each table has fixed internal columns. Row digests make order deterministic.
        values = [
            hashlib.sha256(json.dumps(row, default=str).encode()).digest()
            for row in store.rows(f"SELECT * FROM {table} WHERE run_id=?", [run])
        ]
        digest.update(table.encode())
        for value in sorted(values):
            digest.update(value)
    return digest.hexdigest()


def validate_composition(store, run: str) -> dict:
    data = description(store, run)
    if not data:
        return {"status": "ORIGINAL_IMPORT", "checks": [], "missing_imports": []}
    record = EvidenceComposition.model_validate(data)
    for member in record.source_runs:
        store.require_run(member)
        verify_raw(store, member)
    verify_raw(store, run)
    valid = bool(
        record.materialized_sha256 and record.materialized_sha256 == materialized_digest(store, run)
    )
    return {
        "status": "PASS" if valid else "ERROR",
        "checks": [{"stage": "evidence_composition", "status": "PASS" if valid else "ERROR"}],
        "missing_imports": [],
    }


def description(store, run: str) -> dict:
    store.require_run(run)
    raw = store.db.execute("SELECT package FROM runs WHERE run_id=?", [run]).fetchone()[0]
    return json.loads(raw).get("evidence_composition", {})
