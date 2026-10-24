"""Client-report exclusions: hide a finding from reports without altering its evidence.

Records are append-only and keyed by the stable finding identity (rule ID + canonical
resource ID, independent of the run), so an exclusion survives re-evaluation, enterprise
snapshot builds and restarts. Frozen editions keep their preserved content.

False-positive dispositions (reason FALSE_POSITIVE, with a mandatory reason text) are the
analyst's false-positive layer; rule evaluation (the FAIL result) is never changed. One is in
force for a run when it was recorded in that run, in an enterprise snapshot that contains the
run, or in a member run of the snapshot being viewed. For a different (newer or older) import
of the same project it is carried over only when the finding ID (rule ID + project + native
resource ID) and the principals named by the finding match exactly, and it is then marked
"carried over from <import>" for analyst review. Different projects never share a finding ID,
so nothing is carried across projects. Other exclusion reasons apply by finding ID as before.
"""

import json
import re
from datetime import UTC, datetime

from offline_analyzer.contracts.exclusion import ExclusionRequest, FindingExclusion
from offline_analyzer.contracts.r0 import Candidate, stable_id
from offline_analyzer.ingestion.json_input import SECRET_VALUE, InputError

REASONS = {
    "FALSE_POSITIVE": "False positive",
    "DUPLICATE": "Duplicate of another finding",
    "ACCEPTED_RISK": "Risk accepted by the client",
    "OUT_OF_SCOPE": "Out of assessment scope",
    "COMPENSATING_CONTROL": "Mitigated by a compensating control",
    "NOT_APPLICABLE": "Not applicable to this environment",
    "OTHER": "Other (see note)",
}
FALSE_POSITIVE = "FALSE_POSITIVE"
# Preset false-positive reasons offered in the UI; free text is always allowed.
FALSE_POSITIVE_PRESETS = ("Google-managed service agent (platform-managed)",)
MAX_BULK = 2000
PRINCIPAL = re.compile(r"(?:serviceAccount|user|group|domain|principal|principalSet):[^\s;,()]+")
LATEST_SQL = (
    "SELECT finding_id,data FROM finding_exclusions QUALIFY row_number() OVER "
    "(PARTITION BY finding_id ORDER BY recorded_at DESC,exclusion_id DESC)=1"
)


def principals(finding: Candidate) -> tuple[str, ...]:
    """Principals named by the finding text (sorted, unique); empty when none are named."""
    text = " ".join(filter(None, [finding.technical_observation, finding.native_id]))
    return normalized(PRINCIPAL.findall(text))


def normalized(values) -> tuple[str, ...]:
    """Sorted unique principals without trailing sentence punctuation (records written before
    this normalisation compare equal)."""
    return tuple(sorted({v.rstrip(".:") for v in values if v.rstrip(".:")}))


def related_runs(store, run: str) -> set[str]:
    """The run, the enterprise snapshots that contain it and, for a snapshot, its members."""
    runs = {run}
    for snapshot, members in store.rows("SELECT run_id, members FROM enterprise_snapshots"):
        listed = set(json.loads(members or "[]"))
        if run == snapshot:
            runs |= listed
        elif run in listed:
            runs.add(snapshot)
    return runs


def excluded(store, run: str | None = None) -> dict[str, FindingExclusion]:
    """Findings whose latest exclusion record is EXCLUDE, by finding ID. With `run`, a
    false-positive disposition from an unrelated import applies only on an exact match and
    is returned with `carried_from` set."""
    result = {}
    related = related_runs(store, run) if run else set()
    pending = {}
    for finding_id, raw in store.rows(LATEST_SQL):
        record = FindingExclusion.model_validate_json(raw)
        if record.action != "EXCLUDE":
            continue
        if run and record.reason == FALSE_POSITIVE and record.run_id not in related:
            pending[finding_id] = record
            continue
        result[finding_id] = record
    if pending:
        for raw_id, raw in store.rows(
            "SELECT finding_id, data FROM findings WHERE run_id=? AND finding_id IN "
            "(SELECT unnest(?))",
            [run, sorted(pending)],
        ):
            record = pending[raw_id]
            if principals(Candidate.model_validate_json(raw)) == normalized(record.principals):
                result[raw_id] = record.model_copy(update={"carried_from": record.run_id})
    return result


def false_positives(store, run: str) -> dict[str, FindingExclusion]:
    return {k: v for k, v in excluded(store, run).items() if v.reason == FALSE_POSITIVE}


def record(store, run: str, finding_id: str, request: ExclusionRequest) -> FindingExclusion:
    from offline_analyzer.findings.finalisation import require_editable

    store.require_run(run)
    require_editable(store, run)
    if any(SECRET_VALUE.search(v) for v in (request.note, request.analyst)):
        raise InputError("CREDENTIAL_MATERIAL_REJECTED")
    if any(ord(c) < 32 and c not in "\n\r\t" for c in request.note + request.analyst):
        raise InputError("REPORT_CONTROL_CHARACTERS_REJECTED")
    if not store.db.execute(
        "SELECT 1 FROM findings WHERE run_id=? AND finding_id=?", [run, finding_id]
    ).fetchone():
        raise InputError("FINDING_NOT_FOUND_IN_RUN")
    entry = _entry(store, run, finding_id, request, excluded(store, run))
    with store.transaction():
        _insert(store, entry)
    return entry


def _entry(store, run, finding_id, request, current: dict) -> FindingExclusion:
    from offline_analyzer.findings.generate import validation_status

    active = finding_id in current
    if (request.action == "EXCLUDE") == active:
        raise InputError("FINDING_ALREADY_EXCLUDED" if active else "FINDING_NOT_EXCLUDED")
    row = store.db.execute(
        "SELECT data FROM findings WHERE run_id=? AND finding_id=?", [run, finding_id]
    ).fetchone()
    if not row:
        raise InputError("FINDING_NOT_FOUND_IN_RUN")
    finding = Candidate.model_validate_json(row[0])
    excluding = request.action == "EXCLUDE"
    return FindingExclusion(
        finding_id=finding_id,
        run_id=run,
        action=request.action,
        reason=request.reason if excluding else None,
        note=request.note.strip(),
        analyst=request.analyst.strip(),
        recorded_at=datetime.now(UTC),
        previous_state=validation_status(store, finding)[0]
        if excluding
        else (current[finding_id].reason or "EXCLUDED"),
        principals=principals(finding) if excluding else (),
    )


def _insert(store, entry: FindingExclusion) -> None:
    store.db.execute(
        "INSERT INTO finding_exclusions VALUES (?,?,?,?)",
        [
            stable_id("finding-exclusion", entry.model_dump(mode="json")),
            entry.finding_id,
            entry.recorded_at.isoformat(),
            entry.model_dump_json(),
        ],
    )


def record_many(store, run: str, request) -> list[FindingExclusion]:
    """One disposition (or restore) for many findings of the run, all-or-nothing."""
    from offline_analyzer.findings.finalisation import require_editable

    store.require_run(run)
    require_editable(store, run)
    ids = list(request.finding_ids)
    if not ids or len(ids) > MAX_BULK or len(set(ids)) != len(ids):
        raise InputError("INVALID_REVIEW_SELECTION")
    if any(SECRET_VALUE.search(v) for v in (request.note, request.analyst)):
        raise InputError("CREDENTIAL_MATERIAL_REJECTED")
    if any(ord(c) < 32 and c not in "\n\r\t" for c in request.note + request.analyst):
        raise InputError("REPORT_CONTROL_CHARACTERS_REJECTED")
    current = excluded(store, run)
    entries = [_entry(store, run, fid, request, current) for fid in ids]
    with store.transaction():
        for entry in entries:
            _insert(store, entry)
    return entries


def listing(store, run: str, provider: str = "") -> dict:
    """Excluded findings of this run for the labelled "Excluded findings" section."""
    store.require_run(run)
    records = excluded(store, run)
    items = []
    for (raw,) in store.rows(
        "SELECT data FROM findings WHERE run_id=? AND finding_id IN (SELECT unnest(?))",
        [run, sorted(records)],
    ):
        finding = Candidate.model_validate_json(raw)
        if provider and (finding.provider or "AWS") != provider:
            continue
        entry = records[finding.finding_id]
        items.append(
            {
                "id": finding.finding_id,
                "title": finding.title,
                "severity": finding.suggested_severity,
                "provider": finding.provider or "AWS",
                "scope": finding.project_id or finding.account_id or "",
                "resource": finding.native_id,
                "reason": entry.reason,
                "reason_label": REASONS.get(entry.reason or "", ""),
                "note": entry.note,
                "analyst": entry.analyst,
                "excluded_at": entry.recorded_at.isoformat(),
                "rule": finding.rule_id,
                "false_positive": entry.reason == FALSE_POSITIVE,
                "previous_state": entry.previous_state,
                "carried_from": entry.carried_from,
            }
        )
    items.sort(key=lambda i: (i["excluded_at"], i["id"]), reverse=True)
    return {
        "items": items,
        "reasons": REASONS,
        "false_positive_presets": list(FALSE_POSITIVE_PRESETS),
        "false_positives": sum(i["false_positive"] for i in items),
    }


def appendix(store, run: str, provider: str = "", scope: str = "") -> list[dict]:
    """Excluded findings grouped by rule and reason, with counts and finding IDs."""
    groups: dict[tuple, dict] = {}
    for item in listing(store, run, provider)["items"]:
        if scope and item["scope"] != scope:
            continue
        key = (item["rule"], item["reason_label"], item["note"] or "")
        group = groups.setdefault(
            key,
            {
                "rule": item["rule"],
                "reason": item["reason_label"],
                "detail": item["note"],
                "count": 0,
                "finding_ids": [],
            },
        )
        group["count"] += 1
        group["finding_ids"].append(item["id"])
    return [groups[k] for k in sorted(groups)]


def excluded_ids(store, run: str) -> list[str]:
    """IDs of the run's findings that are excluded (every reason), for count queries."""
    hidden = excluded(store, run)
    if not hidden:
        return []
    return sorted(
        fid
        for (fid,) in store.rows(
            "SELECT finding_id FROM findings WHERE run_id=? AND finding_id IN (SELECT unnest(?))",
            [run, sorted(hidden)],
        )
    )


def evaluation_exclusions(store, run: str) -> dict[str, str]:
    """finding_id -> "excluded (<reason>)" for listings of evaluations (results unchanged)."""
    return {
        fid: f"excluded ({REASONS.get(entry.reason or '', entry.reason or 'unrecorded')})"
        for fid, entry in excluded(store, run).items()
    }
