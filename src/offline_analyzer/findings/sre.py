"""SRE validation records and the derived review stage of each finding (ADR-008)."""

from datetime import UTC, datetime

from offline_analyzer.contracts.r0 import Candidate, stable_id
from offline_analyzer.contracts.sre import SreValidation
from offline_analyzer.findings.generate import fingerprint, validation_status
from offline_analyzer.ingestion.json_input import SECRET_VALUE, InputError

# Ordered as the workflow progresses; labels are what people see in every output.
STAGES = {
    "TRIAGE": "Analyst triage",
    "WITH_SRE": "With SRE",
    "SRE_REVALIDATION": "Evidence changed: revalidate with SRE",
    "NO_GAP_BAU": "No gap (BAU)",
    "SRE_CONFIRMED_GAP": "Gap confirmed by SRE: analyst to confirm",
    "CONFIRMED_VULNERABILITY": "Confirmed vulnerability",
    "REJECTED": "Rejected by analyst",
}
VERDICTS = {
    "SENT_TO_SRE": "Sent to SRE",
    "GAP_CONFIRMED": "Gap confirmed",
    "NO_GAP_BAU": "No gap (BAU)",
    "NEEDS_INFO": "SRE needs more information",
}
MAX_BULK = 2000


def stage(analyst_status: str, sre: SreValidation | None, current_fingerprint: str) -> str:
    """Single definition of the stage; `STAGE_SQL` must stay equivalent.

    The assessor's marking decides: "not valid" (REJECTED) removes a finding, "valid"
    (CONFIRMED) makes it a confirmed vulnerability. An SRE response is optional input;
    it only sets the stage while the assessor has not decided.
    """
    if analyst_status == "REJECTED":
        return "REJECTED"
    if analyst_status == "CONFIRMED":
        return "CONFIRMED_VULNERABILITY"
    if sre is not None and sre.evidence_fingerprint != current_fingerprint:
        return "SRE_REVALIDATION"
    verdict = sre.verdict if sre else None
    if verdict == "GAP_CONFIRMED":
        return "SRE_CONFIRMED_GAP"
    if verdict == "NO_GAP_BAU":
        return "NO_GAP_BAU"
    if verdict in {"SENT_TO_SRE", "NEEDS_INFO"}:
        return "WITH_SRE"
    return "TRIAGE"


def latest_sre(store, run_id: str) -> dict[str, SreValidation]:
    """Latest SRE verdict per finding in the run (same ordering as analyst decisions)."""
    latest = {}
    for finding_id, data in store.rows(
        "SELECT finding_id, data FROM sre_validations WHERE finding_id IN "
        "(SELECT finding_id FROM findings WHERE run_id=?) ORDER BY recorded_at, validation_id",
        [run_id],
    ):
        latest[finding_id] = data
    return {k: SreValidation.model_validate_json(v) for k, v in latest.items()}


def review_state(store, finding: Candidate, decisions: dict, sre: dict) -> tuple[str, str]:
    """(analyst validation status, stage) for one candidate using preloaded maps."""
    status = validation_status(store, finding, decisions)[0]
    return status, stage(status, sre.get(finding.finding_id), fingerprint(finding))


# Equivalent SQL over findings `f`, latest decision `d` and latest SRE verdict `s`.
REVIEW_STATE_SQL = (
    "CASE WHEN d.finding_id IS NULL THEN 'CANDIDATE' "
    "WHEN json_extract_string(d.data,'$.evidence_fingerprint')<>sha256(f.data) "
    "THEN 'NEEDS_REVALIDATION' ELSE json_extract_string(d.data,'$.status') END"
)
STAGE_SQL = (
    f"CASE WHEN ({REVIEW_STATE_SQL})='REJECTED' THEN 'REJECTED' "
    f"WHEN ({REVIEW_STATE_SQL})='CONFIRMED' THEN 'CONFIRMED_VULNERABILITY' "
    "WHEN s.finding_id IS NOT NULL AND "
    "json_extract_string(s.data,'$.evidence_fingerprint')<>sha256(f.data) "
    "THEN 'SRE_REVALIDATION' "
    "WHEN json_extract_string(s.data,'$.verdict')='GAP_CONFIRMED' THEN 'SRE_CONFIRMED_GAP' "
    "WHEN json_extract_string(s.data,'$.verdict')='NO_GAP_BAU' THEN 'NO_GAP_BAU' "
    "WHEN s.finding_id IS NOT NULL THEN 'WITH_SRE' ELSE 'TRIAGE' END"
)
REVIEWED_FINDINGS_SQL = (
    f"(SELECT f.*,{REVIEW_STATE_SQL} AS review_state,{STAGE_SQL} AS stage FROM findings f "
    "LEFT JOIN (SELECT * FROM decisions QUALIFY row_number() OVER "
    "(PARTITION BY finding_id ORDER BY decided_at DESC,decision_id DESC)=1) d "
    "ON f.finding_id=d.finding_id LEFT JOIN (SELECT * FROM sre_validations QUALIFY "
    "row_number() OVER (PARTITION BY finding_id ORDER BY recorded_at DESC,validation_id DESC)"
    "=1) s ON f.finding_id=s.finding_id) AS filtered_findings"
)


def record_sre(
    store,
    run_id: str,
    finding_ids: list[str],
    verdict: str,
    recorded_by: str,
    sre_contact: str = "",
    reason: str = "",
) -> list[str]:
    """Append one verdict for each finding, atomically; returns the validation IDs."""
    store.require_run(run_id)
    from offline_analyzer.findings.finalisation import require_editable

    require_editable(store, run_id)
    if not finding_ids or len(finding_ids) > MAX_BULK or len(set(finding_ids)) != len(finding_ids):
        raise InputError("INVALID_SRE_SELECTION")
    if any(SECRET_VALUE.search(v) for v in (recorded_by, sre_contact, reason)):
        raise InputError("CREDENTIAL_MATERIAL_REJECTED")
    found = {
        fid: Candidate.model_validate_json(raw)
        for fid, raw in store.rows(
            "SELECT finding_id,data FROM findings WHERE run_id=? AND "
            "finding_id IN (SELECT unnest(?))",
            [run_id, finding_ids],
        )
    }
    if len(found) != len(finding_ids):
        raise InputError("FINDING_NOT_FOUND_IN_RUN")
    now = datetime.now(UTC)
    records = []
    for fid in finding_ids:
        try:
            record = SreValidation(
                finding_id=fid,
                run_id=run_id,
                verdict=verdict,
                sre_contact=sre_contact.strip(),
                recorded_by=recorded_by.strip(),
                reason=reason.strip(),
                recorded_at=now,
                evidence_fingerprint=fingerprint(found[fid]),
            )
        except ValueError as exc:
            raise InputError("INVALID_SRE_VERDICT") from exc
        records.append((stable_id("sre", record.model_dump(mode="json")), record))
    with store.transaction():
        for validation_id, record in records:
            store.db.execute(
                "INSERT INTO sre_validations VALUES (?, ?, ?, ?)",
                [validation_id, record.finding_id, now.isoformat(), record.model_dump_json()],
            )
    return [validation_id for validation_id, _ in records]
