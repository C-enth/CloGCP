"""Analyst scope-limitation text per run, rendered in "Coverage and limitations" after the fixed
limitation constants. Append-only; the latest record applies; frozen editions keep the text
they were frozen with."""

import json
from datetime import UTC, datetime

from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.ingestion.json_input import SECRET_VALUE, InputError

MAX_TEXT = 4000


def latest(store, run: str) -> str:
    row = store.db.execute(
        "SELECT data FROM report_limitations WHERE run_id=? "
        "ORDER BY recorded_at DESC, record_id DESC LIMIT 1",
        [run],
    ).fetchone()
    return json.loads(row[0])["text"] if row else ""


def save(store, run: str, text: str, analyst: str) -> dict:
    from offline_analyzer.findings.finalisation import require_editable

    store.require_run(run)
    require_editable(store, run)
    text, analyst = text.strip(), analyst.strip()
    if len(text) > MAX_TEXT or not 1 <= len(analyst) <= 200:
        raise InputError("INVALID_REPORT_LIMITATIONS")
    if SECRET_VALUE.search(text) or SECRET_VALUE.search(analyst):
        raise InputError("CREDENTIAL_MATERIAL_REJECTED")
    if any(ord(c) < 32 and c not in "\n\t" for c in text + analyst):
        raise InputError("REPORT_CONTROL_CHARACTERS_REJECTED")
    record = {
        "run_id": run,
        "text": text,
        "analyst": analyst,
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    with store.transaction():
        store.db.execute(
            "INSERT INTO report_limitations VALUES (?,?,?,?)",
            [
                stable_id("report-limitations", record),
                run,
                record["recorded_at"],
                json.dumps(record),
            ],
        )
    return record
