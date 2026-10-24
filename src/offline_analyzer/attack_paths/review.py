"""Evidence-bound interpretation decisions; source mappings and feasibility stay unchanged."""

import json
from datetime import UTC, datetime

from offline_analyzer.contracts.path_review import PathReview
from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.ingestion.json_input import InputError


def fingerprint(path: dict) -> str:
    """Interpretation identity of a path. Hop-model keys only restate the record, so they are
    excluded: a review recorded before the hop model existed stays valid without re-import."""
    from offline_analyzer.attack_paths.model import HOP_KEYS

    # The false-positive flag is analyst-layer context, not part of the path's identity.
    excluded = {
        "analyst_review",
        "diagram",
        "false_positive_dependency",
        "excluded_dependency",
        *HOP_KEYS,
    }
    return stable_id("path-review", {k: v for k, v in path.items() if k not in excluded})


def attach(store, run: str, paths: list[dict]) -> None:
    """Analyst path interpretation for each path. A review applies to any run whose path has an
    identical fingerprint (owner brief 3); a review recorded for a different fingerprint gives
    NEEDS_REVALIDATION; no review gives UNREVIEWED. The latest matching review decides."""
    ids = sorted({p["path_id"] for p in paths})
    reviews: dict[str, list[PathReview]] = {}
    if ids:
        for pid, raw in store.rows(
            "SELECT path_id,data FROM path_reviews WHERE path_id IN (SELECT unnest(?)) "
            "ORDER BY reviewed_at DESC,review_id DESC",
            [ids],
        ):
            reviews.setdefault(pid, []).append(PathReview.model_validate_json(raw))
    for path in paths:
        records = reviews.get(path["path_id"], [])
        current = fingerprint(path) if records else None
        matching = next((r for r in records if r.fingerprint == current), None)
        path["analyst_review"] = (
            matching.status if matching else "NEEDS_REVALIDATION" if records else "UNREVIEWED"
        )


def record(store, run: str, path_id: str, status: str, analyst: str) -> dict:
    from offline_analyzer.attack_paths.feasibility import attack_paths
    from offline_analyzer.findings.finalisation import require_editable

    require_editable(store, run)
    path = next((p for p in attack_paths(store, run)["items"] if p["path_id"] == path_id), None)
    if path is None:
        raise InputError("PATH_NOT_FOUND")
    review = PathReview(
        run_id=run,
        path_id=path_id,
        fingerprint=fingerprint(path),
        analyst=analyst,
        reviewed_at=datetime.now(UTC),
        status=status,
    )
    data = review.model_dump(mode="json")
    with store.transaction():
        store.db.execute(
            "INSERT INTO path_reviews VALUES (?,?,?,?,?)",
            [
                stable_id("path-decision", data),
                run,
                path_id,
                review.reviewed_at.isoformat(),
                json.dumps(data),
            ],
        )
    return data
