"""Explicit records for every capped view or analysis budget.

A record names the budget, the scope it applies to, how many items are shown and how many
existed. `total` is exact unless `total_basis` says otherwise (for example candidate
combinations that were counted but not evaluated). Views attach records only when items were
actually dropped, so no view can say "not truncated" after dropping a record, and an
untruncated view is unchanged. Caps that refuse the whole operation (snapshot observation and
member limits, per-resource and per-scope evidence limits) are explicit errors, not records.
"""

EXACT = "exact"


def record(
    budget: str,
    scope: str,
    shown: int,
    total: int,
    effect: str,
    total_basis: str = EXACT,
    provider: str = "",
) -> dict:
    return {
        "provider": provider,
        "budget": budget,
        "scope": scope,
        "shown": shown,
        "total": total,
        "dropped": max(total - shown, 0),
        "total_basis": total_basis,
        "effect": effect,
    }


def text(entry: dict) -> str:
    basis = "" if entry["total_basis"] == EXACT else f" ({entry['total_basis']})"
    return (
        f"{entry['budget']}: {entry['shown']} of {entry['total']}{basis} shown for "
        f"{entry['scope']}; {entry['effect']}"
    )


def note(entry: dict) -> dict:
    """Coverage-note form used by the assessment report (Word and Excel)."""
    return {
        "provider": entry.get("provider") or "Run",
        "scope": entry["scope"],
        "name": "",
        "code": "TRUNCATED_" + entry["budget"].upper().replace(" ", "_").replace("-", "_"),
        "reason": text(entry),
        "datasets": entry["dropped"],
    }
