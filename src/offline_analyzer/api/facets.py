"""Bounded choices projected from displayed records; no configuration payloads exposed."""

from offline_analyzer.provenance.execution import checkpoint

ALIASES = {
    "account": ("account_id", "account"),
    "project": ("project_id",),
    "organization": ("organization_id",),
    "folder": ("folder_id",),
    "region": ("region", "regions"),
    "dataset": ("dataset",),
    "collection_domain": ("collection_domain", "domain"),
    "project_number": ("project_number",),
    "resource": ("native_id", "resource_id"),
    "value": ("suggested_severity", "outcome", "state", "effective_coverage"),
    "group": ("groups",),
    "severity": ("severity",),
    "coverage": ("coverage",),
    "source": ("source_account",),
    "destination": ("destination_account",),
    "kind": ("relationship_type", "kind"),
    "q": (
        "title",
        "native_id",
        "operation",
        "role",
        "arn",
        "account",
        "category",
        "finding_id",
        "relationship_id",
        "relationship_type",
    ),
}


def choices(rows: list[dict]) -> dict:
    result = {key: set() for key in (*ALIASES, "service")}
    truncated = set()

    def add(key, value):
        values = value if isinstance(value, (list, tuple)) else [value]
        for item in values:
            if isinstance(item, str) and len(item) > 200:
                truncated.add(key)
            if isinstance(item, str) and item and len(item) <= 200:
                if len(result[key]) < 1000:
                    result[key].add(item)
                elif item not in result[key]:
                    truncated.add(key)

    for row in rows:
        for key, fields in ALIASES.items():
            for field in fields:
                value = row.get(field)
                if isinstance(value, dict) and key == "severity":
                    value = list(value)
                add(key, value)
        from offline_analyzer.rules.registry import PROVIDER_RULES

        rule = next((r for r in PROVIDER_RULES if r.rule_id == row.get("rule_id")), None)
        operation = row.get("operation", "") or (rule.operation if rule else "")
        if operation:
            add(
                "service",
                operation.split(":")[1].split(".")[0]
                if operation.startswith("gcp:")
                else operation.split(":")[0],
            )
    return {
        "choices": {k: sorted(v) for k, v in result.items()},
        "truncated_fields": sorted(truncated),
    }


def facets(views, store, run: str, kind: str, provider: str) -> dict:
    # Native SQL contracts limit stored observations to 250,000 per enterprise snapshot.
    # Read lightweight projections only; never return configuration or raw evidence.
    truncated = False

    def records():
        nonlocal truncated
        offset = 0
        while True:
            checkpoint()
            page = views.records(
                store,
                run,
                kind,
                "",
                "",
                "",
                offset,
                1000,
                {"provider": provider} if provider else {},
            )
            yield from page["items"]
            offset += len(page["items"])
            if offset >= page["total"] or not page["items"] or offset >= 250000:
                truncated = offset < page["total"]
                break

    result = choices(records())
    result["truncated"] = truncated
    return result
