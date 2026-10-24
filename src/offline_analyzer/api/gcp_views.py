"""Provider-aware projections of persisted GCP evidence, without effective-IAM claims."""

from offline_analyzer.inventory.cloud import relationships
from offline_analyzer.rules.gcp import IAM_UNCERTAINTY


def scoped(items: list[dict], filters: dict) -> list[dict]:
    return [
        item
        for item in items
        if all(
            not filters.get(key)
            or (item.get(key) or ("AWS" if key == "provider" else "")) == filters[key]
            for key in (
                "provider",
                "project_id",
                "project_number",
                "organization_id",
                "folder_id",
                "region",
                "dataset",
                "collection_domain",
                "collection_status",
                "support",
            )
        )
    ]


def iam_projection(store, run: str) -> dict:
    items = {kind: [] for kind in ("roles", "policies", "relationships", "investigations", "gaps")}
    projects = set()
    sources = {source["artifact_id"]: source for source in store.source_data(run)}
    refs = store.run_refs(run)
    for obs in store.observations(run, provider="GCP"):
        projects.add(obs.project_id)
        row = {
            key: value
            for key, value in obs.model_dump(mode="json").items()
            if key != "configuration"
        }
        metadata = sources.get(obs.evidence.artifact_id, {}).get("gcp_metadata") or {}
        row.update(
            evidence=[ref.model_dump() for ref, _ in refs.get(obs.observation_id, [])],
            dataset=metadata.get("dataset"),
            domain=metadata.get("domain"),
            support_status="SUPPORTED",
        )
        if obs.resource_type in {
            "GCP::ServiceAccount",
            "GCP::ServiceAccountKey",
            "GCP::IAMBinding",
            "GCP::CustomRole",
            "GCP::WorkloadIdentityPool",
            "GCP::WorkloadIdentityProvider",
        }:
            row.update(
                role=obs.configuration.get("role") or obs.native_id,
                account=obs.project_id,
                privilege="NOT_ESTABLISHED",
                missing=list(IAM_UNCERTAINTY),
            )
            items["roles"].append(row)
        if obs.resource_type in {
            "GCP::IAMPolicy",
            "GCP::IAMDenyPolicy",
            "GCP::PrincipalAccessBoundaryBinding",
            "GCP::OrgPolicy",
            "GCP::OrgPolicyInventory",
        }:
            row.update(
                arn=obs.native_id,
                document_resolved=True,
                gap=(
                    "Observed policy metadata; inherited/conditional effective access "
                    "is not established"
                ),
            )
            items["policies"].append(row)
    for project in sorted(projects):
        items["gaps"].append(
            {
                "provider": "GCP",
                "project_id": project,
                "category": "EFFECTIVE_IAM_NOT_ESTABLISHED",
                "scope": project,
                "missing": list(IAM_UNCERTAINTY),
            }
        )
    for source in store.source_data(run):
        metadata = source.get("gcp_metadata") or {}
        if metadata.get("domain") == "identity" and source["effective_coverage"] in {
            "ERROR",
            "NOT_COLLECTED",
        }:
            items["gaps"].append(
                {
                    "provider": "GCP",
                    "project_id": source.get("project_id"),
                    "category": metadata.get("status") or "MISSING_EVIDENCE",
                    "scope": source["operation"],
                    "missing": source["errors"],
                }
            )
    # Relationships are evidence-backed structural references, never generated attack paths.
    projected = relationships(store, run, limit=500)
    for row in projected["items"]:
        row.update(
            kind=row["relationship"],
            target=row["destination"],
            state=row["status"],
            basis="Observed source evidence; effective authorization is not established",
        )
    items["relationships"] = projected["items"]
    if projected["truncated"]:
        items["gaps"].append(
            {
                "provider": "GCP",
                "category": "RELATIONSHIP_VIEW_LIMIT",
                "scope": "Selected assessment",
                "missing": ["Projection limited to 500 edges; use evidence filtering"],
            }
        )
    return items
