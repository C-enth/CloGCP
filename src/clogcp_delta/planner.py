"""One approved multi-project missing-evidence plan, using existing inventory only."""

import json
from datetime import datetime

from .collector import DeltaError, sha
from .models import Plan, Request

OPERATIONS = {
    "gcp:storage.buckets.getIamPolicy": "BUCKET_IAM",
    "gcp:folders.get": "FOLDER_METADATA",
    "gcp:folders.getIamPolicy": "FOLDER_IAM",
    "gcp:discoveryengine.engines.list": "DISCOVERY_ENGINES",
    "gcp:discoveryengine.dataStores.list": "DISCOVERY_DATASTORES",
    "gcp:discoveryengine.resources.get": "DISCOVERY_RESOURCE",
}


def plan_missing(
    matrix: dict,
    inventory: list[dict],
    *,
    selected_projects: list[str],
    selected_folders: list[str],
    approved_by: str,
    approved_at: datetime,
    matrix_sha256: str,
    quota_project: str | None = None,
    bucket_scopes: dict[str, list[str]] | None = None,
    discovery_scopes: dict[str, list[str]] | None = None,
    include_optional: bool = False,
) -> tuple[Plan | None, list[dict]]:
    """Identifiers must be explicitly supplied or observed in selected imported inventory.

    Counts do not identify buckets; locations/collection IDs are never guessed. Approval
    covers exact requests in the resulting plan, not arbitrary discovery or API enabling.
    """
    requests, pending = [], []
    projects, folders = set(selected_projects), set(selected_folders)
    identities: dict[str, set[str]] = {}
    for source in inventory:
        if source.get("project_id") in projects and source.get("project_number"):
            identities.setdefault(source["project_id"], set()).add(str(source["project_number"]))
    if any(len(values) > 1 for values in identities.values()):
        raise DeltaError("INVENTORY_PROJECT_IDENTITY_CONFLICT")
    numbers = {project: next(iter(values)) for project, values in identities.items()}

    def canonical_resource(project, resource):
        number = numbers.get(project)
        return (
            resource.replace("projects/" + number + "/", "projects/" + project + "/", 1)
            if number
            else resource
        )

    complete = set()
    known_buckets: dict[str, set[str]] = {}
    known_discovery: dict[str, set[str]] = {}
    for source in inventory:
        project = source.get("project_id")
        if project not in projects:
            continue
        params = source.get("request_parameters") or {}
        subject = params.get("subject") or params.get("parent") or ""
        if source.get("resource_type") == "GCP::Bucket":
            name = (
                str(source.get("resource_name") or "")
                .removeprefix("gs://")
                .removeprefix("buckets/")
            )
            if name:
                known_buckets.setdefault(project, set()).add(name)
        if source.get("resource_type") in {"GCP::DiscoveryEngine", "GCP::DiscoveryDataStore"}:
            name = source.get("resource_name") or ""
            if "/collections/" in name:
                known_discovery.setdefault(project, set()).add(name.rsplit("/", 2)[0])
        if source.get("operation") == "gcp:storage.buckets.getIamPolicy":
            name = subject.removeprefix("gs://").removeprefix("buckets/")
            known_buckets.setdefault(project, set()).add(name)
        operation = OPERATIONS.get(source.get("operation"))
        if operation and source.get("effective_coverage", source.get("coverage")) == "COMPLETE":
            resource = (
                subject.removeprefix("gs://").removeprefix("buckets/")
                if operation == "BUCKET_IAM"
                else subject
            )
            complete.add((project, operation, canonical_resource(project, resource)))

    planned = set()

    def add(project, operation, resource, optional=False):
        key = (project, operation, canonical_resource(project, resource))
        if key in complete or key in planned:
            return
        planned.add(key)
        identifier = sha(json.dumps(key).encode())[:24]
        request = Request(
            request_id="delta-" + identifier,
            project_id=project,
            project_number=numbers.get(project),
            operation=operation,
            resource=resource,
            optional=optional,
        )
        if request not in requests:
            requests.append(request)

    for item in matrix.get("bucket_iam", []):
        project = item["project"]
        if project not in projects:
            continue
        names = set((bucket_scopes or {}).get(project, [])) | known_buckets.get(project, set())
        if len(names) < item.get("bucket_count", 0):
            pending.append(
                {
                    "project": project,
                    "operation": "BUCKET_IAM",
                    "reason": "EXACT_BUCKET_IDENTIFIERS_REQUIRED",
                }
            )
        for name in sorted(names):
            add(project, "BUCKET_IAM", name)
    for item in matrix.get("folder_iam", []):
        folder = item["folder"]
        folder = str(folder) if str(folder).startswith("folders/") else "folders/" + str(folder)
        if folder not in folders:
            continue
        for project in sorted(projects.intersection(item["projects"])):
            add(project, "FOLDER_METADATA", folder)
            add(project, "FOLDER_IAM", folder)
    for project in matrix.get("discovery_configuration", []):
        if project not in projects:
            continue
        parents = sorted(
            set((discovery_scopes or {}).get(project, [])) | known_discovery.get(project, set())
        )
        if not parents:
            pending.append(
                {
                    "project": project,
                    "operation": "DISCOVERY_CONFIGURATION",
                    "reason": "EXACT_LOCATION_COLLECTION_SCOPE_REQUIRED",
                }
            )
        for parent in parents:
            add(project, "DISCOVERY_ENGINES", parent)
            add(project, "DISCOVERY_DATASTORES", parent)
    if include_optional:
        for project in matrix.get("optional_recommendations", []):
            if project in projects:
                add(project, "IAM_RECOMMENDATIONS", "projects/" + project, True)
    if len(requests) > 1024:
        raise DeltaError("PLAN_REQUEST_LIMIT")
    plan = (
        Plan(
            approved_by=approved_by,
            approved_at=approved_at,
            catalogue_reconciled=True,
            matrix_sha256=matrix_sha256,
            quota_project=quota_project,
            requests=requests,
        )
        if requests
        else None
    )
    return plan, pending


def main() -> None:
    import argparse
    from pathlib import Path

    from .collector import load

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--selected-project", action="append", required=True)
    parser.add_argument("--selected-folder", action="append", default=[])
    parser.add_argument("--bucket-scopes", type=Path)
    parser.add_argument("--discovery-scopes", type=Path)
    parser.add_argument("--quota-project")
    parser.add_argument("--approved-by", required=True)
    parser.add_argument("--approved-at", required=True)
    parser.add_argument("--include-optional", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise DeltaError("NEW_OUTPUT_DIRECTORY_REQUIRED")
    matrix = load(args.matrix)
    inventory = load(args.inventory)
    if not isinstance(matrix, dict) or not isinstance(inventory, list):
        raise DeltaError("MATRIX_AND_SOURCE_INVENTORY_REQUIRED")
    plan, pending = plan_missing(
        matrix,
        inventory,
        selected_projects=args.selected_project,
        selected_folders=args.selected_folder,
        approved_by=args.approved_by,
        approved_at=datetime.fromisoformat(args.approved_at.replace("Z", "+00:00")),
        matrix_sha256=sha(args.matrix.read_bytes()),
        quota_project=args.quota_project,
        bucket_scopes=load(args.bucket_scopes) if args.bucket_scopes else None,
        discovery_scopes=load(args.discovery_scopes) if args.discovery_scopes else None,
        include_optional=args.include_optional,
    )
    args.output.mkdir(mode=0o700, parents=True)
    if plan:
        (args.output / "approved-plan.json").write_text(plan.model_dump_json(indent=2))
    (args.output / "pending-scopes.json").write_text(json.dumps(pending, indent=2))
    print(
        json.dumps(
            {
                "planned_operations": len(plan.requests) if plan else 0,
                "unresolved_scopes": len(pending),
                "executed": False,
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit("DELTA_PLANNING_INPUT_INVALID") from None
