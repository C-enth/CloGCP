"""Expanded collector transport shapes and canonical identities, without control logic."""

import re
from pathlib import Path

from offline_analyzer.contracts.r0 import Source
from offline_analyzer.ingestion.json_input import InputError, records
from offline_analyzer.normalization.gcp_identity import mismatch

SUMMARY_TYPES = (
    "GCP::Asset",
    "GCP::AssetIAMSearchResult",
    "GCP::AssetResourceSnapshot",
    "GCP::AssetIAMSnapshot",
)


def canonical_resource(project: str, kind: str, native: str, region: str) -> str:
    """A full native path identifies the entity; summaries do not create a second entity."""
    if kind == "GCP::Project":
        return "gcp://projects/" + project
    if native.startswith("projects/"):
        return "gcp://" + native + ("/iamPolicy" if kind == "GCP::IAMPolicy" else "")
    return f"gcp://{project}/{region}/{kind}/{native}"


IAM_SEARCH_FAMILIES = {"asset_iam_search", "folder_iam_search", "organization_iam_search"}


def in_collected_scope(raw: dict, source: Source, ancestors: set[str]) -> bool:
    """IAM search results belong to the collected project or its own parent chain (ADR-010).

    Results about other projects or unrelated folders are dropped before storage, so no
    project appears in CloSec unless its own collector output was imported.
    """
    own = {source.project_id, source.project_number} - {None}
    project = raw.get("project")
    if isinstance(project, str) and project:
        return project.rsplit("/", 1)[-1] in own
    resource = raw.get("resource")
    if not isinstance(resource, str):
        return False
    match = re.search(r"/projects/([^/]+)", resource)
    if match:
        return match[1] in own
    match = re.search(r"/((?:organizations|folders)/\d+)$", resource)
    return bool(match) and match[1] in ancestors


def own_image(raw: dict, source: Source) -> bool:
    """`gcloud compute images list` includes Google's public image projects by default
    (collector 2.2.3 and earlier). Those images belong to other projects (ADR-010)."""
    link = raw.get("selfLink")
    match = re.search(r"/projects/([^/]+)/", link) if isinstance(link, str) else None
    return match is None or match[1] in {source.project_id, source.project_number} - {None}


def expanded_records(path: Path, source: Source, shape: dict):
    metadata = source.gcp_metadata or {}
    contract = metadata.get("dataset_contract", {})
    if not contract:
        # Retain unknown outputs without interpreting them as supported resources.
        prefix = "item" if shape["root"] == "start_array" else ""
        yield from records(path, prefix)
        return
    rest = contract["method"] != "Run"
    if rest and shape["root"] != "start_array":
        raise InputError("GCP_EXPANDED_REST_ARRAY_REQUIRED")
    singleton = contract["family"] in {
        "project",
        "project_iam",
        "parent_org_iam",
        "parent_folder_iam",
        "settings",
        "api_key_detail",
        "sa_iam",
        "bucket_iam",
        "bucket_details",
        "folder_describe",
        "folder_iam",
        "organization_iam",
        "custom_role_detail",
        "effective_policy",
        "run_iam",
        "function_iam",
    }
    if not rest and shape["root"] != ("start_map" if singleton else "start_array"):
        raise InputError("GCP_EXPANDED_GCLOUD_SHAPE_MISMATCH")
    scoped = contract["family"] in IAM_SEARCH_FAMILIES
    ancestors = set(metadata.get("scope_ancestors") or [])
    for index, raw in records(path, "item" if shape["root"] == "start_array" else ""):
        if not isinstance(raw, dict):
            raise InputError("GCP_RECORD_OBJECT_REQUIRED")
        if scoped and not in_collected_scope(raw, source, ancestors):
            continue
        if contract["family"] == "images" and not own_image(raw, source):
            continue
        aggregate = {
            "interconnect_attachments": "interconnectAttachments",
            "psc_forwarding_rules": "forwardingRules",
        }.get(contract["family"])
        if aggregate:
            for scope, body in raw.items():
                if not re.fullmatch(
                    r"(?:regions|zones)/[A-Za-z0-9_-]{1,100}|global", scope
                ) or not isinstance(body, dict):
                    raise InputError("GCP_AGGREGATED_RESPONSE_SHAPE_MISMATCH")
                if aggregate not in body:
                    if (
                        isinstance(body.get("warning"), dict)
                        and body["warning"].get("code") == "NO_RESULTS_ON_PAGE"
                    ):
                        continue
                    raise InputError("GCP_AGGREGATED_RESPONSE_SHAPE_MISMATCH")
                if not isinstance(body[aggregate], list):
                    raise InputError("GCP_AGGREGATED_RESPONSE_SHAPE_MISMATCH")
                for child_index, child in enumerate(body[aggregate]):
                    if not isinstance(child, dict):
                        raise InputError("GCP_RECORD_OBJECT_REQUIRED")
                    escaped = scope.replace("~", "~0").replace("/", "~1")
                    yield f"{index}/{escaped}/{aggregate}/{child_index}", child
        else:
            yield index, raw


def canonical_native(
    raw: dict, source: Source, kind: str, native: str | None
) -> tuple[str | None, str]:
    """Only join names within an explicit type/project/location identity scope."""
    region = (
        raw.get("location") or raw.get("zone") or raw.get("region") or source.region or "global"
    )
    if not isinstance(region, str):
        region = "global"
    region = region.rstrip("/").split("/")[-1]
    full = raw.get("selfLink") or native
    if isinstance(full, str):
        match = re.search(r"(?:^|/)projects/([^/]+)/(.*)$", full)
        if match:
            tail = match[2]
            if match[1] in {source.project_id, source.project_number, "-"}:
                native = f"projects/{source.project_id}/{tail}"
            else:
                native = f"projects/{match[1]}/{tail}"
            location = re.match(r"(?:locations|regions|zones)/([^/]+)/", tail)
            if location:
                region = location[1]
    compute = {
        "GCP::Network": "networks",
        "GCP::Firewall": "firewalls",
        "GCP::Route": "routes",
        "GCP::SecurityPolicy": "securityPolicies",
        "GCP::SSLPolicy": "sslPolicies",
        "GCP::URLMap": "urlMaps",
        "GCP::InstanceTemplate": "instanceTemplates",
        "GCP::Image": "images",
    }
    if native and "/" not in native and kind in compute:
        native = f"projects/{source.project_id}/global/{compute[kind]}/{native}"
        region = "global"
    scoped = {
        "GCP::ComputeInstance": ("zones", "instances"),
        "GCP::Disk": ("zones", "disks"),
        "GCP::Subnet": ("regions", "subnetworks"),
        "GCP::GKECluster": ("locations", "clusters"),
        "GCP::RunService": ("locations", "services"),
        "GCP::RunJob": ("locations", "jobs"),
        "GCP::Function": ("locations", "functions"),
    }
    if native and "/" not in native and kind in scoped and region != "global":
        scope, collection = scoped[kind]
        native = f"projects/{source.project_id}/{scope}/{region}/{collection}/{native}"
    if native and "/" not in native and kind == "GCP::GKENodePool":
        parent = (source.request_parameters or {}).get("parent")
        if isinstance(parent, str):
            native = parent + "/nodePools/" + native
            if source.project_number:
                native = native.replace(
                    f"projects/{source.project_number}/", f"projects/{source.project_id}/", 1
                )
            match = re.search(r"/(?:locations|zones)/([^/]+)/", parent)
            region = match[1] if match else region
        else:
            # A dataset index is not a cluster identity. Retain evidence as unresolved.
            native = None
    if kind == "GCP::Bucket" and native:
        native = native.removeprefix("gs://").rstrip("/")
        region = "global"
    reference = raw.get("datasetReference") or raw.get("tableReference")
    if kind in {"GCP::BigQueryDataset", "GCP::BigQueryTable"} and isinstance(reference, dict):
        if reference.get("projectId") not in {None, source.project_id}:
            raise mismatch(
                source.path or "manifest",
                source.project_id,
                "datasetReference/tableReference.projectId",
                reference.get("projectId"),
            )
        if isinstance(reference.get("datasetId"), str):
            native = f"projects/{source.project_id}/datasets/{reference['datasetId']}"
            if kind == "GCP::BigQueryTable":
                if not isinstance(reference.get("tableId"), str):
                    raise InputError("GCP_NATIVE_IDENTITY_MISSING")
                native += "/tables/" + reference["tableId"]
    return native, region
