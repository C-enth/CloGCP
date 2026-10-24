"""Native gcloud/API JSON profiles. Only identity and metadata normalization."""

import re
from pathlib import Path

from offline_analyzer.contracts.models import EvidenceRef
from offline_analyzer.contracts.r0 import Normalized, Source, stable_id
from offline_analyzer.ingestion.json_input import InputError, records
from offline_analyzer.normalization.gcp_identity import mismatch

VERSION = "gcp-native-1.1.0"

# operation: (resource type, native API list field, identity field); None is singleton.
PROFILES = {
    "gcp:cloudasset.searchAllResources": ("GCP::Asset", "results", "name"),
    "gcp:cloudasset.searchAllIamPolicies": ("GCP::AssetIAMSearchResult", "results", "resource"),
    "gcp:orgpolicy.policies.list": ("GCP::OrgPolicyInventory", "policies", "name"),
    "gcp:projects.get": ("GCP::Project", None, "projectId"),
    "gcp:apikeys.keys.list": ("GCP::APIKey", "keys", "name"),
    "gcp:serviceusage.services.list": ("GCP::Service", "services", "name"),
    "gcp:iam.serviceAccounts.list": ("GCP::ServiceAccount", "accounts", "name"),
    "gcp:iam.serviceAccountKeys.list": ("GCP::ServiceAccountKey", "keys", "name"),
    "gcp:projects.getIamPolicy": ("GCP::IAMPolicy", None, "subject"),
    "gcp:iam.serviceAccounts.getIamPolicy": ("GCP::IAMPolicy", None, "subject"),
    "gcp:folders.getIamPolicy": ("GCP::IAMPolicy", None, "subject"),
    "gcp:organizations.getIamPolicy": ("GCP::IAMPolicy", None, "subject"),
    "gcp:iam.roles.list": ("GCP::CustomRole", "roles", "name"),
    "gcp:orgpolicy.getEffectivePolicy": ("GCP::OrgPolicy", None, "constraint"),
    "gcp:logging.sinks.list": ("GCP::LoggingSink", "sinks", "name"),
    "gcp:logging.exclusions.list": ("GCP::LoggingExclusion", "exclusions", "name"),
    "gcp:logging.buckets.list": ("GCP::LogBucket", "buckets", "name"),
    "gcp:monitoring.alertPolicies.list": ("GCP::AlertPolicy", "alertPolicies", "name"),
    "gcp:securitycenter.findings.list": ("GCP::SCCFinding", "listFindingsResults", "name"),
    "gcp:storage.buckets.list": ("GCP::Bucket", "items", "name"),
    "gcp:storage.buckets.getIamPolicy": ("GCP::IAMPolicy", None, "subject"),
    "gcp:compute.instances.list": ("GCP::ComputeInstance", "items", "name"),
    "gcp:compute.firewalls.list": ("GCP::Firewall", "items", "name"),
    "gcp:compute.networks.list": ("GCP::Network", "items", "name"),
    "gcp:run.services.list": ("GCP::RunService", "items", "name"),
}


EXPANDED_CONTRACTS = {"assessment-expanded-2.1", "assessment-expanded-2.2"}


def expanded_contract(source: Source | None) -> bool:
    """Both expanded collector contracts carry a per-dataset contract for typed parsing."""
    return bool(source) and (source.gcp_metadata or {}).get("contract_version") in (
        EXPANDED_CONTRACTS
    )


def native_records(path: Path, operation: str, shape: dict, source: Source | None = None):
    if expanded_contract(source):
        from offline_analyzer.normalization.gcp_expanded import expanded_records

        yield from expanded_records(path, source, shape)
        return
    profile = PROFILES.get(operation)
    if shape["root"] == "start_array":
        yield from records(path, "item")
    elif profile and profile[1] is not None:
        field = profile[1]
        if shape["fields"].get(field, (None,))[0] != "start_array":
            raise InputError("GCP_RESPONSE_SHAPE_MISMATCH")
        yield from records(path, field + ".item")
    elif shape["root"] == "start_map":
        yield from records(path, "")
    else:
        raise InputError("GCP_RESPONSE_SHAPE_MISMATCH")


def resource_id(project: str, kind: str, native: str, location: str = "global") -> str:
    return "gcp://" + project + "/" + location + "/" + kind + "/" + native


def validate_identity(record: dict, source: Source) -> None:
    """Reject explicit contradictory project scope; no name-only identity joins."""
    declared = {source.project_id, source.project_number} - {None}
    expanded = expanded_contract(source)
    parent_summary = (source.gcp_metadata or {}).get("dataset_contract", {}).get("family") in {
        "folder_iam_search",
        "organization_iam_search",
    }
    project = record.get("projectId")
    if project and project != source.project_id:
        raise mismatch(source.path or "manifest", source.project_id, "projectId", project)
    number = record.get("projectNumber")
    if number is not None and source.project_number and str(number) != source.project_number:
        raise mismatch(source.path or "manifest", source.project_id, "projectNumber", number)
    for field in ("name", "selfLink", "resourceName", "resource"):
        value = record.get(field)
        # Resource Manager v1 projects.get uses name as a display label. Only v3's
        # numeric projects/<number> form is a project resource name, never a label join.
        if field == "name" and source.operation == "gcp:projects.get" and project:
            if not isinstance(value, str) or not re.fullmatch(r"projects/[0-9]{1,20}", value):
                continue
        if isinstance(value, str) and (match := re.search(r"(?:^|/)projects/([^/]+)", value)):
            unverified_number = (
                expanded
                and not source.project_number
                and bool(re.fullmatch(r"[0-9]{1,20}", match[1]))
            )
            if (
                match[1] != "-"
                and match[1] not in declared
                and not parent_summary
                and not unverified_number
            ):
                # A numeric resource name cannot be checked without a declared number;
                # say so instead of implying the evidence belongs to another project.
                code = (
                    "GCP_PROJECT_NUMBER_REQUIRED"
                    if not source.project_number and re.fullmatch(r"[0-9]{1,20}", match[1])
                    else "GCP_PROJECT_IDENTITY_MISMATCH"
                )
                raise mismatch(source.path or "manifest", source.project_id, field, match[1], code)


def gcp_records(path: Path, source: Source, artifact: str, shape: dict):
    profile = PROFILES.get(source.operation)
    expanded = expanded_contract(source)
    contract = (source.gcp_metadata or {}).get("dataset_contract", {}) if expanded else {}
    if contract:
        profile = (
            contract["resource_type"],
            None,
            "resource" if contract["resource_type"] == "GCP::AssetIAMSearchResult" else "name",
        )
        if contract["resource_type"] == "GCP::Project":
            profile = ("GCP::Project", None, "projectId")
    kind, _field, identity_field = profile or ("GCP::Unsupported", None, "name")
    for index, raw in native_records(path, source.operation, shape, source):
        if not isinstance(raw, dict):
            raise InputError("GCP_RECORD_OBJECT_REQUIRED")
        scc_wrapped = kind == "GCP::SCCFinding" and "finding" in raw
        raw = raw.get("finding", raw) if kind == "GCP::SCCFinding" else raw
        if not isinstance(raw, dict):
            raise InputError("GCP_RECORD_OBJECT_REQUIRED")
        validate_identity(raw, source)
        config = dict(raw)
        # The effective-policy flag is operation provenance, not an inferred policy result.
        config["_parameters"] = source.request_parameters or {}
        config["_collection"] = {
            key: value
            for key, value in (source.gcp_metadata or {}).items()
            if key in {"status", "provenance", "completed_at", "max_key_age_days"}
        }
        native = raw.get(identity_field)
        # gcloud's Cloud Run v1 transport is a Knative object, unlike REST v2.
        # The metadata name needs an observed region before canonicalization.
        if kind in {"GCP::RunService", "GCP::RunJob"} and not native:
            meta = raw.get("metadata")
            if isinstance(meta, dict) and isinstance(meta.get("name"), str):
                namespace = meta.get("namespace")
                if namespace and namespace not in {source.project_id, source.project_number}:
                    raise mismatch(
                        source.path or "manifest",
                        source.project_id,
                        "metadata.namespace",
                        namespace,
                    )
                native = meta["name"]
                labels = meta.get("labels") or {}
                if isinstance(labels, dict) and isinstance(
                    labels.get("cloud.googleapis.com/location"), str
                ):
                    config["location"] = labels["cloud.googleapis.com/location"]
        if kind == "GCP::IAMPolicy":
            native = (source.request_parameters or {}).get("subject")
            if source.operation == "gcp:projects.getIamPolicy":
                native = native or f"projects/{source.project_id}"
            if not isinstance(raw.get("bindings", []), list):
                raise InputError("GCP_IAM_BINDINGS_SHAPE")
            config["bindings"] = raw.get("bindings", [])
        if kind == "GCP::OrgPolicy":
            native = native or (source.request_parameters or {}).get("constraint")
        if kind == "GCP::Project":
            native = raw.get("projectId")
        native = native if isinstance(native, str) and native else None
        if native:
            validate_identity({"name": native}, source)
        region = config.get("location") or raw.get("zone") or source.region or "global"
        if not isinstance(region, str):
            region = source.region or "global"
        if expanded:
            from offline_analyzer.normalization.gcp_expanded import canonical_native

            native, region = canonical_native(config, source, kind, native)
            if (
                kind in {"GCP::RunService", "GCP::RunJob"}
                and native
                and "/" not in native
                and region == "global"
            ):
                native = None  # Bare name without an observed region cannot identify a service.
            if native:
                validate_identity({"name": native}, source)
        locator = (
            f"/{index}"
            if shape["root"] == "start_array"
            else f"/{profile[1]}/{index}"
            if profile and profile[1]
            else "/"
        )
        if scc_wrapped:
            locator = locator.rstrip("/") + "/finding"

        def observation(
            record_kind: str,
            record_native: str | None,
            configuration: dict,
            pointer: str = locator,
            record_region: str = region,
        ):
            rid = (
                resource_id(source.project_id, record_kind, record_native, record_region)
                if record_native
                else None
            )
            if expanded and record_native:
                from offline_analyzer.normalization.gcp_expanded import canonical_resource

                rid = canonical_resource(
                    source.project_id, record_kind, record_native, record_region
                )
            return Normalized(
                observation_id=stable_id("gcp-observation", [rid, source.operation, configuration]),
                provider="GCP",
                project_id=source.project_id,
                project_number=source.project_number
                or (
                    str(configuration["projectNumber"])
                    if record_kind == "GCP::Project"
                    and configuration.get("projectNumber") is not None
                    else None
                ),
                organization_id=(source.gcp_metadata or {}).get("organization_id"),
                folder_id=(source.gcp_metadata or {}).get("folder_id"),
                account_id=None,
                region=record_region,
                resource_id=rid,
                native_id=record_native,
                resource_type=record_kind,
                partition="gcp",
                source_tool="gcp",
                source_version=source.collector_version,
                source_details={
                    "parser_profile": "gcp-expanded-native-1.1.0" if expanded else VERSION,
                    **(
                        {
                            "domain": (source.gcp_metadata or {}).get("domain"),
                            "dataset": (source.gcp_metadata or {}).get("dataset"),
                            "support_status": "SUPPORTED" if contract else "UNSUPPORTED",
                            "analysis_support": contract.get("analysis_support", "NOT_EVALUATED"),
                        }
                        if expanded
                        else {}
                    ),
                },
                source_check_id=source.operation,
                source_status=(source.gcp_metadata or {}).get("status"),
                source_severity=configuration.get("severity")
                if record_kind == "GCP::SCCFinding"
                else None,
                source_finding_id=record_native if record_kind == "GCP::SCCFinding" else None,
                collected_at=source.collected_at
                if (source.gcp_metadata or {}).get("completed_at")
                else None,
                operation=source.operation,
                configuration=configuration,
                evidence=EvidenceRef(artifact_id=artifact, locator=pointer),
                integrity_sha256=source.sha256,
                unresolved=("GCP_PROJECT_NUMBER_UNVERIFIED",)
                if expanded
                and not source.project_number
                and record_native
                and re.search(r"(?:^|/)projects/[0-9]{1,20}(?:/|$)", record_native)
                else ("GCP_PARENT_SCOPE_SUMMARY_NOT_EFFECTIVE_PERMISSIONS",)
                if contract.get("family") in {"folder_iam_search", "organization_iam_search"}
                else ()
                if record_native
                else ("GCP_NATIVE_IDENTITY_MISSING",),
            )

        yield observation(kind, native, config)
        if kind == "GCP::LoggingSink" and native and "exclusions" in raw:
            exclusions = raw["exclusions"]
            if not isinstance(exclusions, list):
                raise InputError("GCP_LOGGING_EXCLUSIONS_SHAPE")
            for exclusion_index, exclusion in enumerate(exclusions):
                if not isinstance(exclusion, dict) or not isinstance(exclusion.get("name"), str):
                    raise InputError("GCP_LOGGING_EXCLUSIONS_SHAPE")
                yield observation(
                    "GCP::LoggingExclusion",
                    native + "/exclusions/" + exclusion["name"],
                    {
                        **exclusion,
                        "sink": native,
                        "_parameters": config["_parameters"],
                        "_collection": config["_collection"],
                    },
                    locator.rstrip("/") + f"/exclusions/{exclusion_index}",
                )
        if kind == "GCP::IAMPolicy" and native:
            for binding_index, binding in enumerate(config["bindings"]):
                if not isinstance(binding, dict):
                    raise InputError("GCP_IAM_BINDINGS_SHAPE")
                if not isinstance(binding.get("members"), list) or not isinstance(
                    binding.get("role"), str
                ):
                    raise InputError("GCP_IAM_BINDINGS_SHAPE")
                if any(not isinstance(member, str) for member in binding["members"]):
                    raise InputError("GCP_IAM_BINDINGS_SHAPE")
                binding_native = native + "/bindings/" + stable_id("binding", binding)
                yield observation(
                    "GCP::IAMBinding",
                    binding_native,
                    {
                        **binding,
                        "subject": native,
                        "_parameters": config["_parameters"],
                        "_collection": config["_collection"],
                    },
                    locator.rstrip("/") + f"/bindings/{binding_index}",
                )


def source_record_count(path: Path, source: Source, shape: dict) -> int:
    return sum(1 for _ in native_records(path, source.operation, shape, source))
