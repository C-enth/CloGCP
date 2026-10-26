"""Plain-language reasons for collection gaps and coverage notes (codes only in storage).

Every reason describes a collection gap or limitation. None is a security result, and none
can support a PASS: failed collections are ERROR coverage, limited ones stay PARTIAL.
"""

ERROR_REASONS = {
    "COLLECTION_FAILED": "Collection failed; no evidence for this operation.",
    "API_DISABLED_OR_UNAVAILABLE": (
        "Service not enabled (per enabled-services evidence). A collection gap: it does not "
        "prove that no resources exist and is never a pass."
    ),
    "COLLECTION_PERMISSION_FAILURE": (
        "The collector identity was denied access (HTTP 403 / PERMISSION_DENIED). "
        "Insufficient coverage."
    ),
    "COLLECTOR_COMMAND_ERROR": "The collector command was rejected; the collector needs a fix.",
    "COLLECTION_AUTH_FAILURE": (
        "The gcloud sign-in expired or needed reauthentication; nothing was collected. Sign "
        "in again and recollect."
    ),
    "COLLECTION_TRUNCATED": "The listing stopped at the page or detail budget; incomplete.",
    "COLLECTION_RATE_LIMITED": (
        "The cloud API rate-limited the collector (HTTP 429 / RESOURCE_EXHAUSTED) after "
        "bounded retries; nothing was collected."
    ),
    "COLLECTION_NOT_FOUND": "The requested resource was not found (HTTP 404).",
    "COLLECTION_HTTP_ERROR": "The API returned an HTTP error.",
    "COLLECTION_SERVER_ERROR": "The API returned a server error (5xx) after bounded retries.",
    "COLLECTION_LOCATIONS_UNREACHABLE": "The API reported unreachable locations; incomplete.",
    "COLLECTION_TIMEOUT": "The command exceeded its time limit and was stopped.",
    "COLLECTION_QUOTA_PROJECT_DENIED": (
        "The quota/billing project was refused (user credentials without an approved "
        "-QuotaProject, or the service is disabled in the quota project, not the target). "
        "Insufficient coverage; recollect with an approved -QuotaProject."
    ),
    "COLLECTION_UNEXPECTED_RESPONSE_SCHEMA": "The response shape was not recognised.",
    "COLLECTION_INVALID_OUTPUT": "The command output was not valid JSON.",
    "COLLECTION_UNSUPPORTED_ENDPOINT": "No supported endpoint exists; nothing was requested.",
}
NOTE_REASONS = {
    "COLLECTION_INTERRUPTED": "The collection run was interrupted before completion.",
    "DISCOVERY_DETAIL_COLLECTION_LIMIT_REACHED": (
        "-MaxDetailItems stopped Discovery Engine details; remaining items not described."
    ),
    "BIGQUERY_DETAIL_COLLECTION_LIMIT_REACHED": (
        "-MaxDetailItems stopped BigQuery dataset details; remaining items not described."
    ),
    "DETAIL_LIMIT_REACHED_SERVICE_ACCOUNTS": (
        "-MaxDetailItems stopped service-account key/IAM details; remaining accounts not "
        "described (coverage Partial)."
    ),
    "DETAIL_LIMIT_REACHED_BUCKETS": (
        "-MaxDetailItems stopped bucket IAM/details; remaining buckets not described "
        "(coverage Partial)."
    ),
    "DETAIL_LIMIT_REACHED_API_KEYS": (
        "-MaxDetailItems stopped API-key details; remaining keys not described (coverage Partial)."
    ),
    "DETAIL_LIMIT_REACHED_CUSTOM_ROLES": (
        "-MaxDetailItems stopped custom-role details; remaining roles not described "
        "(coverage Partial)."
    ),
    "DETAIL_LIMIT_REACHED_KMS": (
        "-MaxDetailItems stopped KMS key-ring/key expansion; remaining items not listed "
        "(coverage Partial)."
    ),
    "IAM_TARGET_LIST_INCOMPLETE": (
        "The service/function list was PARTIAL or TRUNCATED; IAM was collected only for the "
        "listed targets (coverage Partial)."
    ),
    "IAM_TARGETS_FROM_GCLOUD_LIST": (
        "The REST list failed; IAM targets came from the gcloud list instead (fallback)."
    ),
    "IAM_TARGETS_FALLBACK_USED": (
        "This list failed; the collector used the gcloud list to find IAM targets."
    ),
    "IAM_TARGETS_UNAVAILABLE": (
        "The service/function lists failed (fallback also failed or absent); IAM was not "
        "collected. UNKNOWN, never a pass."
    ),
}
# Present on every expanded GCP source; not repeated as a per-row note.
ROUTINE = {
    "COLLECTOR_PAGINATION_UNVERIFIED",
    "REST_EMPTY_RESPONSE_FIELD_PRESENCE_UNVERIFIED",
    "SOURCE_CHECKSUMS_ABSENT",
}


def notable(error_category: str | None, limitations) -> list[str]:
    """Codes worth a reader's attention, error first, routine limitations dropped."""
    codes = [error_category] if error_category else []
    codes += [c for c in limitations or () if c not in ROUTINE and c not in codes]
    return codes


def reason_text(error_category: str | None, limitations) -> str:
    texts = [
        ERROR_REASONS.get(code) or NOTE_REASONS.get(code) or code
        for code in notable(error_category, limitations)
    ]
    return " ".join(texts)


def _merge_aws() -> None:
    from offline_analyzer.reporting.aws_collection import ERROR_REASONS as AWS_ERRORS
    from offline_analyzer.reporting.aws_collection import NOTE_REASONS as AWS_NOTES

    ERROR_REASONS.update(AWS_ERRORS)
    NOTE_REASONS.update(AWS_NOTES)


_merge_aws()


def source_category(source: dict) -> str | None:
    """Error category of a stored source: the GCP collector's own category, or the AWS
    error-code category (reporting/aws_collection.py)."""
    metadata = source.get("gcp_metadata") or {}
    if metadata.get("error_category"):
        return metadata["error_category"]
    if source.get("format") == "gcp-json-v1":
        return None
    from offline_analyzer.reporting.aws_collection import error_category

    return error_category(source.get("errors"), source.get("coverage"))
