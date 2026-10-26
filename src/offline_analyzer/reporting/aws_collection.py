"""AWS collector 0.3.3 collection facts and error categories as coverage reasons.

Two inputs, both collection metadata, never security results:

* `collection_facts` from the collector manifest (retries, detail limits, dependency
  fallbacks, Region and organization access, resume) are read from the stored collection
  summary of each AWS import;
* the error code on a failed or skipped AWS source is mapped to a category (throttled,
  expired credentials, timeout, connection error, Region not enabled, service not in use,
  access denied).

Every resulting reason describes a gap or a limitation; none supports a PASS. The code tables
mirror collectors/aws/assessment.py; tests/test_aws_collector_033.py keeps them in sync.
"""

from collections import Counter

# Mirrors of the collector's classification tables (contract-sync test).
THROTTLED = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "RequestThrottledException",
        "TooManyRequestsException",
        "ProvisionedThroughputExceededException",
        "TransactionInProgressException",
        "RequestLimitExceeded",
        "BandwidthLimitExceeded",
        "LimitExceededException",
        "RequestThrottled",
        "SlowDown",
        "PriorRequestNotComplete",
        "EC2ThrottledException",
    }
)
EXPIRED = frozenset({"ExpiredToken", "ExpiredTokenException", "TokenRefreshRequired"})
CREDENTIAL_ERRORS = frozenset(
    {
        "NoCredentialsError",
        "PartialCredentialsError",
        "CredentialRetrievalError",
        "UnauthorizedSSOTokenError",
        "SSOTokenLoadError",
        "TokenRetrievalError",
        "RefreshWithMFAUnsupportedError",
        "CredentialsExpired",
        "CREDENTIALS_EXPIRED",
    }
)
NOT_IN_USE = frozenset(
    {"SubscriptionRequiredException", "OptInRequired", "ENDPOINT_NOT_OFFERED_IN_REGION"}
)
TIMEOUTS = frozenset({"ConnectTimeoutError", "ReadTimeoutError", "TIMEOUT"})
CONNECTION = frozenset(
    {
        "EndpointConnectionError",
        "ConnectionClosedError",
        "ProxyConnectionError",
        "SSLError",
        "HTTPClientError",
        "ConnectionError",
    }
)
DENIED = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "UnauthorizedException",
        "AccessDeniedFault",
        "Forbidden",
        "UnrecognizedClientException",
    }
)

# collection_facts keys written by collector 0.3.3 and how the analyzer consumes each one:
# reason codes for gaps and limitations, PROVENANCE for facts shown with the collection.
FACT_CONSUMERS = {
    "collector_runtime": "PROVENANCE",
    "encoding": "PROVENANCE",
    "options": ("AWS_RETRIES_DISABLED",),
    "retries": ("AWS_RETRIES_PERFORMED",),
    "detail_limits": ("AWS_DETAIL_LIMIT_REACHED",),
    "dependency_fallbacks": ("AWS_DEPENDENCY_FALLBACK",),
    "regions_attempted": ("AWS_REGIONS_PARTIAL",),
    "regions_succeeded": ("AWS_REGIONS_PARTIAL",),
    "regions_partial": ("AWS_REGIONS_PARTIAL",),
    "regions_not_enabled": ("AWS_REGIONS_NOT_ENABLED",),
    "region_status_source": ("AWS_REGION_STATUS_UNAVAILABLE",),
    "organization": (
        "AWS_ORGANIZATION_ACCESS_MISSING",
        "AWS_ORGANIZATION_INCOMPLETE",
        "AWS_NOT_IN_ORGANIZATION",
    ),
    "resumed_from": ("AWS_COLLECTION_RESUMED",),
    "resumed_at": ("AWS_COLLECTION_RESUMED",),
    "carried_operations": ("AWS_COLLECTION_RESUMED",),
    "credentials_expired": ("AWS_COLLECTION_INTERRUPTED_CREDENTIALS",),
}

ERROR_REASONS = {
    "AWS_ACCESS_DENIED": (
        "The collection role was denied this AWS API (AccessDenied or equivalent). The service "
        "state is unknown; insufficient coverage, never a pass."
    ),
    "AWS_THROTTLED_AFTER_RETRIES": (
        "AWS throttled the request and the collector's bounded retries were exhausted; "
        "nothing was collected. Recollect (resume) at a quieter time."
    ),
    "AWS_CREDENTIALS_EXPIRED": (
        "The collection credentials expired or could not be refreshed (sign-in expired); "
        "nothing was collected. Sign in again and resume the collection."
    ),
    "AWS_TIMEOUT": "The AWS API did not answer within the configured timeout after retries.",
    "AWS_CONNECTION_ERROR": (
        "The AWS endpoint could not be reached (network, proxy or TLS failure) after retries."
    ),
    "AWS_REGION_NOT_ENABLED": (
        "The Region is not enabled (opted out) in this account, so no request was made. Not a "
        "pass: the Region was not assessed."
    ),
    "AWS_SERVICE_NOT_IN_USE": (
        "AWS reported that the account is not subscribed to this service, or the service is "
        "not offered in the Region. Not a pass: no evidence exists for it."
    ),
    "AWS_COLLECTION_FAILED": "The AWS API call failed; no evidence for this operation.",
}
NOTE_REASONS = {
    "AWS_RETRIES_PERFORMED": (
        "The collector retried throttled, timed-out or failed requests; every retry is listed "
        "in the package manifest. Retried operations that then succeeded are complete."
    ),
    "AWS_RETRIES_DISABLED": (
        "The collection ran with retries disabled (max_attempts 1); transient failures were "
        "not retried."
    ),
    "AWS_DETAIL_LIMIT_REACHED": (
        "An AWS listing stopped at the page or per-operation time limit; the operation is "
        "partial (coverage Partial)."
    ),
    "AWS_DEPENDENCY_FALLBACK": (
        "A parent listing was incomplete, so its per-resource details were not requested or "
        "were requested through the home Region (listed in the manifest)."
    ),
    "AWS_REGIONS_NOT_ENABLED": (
        "Requested Regions are not enabled in this account and were not collected; they are "
        "outside the assessed scope."
    ),
    "AWS_REGIONS_PARTIAL": (
        "In some declared Regions at least one operation did not complete; results there are "
        "limited to the collected evidence."
    ),
    "AWS_REGION_STATUS_UNAVAILABLE": (
        "The Region opt-in status could not be read (ec2:DescribeRegions failed); every "
        "requested Region was attempted."
    ),
    "AWS_ORGANIZATION_ACCESS_MISSING": (
        "The collector was denied AWS Organizations policy access (normal for member "
        "accounts): organization controls (SCPs, RCPs) were not assessed. Absence is never "
        'read as "no SCP".'
    ),
    "AWS_ORGANIZATION_INCOMPLETE": (
        "The organization hierarchy or its SCP/RCP listings were only partly collected; "
        "organization controls remain unknown."
    ),
    "AWS_NOT_IN_ORGANIZATION": (
        "AWS reported that the account is not a member of an organization; SCPs and RCPs do "
        "not apply."
    ),
    "AWS_COLLECTION_RESUMED": (
        "This package resumes an earlier collection: complete evidence was carried over after "
        "SHA-256 re-verification and only failed or missing operations were collected again."
    ),
    "AWS_COLLECTION_INTERRUPTED_CREDENTIALS": (
        "The collection stopped because the credentials expired; the remaining operations "
        "were not attempted. Resume after signing in."
    ),
}


def error_category(errors, coverage: str | None) -> str | None:
    """Coverage reason code for a failed or skipped AWS source, from its error code."""
    codes = [c for c in errors or () if isinstance(c, str)]
    if coverage not in {"ERROR", "NOT_COLLECTED"} or not codes:
        return None
    code = codes[0]
    if code == "REGION_NOT_ENABLED":
        return "AWS_REGION_NOT_ENABLED"
    if code in EXPIRED or code in CREDENTIAL_ERRORS:
        return "AWS_CREDENTIALS_EXPIRED"
    if code in THROTTLED or code.startswith("ASSUME_ROLE_THROTTLED"):
        return "AWS_THROTTLED_AFTER_RETRIES"
    if code in DENIED or "AccessDenied" in code or code.startswith("ASSUME_ROLE_"):
        return "AWS_ACCESS_DENIED"
    if code in NOT_IN_USE:
        return "AWS_SERVICE_NOT_IN_USE"
    if code in TIMEOUTS:
        return "AWS_TIMEOUT"
    if code in CONNECTION:
        return "AWS_CONNECTION_ERROR"
    return "AWS_COLLECTION_FAILED" if coverage == "ERROR" else None


def fact_notes(facts: dict | None) -> Counter:
    """Reason code -> count for one AWS package's manifest collection_facts."""
    notes: Counter = Counter()
    if not isinstance(facts, dict):
        return notes
    options = facts.get("options") or {}
    if options.get("max_attempts") == 1:
        notes["AWS_RETRIES_DISABLED"] += 1
    total = (facts.get("retries") or {}).get("total")
    if isinstance(total, int) and total > 0:
        notes["AWS_RETRIES_PERFORMED"] += total
    limits = facts.get("detail_limits") or {}
    reached = len(limits.get("reached") or []) + int(limits.get("reached_omitted") or 0)
    if reached:
        notes["AWS_DETAIL_LIMIT_REACHED"] += reached
    fallbacks = facts.get("dependency_fallbacks") or {}
    count = len(fallbacks.get("entries") or []) + int(fallbacks.get("entries_omitted") or 0)
    if count:
        notes["AWS_DEPENDENCY_FALLBACK"] += count
    if facts.get("regions_not_enabled"):
        notes["AWS_REGIONS_NOT_ENABLED"] += len(facts["regions_not_enabled"])
    if facts.get("regions_partial"):
        notes["AWS_REGIONS_PARTIAL"] += len(facts["regions_partial"])
    if str(facts.get("region_status_source") or "").startswith("UNAVAILABLE"):
        notes["AWS_REGION_STATUS_UNAVAILABLE"] += 1
    access = (facts.get("organization") or {}).get("access")
    code = {
        "ACCESS_DENIED": "AWS_ORGANIZATION_ACCESS_MISSING",
        "INCOMPLETE": "AWS_ORGANIZATION_INCOMPLETE",
        "NOT_IN_ORGANIZATION": "AWS_NOT_IN_ORGANIZATION",
    }.get(access)
    if code:
        notes[code] += 1
    if facts.get("resumed_from"):
        notes["AWS_COLLECTION_RESUMED"] += int(facts.get("carried_operations") or 0) or 1
    if facts.get("credentials_expired"):
        notes["AWS_COLLECTION_INTERRUPTED_CREDENTIALS"] += 1
    return notes


def members(store, run_id: str) -> list[str]:
    import json

    row = store.db.execute(
        "SELECT members FROM enterprise_snapshots WHERE run_id=?", [run_id]
    ).fetchone()
    return json.loads(row[0]) if row else [run_id]


def account_notes(store, run_id: str) -> dict[str, Counter]:
    """AWS account -> reason code counts from every member import's collection facts."""
    from offline_analyzer.ingestion.collector import stored_summary

    result: dict[str, Counter] = {}
    for member in members(store, run_id):
        summary = stored_summary(store.workspace, member) or {}
        facts = summary.get("collection_facts")
        account = summary.get("account_id")
        if facts and account:
            result.setdefault(account, Counter()).update(fact_notes(facts))
    return result


def reason(code: str) -> str:
    return ERROR_REASONS.get(code) or NOTE_REASONS.get(code) or code
