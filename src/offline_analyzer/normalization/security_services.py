"""Security-service state profiles: CloudTrail, GuardDuty, AWS Config, Security Hub, KMS.

Parsers only normalize. Regional service-state responses (for example an empty
GuardDuty detector list) become one regional-status observation so that rules can
distinguish "collected and absent" from "not collected"; no control decision is made
here. Identity comes from verified request subjects or response fields, never names.
"""

from offline_analyzer.ingestion.json_input import InputError, records

# operation: (resource kind, identity source, retained fields)
# identity source: "request:<param>", "field:<dotted path>" or "region" (account+Region).
PROFILES = {
    "cloudtrail:GetTrailStatus": (
        "AWS::CloudTrail::TrailStatus",
        "request:Name",
        ("IsLogging", "LatestDeliveryError", "StartLoggingTime", "StopLoggingTime"),
    ),
    "cloudtrail:GetEventSelectors": (
        "AWS::CloudTrail::EventSelectors",
        "field:TrailARN",
        ("EventSelectors", "AdvancedEventSelectors"),
    ),
    "guardduty:ListDetectors": ("AWS::GuardDuty::RegionalStatus", "region", ("DetectorIds",)),
    "guardduty:GetDetector": (
        "AWS::GuardDuty::Detector",
        "request:DetectorId",
        ("Status", "FindingPublishingFrequency", "Features"),
    ),
    "config:DescribeConfigurationRecorderStatus": (
        "AWS::Config::RegionalStatus",
        "region",
        ("ConfigurationRecordersStatus",),
    ),
    "securityhub:DescribeHub": (
        "AWS::SecurityHub::RegionalStatus",
        "region",
        ("HubArn", "SubscribedAt", "AutoEnableControls"),
    ),
    "kms:DescribeKey": ("AWS::KMS::Key", "field:KeyMetadata.Arn", ("KeyMetadata",)),
    "kms:GetKeyRotationStatus": (
        "AWS::KMS::KeyRotation",
        "request:KeyId",
        ("KeyRotationEnabled", "RotationPeriodInDays"),
    ),
}
# AWS-defined error codes that describe a service state rather than a collection failure.
ABSENCE = {"securityhub:DescribeHub": "InvalidAccessException"}
OPERATIONS = tuple(PROFILES)


def _field(document: dict, path: str):
    value = document
    for part in path.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


def service_records(path, source, artifact, shape):
    from offline_analyzer.normalization.adapters import mapping, normalized, text

    kind, identity, keys = PROFILES[source.operation]
    if shape["root"] != "start_map":
        raise InputError("UNSUPPORTED_AWS_RESPONSE_SHAPE")
    params = source.request_parameters or {}
    for _, document in records(path, ""):
        document = mapping(document)
        issues: tuple[str, ...] = ()
        error = document.get("Error") if isinstance(document.get("Error"), dict) else None
        config = {k: document.get(k) for k in keys}
        if error:
            if ABSENCE.get(source.operation) != error.get("Code"):
                return  # A failed call is a collection gap, never a configuration state.
            config = {"Enabled": False, "AbsenceCode": error.get("Code")}
        elif kind.endswith("RegionalStatus"):
            config["Enabled"] = True if kind.startswith("AWS::SecurityHub") else None
        if identity == "region":
            native = (
                f"{source.account_id}:{source.region}:{kind.split('::')[1].lower()}"
                if source.account_id and source.region
                else None
            )
        elif identity.startswith("request:"):
            native = params.get(identity.split(":", 1)[1])
        else:
            native = _field(document, identity.split(":", 1)[1])
        native = text(native)
        if kind in {"AWS::CloudTrail::TrailStatus", "AWS::KMS::KeyRotation"} and not str(
            native or ""
        ).startswith("arn:"):
            issues += ("resource ARN required to correlate with its configuration",)
        if kind == "AWS::GuardDuty::Detector" and native and source.region:
            native = f"{source.account_id}:{source.region}:detector/{native}"
        yield normalized(
            source,
            artifact,
            source.sha256,
            "/" + (keys[0] if not error else "Error"),
            native=native,
            kind=kind,
            account=source.account_id,
            region=source.region,
            timestamp=source.collected_at,
            version=source.collector_version,
            status="OBSERVED",
            config=config,
            issues=issues,
            details={"request_parameters": source.request_parameters},
        )
