"""Local-only compatibility diagnostics: no raw values, filenames or unknown key names."""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from offline_analyzer.contracts.r0 import AWS_OPERATIONS, NORMALIZATION_VERSION, Package
from offline_analyzer.ingestion.coverage import PARAMETERS, collection_facts
from offline_analyzer.ingestion.importer import load_package, single_file_package, snapshot
from offline_analyzer.ingestion.json_input import MAX_PACKAGE_BYTES, InputError, inspect_json
from offline_analyzer.ingestion.safety import resolve_under, sha256_file
from offline_analyzer.normalization.adapters import aws_records, prowler_records
from offline_analyzer.normalization.enterprise_adapters import PROFILES as ENTERPRISE_PROFILES

# Never export arbitrary imported field names: they may themselves contain secrets.
PATHS = {
    "",
    "item",
    "item.class_uid",
    "item.time",
    "item.time_dt",
    "item.status_code",
    "item.status_id",
    "item.status",
    "item.severity",
    "item.metadata",
    "item.metadata.event_code",
    "item.metadata.version",
    "item.metadata.product",
    "item.metadata.product.name",
    "item.metadata.product.version",
    "item.metadata.profiles",
    "item.metadata.profiles.item",
    "item.finding_info",
    "item.finding_info.uid",
    "item.finding_info.desc",
    "item.message",
    "item.status_detail",
    "item.cloud",
    "item.cloud.provider",
    "item.cloud.region",
    "item.cloud.account",
    "item.cloud.account.uid",
    "item.resources",
    "item.resources.item",
    "item.resources.item.uid",
    "item.resources.item.type",
    "item.resources.item.region",
    "item.resources.item.cloud_partition",
    "item.resources.item.data",
    "Reservations",
    "Reservations.item",
    "Reservations.item.Instances",
    "Reservations.item.OwnerId",
    "Reservations.item.Instances.item",
    "Reservations.item.Instances.item.InstanceId",
    "Reservations.item.Instances.item.State",
    "Reservations.item.Instances.item.State.Name",
    "Reservations.item.Instances.item.MetadataOptions",
    "Reservations.item.Instances.item.MetadataOptions.State",
    "Reservations.item.Instances.item.MetadataOptions.HttpTokens",
    "Reservations.item.Instances.item.MetadataOptions.HttpEndpoint",
    "DBInstances",
    "DBInstances.item",
    "DBInstances.item.DBInstanceArn",
    "DBInstances.item.Engine",
    "DBInstances.item.StorageEncrypted",
    "DBInstances.item.DBClusterIdentifier",
    "trailList",
    "trailList.item",
    "trailList.item.TrailARN",
    "trailList.item.HomeRegion",
    "trailList.item.LogFileValidationEnabled",
    "trailList.item.IsOrganizationTrail",
    "trailList.item.IsMultiRegionTrail",
    "DBInstances.item.PubliclyAccessible",
    "Reservations.item.Instances.item.MetadataOptions.HttpPutResponseHopLimit",
    "SecurityGroups",
    "SecurityGroups.item",
    "SecurityGroups.item.GroupId",
    "SecurityGroups.item.OwnerId",
    "SecurityGroups.item.IpPermissions",
    "SecurityGroups.item.IpPermissions.item",
    "SecurityGroups.item.IpPermissions.item.IpProtocol",
    "SecurityGroups.item.IpPermissions.item.FromPort",
    "SecurityGroups.item.IpPermissions.item.ToPort",
    "SecurityGroups.item.IpPermissions.item.IpRanges",
    "SecurityGroups.item.IpPermissions.item.Ipv6Ranges",
    "SecurityGroups.item.IpPermissions.item.PrefixListIds",
    "NetworkInterfaces",
    "NetworkInterfaces.item",
    "NetworkInterfaces.item.NetworkInterfaceId",
    "NetworkInterfaces.item.OwnerId",
    "NetworkInterfaces.item.Status",
    "NetworkInterfaces.item.InterfaceType",
    "NetworkInterfaces.item.RequesterManaged",
    "NetworkInterfaces.item.Groups",
    "NetworkInterfaces.item.Association",
    "NetworkInterfaces.item.Attachment",
    "NetworkInterfaces.item.PrivateIpAddresses",
    "NetworkInterfaces.item.Ipv6Addresses",
    "RoleDetailList",
    "RoleDetailList.item",
    "RoleDetailList.item.Arn",
    "RoleDetailList.item.AssumeRolePolicyDocument",
    "Roles",
    "Roles.item",
    "Roles.item.Arn",
    "Roles.item.AssumeRolePolicyDocument",
    "PublicAccessBlockConfiguration",
    "PublicAccessBlockConfiguration.BlockPublicAcls",
    "PublicAccessBlockConfiguration.IgnorePublicAcls",
    "PublicAccessBlockConfiguration.BlockPublicPolicy",
    "PublicAccessBlockConfiguration.RestrictPublicBuckets",
    "RouteTables",
    "RouteTables.item",
    "RouteTables.item.RouteTableId",
    "RouteTables.item.OwnerId",
    "RouteTables.item.VpcId",
    "RouteTables.item.Associations",
    "RouteTables.item.Routes",
    "PolicyStatus",
    "PolicyStatus.IsPublic",
    "Grants",
    "Grants.item",
    "Grants.item.Grantee",
    "Grants.item.Permission",
    "Policies",
    "Policies.item",
    "Policies.item.Arn",
    "Policies.item.PolicyVersionList",
    "RoleDetailList.item.AttachedManagedPolicies",
    "RoleDetailList.item.RolePolicyList",
    "NetworkInterfaces.item.SubnetId",
    "DBInstances.item.Endpoint",
    "DBInstances.item.VpcSecurityGroups",
    "DBInstances.item.DBSubnetGroup",
    "ResponseMetadata",
    "ResponseMetadata.HTTPStatusCode",
    "Error",
    "Error.Code",
    "Errors",
    "Errors.item",
    "NextToken",
    "Marker",
    "NextMarker",
    "IsTruncated",
}
REQUIRED = {
    "aws-json-v1": {},
    "prowler-ocsf-5.10": {
        "item": [
            "class_uid",
            "metadata.product.name",
            "metadata.product.version",
            "metadata.event_code",
            "finding_info.uid",
            "cloud.account.uid",
            "status_code",
            "status_id",
        ],
        "item.resources.item": ["uid", "type", "region"],
    },
}
REQUIRED["prowler-ocsf-5.26.1"] = REQUIRED["prowler-ocsf-5.10"]
PATHS.update({"Account", "Arn", "UserId"})

REQUIRED_AWS = {
    "sts:GetCallerIdentity": {"": ["Account", "Arn", "UserId"]},
    "ec2:DescribeInstances": {
        "Reservations.item.Instances.item": [
            "InstanceId",
            "State.Name",
            "MetadataOptions.State",
            "MetadataOptions.HttpTokens",
            "MetadataOptions.HttpEndpoint",
        ]
    },
    "rds:DescribeDBInstances": {
        "DBInstances.item": ["DBInstanceArn", "Engine", "StorageEncrypted"]
    },
    "cloudtrail:DescribeTrails": {
        "trailList.item": ["TrailARN", "HomeRegion", "LogFileValidationEnabled"]
    },
    "ec2:DescribeSecurityGroups": {"SecurityGroups.item": ["GroupId", "OwnerId", "IpPermissions"]},
    "ec2:DescribeNetworkInterfaces": {
        "NetworkInterfaces.item": [
            "NetworkInterfaceId",
            "OwnerId",
            "Status",
            "InterfaceType",
            "RequesterManaged",
            "Groups",
        ]
    },
    "iam:GetAccountAuthorizationDetails": {
        "RoleDetailList.item": ["Arn", "AssumeRolePolicyDocument"]
    },
    "iam:ListRoles": {"Roles.item": ["Arn", "AssumeRolePolicyDocument"]},
    "ec2:DescribeRouteTables": {
        "RouteTables.item": ["RouteTableId", "OwnerId", "VpcId", "Associations", "Routes"]
    },
    "s3api:GetPublicAccessBlock": {
        "PublicAccessBlockConfiguration": [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]
    },
    "s3api:GetBucketPolicyStatus": {"PolicyStatus": ["IsPublic"]},
    "s3api:GetBucketAcl": {"Grants.item": ["Grantee", "Permission"]},
    # A defined NoSuchPublicAccessBlockConfiguration response legitimately lacks these.
    "s3control:GetPublicAccessBlock": {
        "PublicAccessBlockConfiguration": [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]
    },
}
# Fixed field names only; no imported keys or policy contents enter diagnostics.
REQUIRED_AWS.update(
    {
        "cloudtrail:GetTrailStatus": {"": ["IsLogging"]},
        "cloudtrail:GetEventSelectors": {"": ["TrailARN"]},
        "guardduty:ListDetectors": {"": ["DetectorIds"]},
        "guardduty:GetDetector": {"": ["Status"]},
        "config:DescribeConfigurationRecorderStatus": {"": ["ConfigurationRecordersStatus"]},
        "securityhub:DescribeHub": {"": ["HubArn"]},
        "kms:DescribeKey": {"KeyMetadata": ["Arn", "KeyManager", "KeyState"]},
        "kms:GetKeyRotationStatus": {"": ["KeyRotationEnabled"]},
        "iam:GetRole": {"Role": ["Arn", "RoleName", "AssumeRolePolicyDocument"]},
        "iam:ListAttachedRolePolicies": {
            "": ["AttachedPolicies", "IsTruncated"],
            "AttachedPolicies.item": ["PolicyArn", "PolicyName"],
        },
        "iam:ListRolePolicies": {"": ["PolicyNames", "IsTruncated"]},
        "iam:GetRolePolicy": {"": ["RoleName", "PolicyName", "PolicyDocument"]},
        "iam:GetPolicy": {"Policy": ["Arn", "PolicyName", "DefaultVersionId"]},
        "iam:GetPolicyVersion": {"PolicyVersion": ["Document", "VersionId", "IsDefaultVersion"]},
        "iam:ListInstanceProfilesForRole": {
            "": ["InstanceProfiles", "IsTruncated"],
            "InstanceProfiles.item": ["Arn", "InstanceProfileName", "Roles"],
            "InstanceProfiles.item.Roles.item": ["Arn"],
        },
        "iam:GetInstanceProfile": {
            "InstanceProfile": ["Arn", "InstanceProfileName", "Roles"],
            "InstanceProfile.Roles.item": ["Arn"],
        },
        "organizations:DescribeOrganization": {
            "Organization": ["Id", "MasterAccountId", "FeatureSet"]
        },
        "organizations:ListRoots": {
            "": ["Roots"],
            "Roots.item": ["Id", "PolicyTypes"],
            "Roots.item.PolicyTypes.item": ["Type", "Status"],
        },
        "organizations:ListOrganizationalUnitsForParent": {
            "": ["OrganizationalUnits"],
            "OrganizationalUnits.item": ["Id"],
        },
        "organizations:ListAccountsForParent": {"": ["Accounts"], "Accounts.item": ["Id"]},
        "organizations:ListAccounts": {"": ["Accounts"], "Accounts.item": ["Id"]},
        "organizations:ListParents": {"": ["Parents"], "Parents.item": ["Id", "Type"]},
        "organizations:ListPolicies": {
            "": ["Policies"],
            "Policies.item": ["Id", "Type", "AwsManaged"],
        },
        "organizations:DescribePolicy": {
            "Policy": ["PolicySummary", "Content"],
            "Policy.PolicySummary": ["Id", "Type", "AwsManaged"],
        },
        "organizations:ListTargetsForPolicy": {
            "": ["Targets"],
            "Targets.item": ["TargetId", "Type"],
        },
        "organizations:ListPoliciesForTarget": {
            "": ["Policies"],
            "Policies.item": ["Id", "Type", "AwsManaged"],
        },
    }
)
for _profile in REQUIRED_AWS.values():
    for _parent, _names in _profile.items():
        if _parent:
            PATHS.add(_parent)
        for _name in _names:
            _path = f"{_parent}.{_name}" if _parent else _name
            PATHS.add(_path)
            # Include intermediate containers for safe structure diagnostics.
            _parts = _path.split(".")
            PATHS.update(".".join(_parts[:i]) for i in range(1, len(_parts)))

TYPE = {
    "start_map": "object",
    "start_array": "array",
    "string": "string",
    "number": "number",
    "boolean": "boolean",
    "null": "null",
}
SEMVER = re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
SAFE_ISSUES = {
    "resource identity missing",
    "account identity missing",
    "region identity missing",
    "partition unresolved",
    "resource identifier format unresolved",
    "resource ARN service mismatch",
    "collection account differs from resource owner",
    "collection region differs from resource region",
    "malformed resource record",
    "reservation owner account unresolved",
    "malformed scanner record",
    "scanner collection timestamp unresolved",
    "scanner timestamps conflict or are malformed",
    "source check ID missing",
    "scanner status unresolved",
    "resource type missing",
    "scanner resource record missing",
    "scanner profile metadata unresolved",
    "scanner provider unresolved",
    "scanner lifecycle unresolved",
    "scanner lifecycle contradicts caption",
    "trust policy document unparseable",
    "network interface security groups unresolved",
    "route table associations or routes unresolved",
    "managed policy default document unresolved",
}
KNOWN_PARAMETERS = set().union(*PARAMETERS.values())
ORIGINS = ("tool-generated", "synthetic")


for _op, (_top, _prefix, _id, _kind, _keys, _subject) in ENTERPRISE_PROFILES.items():
    REQUIRED_AWS[_op] = {_prefix: list(_keys) + ([_id] if _id else [_top])}
    for _field in REQUIRED_AWS[_op][_prefix]:
        PATHS.add(f"{_prefix}.{_field}" if _prefix else _field)
    PATHS.add(_top)
    PATHS.add(_prefix)


class Structure:
    def __init__(self):
        self.fields = defaultdict(Counter)
        self.arrays = defaultdict(list)
        self.stack = []
        self.versions = Counter()
        self.other_events = 0

    def observe(self, prefix: str, event: str, value: object) -> None:
        if self.stack and event not in {"map_key", "end_map", "end_array"}:
            if len(self.stack) == self.stack[-1][2]:
                self.stack[-1][1] += 1
        if event in {"start_map", "start_array"}:
            # Frames retain only whitelisted paths and counts, not imported values.
            depth = len(self.stack) + 1
            self.stack.append([prefix if prefix in PATHS else None, 0, depth, event])
        elif event in {"end_map", "end_array"}:
            path, count, _, kind = self.stack.pop()
            if kind == "start_array" and path is not None:
                self.arrays[path].append(count)
        if prefix in PATHS and event in TYPE:
            self.fields[prefix][TYPE[event]] += 1
        elif event in TYPE:
            self.other_events += 1
        if prefix == "item.metadata.product.version" and event in TYPE:
            self.versions[
                value if isinstance(value, str) and SEMVER.fullmatch(value) else "UNRECOGNIZED"
            ] += 1

    def report(self, source) -> dict:
        required = (
            REQUIRED_AWS[source.operation]
            if source.format == "aws-json-v1"
            else REQUIRED[source.format]
        )
        presence = {}
        for parent, names in required.items():
            count = sum(self.fields[parent].values())
            for name in names:
                path = f"{parent}.{name}" if parent else name
                types = self.fields[path]
                presence[path] = {
                    "expected_records": count,
                    "present": sum(types.values()),
                    "null": types["null"],
                    "absent": max(0, count - sum(types.values())),
                }
        return {
            "structure_types": dict(self.fields),
            "required_fields": presence,
            "array_sizes": {
                path: {
                    "arrays": len(sizes),
                    "minimum": min(sizes),
                    "maximum": max(sizes),
                    "total_items": sum(sizes),
                }
                for path, sizes in self.arrays.items()
            },
            "tool_versions": dict(self.versions),
            "unrecognized_value_events": self.other_events,
        }


class IdentityCounts:
    def __init__(self, key=None):
        self._key = key or secrets.token_bytes(32)
        self.accounts = set()
        self.regions = set()
        self.resources = set()
        self.links = set()

    def token(self, domain: str, value: str | None) -> str | None:
        if value is None:
            return None
        return hmac.new(self._key, f"{domain}:{value}".encode(), hashlib.sha256).hexdigest()

    def add(self, obs) -> None:
        account = self.token("account", obs.account_id)
        region = self.token("region", obs.region)
        resource = self.token("resource", obs.resource_id)
        if account:
            self.accounts.add(account)
        if region:
            self.regions.add(region)
        if resource:
            self.resources.add(resource)
            self.links.add(
                (
                    resource,
                    account,
                    region,
                    self.token("account", obs.collection_account_id),
                    self.token("region", obs.collection_region),
                    self.token("finding", obs.source_finding_id),
                )
            )

    def report(self, include_pseudonyms: bool) -> dict:
        report = {
            "unique_observed_accounts": len(self.accounts),
            "unique_observed_regions": len(self.regions),
            "unique_identified_resources": len(self.resources),
        }
        if include_pseudonyms:
            report["identity_relationships"] = [
                {
                    "resource": r,
                    "owner_account": a,
                    "home_region": g,
                    "collection_account": c,
                    "collection_region": cr,
                    "scanner_finding": f,
                }
                for r, a, g, c, cr, f in sorted(
                    self.links, key=lambda link: tuple(v or "" for v in link)
                )
            ]
        return report


def validation_class(diag: dict, origin: str) -> str:
    """Only operator-declared tool-generated input can support real-export compatibility."""
    if origin != "tool-generated":
        return "SYNTHETIC_NOT_REAL_EXPORT_VALIDATION"
    state = diag.get("compatibility_state")
    if state == "STRUCTURE_ACCEPTED":
        return "TOOL_EXPORT_STRUCTURE_COMPATIBLE"
    if state in {"ACCEPTED_WITH_UNRESOLVED_FIELDS", "ACCEPTED_EMPTY_PROFILE_UNVERIFIED"}:
        return "TOOL_EXPORT_PARTIALLY_COMPATIBLE"
    return "TOOL_EXPORT_INCOMPATIBLE"


def profile_summary(diagnostics: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for diag in diagnostics:
        groups[(diag["profile"], diag["operation"])].append(diag)
    return [
        {
            "profile": profile,
            "operation": operation,
            "sources": len(items),
            "parser_accepted": sum(d.get("parser_accepted", False) for d in items),
            "validation_classes": dict(Counter(d["validation_class"] for d in items)),
            "effective_coverage": dict(
                Counter(d.get("effective_coverage", "REJECTED") for d in items)
            ),
            "rejection_codes": dict(
                Counter(d["rejection_code"] for d in items if "rejection_code" in d)
            ),
            "tool_versions": dict(
                sum((Counter(d.get("tool_versions", {})) for d in items), Counter())
            ),
            "duplicate_resource_records": sum(
                d.get("duplicate_resource_records", 0) for d in items
            ),
        }
        for (profile, operation), items in sorted(groups.items())
    ]


def verify_package(
    directory: Path,
    package: Package | None = None,
    *,
    include_pseudonyms=False,
    origin: str = "synthetic",
) -> dict:
    """Never returns raw values/mappings/salts; outputs still need sharing approval."""
    from offline_analyzer.provenance.execution import WorkCancelled, checkpoint

    checkpoint("EVIDENCE_PARSING")
    if directory.is_file():
        from offline_analyzer.ingestion.archive import unpack_package

        with tempfile.TemporaryDirectory() as staging:
            root = unpack_package(directory, Path(staging))
            return verify_package(
                root, package, include_pseudonyms=include_pseudonyms, origin=origin
            )
    from offline_analyzer.ingestion.gcp import inspect_package, is_gcp

    if is_gcp(directory):
        gcp_package, report = inspect_package(directory)
        if origin == "tool-generated" and any(
            source.gcp_metadata.get("dataset_origin") == "synthetic"
            for source in gcp_package.sources
        ):
            raise InputError("INPUT_ORIGIN_CONFLICT")
        report["declared_input_origin"] = origin
        report["real_export_validation"] = (
            "LOCAL_TOOL_GENERATED_INPUT_VERIFIED"
            if origin == "tool-generated"
            else "NOT_ESTABLISHED"
        )
        return report
    package = package or load_package(directory)
    identity = IdentityCounts()
    diagnostics = []
    total_bytes = 0
    with tempfile.TemporaryDirectory() as temp:
        for index, source in enumerate(package.sources):
            checkpoint("EVIDENCE_PARSING", index, len(package.sources))
            diag = {
                "source_index": index,
                "profile": source.format,
                "operation": source.operation,
                "request_parameter_names": sorted(
                    k for k in (source.request_parameters or {}) if k in KNOWN_PARAMETERS
                ),
                "request_parameter_unknown_count": sum(
                    k not in KNOWN_PARAMETERS for k in (source.request_parameters or {})
                ),
                "request_parameters_recorded": source.request_parameters is not None,
                "declared_account": source.account_id is not None,
                "declared_region": source.region is not None,
                "declared_error_records": len(source.errors),
            }
            local_identity = IdentityCounts(identity._key)
            seen = Counter()
            structure = Structure()
            unresolved = Counter()
            observations = 0
            shape = None
            try:
                if source.path:
                    local = Path(temp) / f"{index}.json"
                    digest, size = snapshot(resolve_under(directory, source.path), local)
                    total_bytes += size
                    if total_bytes > MAX_PACKAGE_BYTES:
                        raise InputError("PACKAGE_BYTE_LIMIT")
                    if digest != source.sha256:
                        raise InputError("ARTIFACT_CHECKSUM_MISMATCH")
                    shape = inspect_json(local, observer=structure.observe)
                    diag.update(structure.report(source))
                    adapter = aws_records if source.format == "aws-json-v1" else prowler_records
                    for obs in adapter(local, source, "local-verification", shape):
                        observations += 1
                        if observations > 100000:
                            raise InputError("RECORD_LIMIT")
                        local_identity.add(obs)
                        if obs.resource_id:
                            seen[obs.resource_id] += 1
                        if len(local_identity.links) + len(identity.links) > 100000:
                            raise InputError("IDENTITY_DIAGNOSTIC_BUDGET")
                        unresolved.update(
                            issue if issue in SAFE_ISSUES else "OTHER_UNRESOLVED"
                            for issue in obs.unresolved
                        )
                    diag["integrity_unchanged"] = (
                        sha256_file(resolve_under(directory, source.path)) == digest
                    )
                    if not diag["integrity_unchanged"]:
                        raise InputError("SOURCE_CHANGED_DURING_VERIFICATION")
                identity.accounts.update(local_identity.accounts)
                identity.regions.update(local_identity.regions)
                identity.resources.update(local_identity.resources)
                identity.links.update(local_identity.links)
                diag.update(structure.report(source))
                facts = collection_facts(source, shape, bool(unresolved))
                diag.update(
                    {
                        "effective_coverage": facts["effective_coverage"],
                        "coverage_diagnostics": facts["limitations"],
                        "collection_error_records": len(facts["errors"]),
                        "normalized_resource_records": observations,
                        "duplicate_resource_records": sum(n - 1 for n in seen.values() if n > 1),
                        "unresolved_diagnostics": dict(unresolved),
                        "parser_accepted": True,
                        "compatibility_state": "ACCEPTED_EMPTY_PROFILE_UNVERIFIED"
                        if source.format.startswith("prowler-") and observations == 0
                        else "ACCEPTED_WITH_UNRESOLVED_FIELDS"
                        if unresolved
                        or any(
                            v["absent"] or v["null"]
                            for v in diag.get("required_fields", {}).values()
                        )
                        else "STRUCTURE_ACCEPTED",
                    }
                )
            except WorkCancelled:
                raise
            except InputError as exc:
                if str(exc) == "JOB_TIME_LIMIT":
                    raise
                diag.update(
                    parser_accepted=False, compatibility_state="REJECTED", rejection_code=str(exc)
                )
                # Partial parser state is not presented as verified structure/identity.
            except Exception:
                diag.update(
                    parser_accepted=False,
                    compatibility_state="REJECTED",
                    rejection_code="LOCAL_VERIFICATION_FAILED",
                )
            diag["validation_class"] = validation_class(diag, origin)
            diagnostics.append(diag)
    classes = {d["validation_class"] for d in diagnostics}
    return {
        "diagnostic_version": "r1.1",
        "normalization_version": NORMALIZATION_VERSION,
        "declared_origin": origin,
        "real_export_validation": "NOT_ESTABLISHED"
        if origin != "tool-generated"
        else "STRUCTURE_COMPATIBLE_OPERATOR_DECLARED"
        if classes == {"TOOL_EXPORT_STRUCTURE_COMPATIBLE"}
        else "INCOMPLETE_OR_INCOMPATIBLE",
        "raw_values_included": False,
        "pseudonyms_included": include_pseudonyms,
        "sharing_status": "LOCAL_ONLY_REQUIRES_HUMAN_APPROVAL",
        "profiles": profile_summary(diagnostics),
        "sources": diagnostics,
        "observed_identity_totals": identity.report(include_pseudonyms),
        "identity_totals_scope": "PARSER_ACCEPTED_SOURCES_ONLY",
        "live_source_verification": "NOT_ESTABLISHED_BY_THIS_UTILITY",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--package", type=Path)
    group.add_argument("--file", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--format", choices=["aws-json-v1", "prowler-ocsf-5.10", "prowler-ocsf-5.26.1"]
    )
    parser.add_argument("--operation", choices=[*AWS_OPERATIONS, "prowler:Scan"])
    parser.add_argument("--collected-at")
    parser.add_argument("--account", help="collection account for --file")
    parser.add_argument("--region", help="collection Region for --file")
    parser.add_argument(
        "--origin",
        required=True,
        choices=ORIGINS,
        help="Declared input origin; only tool-generated exports count as real validation",
    )
    parser.add_argument("--include-pseudonyms", action="store_true")
    args = parser.parse_args(argv)
    try:
        package = None
        directory = args.package
        if args.file:
            if not all((args.format, args.operation, args.collected_at)):
                raise InputError("FILE_CONTEXT_REQUIRED")
            package = single_file_package(
                args.file,
                format=args.format,
                operation=args.operation,
                account_id=args.account,
                region=args.region,
                collected_at=args.collected_at,
            )
            directory = args.file.parent
        report = verify_package(
            directory, package, include_pseudonyms=args.include_pseudonyms, origin=args.origin
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
        print("Local verification complete. Diagnostics require human approval before sharing.")
        return 0 if all(s["parser_accepted"] for s in report["sources"]) else 2
    except Exception:
        print("Verification failed. Customer paths, values and exception details were withheld.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
