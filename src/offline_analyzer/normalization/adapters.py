"""Explicit AWS response / Prowler 5.10 OCSF structural adapters, no rules."""

import json
import re
from datetime import UTC, datetime
from urllib.parse import unquote

from offline_analyzer.contracts.models import EvidenceRef
from offline_analyzer.contracts.r0 import NORMALIZATION_VERSION, Normalized, Source, stable_id
from offline_analyzer.ingestion.json_input import InputError, records

AWS_SHAPES = {
    "ec2:DescribeInstances": (
        "Reservations",
        "Reservations.item",
        "Instances",
        "InstanceId",
        "AWS::EC2::Instance",
    ),
    "rds:DescribeDBInstances": (
        "DBInstances",
        "DBInstances.item",
        None,
        "DBInstanceArn",
        "AWS::RDS::DBInstance",
    ),
    "cloudtrail:DescribeTrails": (
        "trailList",
        "trailList.item",
        None,
        "TrailARN",
        "AWS::CloudTrail::Trail",
    ),
    "ec2:DescribeSecurityGroups": (
        "SecurityGroups",
        "SecurityGroups.item",
        None,
        "GroupId",
        "AWS::EC2::SecurityGroup",
    ),
    "ec2:DescribeNetworkInterfaces": (
        "NetworkInterfaces",
        "NetworkInterfaces.item",
        None,
        "NetworkInterfaceId",
        "AWS::EC2::NetworkInterface",
    ),
    "iam:GetAccountAuthorizationDetails": (
        "RoleDetailList",
        "RoleDetailList.item",
        None,
        "Arn",
        "AWS::IAM::Role",
    ),
    "iam:ListRoles": ("Roles", "Roles.item", None, "Arn", "AWS::IAM::Role"),
    "ec2:DescribeRouteTables": (
        "RouteTables",
        "RouteTables.item",
        None,
        "RouteTableId",
        "AWS::EC2::RouteTable",
    ),
}
# Optional additional record lists inside the same response.
EXTRA_SHAPES = {
    "iam:GetAccountAuthorizationDetails": (
        ("Policies", "Policies.item", None, "Arn", "AWS::IAM::ManagedPolicy"),
    ),
}
# Singleton S3 responses: (payload key, AWS-defined absence code, resource type).
SINGLETONS = {
    "s3control:GetPublicAccessBlock": (
        "PublicAccessBlockConfiguration",
        "NoSuchPublicAccessBlockConfiguration",
        "AWS::S3::AccountPublicAccessBlock",
    ),
    "s3api:GetPublicAccessBlock": (
        "PublicAccessBlockConfiguration",
        "NoSuchPublicAccessBlockConfiguration",
        "AWS::S3::Bucket",
    ),
    "s3api:GetBucketPolicyStatus": ("PolicyStatus", "NoSuchBucketPolicy", "AWS::S3::Bucket"),
    "s3api:GetBucketAcl": ("Grants", None, "AWS::S3::Bucket"),
}
BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
# Tag keys set by container orchestrators; tag values are never retained.
CONTAINER_TAG_KEYS = {"aws:eks:cluster-name", "eks:cluster-name", "AmazonECSManaged"}
CONTAINER_TAG_PREFIXES = ("kubernetes.io/cluster/",)
# Owner account per resource row (EC2 instances use the reservation owner instead).
ROLE_NAME = r"[\w+=,.@-]{1,64}"
ORG_NODE = r"(?:r-[0-9a-z]{4,32}|ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}|[0-9]{12})"
ORG_POLICY = r"p-[0-9a-zA-Z_]{8,128}"
AWS_MANAGED_POLICY = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):iam::aws:policy/.+$")
ROW_OWNER_OPERATIONS = {
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeRouteTables",
}
GLOBAL_KINDS = {
    "AWS::IAM::Role",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::ManagedPolicyVersion",
    "AWS::IAM::InstanceProfile",
    "AWS::IAM::RoleAttachmentList",
    "AWS::IAM::RoleInlinePolicyList",
    "AWS::IAM::RoleInlinePolicy",
    "AWS::IAM::RoleInstanceProfileList",
    "AWS::Organizations::Organization",
    "AWS::Organizations::Membership",
    "AWS::Organizations::Root",
    "AWS::Organizations::OrganizationalUnit",
    "AWS::Organizations::Account",
    "AWS::Organizations::ParentLink",
    "AWS::Organizations::Policy",
    "AWS::Organizations::PolicyTargetList",
    "AWS::Organizations::TargetPolicyList",
    "AWS::S3::AccountPublicAccessBlock",
    "AWS::S3::Bucket",
}
NATIVE_FORMATS = {
    "AWS::EC2::Instance": r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})",
    "AWS::EC2::SecurityGroup": r"sg-(?:[0-9a-f]{8}|[0-9a-f]{17})",
    "AWS::EC2::NetworkInterface": r"eni-(?:[0-9a-f]{8}|[0-9a-f]{17})",
    "AWS::S3::AccountPublicAccessBlock": r"[0-9]{12}",
    "AWS::EC2::RouteTable": r"rtb-(?:[0-9a-f]{8}|[0-9a-f]{17})",
    "AWS::S3::Bucket": r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]",
    "AWS::IAM::RoleAttachmentList": ROLE_NAME,
    "AWS::IAM::RoleInlinePolicyList": ROLE_NAME,
    "AWS::IAM::RoleInstanceProfileList": ROLE_NAME,
    "AWS::IAM::RoleInlinePolicy": ROLE_NAME + "/" + r"[\w+=,.@-]{1,128}",
    "AWS::Organizations::Organization": r"o-[a-z0-9]{10,32}",
    "AWS::Organizations::Membership": r"[0-9]{12}",
    "AWS::Organizations::Root": r"r-[0-9a-z]{4,32}",
    "AWS::Organizations::OrganizationalUnit": r"ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}",
    "AWS::Organizations::Account": r"[0-9]{12}",
    "AWS::Organizations::ParentLink": ORG_NODE,
    "AWS::Organizations::Policy": ORG_POLICY,
    "AWS::Organizations::PolicyTargetList": ORG_POLICY,
    "AWS::Organizations::TargetPolicyList": ORG_NODE + r"(?:#[A-Z_]{1,64})?",
}
ARN_KINDS = {
    "AWS::RDS::DBInstance": ("rds", "db:"),
    "AWS::CloudTrail::Trail": ("cloudtrail", "trail/"),
    "AWS::IAM::Role": ("iam", "role/"),
    "AWS::IAM::ManagedPolicy": ("iam", "policy/"),
    "AWS::IAM::ManagedPolicyVersion": ("iam", "policy/"),
    "AWS::IAM::InstanceProfile": ("iam", "instance-profile/"),
}
NO_SUCH_BPA = "NoSuchPublicAccessBlockConfiguration"
RESOURCE_TYPES = {
    "AwsEc2Instance": "AWS::EC2::Instance",
    "AwsRdsDbInstance": "AWS::RDS::DBInstance",
    "AwsCloudTrailTrail": "AWS::CloudTrail::Trail",
}
ARN = re.compile(r"^arn:(aws(?:-us-gov|-cn)?):([^:]+):([^:]*):([0-9]{12}):(.+)$")


def text(value: object) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= 512 else None


def mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def region_partition(region: str | None) -> str | None:
    if not region:
        return None
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if re.fullmatch(r"(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:[a-z]+-)+\d+", region):
        return "aws"
    return None


def reject_duplicates(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate policy key")
    return dict(pairs)


def policy_document(value: object) -> tuple[dict | None, str]:
    """IAM returns URL-encoded JSON over the API; CLI/boto3 exports decode it to objects."""
    if isinstance(value, dict):
        return value, "object"
    if value is None:
        return None, "missing"
    if not isinstance(value, str) or len(value) > 65536:
        return None, "malformed"
    try:
        decoded = json.loads(
            unquote(value) if value.lstrip().startswith("%") else value,
            object_pairs_hook=reject_duplicates,
        )
    except (ValueError, RecursionError):
        return None, "malformed"
    return (decoded, "encoded-json") if isinstance(decoded, dict) else (None, "malformed")


def eni_configuration(row: dict) -> dict:
    groups = row.get("Groups")
    addresses = row.get("PrivateIpAddresses")
    ipv6 = row.get("Ipv6Addresses")
    attachment = mapping(row.get("Attachment"))
    return {
        "Status": row.get("Status"),
        "InterfaceType": row.get("InterfaceType"),
        "RequesterManaged": row.get("RequesterManaged"),
        "VpcId": row.get("VpcId"),
        "SubnetId": row.get("SubnetId"),
        "Groups": [mapping(group).get("GroupId") for group in groups]
        if isinstance(groups, list)
        else None,
        "PublicIp": mapping(row.get("Association")).get("PublicIp"),
        # Secondary private addresses can carry their own public association.
        "AddressPublicIps": [
            mapping(mapping(address).get("Association")).get("PublicIp") for address in addresses
        ]
        if isinstance(addresses, list)
        else None,
        "Ipv6AddressCount": len(ipv6) if isinstance(ipv6, list) else None,
        "AttachmentInstanceId": attachment.get("InstanceId"),
        "AttachmentStatus": attachment.get("Status"),
    }


def configuration_for(operation: str, row: dict) -> tuple[dict, tuple[str, ...]]:
    """Retain only fields needed by rules; complete raw bytes are stored separately."""
    if operation == "ec2:DescribeInstances":
        tags = row.get("Tags")
        keys = [mapping(t).get("Key") for t in tags] if isinstance(tags, list) else []
        indicators = sorted(
            k
            for k in keys
            if isinstance(k, str)
            and (k in CONTAINER_TAG_KEYS or k.startswith(CONTAINER_TAG_PREFIXES))
        )
        return {
            "MetadataOptions": row.get("MetadataOptions"),
            "VpcId": row.get("VpcId"),
            "SubnetId": row.get("SubnetId"),
            "State": row.get("State"),
            "ContainerIndicators": indicators,
            "InstanceProfileArn": mapping(row.get("IamInstanceProfile")).get("Arn"),
        }, ()
    if operation == "rds:DescribeDBInstances":
        keys = (
            "StorageEncrypted",
            "Engine",
            "DBInstanceIdentifier",
            "DBClusterIdentifier",
            "PubliclyAccessible",
        )
        groups = row.get("VpcSecurityGroups")
        subnet_group = mapping(row.get("DBSubnetGroup"))
        subnets = subnet_group.get("Subnets")
        return {
            **{key: row.get(key) for key in keys},
            "Port": mapping(row.get("Endpoint")).get("Port", row.get("DbInstancePort")),
            "VpcSecurityGroups": [
                {
                    "GroupId": mapping(g).get("VpcSecurityGroupId"),
                    "Status": mapping(g).get("Status"),
                }
                for g in groups
            ]
            if isinstance(groups, list)
            else None,
            "VpcId": subnet_group.get("VpcId"),
            "SubnetIds": [mapping(n).get("SubnetIdentifier") for n in subnets]
            if isinstance(subnets, list)
            else None,
        }, ()
    if operation == "cloudtrail:DescribeTrails":
        keys = (
            "LogFileValidationEnabled",
            "HomeRegion",
            "IsOrganizationTrail",
            "IsMultiRegionTrail",
            "S3BucketName",
            "CloudWatchLogsLogGroupArn",
            "CloudWatchLogsRoleArn",
            "KmsKeyId",
        )
        return {key: row.get(key) for key in keys}, ()
    if operation == "ec2:DescribeSecurityGroups":
        keys = ("GroupId", "GroupName", "VpcId", "IpPermissions")
        return {key: row.get(key) for key in keys}, ()
    if operation == "ec2:DescribeRouteTables":
        associations = row.get("Associations")
        routes = row.get("Routes")
        route_keys = (
            "DestinationCidrBlock",
            "DestinationIpv6CidrBlock",
            "DestinationPrefixListId",
            "GatewayId",
            "NatGatewayId",
            "TransitGatewayId",
            "NetworkInterfaceId",
            "VpcPeeringConnectionId",
            "EgressOnlyInternetGatewayId",
            "State",
        )
        config = {
            "VpcId": row.get("VpcId"),
            "Associations": [
                {k: mapping(a).get(k) for k in ("SubnetId", "Main", "GatewayId")}
                for a in associations
            ]
            if isinstance(associations, list)
            else None,
            "Routes": [{k: mapping(r).get(k) for k in route_keys} for r in routes]
            if isinstance(routes, list)
            else None,
        }
        missing = config["Associations"] is None or config["Routes"] is None
        return config, ("route table associations or routes unresolved",) if missing else ()
    if operation == "iam:GetAccountAuthorizationDetails#policy":
        versions = row.get("PolicyVersionList")
        defaults = [
            v
            for v in (versions if isinstance(versions, list) else [])
            if mapping(v).get("IsDefaultVersion") is True
        ]
        default = defaults[0] if len(defaults) == 1 else None
        if default and row.get("DefaultVersionId") not in (None, mapping(default).get("VersionId")):
            default = None
        document, encoding = policy_document(mapping(default).get("Document"))
        # A missing default document leaves that policy unresolved for analysis; it does
        # not make the authorization-details inventory incomplete.
        return {"PolicyName": row.get("PolicyName"), "DefaultDocument": document,
                "DefaultVersionId": row.get("DefaultVersionId"),
                "PolicyDocumentEncoding": encoding}, ()  # fmt: skip
    if operation == "ec2:DescribeNetworkInterfaces":
        config = eni_configuration(row)
        groups = config["Groups"]
        # Unreadable group membership would hide attachments; downgrade completeness.
        unresolved = groups is None or not all(isinstance(g, str) and g for g in groups)
        return config, ("network interface security groups unresolved",) if unresolved else ()
    document, encoding = policy_document(row.get("AssumeRolePolicyDocument"))
    issues = ("trust policy document unparseable",) if encoding == "malformed" else ()
    config = {
        "RoleName": row.get("RoleName"),
        "Path": row.get("Path"),
        "AssumeRolePolicyDocument": document,
        "PolicyDocumentEncoding": encoding,
        "PermissionsBoundaryArn": mapping(row.get("PermissionsBoundary")).get(
            "PermissionsBoundaryArn"
        ),
        # Only the authorization-details export carries role permission evidence.
        "PermissionsEvidence": operation == "iam:GetAccountAuthorizationDetails",
        "AttachedPolicyArns": None,
        "InlinePolicies": None,
        "PermissionsResolved": False,
    }
    if config["PermissionsEvidence"]:
        attached, inline = row.get("AttachedManagedPolicies"), row.get("RolePolicyList")
        config["AttachedPolicyArns"] = (
            [mapping(a).get("PolicyArn") for a in attached] if isinstance(attached, list) else None
        )
        documents = [
            policy_document(mapping(i).get("PolicyDocument")) for i in inline
        ] if isinstance(inline, list) else None  # fmt: skip
        config["InlinePolicies"] = [doc for doc, _ in documents] if documents is not None else None
        config["InlinePolicyNames"] = (
            [mapping(i).get("PolicyName") for i in inline] if isinstance(inline, list) else None
        )
        profiles = row.get("InstanceProfileList")
        config["InstanceProfileArns"] = (
            [mapping(p).get("Arn") for p in profiles] if isinstance(profiles, list) else None
        )
        # Permission gaps lower per-role risk context; they never make the role
        # inventory incomplete.
        config["PermissionsResolved"] = not (
            config["AttachedPolicyArns"] is None
            or documents is None
            or any(doc is None for doc, _ in documents)
        )
    return config, issues


# Explicit identity namespaces for additional reference profiles.
NATIVE_FORMATS.update(
    {
        "AWS::EC2::VPC": r"vpc-[0-9a-f]{8,17}",
        "AWS::EC2::Subnet": r"subnet-[0-9a-f]{8,17}",
        "AWS::EC2::NetworkAcl": r"acl-[0-9a-f]{8,17}",
        "AWS::EC2::InternetGateway": r"igw-[0-9a-f]{8,17}",
        "AWS::EC2::VPCPeeringConnection": r"pcx-[0-9a-f]{8,17}",
        "AWS::EC2::TransitGateway": r"tgw-[0-9a-f]{8,17}",
        "AWS::EC2::TransitGatewayAttachment": r"tgw-attach-[0-9a-f]{8,17}",
        "AWS::EC2::TransitGatewayRouteTable": r"tgw-rtb-[0-9a-f]{8,17}",
    }
)
ARN_KINDS.update(
    {
        "AWS::KMS::Key": ("kms", "key/"),
        "AWS::Lambda::Function": ("lambda", "function:"),
        "AWS::ECS::TaskDefinition": ("ecs", "task-definition/"),
        "AWS::RAM::ResourceShare": ("ram", "resource-share/"),
    }
)


def identity(
    native: str | None,
    account: str | None,
    region: str | None,
    kind: str | None,
    partition: str | None = None,
) -> tuple[str | None, str | None, str | None, str | None, str | None, list[str]]:
    issues = []
    native = text(native)
    global_kind = kind in GLOBAL_KINDS
    managed = AWS_MANAGED_POLICY.match(native or "")
    if managed and kind in {"AWS::IAM::ManagedPolicy", "AWS::IAM::ManagedPolicyVersion"}:
        # AWS-managed policies are owned by "aws"; keep the collecting account as scope.
        partition = managed.group(1)
        resource = None
        if account and re.fullmatch(r"[0-9]{12}", account):
            resource = stable_id("resource", [partition, account, "global", kind, native])
        issues = [] if resource else ["account identity missing"]
        return account, "global", native, partition, resource, issues
    match = ARN.fullmatch(native or "")
    if match:
        arn_partition, service, arn_region, arn_account, tail = match.groups()
        # Resource ownership is authoritative, collection scope remains separate.
        if account and account != arn_account:
            issues.append("collection account differs from resource owner")
        account = arn_account
        if region and region != arn_region and not global_kind:
            issues.append("collection region differs from resource region")
        region = arn_region or None
        partition = arn_partition
        if kind == "AWS::EC2::Instance" and service == "ec2" and tail.startswith("instance/"):
            native = tail.removeprefix("instance/")
        elif kind in ARN_KINDS and service != ARN_KINDS[kind][0]:
            issues.append("resource ARN service mismatch")
    if global_kind:
        # IAM/account-level configuration is not Regional; collection Region is retained
        # separately on the observation and never becomes the resource Region.
        region = "global"
    if kind in NATIVE_FORMATS and native and not re.fullmatch(NATIVE_FORMATS[kind], native):
        issues.append("resource identifier format unresolved")
    if kind in ARN_KINDS:
        if not match or not match.group(5).startswith(ARN_KINDS[kind][1]):
            issues.append("resource identifier format unresolved")
    if account is not None and not re.fullmatch(r"[0-9]{12}", account):
        account = None
    if not native:
        issues.append("resource identity missing")
    if not account:
        issues.append("account identity missing")
    if not region:
        issues.append("region identity missing")
    # Partition is derived only from explicit AWS regional namespaces when no ARN exists.
    if not partition and region:
        partition = region_partition(region)
    if not partition:
        issues.append("partition unresolved")
    blocking = {
        "resource ARN service mismatch",
        "resource identity missing",
        "account identity missing",
        "region identity missing",
        "partition unresolved",
        "resource identifier format unresolved",
    }
    resource = None
    if not blocking.intersection(issues) and kind:
        resource = stable_id("resource", [partition, account, region, kind, native])
    return account, region, native, partition, resource, issues


def normalized(
    source,
    artifact,
    sha,
    locator,
    *,
    native=None,
    kind=None,
    account=None,
    region=None,
    partition=None,
    tool="aws",
    version="unspecified",
    check=None,
    status=None,
    severity=None,
    timestamp=None,
    config=None,
    issues=(),
    finding_id=None,
    status_id=None,
    status_caption=None,
    details=None,
):
    partition = source.partition or partition
    account, region, native, partition, resource, identity_issues = identity(
        native, account, region, kind, partition
    )
    if source.partition and partition != source.partition:
        identity_issues.append("collection partition differs from resource partition")
    if tool == "aws" and kind == "AWS::CloudTrail::Trail":
        home = (config or {}).get("HomeRegion")
        if isinstance(home, str) and home == region and source.region:
            relation = "HOME_REGION"
            if source.region != home:
                relation = "REGIONAL_SHADOW"
                identity_issues = [
                    i
                    for i in identity_issues
                    if i != "collection region differs from resource region"
                ]
            if source.account_id and source.account_id != account:
                if (config or {}).get("IsOrganizationTrail") is True:
                    relation = "ORGANIZATION_SHADOW"
                    identity_issues = [
                        i
                        for i in identity_issues
                        if i != "collection account differs from resource owner"
                    ]
                else:
                    relation = "UNRESOLVED_OWNER_RELATIONSHIP"
            details = {**(details or {}), "trail_relationship": relation}
        else:
            details = {**(details or {}), "trail_relationship": "UNRESOLVED_HOME_REGION"}
    timestamp = timestamp.astimezone(UTC) if timestamp else None
    values = dict(
        account_id=account,
        region=text(region),
        resource_id=resource,
        native_id=native,
        resource_type=kind,
        partition=partition,
        source_tool=tool,
        source_version=version,
        source_check_id=check or source.operation,
        source_status=status,
        source_severity=severity,
        collected_at=timestamp,
        operation=source.operation,
        normalization_version=NORMALIZATION_VERSION,
        source_finding_id=text(finding_id),
        source_status_id=status_id,
        source_status_caption=text(status_caption),
        source_details=details or {},
        collection_account_id=source.account_id,
        collection_region=source.region,
        configuration=config or {},
        unresolved=tuple(sorted(set(issues + tuple(identity_issues)))),
    )
    oid = stable_id(
        "observation",
        {
            **values,
            "collected_at": timestamp.isoformat() if timestamp else None,
            "source_details": {
                k: v for k, v in values["source_details"].items() if k != "source_record_locator"
            },
        },
    )
    return Normalized(
        observation_id=oid,
        evidence=EvidenceRef(artifact_id=artifact, locator=locator),
        integrity_sha256=sha,
        **values,
    )


def singleton_records(path, source: Source, artifact: str, shape):
    """Singleton S3 responses; bucket identity comes only from the recorded request."""
    payload, absence, kind = SINGLETONS[source.operation]
    fields = shape["fields"] if shape and shape["root"] == "start_map" else None
    if fields is None:
        raise InputError("UNSUPPORTED_AWS_RESPONSE_SHAPE")
    if absence and fields.get("Error.Code") == ("string", absence):
        # AWS-defined response meaning the configuration does not exist.
        config, locator = {"configured": False}, "/Error"
    elif fields.get(payload, (None,))[0] in {"start_map", "start_array"}:
        config, locator = {"configured": True}, f"/{payload}"
        if payload == "Grants":
            grants = [mapping(g) for _, g in records(path, "Grants.item")]
            config["PublicGrants"] = sorted(
                {
                    f"{mapping(g.get('Grantee')).get('URI')}:{g.get('Permission')}"
                    for g in grants
                    if mapping(g.get("Grantee")).get("URI") in PUBLIC_GRANTEES
                }
            )
            config["GrantCount"] = len(grants)
        else:
            for _, block in records(path, payload):
                keys = ("IsPublic",) if payload == "PolicyStatus" else BPA_FLAGS
                config.update({key: mapping(block).get(key) for key in keys})
    elif "Error" in fields or "Errors" in fields:
        return
    else:
        raise InputError("UNSUPPORTED_AWS_RESPONSE_SHAPE")
    if kind == "AWS::S3::Bucket":
        native = (source.request_parameters or {}).get("Bucket")
        native = native if isinstance(native, str) else None
    else:
        native = source.account_id
    yield normalized(
        source,
        artifact,
        source.sha256,
        locator,
        native=native,
        kind=kind,
        account=source.account_id,
        region=source.region,
        partition=region_partition(source.region),
        timestamp=source.collected_at,
        version=source.collector_version,
        status="OBSERVED",
        config=config,
        details={"request_parameters": source.request_parameters},
    )


def aws_records(path, source: Source, artifact: str, shape):
    if source.operation == "sts:GetCallerIdentity":
        for _, response in records(path, ""):
            if not isinstance(response, dict) or response.get("Account") != source.account_id:
                raise InputError("COLLECTOR_IDENTITY_MISMATCH")
            arn = response.get("Arn")
            if not isinstance(arn, str) or not arn.startswith("arn:") or not response.get("UserId"):
                raise InputError("UNSUPPORTED_AWS_RESPONSE_SHAPE")
        return

    if source.operation in SINGLETONS:
        yield from singleton_records(path, source, artifact, shape)
        return
    from offline_analyzer.normalization import enterprise_adapters, iam_adapters, security_services

    if source.operation in security_services.OPERATIONS:
        yield from security_services.service_records(path, source, artifact, shape)
        return

    if source.operation in enterprise_adapters.OPERATIONS:
        yield from enterprise_adapters.export_records(path, source, artifact, shape)
        return

    if source.operation in iam_adapters.OPERATIONS:
        yield from iam_adapters.iam_records(path, source, artifact, shape)
        return
    top, prefix, children, id_key, kind = AWS_SHAPES[source.operation]
    if shape["root"] != "start_map" or shape["fields"].get(top, (None,))[0] != "start_array":
        if shape["root"] == "start_map" and (
            shape["fields"].get("Error", (None,))[0] == "start_map"
            or shape["fields"].get("Errors", (None,))[0] == "start_array"
        ):
            return
        raise InputError("UNSUPPORTED_AWS_RESPONSE_SHAPE")
    shapes = [(top, prefix, children, id_key, kind, source.operation)]
    for extra in EXTRA_SHAPES.get(source.operation, ()):
        if shape["fields"].get(extra[0], (None,))[0] == "start_array":
            shapes.append((*extra, f"{source.operation}#policy"))
    count = 0
    malformed = False
    for top, prefix, children, id_key, kind, config_operation in shapes:
        for index, record in records(path, prefix):
            record_map = mapping(record)
            missing_children = False
            if children:
                child_records = record_map.get(children)
                if not isinstance(child_records, list):
                    child_records = [None]
                    missing_children = True
                    malformed = True
                items = enumerate(child_records)
            else:
                items = [(None, record)]
            for child_index, item in items:
                count += 1
                if count > 100000:
                    raise InputError("RECORD_LIMIT")
                issues = ()
                if not isinstance(item, dict):
                    issues = ("malformed resource record",)
                    malformed = True
                row = mapping(item)
                owner = text(record_map.get("OwnerId")) if children else None
                if source.operation in ROW_OWNER_OPERATIONS:
                    owner = text(row.get("OwnerId"))
                account = source.account_id
                if owner:
                    if re.fullmatch(r"[0-9]{12}", owner):
                        account = owner
                        if source.account_id and account != source.account_id:
                            issues += ("collection account differs from resource owner",)
                    else:
                        account = None
                        issues += ("reservation owner account unresolved",)
                locator = f"/{top}/{index}" + (
                    f"/{children}/{child_index}" if children and not missing_children else ""
                )
                config, config_issues = configuration_for(config_operation, row)
                issues += config_issues
                yield normalized(
                    source,
                    artifact,
                    source.sha256,
                    locator,
                    native=row.get(id_key),
                    kind=kind,
                    account=account,
                    region=source.region,
                    timestamp=source.collected_at,
                    version=source.collector_version,
                    status="OBSERVED"
                    if source.coverage not in {"ERROR", "NOT_COLLECTED"}
                    else source.coverage,
                    config=config,
                    issues=issues,
                    details={"request_parameters": source.request_parameters},
                )
    # Coverage is finalized by the importer; pagination tokens always downgrade COMPLETE.
    return count, malformed


PROWLER_PROFILES = {"prowler-ocsf-5.10": "5.10.0", "prowler-ocsf-5.26.1": "5.26.1"}


def prowler_records(path, source, artifact, shape):
    expected_version = PROWLER_PROFILES[source.format]
    if shape["root"] != "start_array":
        raise InputError("UNSUPPORTED_PROWLER_RESPONSE_SHAPE")
    for index, record in records(path, "item"):
        row = mapping(record)
        metadata = mapping(row.get("metadata"))
        product = mapping(metadata.get("product"))
        profile_issues = []
        # Explicitly different profiles fail closed. Absent/invalid metadata is retained
        # as unresolved, with raw record provenance, rather than silently promoted.
        if (
            text(product.get("name")) not in (None, "Prowler")
            or text(product.get("version")) not in (None, expected_version)
            or (type(row.get("class_uid")) is int and row["class_uid"] != 2004)
        ):
            raise InputError("UNSUPPORTED_PROWLER_VERSION_OR_CLASS")
        if (
            product.get("name") != "Prowler"
            or product.get("version") != expected_version
            or type(row.get("class_uid")) is not int
            or row.get("class_uid") != 2004
        ):
            profile_issues.append("scanner profile metadata unresolved")
        cloud = mapping(row.get("cloud"))
        if cloud.get("provider") not in (None, "aws"):
            raise InputError("UNSUPPORTED_PROWLER_PROVIDER")
        resources = row.get("resources")
        missing_resources = not isinstance(resources, list) or not resources
        if not isinstance(resources, list) or not resources:
            resources = [None]
        timestamp = None
        timestamp_conflict = False
        try:
            if text(row.get("time_dt")):
                timestamp = datetime.fromisoformat(row["time_dt"].replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    timestamp = None
                elif type(row.get("time")) in {int, float}:
                    epoch = datetime.fromtimestamp(row["time"], UTC)
                    timestamp_conflict = abs((timestamp - epoch).total_seconds()) >= 1
            elif type(row.get("time")) in {int, float}:
                # Prowler 5.10 emitter uses seconds (not an assumed OCSF millisecond clock).
                timestamp = datetime.fromtimestamp(row["time"], UTC)
        except (ValueError, OverflowError, OSError):
            timestamp_conflict = True
        for resource_index, resource in enumerate(resources):
            data = mapping(resource)
            source_type = text(data.get("type"))
            kind = RESOURCE_TYPES.get(source_type, source_type)
            issues = list(profile_issues)
            if cloud.get("provider") != "aws":
                issues.append("scanner provider unresolved")
            if not isinstance(record, dict):
                issues.append("malformed scanner record")
            if timestamp_conflict:
                issues.append("scanner timestamps conflict or are malformed")
            if not timestamp:
                issues.append("scanner collection timestamp unresolved")
            check = text(metadata.get("event_code"))
            if not check:
                issues.append("source check ID missing")
            status = text(row.get("status_code"))
            if status not in {"PASS", "FAIL", "MANUAL"}:
                issues.append("scanner status unresolved")
            lifecycle = row.get("status_id")
            lifecycle = lifecycle if type(lifecycle) is int else None
            caption = text(row.get("status"))
            labels = {
                0: "Unknown",
                1: "New",
                2: "InProgress",
                3: "Suppressed",
                4: "Resolved",
                5: "Archived",
                99: "Other",
            }
            if lifecycle not in labels:
                issues.append("scanner lifecycle unresolved")
            elif caption and caption.replace(" ", "") != labels[lifecycle]:
                issues.append("scanner lifecycle contradicts caption")
            finding = mapping(row.get("finding_info"))
            # UID is a scanner-finding identity, not a check ID or resource identity.
            if not text(finding.get("uid")):
                profile_issues_uid = True
            else:
                profile_issues_uid = False
            if not kind:
                issues.append("resource type missing")
            if not isinstance(resource, dict):
                issues.append("scanner resource record missing")
            yield normalized(
                source,
                artifact,
                source.sha256,
                f"/{index}" if missing_resources else f"/{index}/resources/{resource_index}",
                native=data.get("uid"),
                kind=kind,
                account=text(mapping(cloud.get("account")).get("uid")),
                region=text(data.get("region")) or text(cloud.get("region")),
                partition=text(data.get("cloud_partition")),
                tool="prowler",
                version=text(product.get("version")) or "unresolved",
                check=check or "UNRESOLVED_CHECK",
                status=status,
                severity=text(row.get("severity")),
                timestamp=timestamp,
                config={
                    "status_detail": row.get("status_detail"),
                    "muted": lifecycle == 3 or caption == "Suppressed",
                    "inactive": lifecycle in (3, 4, 5)
                    or caption in ("Suppressed", "Resolved", "Archived"),
                },
                issues=tuple(issues),
                finding_id=finding.get("uid"),
                status_id=lifecycle,
                status_caption=caption,
                details={
                    "finding_uid_missing": profile_issues_uid,
                    "source_record_locator": f"/{index}",
                    "finding_description": finding.get("desc"),
                    "message": row.get("message"),
                    "metadata_version": metadata.get("version"),
                    "profiles": metadata.get("profiles"),
                    "resource_data": data.get("data"),
                },
            )
