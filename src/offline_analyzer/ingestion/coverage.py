"""Collection facts are separate from per-resource configuration conclusions."""

from offline_analyzer.contracts.r0 import Source
from offline_analyzer.normalization.enterprise_adapters import PROFILES as ENTERPRISE_PROFILES

SELECTORS = {
    "sts:GetCallerIdentity": set(),
    "ec2:DescribeInstances": {"InstanceIds", "Filters"},
    "rds:DescribeDBInstances": {"DBInstanceIdentifier", "Filters"},
    "cloudtrail:DescribeTrails": {"trailNameList"},
    "ec2:DescribeSecurityGroups": {"GroupIds", "GroupNames", "Filters"},
    "ec2:DescribeNetworkInterfaces": {"NetworkInterfaceIds", "Filters"},
    "iam:GetAccountAuthorizationDetails": set(),
    "iam:ListRoles": set(),
    "s3control:GetPublicAccessBlock": set(),
    "ec2:DescribeRouteTables": {"RouteTableIds", "Filters"},
    # Per-bucket requests never establish complete bucket inventory coverage.
    "s3api:GetPublicAccessBlock": {"Bucket"},
    "s3api:GetBucketPolicyStatus": {"Bucket"},
    "s3api:GetBucketAcl": {"Bucket"},
    # Subject parameters (RoleName, PolicyArn, ParentId, ...) identify the resource;
    # they do not filter a listing, so they are not selectors.
    "iam:GetRole": set(),
    "iam:ListAttachedRolePolicies": set(),
    "iam:ListRolePolicies": set(),
    "iam:GetRolePolicy": set(),
    "iam:GetPolicy": set(),
    "iam:GetPolicyVersion": set(),
    "iam:ListInstanceProfilesForRole": set(),
    "iam:GetInstanceProfile": set(),
    "organizations:DescribeOrganization": set(),
    "organizations:ListRoots": set(),
    "organizations:ListOrganizationalUnitsForParent": set(),
    "organizations:ListAccountsForParent": set(),
    "organizations:ListAccounts": set(),
    "organizations:ListParents": set(),
    "organizations:ListPolicies": set(),
    "organizations:DescribePolicy": set(),
    "organizations:ListTargetsForPolicy": set(),
    "organizations:ListPoliciesForTarget": set(),
}
PARAMETERS = {
    "sts:GetCallerIdentity": set(),
    "ec2:DescribeInstances": {"InstanceIds", "Filters", "MaxResults", "NextToken", "DryRun"},
    "rds:DescribeDBInstances": {"DBInstanceIdentifier", "Filters", "MaxRecords", "Marker"},
    "cloudtrail:DescribeTrails": {"trailNameList", "includeShadowTrails"},
    "ec2:DescribeSecurityGroups": {
        "GroupIds",
        "GroupNames",
        "Filters",
        "MaxResults",
        "NextToken",
        "DryRun",
    },
    "ec2:DescribeNetworkInterfaces": {
        "NetworkInterfaceIds",
        "Filters",
        "MaxResults",
        "NextToken",
        "DryRun",
    },
    "iam:GetAccountAuthorizationDetails": {"Filter", "MaxItems", "Marker"},
    "iam:ListRoles": {"PathPrefix", "MaxItems", "Marker"},
    "s3control:GetPublicAccessBlock": {"AccountId"},
    "ec2:DescribeRouteTables": {"RouteTableIds", "Filters", "MaxResults", "NextToken", "DryRun"},
    "s3api:GetPublicAccessBlock": {"Bucket", "ExpectedBucketOwner"},
    "s3api:GetBucketPolicyStatus": {"Bucket", "ExpectedBucketOwner"},
    "s3api:GetBucketAcl": {"Bucket", "ExpectedBucketOwner"},
    "iam:GetRole": {"RoleName"},
    "iam:ListAttachedRolePolicies": {"RoleName", "PathPrefix", "MaxItems", "Marker"},
    "iam:ListRolePolicies": {"RoleName", "MaxItems", "Marker"},
    "iam:GetRolePolicy": {"RoleName", "PolicyName"},
    "iam:GetPolicy": {"PolicyArn"},
    "iam:GetPolicyVersion": {"PolicyArn", "VersionId"},
    "iam:ListInstanceProfilesForRole": {"RoleName", "MaxItems", "Marker"},
    "iam:GetInstanceProfile": {"InstanceProfileName"},
    "organizations:DescribeOrganization": set(),
    "organizations:ListRoots": {"NextToken", "MaxResults"},
    "organizations:ListOrganizationalUnitsForParent": {"ParentId", "NextToken", "MaxResults"},
    "organizations:ListAccountsForParent": {"ParentId", "NextToken", "MaxResults"},
    "organizations:ListAccounts": {"NextToken", "MaxResults"},
    "organizations:ListParents": {"ChildId", "NextToken", "MaxResults"},
    "organizations:ListPolicies": {"NextToken", "Filter", "MaxResults"},
    "organizations:DescribePolicy": {"PolicyId"},
    "organizations:ListTargetsForPolicy": {"PolicyId", "NextToken", "MaxResults"},
    "organizations:ListPoliciesForTarget": {"NextToken", "Filter", "TargetId", "MaxResults"},
}
# AWS-defined "not configured" answers: configuration states, not collection errors.
DEFINED_ABSENCE = {
    "securityhub:DescribeHub": "InvalidAccessException",
    "s3control:GetPublicAccessBlock": "NoSuchPublicAccessBlockConfiguration",
    "s3api:GetPublicAccessBlock": "NoSuchPublicAccessBlockConfiguration",
    "s3api:GetBucketPolicyStatus": "NoSuchBucketPolicy",
    "s3api:GetBucketPolicy": "NoSuchBucketPolicy",
    "organizations:DescribeOrganization": "AWSOrganizationsNotInUseException",
}


def collection_facts(source: Source, shape: dict | None, unresolved: bool) -> dict:
    if source.format == "gcp-json-v1":
        from offline_analyzer.normalization.gcp import PROFILES

        # Expanded (2.1/2.2) datasets are parsed by their typed dataset contract, not PROFILES.
        typed = bool((source.gcp_metadata or {}).get("dataset_contract"))
        incomplete = (
            unresolved
            or (source.operation not in PROFILES and not typed)
            or bool((source.request_parameters or {}).get("filter"))
            or bool((source.request_parameters or {}).get("limit"))
            or bool(shape and shape["fields"].get("nextPageToken", (None, None))[1])
        )
        return {
            "effective_coverage": "PARTIAL" if incomplete and source.path else source.coverage,
            "errors": list(source.errors),
            "limitations": ["GCP pagination, identity or parser support unresolved"]
            if incomplete
            else [],
        }
    effective = source.coverage
    limitations = []
    errors = list(source.errors)
    fields = (shape or {}).get("fields", {})
    status = fields.get("ResponseMetadata.HTTPStatusCode", (None, None))
    # AWS-defined "not configured" answer: a configuration state, not a collection error.
    defined_absence = (
        source.operation in DEFINED_ABSENCE
        and fields.get("Error.Code") == ("string", DEFINED_ABSENCE[source.operation])
        and not errors
        and status[1] in (None, 404)
    )
    if not defined_absence and (
        fields.get("Error", (None,))[0] == "start_map"
        or fields.get("Errors", (None,))[0]
        in {
            "start_map",
            "start_array",
        }
        or (status[0] is not None and (type(status[1]) is not int or status[1] != 200))
    ):
        effective = "ERROR"
        if not errors:
            errors.append(
                "AWS_RESPONSE_ERROR" if source.format == "aws-json-v1" else "SOURCE_RESPONSE_ERROR"
            )
    for token in ("NextToken", "nextToken", "Marker", "NextMarker"):
        if token in fields and fields[token] != ("null", None) and fields[token] != ("string", ""):
            limitations.append("pagination marker present or malformed")
    if fields.get("AdditionalRoutesAvailable") == ("boolean", True):
        limitations.append("additional transit gateway routes available")
    if "IsTruncated" in fields and fields["IsTruncated"] != ("boolean", False):
        limitations.append("truncated response or malformed truncation flag")
    if source.format == "aws-json-v1":
        params = source.request_parameters
        if params is None:
            limitations.append("request parameters not recorded; selection scope unresolved")
        else:
            expected_types = {
                "InstanceIds": list,
                "Filters": list,
                "DBInstanceIdentifier": str,
                "trailNameList": list,
                "includeShadowTrails": bool,
                "DryRun": bool,
                "MaxResults": int,
                "MaxRecords": int,
                "NextToken": str,
                "Marker": str,
                "GroupIds": list,
                "GroupNames": list,
                "NetworkInterfaceIds": list,
                "Filter": list,
                "MaxItems": int,
                "PathPrefix": str,
                "AccountId": str,
                "RouteTableIds": list,
                "SubnetIds": list,
                "NetworkAclIds": list,
                "InternetGatewayIds": list,
                "Bucket": str,
                "ExpectedBucketOwner": str,
                "RoleName": str,
                "PolicyName": str,
                "PolicyArn": str,
                "VersionId": str,
                "InstanceProfileName": str,
                "ParentId": str,
                "ChildId": str,
                "PolicyId": str,
                "TargetId": str,
                "Name": str,
                "TrailName": str,
                "DetectorId": str,
                "HubArn": str,
                "KeyId": str,
                "GrantTokens": list,
                "ConfigurationRecorderNames": list,
            }
            if source.operation.startswith("organizations:"):
                expected_types["Filter"] = str  # policy-type filter, not an entity list
            if any(type(value) is not expected_types.get(key) for key, value in params.items()):
                limitations.append("malformed request parameter type; scope unresolved")
            if params.get("includeShadowTrails") is False:
                limitations.append("shadow trails omitted by request")
            if any(key not in PARAMETERS[source.operation] for key in params):
                limitations.append("unreviewed request parameter; scope unresolved")
            if any(params.get(key) for key in SELECTORS[source.operation]):
                limitations.append("filtered or resource-selected request")
            if params.get("PathPrefix") not in (None, "/"):
                limitations.append("filtered or resource-selected request")
            entity_filter = params.get("Filter")
            if (
                source.operation == "iam:GetAccountAuthorizationDetails"
                and isinstance(entity_filter, list)
                and entity_filter
                and "Role" not in entity_filter
            ):
                limitations.append("filtered or resource-selected request")
            if "AccountId" in params and params["AccountId"] != source.account_id:
                limitations.append("request account differs from collection account")
            owner = params.get("ExpectedBucketOwner")
            if owner is not None and owner != source.account_id:
                limitations.append("request account differs from collection account")
            if any(key in params for key in ("NextToken", "Marker")):
                limitations.append("request starts from a pagination marker")
            if params.get("DryRun") is not None and params.get("DryRun") is not False:
                limitations.append("dry-run request does not establish collection")
    else:
        limitations.append("scanner output cannot establish AWS inventory completeness")
    if unresolved:
        limitations.append("records with unresolved fields/scope retained; completeness downgraded")
    if limitations and effective == "COMPLETE":
        effective = "PARTIAL"
    return {
        "effective_coverage": effective,
        "errors": sorted(set(errors)),
        "limitations": limitations,
    }


# Additional reference profiles; request identity never proves inventory completeness.

for _op, (_top, _prefix, _id, _kind, _keys, _subject) in ENTERPRISE_PROFILES.items():
    SELECTORS[_op] = {"Filters", "VpcIds", "TransitGatewayIds", "resourceShareArns"}
    PARAMETERS[_op] = {
        "NextToken",
        "nextToken",
        "Marker",
        "MaxResults",
        "maxResults",
        "MaxItems",
        "Limit",
        "Filters",
        "DryRun",
        "resourceOwner",
        "resourceShareArns",
        "principals",
        "resourceType",
        "resourceArns",
        "VpcIds",
        "VpcPeeringConnectionIds",
        "TransitGatewayIds",
        "TransitGatewayAttachmentIds",
        "TransitGatewayRouteTableIds",
        "KeyId",
        "PolicyName",
        "GrantId",
        "GranteePrincipal",
        "Bucket",
        "ExpectedBucketOwner",
        "MasterRegion",
        "FunctionVersion",
        "taskDefinition",
        "include",
    }
    if _subject:
        PARAMETERS[_op].add(_subject)
        SELECTORS[_op].add(_subject)

# Exact accepted request fields for each added export profile.
PARAMETERS.update(
    {
        "s3api:GetBucketPolicy": {"Bucket", "ExpectedBucketOwner"},
        "kms:GetKeyPolicy": {"KeyId", "PolicyName"},
        "kms:ListGrants": {"KeyId", "GrantId", "GranteePrincipal", "Marker", "Limit"},
        "lambda:ListFunctions": {"MasterRegion", "FunctionVersion", "Marker", "MaxItems"},
        "ecs:DescribeTaskDefinition": {"taskDefinition", "include"},
        "ec2:DescribeVpcs": {"VpcIds", "Filters", "NextToken", "MaxResults", "DryRun"},
        "ec2:DescribeVpcPeeringConnections": {
            "VpcPeeringConnectionIds",
            "Filters",
            "NextToken",
            "MaxResults",
            "DryRun",
        },
        "ec2:DescribeTransitGateways": {
            "TransitGatewayIds",
            "Filters",
            "NextToken",
            "MaxResults",
            "DryRun",
        },
        "ec2:DescribeTransitGatewayAttachments": {
            "TransitGatewayAttachmentIds",
            "Filters",
            "NextToken",
            "MaxResults",
            "DryRun",
        },
        "ec2:DescribeTransitGatewayRouteTables": {
            "TransitGatewayRouteTableIds",
            "Filters",
            "NextToken",
            "MaxResults",
            "DryRun",
        },
        "ec2:GetTransitGatewayRouteTableAssociations": {
            "TransitGatewayRouteTableId",
            "Filters",
            "NextToken",
            "MaxResults",
            "DryRun",
        },
        "ec2:GetTransitGatewayRouteTablePropagations": {
            "TransitGatewayRouteTableId",
            "Filters",
            "NextToken",
            "MaxResults",
            "DryRun",
        },
        "ec2:SearchTransitGatewayRoutes": {
            "TransitGatewayRouteTableId",
            "Filters",
            "MaxResults",
            "DryRun",
        },
        "ram:GetResourceShares": {
            "resourceOwner",
            "resourceShareArns",
            "resourceShareStatus",
            "name",
            "tagFilters",
            "permissionArn",
            "nextToken",
            "maxResults",
        },
        "ram:ListResources": {
            "resourceOwner",
            "resourceShareArns",
            "resourceType",
            "resourceArns",
            "nextToken",
            "maxResults",
        },
        "ram:ListPrincipals": {
            "resourceOwner",
            "resourceShareArns",
            "resourceType",
            "resourceArns",
            "principals",
            "nextToken",
            "maxResults",
        },
    }
)

for _operation, _selector in (
    ("ec2:DescribeSubnets", "SubnetIds"),
    ("ec2:DescribeNetworkAcls", "NetworkAclIds"),
    ("ec2:DescribeInternetGateways", "InternetGatewayIds"),
):
    PARAMETERS[_operation] = {_selector, "Filters", "NextToken", "MaxResults", "DryRun"}
    SELECTORS[_operation] = {_selector, "Filters"}


# Security-service state operations. Subject parameters identify one resource; regional
# status listings take no selectors.
for _operation, _parameters, _selectors in (
    ("cloudtrail:GetTrailStatus", {"Name"}, set()),
    ("cloudtrail:GetEventSelectors", {"TrailName"}, set()),
    ("guardduty:ListDetectors", {"MaxResults", "NextToken"}, set()),
    ("guardduty:GetDetector", {"DetectorId"}, set()),
    (
        "config:DescribeConfigurationRecorderStatus",
        {"ConfigurationRecorderNames", "ServicePrincipal", "Arn"},
        {"ConfigurationRecorderNames", "ServicePrincipal", "Arn"},
    ),
    ("securityhub:DescribeHub", {"HubArn"}, set()),
    ("kms:DescribeKey", {"KeyId", "GrantTokens"}, set()),
    ("kms:GetKeyRotationStatus", {"KeyId"}, set()),
):
    PARAMETERS[_operation] = _parameters
    SELECTORS[_operation] = _selectors
