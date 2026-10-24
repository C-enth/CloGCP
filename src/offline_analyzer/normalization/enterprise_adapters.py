"""Explicit additional AWS export profiles: references only, no authorization decisions."""

from offline_analyzer.ingestion.json_input import InputError, records

# operation: (root, record prefix, identity field, kind, retained fields, request subject)
PROFILES = {
    "ec2:DescribeSubnets": (
        "Subnets",
        "Subnets.item",
        "SubnetId",
        "AWS::EC2::Subnet",
        ("OwnerId", "VpcId", "CidrBlock", "AvailabilityZone", "MapPublicIpOnLaunch"),
        None,
    ),
    "ec2:DescribeNetworkAcls": (
        "NetworkAcls",
        "NetworkAcls.item",
        "NetworkAclId",
        "AWS::EC2::NetworkAcl",
        ("OwnerId", "VpcId", "Entries", "Associations", "IsDefault"),
        None,
    ),
    "ec2:DescribeInternetGateways": (
        "InternetGateways",
        "InternetGateways.item",
        "InternetGatewayId",
        "AWS::EC2::InternetGateway",
        ("OwnerId", "Attachments"),
        None,
    ),
    "s3api:GetBucketPolicy": ("Policy", "", None, "AWS::S3::Bucket", (), "Bucket"),
    "kms:GetKeyPolicy": ("Policy", "", None, "AWS::KMS::Key", (), "KeyId"),
    "kms:ListGrants": (
        "Grants",
        "Grants.item",
        "GrantId",
        "AWS::KMS::Grant",
        ("KeyId", "GranteePrincipal", "RetiringPrincipal", "Operations", "Constraints"),
        "KeyId",
    ),
    "lambda:ListFunctions": (
        "Functions",
        "Functions.item",
        "FunctionArn",
        "AWS::Lambda::Function",
        ("Role",),
        None,
    ),
    "ecs:DescribeTaskDefinition": (
        "taskDefinition",
        "taskDefinition",
        "taskDefinitionArn",
        "AWS::ECS::TaskDefinition",
        ("taskRoleArn", "executionRoleArn"),
        None,
    ),
    "ec2:DescribeVpcs": (
        "Vpcs",
        "Vpcs.item",
        "VpcId",
        "AWS::EC2::VPC",
        ("OwnerId", "CidrBlock", "State"),
        None,
    ),
    "ec2:DescribeVpcPeeringConnections": (
        "VpcPeeringConnections",
        "VpcPeeringConnections.item",
        "VpcPeeringConnectionId",
        "AWS::EC2::VPCPeeringConnection",
        ("RequesterVpcInfo", "AccepterVpcInfo", "Status"),
        None,
    ),
    "ec2:DescribeTransitGateways": (
        "TransitGateways",
        "TransitGateways.item",
        "TransitGatewayId",
        "AWS::EC2::TransitGateway",
        ("OwnerId", "State"),
        None,
    ),
    "ec2:DescribeTransitGatewayAttachments": (
        "TransitGatewayAttachments",
        "TransitGatewayAttachments.item",
        "TransitGatewayAttachmentId",
        "AWS::EC2::TransitGatewayAttachment",
        (
            "TransitGatewayId",
            "TransitGatewayOwnerId",
            "ResourceId",
            "ResourceOwnerId",
            "ResourceType",
            "State",
            "Association",
        ),
        None,
    ),
    "ec2:DescribeTransitGatewayRouteTables": (
        "TransitGatewayRouteTables",
        "TransitGatewayRouteTables.item",
        "TransitGatewayRouteTableId",
        "AWS::EC2::TransitGatewayRouteTable",
        ("TransitGatewayId", "State"),
        None,
    ),
    "ec2:GetTransitGatewayRouteTableAssociations": (
        "Associations",
        "Associations.item",
        "TransitGatewayAttachmentId",
        "AWS::EC2::TransitGatewayAssociation",
        ("ResourceId", "ResourceType", "State"),
        "TransitGatewayRouteTableId",
    ),
    "ec2:GetTransitGatewayRouteTablePropagations": (
        "TransitGatewayRouteTablePropagations",
        "TransitGatewayRouteTablePropagations.item",
        "TransitGatewayAttachmentId",
        "AWS::EC2::TransitGatewayPropagation",
        ("ResourceId", "ResourceType", "State"),
        "TransitGatewayRouteTableId",
    ),
    "ec2:SearchTransitGatewayRoutes": (
        "Routes",
        "Routes.item",
        "DestinationCidrBlock",
        "AWS::EC2::TransitGatewayRoute",
        ("Type", "State", "TransitGatewayAttachments", "PrefixListId"),
        "TransitGatewayRouteTableId",
    ),
    "ram:GetResourceShares": (
        "resourceShares",
        "resourceShares.item",
        "resourceShareArn",
        "AWS::RAM::ResourceShare",
        ("owningAccountId", "status", "allowExternalPrincipals"),
        None,
    ),
    "ram:ListResources": (
        "resources",
        "resources.item",
        "arn",
        "AWS::RAM::ResourceReference",
        ("resourceShareArn", "status", "type"),
        None,
    ),
    "ram:ListPrincipals": (
        "principals",
        "principals.item",
        "id",
        "AWS::RAM::PrincipalReference",
        ("resourceShareArn", "external"),
        None,
    ),
}
OPERATIONS = tuple(PROFILES)


def export_records(path, source, artifact, shape):
    from offline_analyzer.normalization.adapters import mapping, normalized, policy_document, text

    top, prefix, identifier, kind, keys, subject = PROFILES[source.operation]
    fields = shape["fields"]
    expected = "start_array" if prefix.endswith(".item") else "start_map"
    if top == "Policy":
        expected = "string"
    if fields.get(top, (None,))[0] != expected:
        if "Error" in fields or "Errors" in fields:
            return
        raise InputError("UNSUPPORTED_AWS_RESPONSE_SHAPE")
    params = source.request_parameters or {}
    for index, row in records(path, prefix):
        row = mapping(row)
        config = {k: row.get(k) for k in keys}
        issues = ()
        native = row.get(identifier) if identifier else params.get(subject)
        if subject:
            config[subject] = params.get(subject)
            if not isinstance(params.get(subject), str):
                issues += ("request subject not recorded",)
        if top == "Policy":
            document, encoding = policy_document(row.get("Policy"))
            config.update(PolicyDocument=document, PolicyDocumentEncoding=encoding)
            if document is None:
                issues += ("resource policy document unresolved",)
        if source.operation == "kms:GetKeyPolicy" and not str(native).startswith("arn:"):
            native = None
            issues += ("KMS KeyId ARN required; aliases and UUIDs need DescribeKey resolution",)
        if subject and identifier:
            native = f"{params.get(subject)}#{native}" if native and params.get(subject) else None
        if kind.startswith("AWS::RAM::") and kind != "AWS::RAM::ResourceShare":
            native = (
                f"{row.get('resourceShareArn')}#{native}"
                if row.get("resourceShareArn") and native
                else None
            )
        owner = text(
            row.get("OwnerId")
            or row.get("owningAccountId")
            or row.get("TransitGatewayOwnerId")
            or source.account_id
        )
        # RAM references represent a collector's reference, not ownership of the referenced ARN.
        if kind in {"AWS::RAM::ResourceReference", "AWS::RAM::PrincipalReference"}:
            owner = source.account_id
        yield normalized(
            source,
            artifact,
            source.sha256,
            f"/{top}/{index}" if prefix.endswith(".item") else f"/{top}",
            native=native,
            kind=kind,
            account=owner,
            region=source.region,
            timestamp=source.collected_at,
            version=source.collector_version,
            status="OBSERVED",
            config=config,
            issues=issues,
            details={"request_parameters": source.request_parameters},
        )
