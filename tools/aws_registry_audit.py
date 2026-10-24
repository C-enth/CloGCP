"""Offline audit: collector registry vs installed botocore service models. No AWS calls.

Usage (in an environment with boto3/botocore, never the analyzer runtime):
    python tools/aws_registry_audit.py collectors/aws/assessment.py operation-names.json
Reports unknown operations, invalid/missing parameters and silent-truncation risks, and
writes the boto3-method -> API-name table used by contracts/aws_operation_names.py.
"""

import ast
import json
import sys

import botocore.session

src = open(sys.argv[1]).read()
tree = ast.parse(src)
reg = {}
for node in tree.body:
    if (
        isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in ("GLOBAL", "REGIONAL", "DEPENDENT", "MANUAL_PAGINATION")
    ):
        reg[node.targets[0].id] = ast.literal_eval(node.value)
# dependent calls issued inline with explicit params (from source reading)
inline = {
    ("cloudtrail", "get_trail_status"): {"Name"},
    ("cloudtrail", "get_event_selectors"): {"TrailName"},
    ("lambda", "get_policy"): {"FunctionName"},
    ("organizations", "list_policies_for_target"): {"TargetId", "Filter"},
    ("organizations", "describe_policy"): {"PolicyId"},
    ("organizations", "list_parents"): {"ChildId"},
    ("guardduty", "get_detector"): {"DetectorId"},
    ("iam", "get_policy_version"): {"PolicyArn", "VersionId"},
    ("elbv2", "describe_listeners"): {"LoadBalancerArn"},
    ("elbv2", "describe_target_groups"): {"LoadBalancerArn"},
    ("elbv2", "describe_rules"): {"ListenerArn"},
    ("ec2", "get_transit_gateway_route_table_associations"): {"TransitGatewayRouteTableId"},
    ("ec2", "get_transit_gateway_route_table_propagations"): {"TransitGatewayRouteTableId"},
    ("ec2", "search_transit_gateway_routes"): {"TransitGatewayRouteTableId", "Filters"},
    ("ecs", "describe_clusters"): {"clusters", "include"},
    ("eks", "describe_cluster"): {"name"},
    ("dynamodb", "describe_table"): {"TableName"},
    ("kms", "describe_key"): {"KeyId"},
    ("kms", "get_key_policy"): {"KeyId", "PolicyName"},
    ("kms", "get_key_rotation_status"): {"KeyId"},
    ("kms", "list_grants"): {"KeyId"},
    ("kms", "list_key_policies"): {"KeyId"},
}
for op in reg["DEPENDENT"]["s3"]:
    inline[("s3", op)] = {"Bucket"}
params_src = {
    ("s3control", "get_public_access_block"): {"AccountId"},
    ("wafv2", "list_web_acls"): {"Scope"},
    ("ram", "list_resources"): {"resourceOwner"},
    ("inspector2", "list_findings"): {"maxResults"},
    ("securityhub", "get_findings"): {"MaxResults"},
    ("resourcegroupstaggingapi", "get_resources"): {"ResourcesPerPage"},
    ("iam", "list_policies"): {"Scope"},
}
s = botocore.session.get_session()
problems = []
mapping = {}


def check(service, method, given):
    try:
        model = s.get_service_model(service)
    except Exception:
        problems.append(f"{service}: unknown service")
        return
    names = {botocore.xform_name(n): n for n in model.operation_names}
    if method not in names:
        problems.append(f"{service}.{method}: unknown operation")
        return
    op = model.operation_model(names[method])
    mapping[f"{service}.{method}"] = names[method]
    members = set(op.input_shape.members) if op.input_shape else set()
    required = set(op.input_shape.required_members) if op.input_shape else set()
    bad = given - members
    missing = required - given
    if bad:
        problems.append(
            f"{service}.{method}: invalid parameter(s) {sorted(bad)} "
            f"(valid: {sorted(members)[:12]})"
        )
    if missing:
        problems.append(f"{service}.{method}: missing required {sorted(missing)}")
    try:
        paginated = s.get_paginator_model(service).get_paginator(names[method]) is not None
    except Exception:
        paginated = False
    out = set(op.output_shape.members) if op.output_shape else set()
    tokens = out & {
        "NextToken",
        "Marker",
        "NextMarker",
        "nextToken",
        "IsTruncated",
        "NextContinuationToken",
        "NextPageToken",
    }
    if tokens and not paginated and (service, method) not in reg.get("MANUAL_PAGINATION", {}):
        problems.append(
            f"{service}.{method}: NOT paginatable but returns {sorted(tokens)} "
            "-> silent truncation risk"
        )


for scope in ("GLOBAL", "REGIONAL"):
    for svc, ops in reg[scope].items():
        for m in ops:
            check(svc, m, params_src.get((svc, m), set()))
for (svc, m), p in inline.items():
    check(svc, m, p)
print(json.dumps({"checked": len(mapping), "problems": problems}, indent=1))
json.dump(mapping, open(sys.argv[2], "w"), indent=1, sort_keys=True)
