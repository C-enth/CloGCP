"""AWS-native IAM and Organizations response adapters (structure only, no decisions).

Per-role/per-policy responses do not repeat their subject, so identity comes only from
the recorded request parameter (RoleName, PolicyArn, ParentId, ...). Listings record
whether they were truncated; a truncated or missing listing is never read as "none".
Attachment references are kept separately from resolved policy documents.
"""

from offline_analyzer.ingestion.json_input import InputError, records
from offline_analyzer.normalization import adapters as base

ROLE = "AWS::IAM::Role"
LIST_KINDS = {
    "iam:ListAttachedRolePolicies": (
        "AttachedPolicies",
        "AWS::IAM::RoleAttachmentList",
        "RoleName",
    ),
    "iam:ListRolePolicies": ("PolicyNames", "AWS::IAM::RoleInlinePolicyList", "RoleName"),
    "iam:ListInstanceProfilesForRole": (
        "InstanceProfiles",
        "AWS::IAM::RoleInstanceProfileList",
        "RoleName",
    ),
    "organizations:ListTargetsForPolicy": (
        "Targets",
        "AWS::Organizations::PolicyTargetList",
        "PolicyId",
    ),
    "organizations:ListPoliciesForTarget": (
        "Policies",
        "AWS::Organizations::TargetPolicyList",
        "TargetId",
    ),
}
ORG_LISTS = {
    "organizations:ListRoots": ("Roots", "AWS::Organizations::Root"),
    "organizations:ListOrganizationalUnitsForParent": (
        "OrganizationalUnits",
        "AWS::Organizations::OrganizationalUnit",
    ),
    "organizations:ListAccountsForParent": ("Accounts", "AWS::Organizations::Account"),
    "organizations:ListAccounts": ("Accounts", "AWS::Organizations::Account"),
    "organizations:ListParents": ("Parents", "AWS::Organizations::ParentLink"),
    "organizations:ListPolicies": ("Policies", "AWS::Organizations::Policy"),
}
SINGLE = {
    "iam:GetRole": ("Role", ROLE),
    "iam:GetPolicy": ("Policy", "AWS::IAM::ManagedPolicy"),
    "iam:GetPolicyVersion": ("PolicyVersion", "AWS::IAM::ManagedPolicyVersion"),
    "iam:GetInstanceProfile": ("InstanceProfile", "AWS::IAM::InstanceProfile"),
    "iam:GetRolePolicy": ("", "AWS::IAM::RoleInlinePolicy"),
    "organizations:DescribeOrganization": ("Organization", "AWS::Organizations::Organization"),
    "organizations:DescribePolicy": ("Policy", "AWS::Organizations::Policy"),
}
OPERATIONS = set(LIST_KINDS) | set(ORG_LISTS) | set(SINGLE)
NOT_IN_ORGANIZATION = "AWSOrganizationsNotInUseException"


def emit(source, artifact, locator, native, kind, config, issues=()):
    return base.normalized(
        source,
        artifact,
        source.sha256,
        locator,
        native=native,
        kind=kind,
        account=source.account_id,
        region=source.region,
        partition=base.region_partition(source.region),
        timestamp=source.collected_at,
        version=source.collector_version,
        status="OBSERVED",
        config=config,
        issues=tuple(issues),
        details={"request_parameters": source.request_parameters},
    )


def instance_profile(row: dict) -> dict:
    roles = row.get("Roles")
    return {
        "InstanceProfileName": row.get("InstanceProfileName"),
        "RoleArns": [base.mapping(r).get("Arn") for r in roles]
        if isinstance(roles, list)
        else None,
    }


def org_policy(row: dict) -> dict:
    summary = base.mapping(row.get("PolicySummary")) or row
    config = {k: summary.get(k) for k in ("Id", "Name", "Type", "AwsManaged")}
    if "Content" in row:
        content, encoding = base.policy_document(row.get("Content"))
        config.update(Content=content, ContentEncoding=encoding)
    return config


def single_config(operation: str, row: dict, params: dict) -> tuple[object, dict, tuple]:
    if operation == "iam:GetRole":
        config, issues = base.configuration_for(operation, row)
        return row.get("Arn"), config, issues
    if operation == "iam:GetPolicy":
        keys = ("PolicyName", "DefaultVersionId", "AttachmentCount", "IsAttachable")
        return row.get("Arn"), {k: row.get(k) for k in keys}, ()
    if operation == "iam:GetPolicyVersion":
        arn, version = params.get("PolicyArn"), row.get("VersionId") or params.get("VersionId")
        document, encoding = base.policy_document(row.get("Document"))
        issues = () if document else ("managed policy version document unresolved",)
        config = {
            "PolicyArn": arn,
            "VersionId": version,
            "IsDefaultVersion": row.get("IsDefaultVersion"),
            "Document": document,
            "PolicyDocumentEncoding": encoding,
        }
        native = f"{arn}#{version}" if isinstance(arn, str) and isinstance(version, str) else None
        return native, config, issues
    if operation == "iam:GetInstanceProfile":
        return row.get("Arn"), instance_profile(row), ()
    if operation == "iam:GetRolePolicy":
        role, name = row.get("RoleName") or params.get("RoleName"), row.get("PolicyName")
        document, encoding = base.policy_document(row.get("PolicyDocument"))
        issues = () if document else ("inline policy document unresolved",)
        native = f"{role}/{name}" if isinstance(role, str) and isinstance(name, str) else None
        config = {
            "RoleName": role,
            "PolicyName": name,
            "Document": document,
            "PolicyDocumentEncoding": encoding,
        }
        return native, config, issues
    if operation == "organizations:DescribeOrganization":
        keys = ("Id", "MasterAccountId", "FeatureSet")
        return row.get("Id"), {**{k: row.get(k) for k in keys}, "in_organization": True}, ()
    return (
        row.get("PolicySummary", {}).get("Id")
        if isinstance(row.get("PolicySummary"), dict)
        else None,
        org_policy(row),
        (),
    )


def iam_records(path, source, artifact, shape):
    operation, params = source.operation, source.request_parameters or {}
    fields = shape["fields"] if shape and shape["root"] == "start_map" else None
    if fields is None:
        raise InputError("UNSUPPORTED_AWS_RESPONSE_SHAPE")
    truncated = (
        fields.get("IsTruncated") == ("boolean", True)
        or fields.get("NextToken", (None,))[0] == "string"
    )
    if operation == "organizations:DescribeOrganization" and fields.get("Error.Code") == (
        "string",
        NOT_IN_ORGANIZATION,
    ):
        # AWS-defined answer: this account is not in an organization (SCPs not applicable).
        yield emit(
            source,
            artifact,
            "/Error",
            source.account_id,
            "AWS::Organizations::Membership",
            {"in_organization": False},
        )
        return
    if operation in SINGLE:
        payload, kind = SINGLE[operation]
        if payload and fields.get(payload, (None,))[0] != "start_map":
            if "Error" in fields or "Errors" in fields:
                return
            raise InputError("UNSUPPORTED_AWS_RESPONSE_SHAPE")
        for _, row in records(path, payload):
            native, config, issues = single_config(operation, base.mapping(row), params)
            yield emit(source, artifact, f"/{payload}", native, kind, config, issues)
        return
    if operation in LIST_KINDS:
        top, kind, subject_key = LIST_KINDS[operation]
        if fields.get(top, (None,))[0] != "start_array":
            if "Error" in fields or "Errors" in fields:
                return
            raise InputError("UNSUPPORTED_AWS_RESPONSE_SHAPE")
        items = [item for _, item in records(path, f"{top}.item")]
        subject = params.get(subject_key)
        config = {"Subject": subject, "Truncated": truncated, "Filter": params.get("Filter")}
        if operation == "iam:ListAttachedRolePolicies":
            config["PolicyArns"] = [base.mapping(i).get("PolicyArn") for i in items]
        elif operation == "iam:ListRolePolicies":
            config["PolicyNames"] = items
        elif operation == "iam:ListInstanceProfilesForRole":
            config["ProfileArns"] = [base.mapping(i).get("Arn") for i in items]
            for index, item in enumerate(items):
                row = base.mapping(item)
                yield emit(
                    source,
                    artifact,
                    f"/{top}/{index}",
                    row.get("Arn"),
                    "AWS::IAM::InstanceProfile",
                    instance_profile(row),
                )
        elif operation == "organizations:ListTargetsForPolicy":
            config["TargetIds"] = [base.mapping(i).get("TargetId") for i in items]
        else:
            config["PolicyIds"] = [base.mapping(i).get("Id") for i in items]
            config["PolicyTypes"] = [base.mapping(i).get("Type") for i in items]
        native = subject if not params.get("Filter") else f"{subject}#{params.get('Filter')}"
        valid = all(
            isinstance(v, str)
            for v in config.get("PolicyArns", config.get("PolicyNames", [])) or []
        )
        yield emit(
            source,
            artifact,
            f"/{top}",
            native,
            kind,
            config,
            () if valid else ("listing entries unresolved",),
        )
        return
    top, kind = ORG_LISTS[operation]
    if fields.get(top, (None,))[0] != "start_array":
        if "Error" in fields or "Errors" in fields:
            return
        raise InputError("UNSUPPORTED_AWS_RESPONSE_SHAPE")
    parent = params.get("ParentId")
    for index, item in enumerate(records(path, f"{top}.item")):
        row = base.mapping(item[1])
        if operation == "organizations:ListParents":
            native = params.get("ChildId")
            config = {"ParentId": row.get("Id"), "ParentType": row.get("Type")}
        elif operation == "organizations:ListPolicies":
            native, config = row.get("Id"), org_policy(row)
        else:
            native = row.get("Id")
            config = {
                "Name": row.get("Name"),
                "ParentId": parent,
                "Status": row.get("Status"),
                "PolicyTypes": row.get("PolicyTypes"),
            }
        yield emit(source, artifact, f"/{top}/{index}", native, kind, config)
