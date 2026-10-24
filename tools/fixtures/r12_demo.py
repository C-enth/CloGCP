"""R1.2 IAM golden demonstration (synthetic AWS-native IAM and Organizations evidence).

Accounts: T target (member), S source (member, per-role IAM API exports), M management
(Organizations exports), N outside any organization, U collected but absent from the
hierarchy. Run: python -m tools.fixtures.r12_demo --output artifacts/r12-demo-new
"""

import argparse
import json
from pathlib import Path
from urllib.parse import quote

from offline_analyzer.cli import summary
from offline_analyzer.contracts.r0 import Package, Scope, Source
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.safety import sha256_file
from offline_analyzer.inventory.accounts import install_registry
from offline_analyzer.reporting.excel import export_excel
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store

TIME = "2026-10-10T07:00:00+00:00"
T, S, M, N, U, X = (
    "111111111111",
    "222222222222",
    "999999999999",
    "555555555555",
    "666666666666",
    "333333333333",
)
ORG, ROOT, OU = "o-golden00001", "r-ab12", "ou-ab12-workload1"
OK = {"ResponseMetadata": {"HTTPStatusCode": 200}}


def arn(account, name):
    return f"arn:aws:iam::{account}:role/{name}"


def policy_arn(account, name):
    return f"arn:aws:iam::{account}:policy/{name}"


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def deny(action, resource="*", **extra):
    return {"Effect": "Deny", "Action": action, "Resource": resource, **extra}


def trust(principal, condition=None, action="sts:AssumeRole"):
    statement = {"Effect": "Allow", "Principal": principal, "Action": action}
    if condition:
        statement["Condition"] = condition
    return doc(statement)


ADMIN = doc(allow("*"))
SERVICE = {
    "ec2": {"Service": "ec2.amazonaws.com"},
    "lambda": {"Service": "lambda.amazonaws.com"},
    "ecs": {"Service": "ecs-tasks.amazonaws.com"},
}


def gaad_role(account, name, trust_doc, attached=(), inline=None, profiles=(), boundary=None):
    role = {
        "Path": "/",
        "RoleName": name,
        "RoleId": "AROA" + name.upper().replace("-", "")[:16].ljust(16, "X"),
        "Arn": arn(account, name),
        "AssumeRolePolicyDocument": trust_doc,
        "AttachedManagedPolicies": [
            {"PolicyName": a.split("/")[-1], "PolicyArn": a} for a in attached
        ],
        "RolePolicyList": [
            {"PolicyName": k, "PolicyDocument": v} for k, v in (inline or {}).items()
        ],
        "InstanceProfileList": [
            {
                "InstanceProfileName": p,
                "Arn": f"arn:aws:iam::{account}:instance-profile/{p}",
                "Roles": [{"Arn": arn(account, name)}],
            }
            for p in profiles
        ],
    }
    if boundary:
        role["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary}
    return role


def managed(account, name, document):
    return {
        "PolicyName": name,
        "Arn": policy_arn(account, name),
        "DefaultVersionId": "v1",
        "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": document}],
    }


def target_account():
    admin = policy_arn(T, "t-admin-policy")
    roles = [
        # Cross-account targets.
        gaad_role(T, "t-admin-target", trust({"AWS": f"arn:aws:iam::{S}:root"}), [admin]),
        gaad_role(
            T,
            "t-wildcard-conditioned",
            trust("*", {"StringEquals": {"aws:PrincipalOrgID": ORG}}),
            [admin],
        ),
        gaad_role(T, "t-specific-external", trust({"AWS": arn(X, "vendor-role")})),
        gaad_role(
            T,
            "t-mfa-target",
            trust(
                {"AWS": f"arn:aws:iam::{S}:root"}, {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
            ),
        ),
        # PassRole targets.
        gaad_role(T, "t-ec2-admin", trust(SERVICE["ec2"]), [admin], profiles=["ip-ec2-admin"]),
        gaad_role(
            T,
            "t-ec2-readonly",
            trust(SERVICE["ec2"]),
            inline={"read": doc(allow("s3:Get*"))},
            profiles=["ip-ec2-readonly"],
        ),
        gaad_role(T, "t-lambda-admin", trust(SERVICE["lambda"]), [admin]),
        gaad_role(T, "t-ecs-only", trust(SERVICE["ecs"]), [admin]),
        # PassRole principals.
        gaad_role(
            T,
            "p-broad-passrole",
            trust(SERVICE["ec2"]),
            inline={"ops": doc(allow("iam:PassRole"), allow("ec2:RunInstances"))},
            profiles=["ip-app"],
        ),
        gaad_role(
            T,
            "p-restricted-passrole",
            trust(SERVICE["ec2"]),
            inline={
                "ops": doc(
                    allow(
                        "iam:PassRole",
                        arn(T, "t-ec2-readonly"),
                        Condition={"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}},
                    ),
                    allow("ec2:RunInstances"),
                )
            },
        ),
        gaad_role(
            T,
            "p-ecs-mismatch",
            trust(SERVICE["ec2"]),
            inline={
                "ops": doc(allow("iam:PassRole", arn(T, "t-ecs-only")), allow("ec2:RunInstances"))
            },
        ),
        gaad_role(
            T,
            "p-potential",
            trust(SERVICE["ec2"]),
            [policy_arn(T, "not-exported")],
            inline={"pass": doc(allow("iam:PassRole"))},
            profiles=["ip-potential"],
        ),
        gaad_role(
            T,
            "p-unsupported-condition",
            trust(SERVICE["ec2"]),
            inline={
                "ops": doc(
                    allow(
                        "iam:PassRole",
                        Condition={"DateLessThan": {"aws:CurrentTime": "2030-01-01T00:00:00Z"}},
                    ),
                    allow("ec2:RunInstances"),
                )
            },
        ),
        gaad_role(
            T,
            "p-notaction",
            trust(SERVICE["ec2"]),
            inline={
                "ops": {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
            },
        ),
        gaad_role(
            T,
            "p-notresource",
            trust(SERVICE["ec2"]),
            inline={
                "ops": doc(
                    {
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "NotResource": arn(T, "t-ec2-admin"),
                    },
                    allow("ec2:RunInstances"),
                )
            },
        ),
    ]
    policies = [managed(T, "t-admin-policy", ADMIN)]
    instances = [
        {
            "InstanceId": f"i-{n:017x}",
            "State": {"Name": "running"},
            "MetadataOptions": {
                "State": "applied",
                "HttpTokens": "required",
                "HttpEndpoint": "enabled",
                "HttpPutResponseHopLimit": 1,
            },
            "IamInstanceProfile": {"Arn": f"arn:aws:iam::{T}:instance-profile/{profile}"},
        }
        for n, profile in ((1, "ip-app"), (2, "ip-potential"))
    ]
    return [
        (
            {"RoleDetailList": roles, "Policies": policies, "IsTruncated": False, **OK},
            "iam:GetAccountAuthorizationDetails",
            T,
            {},
        ),
        (
            {"Reservations": [{"OwnerId": T, "Instances": instances}], **OK},
            "ec2:DescribeInstances",
            T,
            {},
        ),
    ]


def source_account():
    """Per-role IAM API exports, including truncated and conflicting collections."""
    roles = {
        "s-caller": {"assume": doc(allow("sts:AssumeRole", f"arn:aws:iam::{T}:role/t-*"))},
        "s-deny-caller": {
            "assume": doc(allow("sts:AssumeRole"), deny("sts:AssumeRole", arn(T, "t-admin-target")))
        },
        "s-no-permission": {"read": doc(allow("s3:GetObject"))},
        "scp-restricted-caller": {"assume": doc(allow("sts:AssumeRole"))},
        "s-boundary-missing": {"assume": doc(allow("sts:AssumeRole"))},
        "s-truncated": {"assume": doc(allow("sts:AssumeRole"))},
        "s-conflict": {"assume": doc(allow("sts:AssumeRole"))},
    }
    listed = [
        {
            "Path": "/",
            "RoleName": name,
            "Arn": arn(S, name),
            "AssumeRolePolicyDocument": quote(json.dumps(trust(SERVICE["ec2"]))),
        }
        for name in roles
    ]
    sources = [
        ({"Roles": listed, "IsTruncated": False, **OK}, "iam:ListRoles", S, {}),
        # Duplicate identical collection: deduplicated, never double counted.
        ({"Roles": listed, "IsTruncated": False, **OK}, "iam:ListRoles", S, {"PathPrefix": "/"}),
        (
            {
                "Role": {
                    **listed[4],
                    "PermissionsBoundary": {
                        "PermissionsBoundaryArn": policy_arn(S, "missing-boundary")
                    },
                }
            },
            "iam:GetRole",
            S,
            {"RoleName": "s-boundary-missing"},
        ),
    ]
    for name, inline in roles.items():
        truncated = name == "s-truncated"
        sources.append(
            (
                {
                    "AttachedPolicies": [],
                    "IsTruncated": truncated,
                    **({"Marker": "next"} if truncated else {}),
                    **OK,
                },
                "iam:ListAttachedRolePolicies",
                S,
                {"RoleName": name},
            )
        )
        sources.append(
            (
                {"PolicyNames": list(inline), "IsTruncated": False, **OK},
                "iam:ListRolePolicies",
                S,
                {"RoleName": name},
            )
        )
        for policy_name, document in inline.items():
            sources.append(
                (
                    {
                        "RoleName": name,
                        "PolicyName": policy_name,
                        "PolicyDocument": quote(json.dumps(document)),
                        **OK,
                    },
                    "iam:GetRolePolicy",
                    S,
                    {"RoleName": name, "PolicyName": policy_name},
                )
            )
    # Conflicting second snapshot of one inline policy: the document becomes unresolved.
    sources.append(
        (
            {
                "RoleName": "s-conflict",
                "PolicyName": "assume",
                "PolicyDocument": doc(allow("s3:ListBucket")),
                **OK,
            },
            "iam:GetRolePolicy",
            S,
            {"RoleName": "s-conflict", "PolicyName": "assume"},
        )
    )
    return sources


def organization():
    full = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    restrict = doc(
        deny(
            "sts:AssumeRole",
            Condition={
                "StringLike": {"aws:PrincipalArn": f"arn:aws:iam::{S}:role/scp-restricted-*"}
            },
        )
    )
    rcp_full = {
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]
    }
    policies = {
        "p-FullAWSAccess": ("SERVICE_CONTROL_POLICY", full, True),
        "p-denyassume01": ("SERVICE_CONTROL_POLICY", restrict, False),
        "p-RCPFullAWSAccess": ("RESOURCE_CONTROL_POLICY", rcp_full, True),
    }
    attachments = {
        "SERVICE_CONTROL_POLICY": {
            ROOT: ["p-FullAWSAccess"],
            OU: ["p-FullAWSAccess"],
            T: ["p-FullAWSAccess"],
            S: ["p-FullAWSAccess", "p-denyassume01"],
        },
        "RESOURCE_CONTROL_POLICY": {
            ROOT: ["p-RCPFullAWSAccess"],
            OU: ["p-RCPFullAWSAccess"],
            T: ["p-RCPFullAWSAccess"],
            S: ["p-RCPFullAWSAccess"],
        },
    }
    sources = [
        (
            {"Organization": {"Id": ORG, "MasterAccountId": M, "FeatureSet": "ALL"}, **OK},
            "organizations:DescribeOrganization",
            M,
            {},
        ),
        (
            {
                "Roots": [
                    {
                        "Id": ROOT,
                        "Name": "Root",
                        "PolicyTypes": [
                            {"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"},
                            {"Type": "RESOURCE_CONTROL_POLICY", "Status": "ENABLED"},
                        ],
                    }
                ],
                **OK,
            },
            "organizations:ListRoots",
            M,
            {},
        ),
        (
            {"OrganizationalUnits": [{"Id": OU, "Name": "workloads"}], **OK},
            "organizations:ListOrganizationalUnitsForParent",
            M,
            {"ParentId": ROOT},
        ),
        (
            {"Accounts": [{"Id": M, "Name": "management", "Status": "ACTIVE"}], **OK},
            "organizations:ListAccountsForParent",
            M,
            {"ParentId": ROOT},
        ),
        (
            {
                "Accounts": [
                    {"Id": T, "Name": "target", "Status": "ACTIVE"},
                    {"Id": S, "Name": "source", "Status": "ACTIVE"},
                ],
                **OK,
            },
            "organizations:ListAccountsForParent",
            M,
            {"ParentId": OU},
        ),
        # Account N proves it is outside any organization.
        (
            {"Error": {"Code": "AWSOrganizationsNotInUseException"}},
            "organizations:DescribeOrganization",
            N,
            {},
        ),
    ]
    for kind in ("SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"):
        summaries = [
            {"Id": p, "Name": p, "Type": t, "AwsManaged": m}
            for p, (t, _, m) in policies.items()
            if t == kind
        ]
        sources.append(
            ({"Policies": summaries, **OK}, "organizations:ListPolicies", M, {"Filter": kind})
        )
        for target, ids in attachments[kind].items():
            listed = [{"Id": p, "Type": kind, "Name": p} for p in ids]
            sources.append(
                (
                    {"Policies": listed, **OK},
                    "organizations:ListPoliciesForTarget",
                    M,
                    {"TargetId": target, "Filter": kind},
                )
            )
    for policy_id, (kind, content, managed_flag) in policies.items():
        sources.append(
            (
                {
                    "Policy": {
                        "PolicySummary": {
                            "Id": policy_id,
                            "Name": policy_id,
                            "Type": kind,
                            "AwsManaged": managed_flag,
                        },
                        "Content": json.dumps(content),
                    },
                    **OK,
                },
                "organizations:DescribePolicy",
                M,
                {"PolicyId": policy_id},
            )
        )
    return sources


def outside_accounts():
    caller = {"assume": doc(allow("sts:AssumeRole"))}
    return [
        (
            {
                "RoleDetailList": [gaad_role(N, "n-caller", trust(SERVICE["ec2"]), inline=caller)],
                "Policies": [],
                "IsTruncated": False,
                **OK,
            },
            "iam:GetAccountAuthorizationDetails",
            N,
            {},
        ),
        (
            {
                "RoleDetailList": [gaad_role(U, "u-caller", trust(SERVICE["ec2"]), inline=caller)],
                "Policies": [],
                "IsTruncated": False,
                **OK,
            },
            "iam:GetAccountAuthorizationDetails",
            U,
            {},
        ),
    ]


def build(directory: Path) -> Package:
    directory.mkdir(parents=True)
    sources = []
    for index, (body, operation, account, params) in enumerate(
        target_account() + source_account() + organization() + outside_accounts()
    ):
        name = f"{index:03}.json"
        (directory / name).write_text(json.dumps(body))
        sources.append(
            Source(
                path=name,
                sha256=sha256_file(directory / name),
                format="aws-json-v1",
                operation=operation,
                account_id=account,
                region="us-east-1",
                collected_at=TIME,
                coverage="COMPLETE",
                collector_version="synthetic-r12",
                request_parameters=params,
            )
        )
    package = Package(targets=(Scope(account_id=T, region="us-east-1"),), sources=tuple(sources))
    (directory / "manifest.json").write_text(package.model_dump_json())
    return package


def registry_file(path: Path) -> Path:
    keys = {T: "ACCT-001", S: "ACCT-002", M: "ACCT-003", N: "ACCT-004", U: "ACCT-005"}
    path.write_text(
        json.dumps(
            {
                "schema_version": "account-registry-1",
                "source": "synthetic approved inventory",
                "approved_by": "synthetic-analyst",
                "approved_at": TIME,
                "entries": [
                    {"account_id": a, "tracker_key": k, "in_scope": True} for a, k in keys.items()
                ],
            }
        )
    )
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.exit(1, "Output directory must not exist.\n")
    args.output.mkdir(parents=True)
    build(args.output / "input")
    with Store(args.output / "workspace") as store:
        install_registry(store.workspace, registry_file(args.output / "account-registry.json"))
        run = import_package(store, args.output / "input")
        assess(store, run)
        report = export_excel(store, run, args.output / "R12-assessment.xlsx")
        print(json.dumps({"run_id": run, "report": str(report), **summary(store, run)}, indent=2))


if __name__ == "__main__":
    main()
