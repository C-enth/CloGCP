"""Synthetic multi-account AWS packages for the AWS readiness tests (never real evidence).

Accounts use repeated-digit synthetic IDs; IP addresses are documentation ranges. Shapes
follow public AWS API responses; they are not collector exports.
"""

import json
from pathlib import Path

from offline_analyzer.contracts.r0 import Package, Scope, Source
from offline_analyzer.ingestion.safety import sha256_file
from tools.fixtures.r1_demo import group, instance, interface, permission, rid
from tools.fixtures.r12_demo import OK, allow, doc, gaad_role, managed, trust

A, B = "444444444444", "777777777777"  # documented synthetic IDs (tools/source_release.py)
R1, R2 = "us-east-1", "eu-west-1"


def network(account: str, region: str, open_ssh: bool = True, tokens: str = "optional") -> list:
    """One instance with a public interface whose group (same synthetic ID in every account)
    allows SSH from the internet or from a documentation range, plus an IGW route."""
    vm = instance(1, tokens, 1)
    vm.update(SubnetId=rid("subnet", 1), VpcId=rid("vpc", 1))
    eni = interface(account, 1, [1], public="198.51.100.10", instance=1)
    eni.update(SubnetId=rid("subnet", 1))
    cidr = "0.0.0.0/0" if open_ssh else "192.0.2.0/24"
    table = {
        "RouteTableId": rid("rtb", 1),
        "VpcId": rid("vpc", 1),
        "OwnerId": account,
        "Associations": [{"Main": True}],
        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-x", "State": "active"}],
    }
    return [
        ({"Reservations": [{"OwnerId": account, "Instances": [vm]}], **OK},
         "ec2:DescribeInstances", account, region),
        ({"SecurityGroups": [group(account, 1, "web", [permission(22, cidr)])], **OK},
         "ec2:DescribeSecurityGroups", account, region),
        ({"NetworkInterfaces": [eni], **OK}, "ec2:DescribeNetworkInterfaces", account, region),
        ({"RouteTables": [table], **OK}, "ec2:DescribeRouteTables", account, region),
    ]  # fmt: skip


def iam(account: str, other: str, roles: list | None = None, policies: list | None = None) -> list:
    """Same-named roles in every account: an unconditioned cross-account trust and an
    administrator role trusted by Lambda."""
    admin = f"arn:aws:iam::{account}:policy/admin"
    body = {
        "RoleDetailList": [
            gaad_role(account, "shared-name-trust", trust({"AWS": f"arn:aws:iam::{other}:root"})),
            gaad_role(
                account, "shared-name-admin", trust({"Service": "lambda.amazonaws.com"}), [admin]
            ),
            *(roles or []),
        ],
        "Policies": [managed(account, "admin", doc(allow("*"))), *(policies or [])],
        "UserDetailList": [],
        "GroupDetailList": [],
        "IsTruncated": False,
        **OK,
    }  # fmt: skip
    return [(body, "iam:GetAccountAuthorizationDetails", account, "global")]


def write(directory: Path, items: list, when: str, version: str = "synthetic-readiness") -> Path:
    """Package of (body, operation, account, region) items collected at `when`."""
    directory.mkdir(parents=True)
    sources, targets = [], set()
    for index, (body, operation, account, region) in enumerate(items):
        name = f"{index:03}.json"
        (directory / name).write_text(json.dumps(body))
        sources.append(
            Source(
                path=name,
                sha256=sha256_file(directory / name),
                format="aws-json-v1",
                operation=operation,
                account_id=account,
                region=region,
                collected_at=when,
                coverage="COMPLETE",
                collector_version=version,
                request_parameters={},
            )
        )
        if region != "global":
            targets.add((account, region))
    package = Package(
        targets=tuple(Scope(account_id=a, region=r) for a, r in sorted(targets)),
        sources=tuple(sources),
    )
    (directory / "manifest.json").write_text(package.model_dump_json())
    return directory


ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
SLR_POLICY = "arn:aws:iam::aws:policy/aws-service-role/SyntheticAutoScalingRolePolicy"


def _service_linked(account: str, name: str, service: str, attached=()) -> dict:
    role = gaad_role(account, name, trust({"Service": service}), list(attached))
    role["Path"] = f"/aws-service-role/{service}/"
    role["Arn"] = f"arn:aws:iam::{account}:role/aws-service-role/{service}/{name}"
    return role


def platform_roles(account: str, management: str) -> list[dict]:
    """Platform-managed identities and AWS service principals in trust policies."""
    sso_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": f"arn:aws:iam::{account}:saml-provider/AWSSSO_0000_DO_NOT_DELETE"
                },
                "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
                "Condition": {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
            }
        ],
    }
    sso_name = "AWSReservedSSO_AdministratorAccess_0123456789abcdef"
    sso = gaad_role(account, sso_name, sso_trust, [ADMIN_ARN])
    sso["Path"] = "/aws-reserved/sso.amazonaws.com/"
    sso["Arn"] = f"arn:aws:iam::{account}:role/aws-reserved/sso.amazonaws.com/{sso_name}"
    root = {"AWS": f"arn:aws:iam::{management}:root"}
    return [
        _service_linked(account, "AWSServiceRoleForAutoScaling", "autoscaling.amazonaws.com",
                        [SLR_POLICY]),
        sso,
        gaad_role(account, "OrganizationAccountAccessRole", trust(root), [ADMIN_ARN]),
        gaad_role(account, "AWSControlTowerExecution", trust(root), [ADMIN_ARN]),
        gaad_role(account, "svc-lambda-admin", trust({"Service": "lambda.amazonaws.com"}),
                  [ADMIN_ARN]),
        gaad_role(
            account,
            "svc-config-bound",
            trust({"Service": "config.amazonaws.com"},
                  {"StringEquals": {"aws:SourceAccount": account}}),
            inline={"put": doc(allow("config:Put*"))},
        ),
        gaad_role(
            account,
            "vendor-external-id",
            trust({"AWS": "arn:aws:iam::333333333333:root"},
                  {"StringEquals": {"sts:ExternalId": "synthetic-shared-value"}}),
        ),
    ]  # fmt: skip


def platform_policies(admin_document: bool = True) -> list[dict]:
    found = [
        {
            # Synthetic shape (not the AWS-published document): unconditioned PassRole with
            # launch permissions, as several service-linked policies grant.
            **managed("000000000001", "x", doc(allow(["ec2:RunInstances", "iam:PassRole"]))),
            "PolicyName": "SyntheticAutoScalingRolePolicy",
            "Arn": SLR_POLICY,
        }
    ]
    if admin_document:
        found.append(
            {**managed("000000000001", "x", doc(allow("*"))), "PolicyName": "AdministratorAccess",
             "Arn": ADMIN_ARN}
        )  # fmt: skip
    return found


def organization(account: str, management: str) -> list:
    """DescribeOrganization as a member account sees it (no hierarchy or SCP listing)."""
    body = {
        "Organization": {"Id": "o-synthetic01", "MasterAccountId": management, "FeatureSet": "ALL"},
        **OK,
    }
    return [(body, "organizations:DescribeOrganization", account, "global")]


def workload(account: str, role_name: str, role_document: dict | None, routes: bool) -> list:
    """Internet-exposed instance whose instance profile holds `role_name` (None: the role is
    not collected); route tables are omitted when `routes` is False (MEDIUM exposure)."""
    vm = instance(1, "required", 1)
    vm.update(SubnetId=rid("subnet", 1), VpcId=rid("vpc", 1))
    vm["IamInstanceProfile"] = {"Arn": f"arn:aws:iam::{account}:instance-profile/ip-workload"}
    roles = []
    if role_document is not None:
        roles.append(
            gaad_role(account, role_name, trust({"Service": "ec2.amazonaws.com"}),
                      inline={"policy": role_document}, profiles=["ip-workload"])
        )  # fmt: skip
    items = [item for item in network(account, R1) if item[1] != "ec2:DescribeInstances"]
    if not routes:
        items = [item for item in items if item[1] != "ec2:DescribeRouteTables"]
    gaad = {"RoleDetailList": roles, "Policies": [], "UserDetailList": [], "GroupDetailList": [],
            "IsTruncated": False, **OK}  # fmt: skip
    return items + [
        ({"Reservations": [{"OwnerId": account, "Instances": [vm]}], **OK},
         "ec2:DescribeInstances", account, R1),
        (gaad, "iam:GetAccountAuthorizationDetails", account, "global"),
    ]  # fmt: skip
