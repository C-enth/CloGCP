"""R1.1 golden demonstration: false-positive-prone conditions as synthetic AWS evidence.

All values are synthetic (repeated-digit accounts, documentation IPs). Shapes follow public
AWS API responses; this is never real-export validation. Run:
    python -m tools.fixtures.r11_demo --output artifacts/r11-demo-new
"""

import argparse
import json
from pathlib import Path

from offline_analyzer.cli import summary
from offline_analyzer.contracts.r0 import Package, Scope, Source
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.safety import sha256_file
from offline_analyzer.inventory.accounts import install_registry
from offline_analyzer.reporting.excel import export_excel
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from offline_analyzer.verification import verify_package
from tools.fixtures.r1_demo import (
    database,
    group,
    instance,
    interface,
    permission,
    rid,
    role,
    trust,
)

TIME = "2026-10-10T06:00:00+00:00"
A, B, C = "111111111111", "222222222222", "666666666666"
INTERNAL, VENDOR = "555555555555", "333333333333"
OK = {"ResponseMetadata": {"HTTPStatusCode": 200}}
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
SCP = "Organizations SCP/RCP evidence"


def registry_file(path, accounts=((A, "ACCT-001"), (B, "ACCT-002"), (INTERNAL, "ACCT-003"),
                                   ("777777777777", "ACCT-004"))):  # fmt: skip
    path.write_text(
        json.dumps(
            {
                "schema_version": "account-registry-1",
                "source": "synthetic approved inventory",
                "approved_by": "synthetic-analyst",
                "approved_at": TIME,
                "entries": [
                    {"account_id": a, "tracker_key": k, "in_scope": True} for a, k in accounts
                ],
            }
        )
    )
    return path


def full_role(account, name, document, attached=(), inline=(), boundary=None):
    item = role(account, name, document)
    item["AttachedManagedPolicies"] = [
        {"PolicyArn": a, "PolicyName": a.split("/")[-1]} for a in attached
    ]
    item["RolePolicyList"] = [
        {"PolicyName": f"inline{i}", "PolicyDocument": d} for i, d in enumerate(inline)
    ]
    if boundary:
        item["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary}
    return item


ADMIN_DOC = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
ROOT = lambda account: {"AWS": f"arn:aws:iam::{account}:root"}  # noqa: E731


def route_table(account, n, vpc, subnets=(), main=False, gateway="igw-0abc", v6=None):
    routes = [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"}]
    if gateway:
        key = "GatewayId" if gateway.startswith("igw-") else "NatGatewayId"
        routes.append({"DestinationCidrBlock": "0.0.0.0/0", key: gateway, "State": "active"})
    if v6:
        routes.append({"DestinationIpv6CidrBlock": "::/0", "GatewayId": v6, "State": "active"})
    associations = [{"SubnetId": s, "Main": False} for s in subnets]
    if main:
        associations.append({"Main": True})
    return {"RouteTableId": rid("rtb", n), "OwnerId": account, "VpcId": vpc,
            "Associations": associations, "Routes": routes}  # fmt: skip


def eni(account, n, groups, subnet, public="203.0.113.50", instance_n=None):
    item = interface(account, n, groups, public=public, instance=instance_n)
    item["SubnetId"] = subnet
    return item


def bucket_sources(account, bucket, bpa=None, policy=None, acl=None):
    """bpa: dict | 'absent'; policy: bool | 'absent'; acl: list of public grantee URIs."""
    sources = []
    if bpa is not None:
        body = (
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}
            if bpa == "absent"
            else {"PublicAccessBlockConfiguration": bpa, **OK}
        )
        sources.append((body, "s3api:GetPublicAccessBlock", account, {"Bucket": bucket}))
    if policy is not None:
        body = (
            {"Error": {"Code": "NoSuchBucketPolicy"}}
            if policy == "absent"
            else {"PolicyStatus": {"IsPublic": policy}, **OK}
        )
        sources.append((body, "s3api:GetBucketPolicyStatus", account, {"Bucket": bucket}))
    if acl is not None:
        grants = [
            {"Grantee": {"Type": "CanonicalUser", "ID": "owner"}, "Permission": "FULL_CONTROL"}
        ]
        grants += [{"Grantee": {"Type": "Group", "URI": uri}, "Permission": "READ"} for uri in acl]
        sources.append(({"Owner": {"ID": "owner"}, "Grants": grants, **OK},
                        "s3api:GetBucketAcl", account, {"Bucket": bucket}))  # fmt: skip
    return sources


ALL_ON = dict.fromkeys(
    ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True
)
ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"


def scenario_sources():
    """(body, operation, account, request_parameters[, region, coverage])."""
    vpc = rid("vpc", 1)
    sg = [
        group(A, 21, "golden-routed", [permission(22, "0.0.0.0/0")]),
        group(A, 22, "golden-nat-only", [permission(3389, "0.0.0.0/0")]),
        group(A, 23, "golden-main-table", [permission(22, "0.0.0.0/0")]),
        group(A, 31, "golden-db-restricted", [permission(5432, "10.0.0.0/8")]),
        group(A, 32, "golden-db-open", [permission(5432, "0.0.0.0/0")]),
    ]
    enis = [
        eni(A, 21, [21], "subnet-routed", instance_n=21),
        eni(A, 22, [22], "subnet-nat"),
        eni(A, 23, [23], "subnet-unassociated"),
    ]
    tables = [
        route_table(A, 1, vpc, ["subnet-routed", "subnet-db-public"]),
        route_table(A, 2, vpc, ["subnet-nat", "subnet-db-private"], gateway="nat-0abc"),
        route_table(A, 3, vpc, main=True),
    ]
    instances = [
        instance(21, "optional", 1),
        instance(22, "required", 2),
        instance(23, "optional", 1),
    ]
    instances[1]["Tags"] = [{"Key": "eks:cluster-name", "Value": "golden-cluster"}]
    instances[2]["State"] = {"Name": "stopped"}
    pending = instance(24, "required", 1)
    pending["MetadataOptions"]["State"] = "pending"
    instances.append(pending)

    def db(name, groups, subnets, public=True):
        item = database(A, name, "postgres", public, True)
        item["Endpoint"] = {"Port": 5432}
        item["VpcSecurityGroups"] = [
            {"VpcSecurityGroupId": rid("sg", g), "Status": "active"} for g in groups
        ]
        item["DBSubnetGroup"] = {
            "VpcId": vpc,
            "Subnets": [{"SubnetIdentifier": s} for s in subnets],
        }
        return item

    databases = [
        db("golden-restricted", [31], ["subnet-db-public"]),
        db("golden-open-routed", [32], ["subnet-db-public"]),
        db("golden-sg-missing", [99], ["subnet-db-public"]),
        db("golden-open-private", [32], ["subnet-db-private"]),
    ]
    managed = {
        "PolicyName": "golden-admin",
        "Arn": f"arn:aws:iam::{A}:policy/golden-admin",
        "DefaultVersionId": "v1",
        "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": ADMIN_DOC}],
    }
    aws_managed = {"PolicyName": "AdministratorAccess", "Arn": ADMIN, "PolicyVersionList": []}
    roles = [
        full_role(A, "golden-narrow-internal",
                  trust({"AWS": f"arn:aws:iam::{INTERNAL}:role/deployer"})),
        full_role(A, "golden-vendor-admin", trust(ROOT(VENDOR)), attached=[ADMIN]),
        full_role(A, "golden-internal-root", trust(ROOT(INTERNAL))),
        full_role(A, "golden-public-admin", trust("*"), inline=[ADMIN_DOC]),
        full_role(A, "golden-vendor-customer-admin", trust(ROOT(VENDOR)),
                  attached=[managed["Arn"]], boundary=f"arn:aws:iam::{A}:policy/boundary"),
        full_role(A, "golden-vendor-unknown-policy", trust(ROOT(VENDOR)),
                  attached=[f"arn:aws:iam::{A}:policy/not-exported"]),
    ]  # fmt: skip
    listed = [role(B, "golden-listroles-vendor", trust(ROOT(VENDOR)))]
    sources = [
        ({"SecurityGroups": sg, **OK}, "ec2:DescribeSecurityGroups", A, {}),
        ({"NetworkInterfaces": enis, **OK}, "ec2:DescribeNetworkInterfaces", A, {}),
        ({"RouteTables": tables, **OK}, "ec2:DescribeRouteTables", A, {}),
        ({"Reservations": [{"OwnerId": A, "Instances": instances}], **OK},
         "ec2:DescribeInstances", A, {}),
        ({"DBInstances": databases, **OK}, "rds:DescribeDBInstances", A, {}),
        ({"RoleDetailList": roles, "Policies": [managed, aws_managed], "IsTruncated": False, **OK},
         "iam:GetAccountAuthorizationDetails", A, {}),
        ({"Roles": listed, "IsTruncated": False, **OK}, "iam:ListRoles", B, {}),
        # Account B: interfaces present, route tables never collected.
        ({"SecurityGroups": [group(B, 41, "golden-b", [permission(22, "0.0.0.0/0")])], **OK},
         "ec2:DescribeSecurityGroups", B, {}, "eu-west-1"),
        ({"NetworkInterfaces": [eni(B, 41, [41], "subnet-b")], **OK},
         "ec2:DescribeNetworkInterfaces", B, {}, "eu-west-1"),
        # S3: account A has no account-level BPA; account C enforces it fully.
        ({"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}},
         "s3control:GetPublicAccessBlock", A, {"AccountId": A}),
        ({"PublicAccessBlockConfiguration": ALL_ON, **OK},
         "s3control:GetPublicAccessBlock", C, {"AccountId": C}),
        *bucket_sources(A, "golden-restricted-bucket", bpa=ALL_ON, policy=True, acl=[ALL_USERS]),
        *bucket_sources(A, "golden-public-policy", bpa="absent", policy=True, acl=[]),
        *bucket_sources(A, "golden-public-acl", bpa="absent", policy="absent", acl=[ALL_USERS]),
        *bucket_sources(A, "golden-object-acls", bpa="absent", policy=False, acl=[]),
        *bucket_sources(A, "golden-missing-bucket-bpa", policy=True, acl=[]),
        *bucket_sources(C, "golden-account-restricted", policy=True),
    ]  # fmt: skip
    return sources


def build(directory):
    directory.mkdir()
    sources = []
    for index, item in enumerate(scenario_sources()):
        body, operation, account, params = item[:4]
        region = item[4] if len(item) > 4 else "us-east-1"
        name = f"{index:02}.json"
        (directory / name).write_text(json.dumps(body))
        sources.append(
            Source(path=name, sha256=sha256_file(directory / name), format="aws-json-v1",
                   operation=operation, account_id=account, region=region, collected_at=TIME,
                   coverage="COMPLETE", collector_version="synthetic-golden",
                   request_parameters=params)
        )  # fmt: skip
    package = Package(targets=(Scope(account_id=A, region="us-east-1"),), sources=tuple(sources))
    (directory / "manifest.json").write_text(package.model_dump_json())
    return package


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.exit(1, "Output directory must not exist.\n")
    args.output.mkdir(parents=True)
    package = build(args.output / "input")
    registry = registry_file(args.output / "account-registry.json")
    verification = verify_package(args.output / "input", package, origin="synthetic")
    (args.output / "verification.json").write_text(json.dumps(verification, indent=2))
    with Store(args.output / "workspace") as store:
        install_registry(store.workspace, registry)
        run = import_package(store, args.output / "input")
        assess(store, run)
        report = export_excel(store, run, args.output / "R11-assessment.xlsx")
        print(json.dumps({"run_id": run, "report": str(report), **summary(store, run)}, indent=2))


if __name__ == "__main__":
    main()
