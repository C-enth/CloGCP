"""R1 synthetic demonstration: methodology-mapped IAM, network, S3, RDS and EC2 rules.

All identifiers are synthetic (documentation IP ranges, repeated-digit accounts). The
structure follows public AWS API response shapes; it is not a real collector export.
"""

import argparse
import json
from pathlib import Path
from urllib.parse import quote

from offline_analyzer.cli import summary
from offline_analyzer.contracts.r0 import Package, Scope, Source
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.safety import sha256_file
from offline_analyzer.reporting.excel import export_excel
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store

TIME = "2026-10-09T08:00:00+00:00"
A, B = "111111111111", "222222222222"
VENDOR, PARTNER = "333333333333", "444444444444"
ACCOUNT_KEYS = {A: "ACCT-001"}  # B deliberately unmapped to show the required step


def rid(prefix: str, n: int) -> str:
    return f"{prefix}-{n:017x}"


def trust(principal, condition=None, effect="Allow", action="sts:AssumeRole") -> dict:
    statement = {"Effect": effect, "Principal": principal, "Action": action}
    if condition is not None:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


def role(account: str, name: str, document) -> dict:
    return {
        "Path": "/",
        "RoleName": name,
        "RoleId": "AROA" + name.upper().replace("-", "")[:16].ljust(16, "X"),
        "Arn": f"arn:aws:iam::{account}:role/{name}",
        "AssumeRolePolicyDocument": document,
    }


def permission(port: int, cidr: str | None = None, ipv6: str | None = None) -> dict:
    return {
        "IpProtocol": "tcp",
        "FromPort": port,
        "ToPort": port,
        "IpRanges": [{"CidrIp": cidr}] if cidr else [],
        "Ipv6Ranges": [{"CidrIpv6": ipv6}] if ipv6 else [],
        "PrefixListIds": [],
        "UserIdGroupPairs": [],
    }


def group(account: str, n: int, name: str, permissions: list) -> dict:
    return {
        "GroupId": rid("sg", n),
        "GroupName": name,
        "OwnerId": account,
        "VpcId": rid("vpc", 1),
        "IpPermissions": permissions,
    }


def interface(account, n, groups, public=None, instance=None, managed=False, ipv6=False):
    return {
        "NetworkInterfaceId": rid("eni", n),
        "OwnerId": account,
        "Status": "in-use",
        "InterfaceType": "network_load_balancer" if managed else "interface",
        "RequesterManaged": managed,
        "VpcId": rid("vpc", 1),
        "Groups": [{"GroupId": rid("sg", g), "GroupName": f"group-{g}"} for g in groups],
        "Association": {"PublicIp": public, "IpOwnerId": "amazon"} if public else None,
        "PrivateIpAddresses": [
            {"Primary": True, "Association": {"PublicIp": public}} if public else {"Primary": True}
        ],
        "Ipv6Addresses": [{"Ipv6Address": "2001:db8::10"}] if ipv6 else [],
        "Attachment": {"InstanceId": rid("i", instance), "Status": "attached"}
        if instance
        else None,
    }


def instance(n: int, tokens: str, hops: int) -> dict:
    return {
        "InstanceId": rid("i", n),
        "State": {"Name": "running"},
        "MetadataOptions": {
            "State": "applied",
            "HttpTokens": tokens,
            "HttpEndpoint": "enabled",
            "HttpPutResponseHopLimit": hops,
        },
    }


def database(account: str, name: str, engine: str, public: bool, encrypted: bool) -> dict:
    return {
        "DBInstanceIdentifier": name,
        "DBInstanceArn": f"arn:aws:rds:us-east-1:{account}:db:{name}",
        "Engine": engine,
        "PubliclyAccessible": public,
        "StorageEncrypted": encrypted,
    }


def evidence() -> list[tuple]:
    """(file, body, operation, account, region, coverage, errors) — synthetic only."""
    ok = {"ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "synthetic-request"}}
    bound = trust(
        {"AWS": f"arn:aws:iam::{VENDOR}:root"},
        {"StringEquals": {"aws:PrincipalOrgID": "o-synthetic01"}},
    )
    roles = [
        role(A, "synthetic-vendor-root", trust({"AWS": f"arn:aws:iam::{VENDOR}:root"})),
        role(A, "synthetic-public-trust", trust("*")),
        role(A, "synthetic-org-bound", trust({"AWS": VENDOR}, bound["Statement"][0]["Condition"])),
        role(
            A,
            "synthetic-external-id",
            trust(
                {"AWS": f"arn:aws:iam::{PARTNER}:root"},
                {"StringEquals": {"sts:ExternalId": "synthetic-shared-value"}},
            ),
        ),
        role(A, "synthetic-encoded-bound", quote(json.dumps(bound))),
        role(A, "synthetic-ec2-service", trust({"Service": "ec2.amazonaws.com"})),
        role(A, "synthetic-same-account", trust({"AWS": f"arn:aws:iam::{A}:root"})),
        role(
            A,
            "synthetic-specific-principal",
            trust({"AWS": f"arn:aws:iam::{PARTNER}:role/synthetic-deployer"}),
        ),
        role(
            A,
            "synthetic-mfa-only",
            trust(
                {"AWS": f"arn:aws:iam::{VENDOR}:root"},
                {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            ),
        ),
        role(
            A,
            "synthetic-ifexists",
            trust(
                {"AWS": f"arn:aws:iam::{VENDOR}:root"},
                {"StringEqualsIfExists": {"sts:ExternalId": "synthetic-shared-value"}},
            ),
        ),
    ]
    groups_a = [
        group(A, 1, "synthetic-admin", [permission(22, "0.0.0.0/0")]),
        group(
            A, 2, "synthetic-web", [permission(443, "0.0.0.0/0"), permission(5432, "10.0.0.0/8")]
        ),
        group(A, 3, "synthetic-latent-db", [permission(3306, "0.0.0.0/0")]),
        group(A, 4, "synthetic-app", [permission(8080, "0.0.0.0/0")]),
        group(A, 5, "synthetic-partner", [permission(22, "198.51.100.0/24")]),
        group(A, 6, "synthetic-lb", [permission(22, "0.0.0.0/0")]),
        group(A, 7, "synthetic-ipv6", [permission(3389, ipv6="::/0")]),
    ]
    interfaces_a = [
        interface(A, 1, [1], public="203.0.113.10", instance=1),
        interface(A, 2, [3], instance=2),
        interface(A, 3, [6], public="203.0.113.20", managed=True),
        interface(A, 4, [7], ipv6=True),
    ]
    return [
        ("ec2-a.json", {"Reservations": [{"OwnerId": A, "Instances": [
            instance(1, "optional", 2), instance(2, "required", 1)]}], **ok},
         "ec2:DescribeInstances", A, "us-east-1", "COMPLETE", ()),
        ("sg-a.json", {"SecurityGroups": groups_a, **ok},
         "ec2:DescribeSecurityGroups", A, "us-east-1", "COMPLETE", ()),
        ("eni-a.json", {"NetworkInterfaces": interfaces_a, **ok},
         "ec2:DescribeNetworkInterfaces", A, "us-east-1", "COMPLETE", ()),
        ("rds-a.json", {"DBInstances": [
            database(A, "synthetic-public-db", "postgres", True, True),
            database(A, "synthetic-private-db", "mysql", False, False)], **ok},
         "rds:DescribeDBInstances", A, "us-east-1", "COMPLETE", ()),
        ("iam-a.json", {"RoleDetailList": roles, "IsTruncated": False, **ok},
         "iam:GetAccountAuthorizationDetails", A, "us-east-1", "COMPLETE", ()),
        ("bpa-a.json", {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True}, **ok},
         "s3control:GetPublicAccessBlock", A, "us-east-1", "COMPLETE", ()),
        # Account B: interface evidence absent, IAM collection failed, BPA not configured.
        ("sg-b.json", {"SecurityGroups": [
            group(B, 11, "synthetic-admin-b", [permission(3389, "0.0.0.0/0")])], **ok},
         "ec2:DescribeSecurityGroups", B, "eu-west-1", "COMPLETE", ()),
        ("bpa-b.json", {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration",
                                  "Message": "synthetic"},
                        "ResponseMetadata": {"HTTPStatusCode": 404}},
         "s3control:GetPublicAccessBlock", B, "eu-west-1", "COMPLETE", ()),
        (None, None, "iam:GetAccountAuthorizationDetails", B, "eu-west-1", "ERROR",
         ("AccessDenied",)),
    ]  # fmt: skip


def build_r1_package(directory: Path) -> Package:
    directory.mkdir(parents=True, exist_ok=False)
    sources = []
    for name, body, operation, account, region, coverage, errors in evidence():
        path = directory / name if name else None
        if path:
            path.write_text(json.dumps(body, indent=2), encoding="utf-8")
        parameters = {"AccountId": account} if operation.startswith("s3control") else {}
        sources.append(
            Source(
                path=name,
                sha256=sha256_file(path) if path else None,
                format="aws-json-v1",
                operation=operation,
                account_id=account,
                region=region,
                collected_at=TIME,
                coverage=coverage,
                errors=errors,
                collector_version="synthetic-r1",
                request_parameters=parameters,
            )
        )
    package = Package(
        targets=(Scope(account_id=A, region="us-east-1"), Scope(account_id=B, region="eu-west-1")),
        sources=tuple(sources),
    )
    (directory / "manifest.json").write_text(package.model_dump_json(indent=2), encoding="utf-8")
    (directory / "account-keys.json").write_text(json.dumps(ACCOUNT_KEYS, indent=2))
    return package


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.exit(1, "Output directory must not exist.\n")
    inputs = args.output / "input"
    build_r1_package(inputs)
    with Store(args.output / "workspace") as store:
        run = import_package(store, inputs)
        assess(store, run)
        report = export_excel(store, run, args.output / "R1-assessment.xlsx", ACCOUNT_KEYS)
        print(json.dumps({"run_id": run, "report": str(report), **summary(store, run)}, indent=2))


if __name__ == "__main__":
    main()
