"""SYNTHETIC packages in the exact CloSec AWS collector v0.3.x on-disk format.

Journal rows use the same keys as collectors/aws/assessment.py `api()`/`skipped()`
records (tests compare them through the collector's AST). Never proof of real-export
compatibility; real compatibility needs the local verifier on tool-generated packages.
"""

import hashlib
import json
import zipfile
from pathlib import Path

ACCOUNT = "123456789012"
PARTNER = "222222222222"
REGION = "ap-south-1"
COLLECTION = "20261014T000000Z-5e1f0a01"
T0 = "2026-10-14T00:00:00.000000Z"
T1 = "2026-10-14T00:05:00.000000Z"


def _document(statement: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": [statement]}


def _pages() -> dict:
    trust_ec2 = _document(
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    )
    trust_partner = _document(
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{PARTNER}:root"},
            "Action": "sts:AssumeRole",
        }
    )
    admin = {
        "Path": "/",
        "RoleName": "synthetic-app-admin",
        "RoleId": "AROASYNTHETIC00000001",
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/synthetic-app-admin",
        "CreateDate": "2026-01-01T00:00:00+00:00",
        "AssumeRolePolicyDocument": trust_ec2,
        "InstanceProfileList": [
            {
                "Path": "/",
                "InstanceProfileName": "synthetic-app-admin",
                "InstanceProfileId": "AIPASYNTHETIC0000001",
                "Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/synthetic-app-admin",
                "CreateDate": "2026-01-01T00:00:00+00:00",
                "Roles": [],
            }
        ],
        "RolePolicyList": [
            {
                "PolicyName": "star",
                "PolicyDocument": _document({"Effect": "Allow", "Action": "*", "Resource": "*"}),
            }
        ],
        "AttachedManagedPolicies": [],
        "Tags": [],
    }
    partner = {
        **admin,
        "RoleName": "synthetic-partner-access",
        "RoleId": "AROASYNTHETIC00000002",
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/synthetic-partner-access",
        "AssumeRolePolicyDocument": trust_partner,
        "InstanceProfileList": [],
        "RolePolicyList": [],
    }
    policy = {
        "PolicyName": "synthetic-read",
        "PolicyId": "ANPASYNTHETIC0000001",
        "Arn": f"arn:aws:iam::{ACCOUNT}:policy/synthetic-read",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 0,
        "IsAttachable": True,
        "CreateDate": "2026-01-01T00:00:00+00:00",
        "UpdateDate": "2026-01-01T00:00:00+00:00",
        "PolicyVersionList": [
            {
                "Document": _document(
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                ),
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "CreateDate": "2026-01-01T00:00:00+00:00",
            }
        ],
    }
    vpc, subnet, sg = "vpc-0a1b2c3d4e5f60001", "subnet-0a1b2c3d4e5f60001", "sg-0a1b2c3d4e5f60001"
    instance = {
        "InstanceId": "i-0a1b2c3d4e5f60001",
        "ImageId": "ami-12c6146b",
        "State": {"Code": 16, "Name": "running"},
        "SubnetId": subnet,
        "VpcId": vpc,
        "PrivateIpAddress": "10.20.1.10",
        "IamInstanceProfile": {
            "Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/synthetic-app-admin",
            "Id": "AIPASYNTHETIC0000001",
        },
        "MetadataOptions": {
            "State": "applied",
            "HttpTokens": "optional",
            "HttpPutResponseHopLimit": 1,
            "HttpEndpoint": "enabled",
        },
        "SecurityGroups": [{"GroupName": "synthetic-admin-ssh", "GroupId": sg}],
        "NetworkInterfaces": [],
    }
    public_policy = json.dumps(
        _document(
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::synthetic-public-bucket/*",
            }
        )
    )
    owner = {"ID": "synthetic-canonical-owner"}
    return {
        "iam.get_account_authorization_details": [
            {
                "UserDetailList": [],
                "GroupDetailList": [],
                "RoleDetailList": [admin],
                "Policies": [],
                "IsTruncated": True,
                "Marker": "synthetic-page-2",
            },
            {
                "UserDetailList": [],
                "GroupDetailList": [],
                "RoleDetailList": [partner],
                "Policies": [policy],
                "IsTruncated": False,
            },
        ],
        "iam.list_roles": [{"Roles": [admin, partner], "IsTruncated": False}],
        "s3.list_buckets": [
            {"Buckets": [{"Name": "synthetic-public-bucket", "CreationDate": T0}], "Owner": owner}
        ],
        "s3.get_bucket_location": [{"LocationConstraint": REGION}],
        "s3.get_bucket_policy": [{"Policy": public_policy}],
        "s3.get_bucket_policy_status": [{"PolicyStatus": {"IsPublic": True}}],
        "s3.get_bucket_acl": [
            {
                "Owner": owner,
                "Grants": [
                    {
                        "Grantee": {"ID": owner["ID"], "Type": "CanonicalUser"},
                        "Permission": "FULL_CONTROL",
                    }
                ],
            }
        ],
        "ec2.describe_vpcs": [
            {
                "Vpcs": [
                    {
                        "VpcId": vpc,
                        "CidrBlock": "10.20.0.0/16",
                        "OwnerId": ACCOUNT,
                        "State": "available",
                    }
                ]
            }
        ],
        "ec2.describe_subnets": [
            {
                "Subnets": [
                    {
                        "SubnetId": subnet,
                        "VpcId": vpc,
                        "CidrBlock": "10.20.1.0/24",
                        "OwnerId": ACCOUNT,
                        "MapPublicIpOnLaunch": False,
                    }
                ]
            }
        ],
        "ec2.describe_security_groups": [
            {
                "SecurityGroups": [
                    {
                        "GroupId": sg,
                        "GroupName": "synthetic-admin-ssh",
                        "Description": "synthetic",
                        "VpcId": vpc,
                        "OwnerId": ACCOUNT,
                        "IpPermissionsEgress": [],
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                "Ipv6Ranges": [],
                                "PrefixListIds": [],
                                "UserIdGroupPairs": [],
                            }
                        ],
                    }
                ]
            }
        ],
        "ec2.describe_instances": [
            {
                "Reservations": [
                    {
                        "ReservationId": "r-0a1b2c3d4e5f60001",
                        "OwnerId": ACCOUNT,
                        "Instances": [instance],
                    }
                ]
            }
        ],
        "ec2.describe_network_interfaces": [{"NetworkInterfaces": []}],
        "ec2.describe_route_tables": [{"RouteTables": []}],
        "cloudtrail.describe_trails": [
            {
                "trailList": [
                    {
                        "Name": "synthetic-trail",
                        "TrailARN": f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/synthetic-trail",
                        "S3BucketName": "synthetic-trail-logs",
                        "IsMultiRegionTrail": False,
                        "LogFileValidationEnabled": False,
                        "HomeRegion": REGION,
                    }
                ]
            }
        ],
        "cloudtrail.get_event_selectors": [{"TrailARN": "synthetic", "EventSelectors": []}],
        # v0.3.0 records COMPLETE for this non-paginatable response although it still
        # carries NextMarker; the analyzer must downgrade it to partial coverage.
        "wafv2.list_web_acls": [{"WebACLs": [], "NextMarker": "synthetic-marker"}],
        "guardduty.list_detectors": [{"DetectorIds": ["synthetic-detector"]}],
    }


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(**fields) -> dict:
    """One journal row with exactly the collector's api()/skipped() record keys."""
    row = {
        "collection_id": COLLECTION,
        "assessment_id": "SYNTHETIC",
        "account_id": ACCOUNT,
        "partition": "aws",
        "region": REGION,
        "service": None,
        "operation": None,
        "source_tool": "boto3",
        "source_tool_version": "1.35.0",
        "collector_version": "0.3.0",
        "started_at": T0,
        "completed_at": T0,
        "duration_seconds": 0.1,
        "request_parameters": {},
        "pagination_expected": False,
        "pagination_complete": True,
        "pages_processed": 0,
        "records_returned": 0,
        "output_bytes": 0,
        "outcome": "COMPLETE",
        "error": None,
        "files": [],
        "sensitivity": "CONFIDENTIAL",
    }
    row.update(fields)
    return row


def package(directory: Path, *, archive: bool = False) -> Path:
    """Write a v0.3.0-format run directory (or its AWS-EVIDENCE/ ZIP) and return the path."""
    root = directory / ACCOUNT / COLLECTION
    root.mkdir(parents=True)
    account = root / "accounts" / ACCOUNT
    account.mkdir(parents=True)
    (account / "identity.json").write_text(
        json.dumps(
            {
                "UserId": "AROASYNTHETIC:csao-evidence",
                "Account": ACCOUNT,
                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/spoke-readonly/csao-evidence",
            }
        )
    )
    (account / "regions.json").write_text(
        json.dumps(
            {
                "enabled_regions": [REGION],
                "approved_regions": [REGION],
                "selected_regions": [REGION],
            }
        )
    )
    rows = []

    def call(service, operation, region, params=None, rel=None, **extra):
        pages = _pages()[f"{service}.{operation}"]
        key = rel or (
            f"accounts/{ACCOUNT}/{'global' if region == 'global' else 'regions/' + region}"
            f"/{service}/{operation}"
        )
        files = []
        for index, page in enumerate(pages, 1):
            path = root / key / f"page-{index:06d}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(page, separators=(",", ":")) + "\n")
            files.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": _sha(path),
                    "bytes": path.stat().st_size,
                }
            )
        rows.append(
            record(
                service=service,
                operation=operation,
                region=region,
                request_parameters=params or {},
                files=files,
                pages_processed=len(files),
                pagination_expected=len(files) > 1,
                records_returned=sum(
                    len(v) for p in pages for v in p.values() if isinstance(v, list)
                ),
                **extra,
            )
        )

    def failed(service, operation, region, outcome, code, params=None):
        rows.append(
            record(
                service=service,
                operation=operation,
                region=region,
                request_parameters=params or {},
                outcome=outcome,
                pagination_complete=False,
                error={"code": code, "message": f"synthetic {code}"},
            )
        )

    call("iam", "get_account_authorization_details", "global")
    call("iam", "list_roles", "global")
    call("s3", "list_buckets", "global")
    bucket = {"Bucket": "synthetic-public-bucket"}
    prefix = f"accounts/{ACCOUNT}/regions/{REGION}/s3/buckets/synthetic-public-bucket"
    call(
        "s3",
        "get_bucket_location",
        "global",
        bucket,
        f"accounts/{ACCOUNT}/global/s3/buckets/synthetic-public-bucket/get_bucket_location",
    )
    failed(
        "s3",
        "get_public_access_block",
        REGION,
        "NOT_ENABLED",
        "NoSuchPublicAccessBlockConfiguration",
        bucket,
    )
    for operation in ("get_bucket_policy", "get_bucket_policy_status", "get_bucket_acl"):
        call("s3", operation, REGION, bucket, f"{prefix}/{operation}")
    failed(
        "s3control",
        "get_public_access_block",
        "global",
        "NOT_ENABLED",
        "NoSuchPublicAccessBlockConfiguration",
        {"AccountId": ACCOUNT},
    )
    failed(
        "organizations",
        "describe_organization",
        "global",
        "API_ERROR",
        "AWSOrganizationsNotInUseException",
    )
    for operation in (
        "describe_vpcs",
        "describe_subnets",
        "describe_security_groups",
        "describe_instances",
        "describe_network_interfaces",
        "describe_route_tables",
    ):
        call("ec2", operation, REGION)
    call("cloudtrail", "describe_trails", REGION)
    call(
        "cloudtrail",
        "get_event_selectors",
        REGION,
        {"TrailName": f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/synthetic-trail"},
        f"accounts/{ACCOUNT}/regions/{REGION}/cloudtrail/trails/synthetic-trail/get_event_selectors",
    )
    call("wafv2", "list_web_acls", REGION, {"Scope": "REGIONAL"})
    call("guardduty", "list_detectors", REGION)
    failed(
        "securityhub",
        "get_findings",
        REGION,
        "ACCESS_DENIED",
        "AccessDeniedException",
        {"MaxResults": 100},
    )
    for service, reason in (
        ("prowler", "Disabled by operator"),
        ("cloudsplaining", "Supplementary scanner deferred"),
        ("steampipe", "Supplementary scanner deferred"),
    ):
        rows.append(
            record(
                service=service,
                operation="scan",
                region=REGION,
                outcome="NOT_COLLECTED",
                pagination_expected=None,
                pagination_complete=False,
                duration_seconds=0,
                error={"code": "NOT_COLLECTED", "message": reason},
            )
        )
    (root / "operations.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)
    )
    missing = [r for r in rows if r["outcome"] != "COMPLETE"]
    (root / "retry-requests.json").write_text(
        json.dumps({"collection_id": COLLECTION, "requests": len(missing)})
    )
    (root / "collection-summary.json").write_text(
        json.dumps(
            {
                "collection_id": COLLECTION,
                "account_id": ACCOUNT,
                "status": "PARTIAL",
                "operations_total": len(rows),
                "analyzer_compatibility": "UNVERIFIED",
            }
        )
    )
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "closec-provisional-0.3",
                "assessment_id": "SYNTHETIC",
                "collection_id": COLLECTION,
                "account_id": ACCOUNT,
                "partition": "aws",
                "started_at": T0,
                "completed_at": T1,
                "regions": [REGION],
                "role_arn": f"arn:aws:iam::{ACCOUNT}:role/spoke-readonly",
                "collector_version": "0.3.0",
                "operation_index": "operations.jsonl",
                "summary": "collection-summary.json",
                "retry_requests": "retry-requests.json",
                "status": "PARTIAL",
                "dataset_origin": "SYNTHETIC",
                "account_name": "Synthetic Payments",
                "analyzer_contract_status": "AWAITING_ANALYZER_COLLECTOR_CONTRACT_JSON",
            }
        )
    )
    with (root / "checksums.sha256").open("w") as handle:
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.name != "checksums.sha256":
                handle.write(f"{_sha(path)}  {path.relative_to(root).as_posix()}\n")
    if not archive:
        return root
    target = root.parent / (root.name + ".zip")
    with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED) as handle:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                handle.write(path, "AWS-EVIDENCE/" + path.relative_to(root).as_posix())
    return target
