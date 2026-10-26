"""In-process fake of the boto3/botocore surface the AWS collector uses. SYNTHETIC only.

`install(cloud)` places fake `boto3` and `botocore` modules in `sys.modules` so that the real
collectors/aws/assessment.py (and preflight.py, batch.py) run unchanged against a synthetic
estate: no network, no AWS SDK, no credentials. It reproduces only the behaviour the
collector depends on (clients, paginators, ClientError shapes, refreshable assume-role
credentials, Region lists). It is not botocore: request parameters are not validated
against service models, so it never proves real-API compatibility.

Every call is checked against a read-only verb list; anything else raises AssertionError, so
tests also prove at runtime that the collector issues read operations only.
"""

import datetime
import re
import sys
import threading
import types
from dataclasses import dataclass, field

HUB = "999999999999"
FLEET_BASE = 800000000000  # documented synthetic range (tools/source_release.py)
MANAGEMENT = "899999999999"
ORGANIZATION = "o-synthetic0001"
ROOT = "r-syn1"
READ = re.compile(r"^(list|describe|get|search)_[a-z0-9_]+$")
NOT_PAGINATED = {
    "get_account_summary",
    "get_account_password_policy",
    "get_public_access_block",
    "describe_organization",
    "describe_hub",
    "get_macie_session",
    "describe_configuration_recorder_status",
    "describe_configuration_recorders",
    "describe_delivery_channels",
    "list_web_acls",
    "describe_regions",
    "describe_key",
    "get_key_policy",
    "get_key_rotation_status",
    "get_trail_status",
    "get_event_selectors",
    "get_detector",
    "get_policy",
    "describe_policy",
    "describe_cluster",
    "describe_clusters",
    "describe_table",
    "describe_trails",
    "get_policy_version",
}


# botocore paginates these although their names start with get_.
PAGINATED_GET = {
    "get_account_authorization_details",
    "get_resources",
    "get_findings",
    "get_rest_apis",
}


def fleet_account(index: int) -> str:
    return str(FLEET_BASE + index)


@dataclass
class Fault:
    """Inject an error: `code` is an AWS error code (ClientError) or an exception class name
    (ReadTimeoutError, EndpointConnectionError, ...). `times` bounds how often it fires."""

    service: str
    method: str
    code: str
    account: str | None = None
    region: str | None = None
    times: int = 10**9
    status: int = 400
    after_pages: int = 0


@dataclass
class Account:
    account_id: str
    name: str = ""
    regions: dict = field(default_factory=dict)
    size: int = 1
    member: bool = True  # False: the management account with Organizations access
    in_organization: bool = True
    assume_error: str | None = None
    rcp_enabled: bool = True
    compliant: bool = False  # every evaluated configuration compliant (PASS reachability)
    data: dict = field(default_factory=dict)


@dataclass
class Cloud:
    accounts: dict
    faults: list = field(default_factory=list)
    hub_expires_after: int | None = None  # member credential refreshes before ExpiredToken
    credential_ttl_calls: int = 10**9  # member calls per credential lifetime
    calls: list = field(default_factory=list)
    refreshes: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def fault(self, account, service, method, region, pages):
        with self.lock:
            for f in self.faults:
                if (
                    f.service == service
                    and f.method == method
                    and f.times > 0
                    and f.after_pages == pages
                    and (f.account in (None, account))
                    and (f.region in (None, region))
                ):
                    f.times -= 1
                    return f
        return None


# ---------------------------------------------------------------- exceptions and modules
class BotoCoreError(Exception):
    pass


class ClientError(Exception):
    def __init__(self, error_response, operation_name):
        super().__init__(f"An error occurred ({error_response['Error']['Code']})")
        self.response = error_response
        self.operation_name = operation_name


def _error_class(name):
    return type(name, (BotoCoreError,), {})


EXCEPTIONS = {
    n: _error_class(n)
    for n in (
        "ConnectTimeoutError",
        "ReadTimeoutError",
        "EndpointConnectionError",
        "ConnectionClosedError",
        "ProxyConnectionError",
        "SSLError",
        "ParamValidationError",
        "NoCredentialsError",
        "UnauthorizedSSOTokenError",
        "TokenRetrievalError",
        "UnknownEndpointError",
    )
}


def raise_fault(fault, method):
    if fault.code in EXCEPTIONS:
        raise EXCEPTIONS[fault.code](f"synthetic {fault.code}")
    raise ClientError(
        {
            "Error": {"Code": fault.code, "Message": f"synthetic {fault.code}"},
            "ResponseMetadata": {"HTTPStatusCode": fault.status},
        },
        method,
    )


class Config:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class DeferredRefreshableCredentials:
    def __init__(self, method=None, refresh_using=None):
        self.method, self.refresh_using = method, refresh_using
        self.current, self.used = None, 0

    def get(self, cloud):
        with cloud.lock:
            stale = self.current is None or self.used >= cloud.credential_ttl_calls
        if stale:
            self.current = self.refresh_using()
            self.used = 0
        self.used += 1
        return self.current


class BotocoreSession:
    def __init__(self):
        self._credentials = None
        self.config = {}

    def set_config_variable(self, key, value):
        self.config[key] = value


STATE: dict = {"cloud": None}


def cloud() -> Cloud:
    return STATE["cloud"]


class Session:
    def __init__(self, region_name=None, botocore_session=None, **_):
        self.region_name = region_name
        self.bc = botocore_session

    def client(self, service, region_name=None, config=None):
        return Client(self, service, region_name or self.region_name or "us-east-1")

    def get_available_regions(self, service, partition_name="aws"):
        return []

    def identity(self):
        """Account of this session: the hub, or the member whose role was assumed."""
        if self.bc is None:
            return HUB
        creds = self.bc._credentials.get(cloud())
        return creds["access_key"][len("FAKE") :]


class Paginator:
    def __init__(self, client, method):
        self.client, self.method = client, method

    def paginate(self, **params):
        yield from self.client.pages(self.method, params)


class Meta:
    def __init__(self, service):
        from offline_analyzer.contracts.aws_operation_names import API_OPERATIONS

        self.method_to_api_mapping = {
            k.split(".", 1)[1]: v for k, v in API_OPERATIONS.items() if k.startswith(service + ".")
        }


class Client:
    def __init__(self, session, service, region):
        self.session, self.service, self.region = session, service, region
        self.meta = Meta(service)

    def can_paginate(self, method):
        return method in PAGINATED_GET or (
            method not in NOT_PAGINATED and method.startswith(("list_", "describe_"))
        )

    def get_paginator(self, method):
        return Paginator(self, method)

    def __getattr__(self, method):
        if method.startswith("_"):
            raise AttributeError(method)

        def call(**params):
            pages = list(self.pages(method, params))
            return pages[0] if pages else {}

        return call

    def pages(self, method, params):
        c = cloud()
        if self.service == "sts":
            yield self.sts(method, params)
            return
        if not READ.fullmatch(method):
            raise AssertionError(f"non-read AWS call {self.service}.{method}")
        account = self.session.identity()
        region = "global" if self.service in GLOBAL_SERVICES else self.region
        with c.lock:
            c.calls.append((account, self.service, method, region))
        spec = c.accounts.get(account)
        if spec is None:
            raise_fault(Fault(self.service, method, "AccessDenied"), method)
        produced = respond(spec, self.service, method, self.region, params)
        for index, page in enumerate(produced):
            fault = c.fault(account, self.service, method, self.region, index)
            if fault:
                raise_fault(fault, method)
            yield page
        fault = c.fault(account, self.service, method, self.region, len(produced))
        if fault and fault.after_pages:
            raise_fault(fault, method)

    def sts(self, method, params):
        c = cloud()
        if method == "get_caller_identity":
            account = self.session.identity()
            role = "hub-operator" if account == HUB else "CloSecEvidenceReadOnly"
            kind = "assumed-role"
            return {
                "UserId": "AROASYNTHETIC:csao-evidence",
                "Account": account,
                "Arn": f"arn:aws:sts::{account}:{kind}/{role}/csao-evidence",
            }
        if method == "assume_role":
            target = params["RoleArn"].split(":")[4]
            with c.lock:
                c.refreshes += 1
                expired = c.hub_expires_after is not None and c.refreshes > c.hub_expires_after
            if expired:
                raise_fault(Fault("sts", method, "ExpiredToken"), "AssumeRole")
            spec = c.accounts.get(target)
            if spec is None or spec.assume_error:
                raise_fault(
                    Fault("sts", method, spec.assume_error if spec else "AccessDenied", status=403),
                    "AssumeRole",
                )
            return {
                "Credentials": {
                    "AccessKeyId": f"FAKE{target}",
                    "SecretAccessKey": "synthetic",
                    "SessionToken": "synthetic",
                    "Expiration": datetime.datetime(2099, 1, 1, tzinfo=datetime.UTC),
                }
            }
        raise AssertionError(f"unexpected sts.{method}")


GLOBAL_SERVICES = {"iam", "s3control", "cloudfront", "route53", "organizations"}


def install(fake_cloud: Cloud) -> None:
    """Register fake boto3/botocore modules (idempotent) and select the cloud."""
    STATE["cloud"] = fake_cloud
    boto3 = types.ModuleType("boto3")
    boto3.__version__ = "0.0.0-synthetic"
    boto3.Session = Session
    botocore = types.ModuleType("botocore")
    botocore.__version__ = "0.0.0-synthetic"
    config = types.ModuleType("botocore.config")
    config.Config = Config
    exceptions = types.ModuleType("botocore.exceptions")
    exceptions.ClientError = ClientError
    exceptions.BotoCoreError = BotoCoreError
    for name, cls in EXCEPTIONS.items():
        setattr(exceptions, name, cls)
    credentials = types.ModuleType("botocore.credentials")
    credentials.DeferredRefreshableCredentials = DeferredRefreshableCredentials
    session = types.ModuleType("botocore.session")
    session.get_session = BotocoreSession
    botocore.config, botocore.exceptions = config, exceptions
    botocore.credentials, botocore.session = credentials, session
    sys.modules.update(
        {
            "boto3": boto3,
            "botocore": botocore,
            "botocore.config": config,
            "botocore.exceptions": exceptions,
            "botocore.credentials": credentials,
            "botocore.session": session,
        }
    )


# ---------------------------------------------------------------- synthetic estate
def hexid(prefix: str, account: str, region: str, index: int) -> str:
    """AWS-shaped identifier (17 hex characters), unique per account, Region and index."""
    import hashlib

    return f"{prefix}-" + hashlib.sha256(f"{account}/{region}/{index}".encode()).hexdigest()[:17]


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def estate(spec: Account, region: str) -> dict:
    """Responses for one account and Region. `spec.size` scales the resource counts."""
    a, n = spec.account_id, max(1, spec.size)
    cached = spec.data.get(region)
    if cached is not None:
        return cached
    vpc = hexid("vpc", a, region, 0)
    subnet = hexid("subnet", a, region, 0)
    igw = hexid("igw", a, region, 0)
    rtb = hexid("rtb", a, region, 0)
    instances, enis, groups = [], [], []
    for i in range(2 * n):
        sg = hexid("sg", a, region, i)
        open_ssh = i % 3 == 0
        groups.append(
            {
                "GroupId": sg,
                "GroupName": f"synthetic-sg-{i}",
                "Description": "synthetic",
                "VpcId": vpc,
                "OwnerId": a,
                "IpPermissionsEgress": [],
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22 if open_ssh else 443,
                        "ToPort": 22 if open_ssh else 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0" if open_ssh else "10.0.0.0/8"}],
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "UserIdGroupPairs": [],
                    }
                ],
            }
        )
        iid = hexid("i", a, region, i)
        eni = hexid("eni", a, region, i)
        public = i % 2 == 0
        enis.append(
            {
                "NetworkInterfaceId": eni,
                "SubnetId": subnet,
                "VpcId": vpc,
                "OwnerId": a,
                "Status": "in-use",
                "Groups": [{"GroupId": sg, "GroupName": f"synthetic-sg-{i}"}],
                "Attachment": {"InstanceId": iid, "Status": "attached"},
                "Association": {"PublicIp": f"203.0.113.{i % 250}"} if public else {},
                "PrivateIpAddress": f"10.20.{i // 250}.{i % 250}",
            }
        )
        instances.append(
            {
                "InstanceId": iid,
                "State": {"Name": "running"},
                "SubnetId": subnet,
                "VpcId": vpc,
                "MetadataOptions": {
                    "HttpTokens": "optional" if i % 4 == 0 else "required",
                    "HttpPutResponseHopLimit": 2 if i % 5 == 0 else 1,
                    "State": "applied",
                    "HttpEndpoint": "enabled",
                },
                "IamInstanceProfile": {"Arn": f"arn:aws:iam::{a}:instance-profile/synthetic-role-0"}
                if i % 2 == 0
                else None,
                "NetworkInterfaces": [{"NetworkInterfaceId": eni, "Groups": [{"GroupId": sg}]}],
                "SecurityGroups": [{"GroupId": sg, "GroupName": f"synthetic-sg-{i}"}],
            }
        )
    for item in instances:
        if item["IamInstanceProfile"] is None:
            del item["IamInstanceProfile"]
    key_ids = [
        str(__import__("uuid").uuid5(__import__("uuid").NAMESPACE_URL, f"{a}/{region}/{i}"))
        for i in range(n)
    ]
    keys = [{"KeyId": k, "KeyArn": f"arn:aws:kms:{region}:{a}:key/{k}"} for k in key_ids]
    trail = f"arn:aws:cloudtrail:{region}:{a}:trail/synthetic-trail"
    result = {
        "ec2.describe_vpcs": [
            {
                "Vpcs": [
                    {"VpcId": vpc, "CidrBlock": "10.20.0.0/16", "OwnerId": a, "State": "available"}
                ]
            }
        ],  # fmt: skip
        "ec2.describe_subnets": [
            {
                "Subnets": [
                    {
                        "SubnetId": subnet,
                        "VpcId": vpc,
                        "CidrBlock": "10.20.1.0/24",
                        "OwnerId": a,
                        "MapPublicIpOnLaunch": True,
                    }
                ]
            }
        ],  # fmt: skip
        "ec2.describe_route_tables": [
            {
                "RouteTables": [
                    {
                        "RouteTableId": rtb,
                        "VpcId": vpc,
                        "OwnerId": a,
                        "Associations": [{"Main": True}],
                        "Routes": [
                            {
                                "DestinationCidrBlock": "0.0.0.0/0",
                                "GatewayId": igw,
                                "State": "active",
                            }
                        ],
                    }
                ]
            }
        ],  # fmt: skip
        "ec2.describe_internet_gateways": [
            {
                "InternetGateways": [
                    {
                        "InternetGatewayId": igw,
                        "OwnerId": a,
                        "Attachments": [{"VpcId": vpc, "State": "available"}],
                    }
                ]
            }
        ],  # fmt: skip
        "ec2.describe_network_acls": [{"NetworkAcls": []}],
        "ec2.describe_security_groups": [{"SecurityGroups": groups}],
        "ec2.describe_network_interfaces": [{"NetworkInterfaces": enis}],
        "ec2.describe_instances": [
            {
                "Reservations": [
                    {
                        "ReservationId": hexid("r", a, region, 0),
                        "OwnerId": a,
                        "Instances": instances,
                    }
                ]
            }
        ],  # fmt: skip
        "ec2.describe_iam_instance_profile_associations": [{"IamInstanceProfileAssociations": []}],
        "rds.describe_db_instances": [
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": f"synthetic-db-{a[-4:]}",
                        "DBInstanceArn": f"arn:aws:rds:{region}:{a}:db:synthetic-db-{a[-4:]}",
                        "Engine": "postgres",
                        "StorageEncrypted": False,
                        "PubliclyAccessible": True,
                        "DBSubnetGroup": {"VpcId": vpc},
                        "VpcSecurityGroups": [],
                        "DBInstanceStatus": "available",
                    }
                ]
            }
        ],  # fmt: skip
        "kms.list_keys": [{"Keys": keys}],
        "kms.describe_key": lambda p: [
            {
                "KeyMetadata": {
                    "KeyId": p["KeyId"].rsplit("/", 1)[-1],
                    "Arn": p["KeyId"],
                    "KeyManager": "CUSTOMER",
                    "Origin": "AWS_KMS",
                    "KeyState": "Enabled",
                    "KeySpec": "SYMMETRIC_DEFAULT",
                    "KeyUsage": "ENCRYPT_DECRYPT",
                }
            }
        ],  # fmt: skip
        "kms.get_key_policy": lambda p: [
            {
                "PolicyName": "default",
                "Policy": __import__("json").dumps(
                    doc(
                        {
                            "Sid": "root",
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{a}:root"},
                            "Action": "kms:*",
                            "Resource": "*",
                        }
                    )
                ),
            }
        ],  # fmt: skip
        "kms.get_key_rotation_status": lambda p: [
            {"KeyRotationEnabled": p["KeyId"] != keys[0]["KeyArn"]}
        ],
        "kms.list_grants": [{"Grants": []}],
        "kms.list_key_policies": [{"PolicyNames": ["default"]}],
        "cloudtrail.describe_trails": [
            {
                "trailList": [
                    {
                        "Name": "synthetic-trail",
                        "TrailARN": trail,
                        "S3BucketName": f"synthetic-{a}-0",
                        "IsMultiRegionTrail": False,
                        "LogFileValidationEnabled": int(a[-1]) % 2 == 0,
                        "HomeRegion": region,
                    }
                ]
            }
        ],  # fmt: skip
        "cloudtrail.get_trail_status": [{"IsLogging": True}],
        "cloudtrail.get_event_selectors": [
            {
                "TrailARN": trail,
                "EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": True}],
            }
        ],  # fmt: skip
        "guardduty.list_detectors": [{"DetectorIds": [f"det{a[-6:]}"]}],
        "guardduty.get_detector": [{"Status": "ENABLED"}],
        "config.describe_configuration_recorder_status": [
            {"ConfigurationRecordersStatus": [{"name": "default", "recording": True}]}
        ],  # fmt: skip
        "securityhub.describe_hub": [{"HubArn": f"arn:aws:securityhub:{region}:{a}:hub/default"}],
        "wafv2.list_web_acls": [{"WebACLs": []}],
        "lambda.get_policy": Fault("lambda", "", "ResourceNotFoundException", status=404),
    }
    if spec.compliant:
        comply_regional(result)
    spec.data[region] = result
    return result


BLOCK_ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def comply_regional(result: dict) -> None:
    for group in result["ec2.describe_security_groups"][0]["SecurityGroups"]:
        for permission in group["IpPermissions"]:
            permission.update(FromPort=443, ToPort=443, IpRanges=[{"CidrIp": "10.0.0.0/8"}])
    for reservation in result["ec2.describe_instances"][0]["Reservations"]:
        for instance in reservation["Instances"]:
            instance["MetadataOptions"].update(HttpTokens="required", HttpPutResponseHopLimit=1)
    for db in result["rds.describe_db_instances"][0]["DBInstances"]:
        db.update(StorageEncrypted=True, PubliclyAccessible=False)
    result["kms.get_key_rotation_status"] = [{"KeyRotationEnabled": True}]
    for trail in result["cloudtrail.describe_trails"][0]["trailList"]:
        trail["LogFileValidationEnabled"] = True


def comply_global(result: dict) -> None:
    result["s3.get_bucket_policy_status"] = [{"PolicyStatus": {"IsPublic": False}}]
    result["s3.get_bucket_policy"] = Fault("s3", "", "NoSuchBucketPolicy", status=404)
    result["s3.get_public_access_block"] = [{"PublicAccessBlockConfiguration": dict(BLOCK_ALL)}]
    result["s3control.get_public_access_block"] = [
        {"PublicAccessBlockConfiguration": dict(BLOCK_ALL)}
    ]


def global_estate(spec: Account) -> dict:
    a = spec.account_id
    cached = spec.data.get("global")
    if cached is not None:
        return cached
    n = max(1, spec.size)
    from copy import deepcopy

    buckets = [
        {"Name": f"synthetic-{a}-{i}", "CreationDate": "2026-01-01T00:00:00Z"} for i in range(n)
    ]
    roles = deepcopy(_roles(spec))
    half = len(roles) // 2 or 1
    result = {
        "iam.get_account_authorization_details": [
            {
                "UserDetailList": [],
                "GroupDetailList": [],
                "RoleDetailList": roles[:half],
                "Policies": [],
                "IsTruncated": True,
                "Marker": "synthetic-2",
            },
            {
                "UserDetailList": [],
                "GroupDetailList": [],
                "RoleDetailList": roles[half:],
                "Policies": [],
                "IsTruncated": False,
            },
        ],  # fmt: skip
        "iam.list_roles": [{"Roles": roles, "IsTruncated": False}],
        "iam.list_instance_profiles": [{"InstanceProfiles": []}],
        "s3.list_buckets": [{"Buckets": buckets, "Owner": {"ID": "synthetic-owner"}}],
        "s3.get_bucket_location": lambda p: [{"LocationConstraint": next(iter(spec.regions))}],
        "s3.get_bucket_policy_status": lambda p: [
            {"PolicyStatus": {"IsPublic": p["Bucket"].endswith("-0")}}
        ],  # fmt: skip
        "s3.get_bucket_acl": [
            {
                "Owner": {"ID": "synthetic-owner"},
                "Grants": [
                    {
                        "Grantee": {"ID": "synthetic-owner", "Type": "CanonicalUser"},
                        "Permission": "FULL_CONTROL",
                    }
                ],
            }
        ],  # fmt: skip
        "s3.get_bucket_policy": bucket_policy,
        "s3.get_public_access_block": lambda p: Fault(
            "s3", "", "NoSuchPublicAccessBlockConfiguration", status=404
        ),
        "s3control.get_public_access_block": [
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            }
        ],  # fmt: skip
    }
    result.update(organizations(spec))
    if spec.compliant:
        comply_global(result)
    spec.data["global"] = result
    return result


def bucket_policy(params):
    """A public-read policy on each account's `-0` bucket; no policy elsewhere."""
    import json

    name = params["Bucket"]
    if not name.endswith("-0"):
        return Fault("s3", "", "NoSuchBucketPolicy", status=404)
    statement = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{name}/*",
    }
    return [{"Policy": json.dumps(doc(statement))}]


def _roles(spec: Account):
    """IAM roles of the account (rebuilt from the estate generator's role section)."""
    cached = spec.data.get("__role_list__")
    if cached is not None:
        return cached
    a, n = spec.account_id, max(1, spec.size)
    roles = []
    for i in range(3 * n):
        kind = i % 6
        admin = doc({"Effect": "Allow", "Action": "*", "Resource": "*"})
        least = doc({"Effect": "Allow", "Action": "s3:GetObject",
                     "Resource": f"arn:aws:s3:::synthetic-{a}-0/*"})  # fmt: skip
        condition = None
        if kind == 0:
            principal, inline = (
                {"Service": "ec2.amazonaws.com"},
                [least if spec.compliant else admin],
            )
        elif kind == 1:
            principal, inline = {"AWS": "arn:aws:iam::222222222222:root"}, []
            if spec.compliant:  # partner trust bound by an external ID
                condition = {"StringEquals": {"sts:ExternalId": f"synthetic-{a}"}}
        elif kind == 2:
            principal = {"AWS": f"arn:aws:iam::{MANAGEMENT}:root"}
            inline = [least] if spec.compliant else [admin]
            if spec.compliant:
                condition = {"StringEquals": {"aws:PrincipalOrgID": ORGANIZATION}}
        else:
            principal = {"Service": "lambda.amazonaws.com"}
            inline = [doc({"Effect": "Allow", "Action": "s3:GetObject",
                           "Resource": f"arn:aws:s3:::synthetic-{a}-0/*"})]  # fmt: skip
        name = "OrganizationAccountAccessRole" if kind == 2 and i < 6 else f"synthetic-role-{i}"
        roles.append(
            {
                "Path": "/",
                "RoleName": name,
                "RoleId": f"AROASYN{a}{i:04d}",
                "Arn": f"arn:aws:iam::{a}:role/{name}",
                "CreateDate": "2026-01-01T00:00:00+00:00",
                "AssumeRolePolicyDocument": doc(
                    {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
                    | ({"Condition": condition} if condition else {})
                ),
                "InstanceProfileList": [
                    {
                        "Path": "/",
                        "InstanceProfileName": name,
                        "InstanceProfileId": f"AIPASYN{a}{i:04d}",
                        "Arn": f"arn:aws:iam::{a}:instance-profile/{name}",
                        "CreateDate": "2026-01-01T00:00:00+00:00",
                        "Roles": [],
                    }
                ]
                if kind == 0
                else [],
                "RolePolicyList": [
                    {"PolicyName": f"inline-{j}", "PolicyDocument": d} for j, d in enumerate(inline)
                ],
                "AttachedManagedPolicies": [],
                "Tags": [],
            }
        )
    spec.data["__role_list__"] = roles
    return roles


def organizations(spec: Account) -> dict:
    a = spec.account_id
    if not spec.in_organization:
        return {
            "organizations.describe_organization": Fault(
                "organizations", "", "AWSOrganizationsNotInUseException"
            )
        }
    described = [{"Organization": {"Id": ORGANIZATION, "MasterAccountId": MANAGEMENT,
                                   "FeatureSet": "ALL"}}]  # fmt: skip
    if spec.member:
        denied = Fault("organizations", "", "AccessDeniedException")
        return {
            "organizations.describe_organization": described,
            "organizations.list_roots": denied,
            "organizations.list_policies_for_target": denied,
            "organizations.list_parents": denied,
        }
    types_ = [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]
    if spec.rcp_enabled:
        types_.append({"Type": "RESOURCE_CONTROL_POLICY", "Status": "ENABLED"})
    full = doc({"Effect": "Allow", "Action": "*", "Resource": "*"})
    outside = {"StringNotEqualsIfExists": {"aws:PrincipalOrgID": ORGANIZATION}}
    deny = {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*"}
    rcp = doc({**deny, "Condition": outside})
    policies = {
        "p-FullAWSAccess": ("SERVICE_CONTROL_POLICY", full),
        "p-rcp00000001": ("RESOURCE_CONTROL_POLICY", rcp),
    }

    def for_target(p):
        ptype = p["Filter"]
        ids = [pid for pid, (t, _) in policies.items() if t == ptype]
        return [{"Policies": [{"Id": pid, "Type": ptype, "Name": pid} for pid in ids]}]

    def parents(p):
        child = p["ChildId"]
        parent = "ou-syn1-unit0001" if child == a else ROOT
        return [
            {
                "Parents": [
                    {"Id": parent, "Type": "ROOT" if parent == ROOT else "ORGANIZATIONAL_UNIT"}
                ]
            }
        ]

    def describe(p):
        ptype, content = policies[p["PolicyId"]]
        import json as _json

        return [{"Policy": {"PolicySummary": {"Id": p["PolicyId"], "Type": ptype,
                                              "Name": p["PolicyId"]},
                            "Content": _json.dumps(content)}}]  # fmt: skip

    return {
        "organizations.describe_organization": described,
        "organizations.list_roots": [
            {"Roots": [{"Id": ROOT, "Name": "Root", "PolicyTypes": types_}]}
        ],
        "organizations.list_policies_for_target": for_target,
        "organizations.list_parents": parents,
        "organizations.describe_policy": describe,
    }


def respond(spec: Account, service: str, method: str, region: str, params: dict) -> list:
    key = f"{service}.{method}"
    if service == "ec2" and method == "describe_regions":
        return [{"Regions": [{"RegionName": r, "OptInStatus": s} for r, s in spec.regions.items()]}]
    table = (
        global_estate(spec)
        if service in GLOBAL_SERVICES or service == "s3"
        else estate(spec, region)
    )
    value = table.get(key)
    if callable(value):
        value = value(params)
    if isinstance(value, Fault):
        raise_fault(value, method)
    if value is None:
        return [empty(service, method)]
    return value


def empty(service: str, method: str) -> dict:
    """An empty but well-formed response, using the analyzer's own shape tables for the
    list key of every normalized operation."""
    from offline_analyzer.ingestion.collector_v030_native import canonical
    from offline_analyzer.normalization import adapters, enterprise_adapters, iam_adapters

    operation = canonical(service, method)[0]
    for table, index in (
        (adapters.AWS_SHAPES, 0),
        (enterprise_adapters.PROFILES, 0),
        (iam_adapters.LIST_KINDS, 0),
        (iam_adapters.ORG_LISTS, 0),
    ):
        if operation in table and table[operation][index]:
            return {table[operation][index]: []}
    return {}


def fleet(count: int, *, regions=("ap-south-1", "eu-west-1"), size: int = 1, **overrides) -> Cloud:
    accounts = {}
    for i in range(count):
        a = fleet_account(i)
        accounts[a] = Account(
            a,
            name=f"Synthetic {i:03d}",
            regions={r: "opt-in-not-required" for r in regions} | {"me-south-1": "not-opted-in"},
            size=size,
        )
    management = Account(
        MANAGEMENT,
        name="Synthetic management",
        regions={r: "opt-in-not-required" for r in regions},
        member=False,
        size=size,
    )
    accounts[MANAGEMENT] = management
    return Cloud(accounts=accounts, **overrides)


COLLECTOR_DIR = __import__("pathlib").Path(__file__).resolve().parents[2] / "collectors/aws"


def load(fake_cloud: Cloud, *names: str):
    """Install the fakes and import fresh copies of the collector modules (as in the kit,
    where the scripts sit side by side and import each other by module name)."""
    import importlib

    install(fake_cloud)
    for name in ("assessment", "fleet", "preflight", "batch"):
        sys.modules.pop(name, None)
    if str(COLLECTOR_DIR) not in sys.path:
        sys.path.insert(0, str(COLLECTOR_DIR))
    modules = [importlib.import_module(n) for n in names or ("assessment",)]
    return modules[0] if len(modules) == 1 else modules


def config(output, regions=("ap-south-1", "eu-west-1"), **extra) -> dict:
    return {
        "assessment_id": "SYNTHETIC",
        "approved_regions": list(regions),
        "spoke_role_name": "CloSecEvidenceReadOnly",
        "dataset_origin": "SYNTHETIC",
        "output_directory": str(output),
        "_config_dir": str(output),
        **extra,
    }


FAKED = (
    "boto3",
    "botocore",
    "botocore.config",
    "botocore.exceptions",
    "botocore.credentials",
    "botocore.session",
    "assessment",
    "fleet",
    "preflight",
    "batch",
)


class installed:
    """Context manager: load collector modules on the fakes, then restore sys.modules and
    sys.path so no fake leaks into other tests."""

    def __init__(self, fake_cloud: Cloud, *names: str):
        self.cloud, self.names = fake_cloud, names or ("assessment",)

    def __enter__(self):
        self.saved = {name: sys.modules.get(name) for name in FAKED}
        self.path = list(sys.path)
        return load(self.cloud, *self.names)

    def __exit__(self, *exc):
        for name, module in self.saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module
        sys.path[:] = self.path
        return False
