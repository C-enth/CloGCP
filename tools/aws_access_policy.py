"""Generate the AWS collection access design from the collector source (never executed).

Every API call the AWS collector, the pre-flight probe and the batch orchestrator can make is
enumerated from their source (registries plus literal `api(...)` calls, via AST), mapped to its
IAM action, and matched against a dated snapshot of the AWS-managed SecurityAudit and
ViewOnlyAccess policies (tools/data/aws_managed_policies.json). Outputs:

* docs/AWS_COLLECTION_ACCESS.md (generated; do not edit by hand);
* collectors/aws/policies/*.json: member-role supplement policy, trust policy, StackSet
  (CloudFormation JSON) template, hub-operator policy and management-account policy.

`--check` fails when committed outputs drift (tests/test_aws_collection_access.py).
`--refresh-snapshot DIR` re-reads saved AWS reference pages (<Name>.html) into the snapshot.
"""

import argparse
import ast
import fnmatch
import html
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWS = ROOT / "collectors/aws"
COLLECTOR = AWS / "assessment.py"
PROBE = AWS / "preflight.py"
SNAPSHOT = ROOT / "tools/data/aws_managed_policies.json"
POLICIES = AWS / "policies"
DOC = ROOT / "docs/AWS_COLLECTION_ACCESS.md"
MANAGED = ("SecurityAudit", "ViewOnlyAccess")

# IAM service prefixes that differ from the boto3 client name.
PREFIX = {
    "s3": "s3",
    "s3control": "s3",
    "elbv2": "elasticloadbalancing",
    "accessanalyzer": "access-analyzer",
    "efs": "elasticfilesystem",
    "resourcegroupstaggingapi": "tag",
    "apigatewayv2": "apigateway",
}
# IAM actions whose name differs from the API operation name (Service Authorization Reference).
ACTION = {
    "s3.list_buckets": "s3:ListAllMyBuckets",
    "s3.get_public_access_block": "s3:GetBucketPublicAccessBlock",
    "s3control.get_public_access_block": "s3:GetAccountPublicAccessBlock",
    "s3.get_bucket_encryption": "s3:GetEncryptionConfiguration",
    "s3.get_bucket_replication": "s3:GetReplicationConfiguration",
    "s3.get_bucket_lifecycle_configuration": "s3:GetLifecycleConfiguration",
    "s3.get_bucket_notification_configuration": "s3:GetBucketNotification",
    "s3.get_bucket_cors": "s3:GetBucketCORS",
    # API Gateway authorizes by HTTP verb on the resource path.
    "apigateway.get_rest_apis": "apigateway:GET",
    "apigatewayv2.get_apis": "apigateway:GET",
}
# Calls made outside the evidence registries (session set-up and region discovery).
SETUP = (
    ("sts", "get_caller_identity", "Identity check; requires no IAM permission"),
    ("ec2", "describe_regions", "Region opt-in status (AllRegions=True)"),
)
# Hub identity (where the operator runs the collector or batch orchestrator).
HUB = (
    ("sts:AssumeRole", "Assume the member read-only role in each approved account"),
    (
        "organizations:ListAccounts",
        "Optional: account search in the interactive collector (management or delegated "
        "administrator only)",
    ),
)
# Organizations reads answered only by the management account or a delegated administrator.
MANAGEMENT = (
    "organizations:DescribeOrganization",
    "organizations:ListRoots",
    "organizations:ListParents",
    "organizations:ListPoliciesForTarget",
    "organizations:DescribePolicy",
    "organizations:ListPolicies",
    "organizations:ListTargetsForPolicy",
    "organizations:ListAccounts",
    "organizations:DescribeAccount",
)
# Explicit guard: data-plane reads the collector never needs. A Deny overrides any Allow that a
# future managed-policy version might add.
DATA_PLANE_DENY = (
    "s3:GetObject",
    "s3:GetObjectVersion",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "kms:Decrypt",
    "dynamodb:GetItem",
    "dynamodb:BatchGetItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "lambda:GetFunction",
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchGetImage",
    "logs:GetLogEvents",
    "logs:FilterLogEvents",
    "logs:StartQuery",
    "athena:GetQueryResults",
    "glue:GetTable",
    "rds:DownloadDBLogFilePortion",
)
READ_VERB = re.compile(r"^(list|describe|get|search)_[a-z0-9_]+$")


def literal(tree, names):
    return {
        n.targets[0].id: ast.literal_eval(n.value)
        for n in tree.body
        if isinstance(n, ast.Assign)
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id in names
    }


def inline_calls(tree) -> list[tuple[str, str]]:
    """Literal `api(session, root, ctx, "<service>", "<operation>", ...)` calls."""
    found = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "api"
            and len(node.args) >= 5
            and all(isinstance(a, ast.Constant) for a in node.args[3:5])
        ):
            found.append((node.args[3].value, node.args[4].value))
    return found


def collector_calls() -> list[dict]:
    """(service, method, phase) for every evidence call of the collector."""
    tree = ast.parse(COLLECTOR.read_text(encoding="utf-8"))
    values = literal(tree, {"GLOBAL", "REGIONAL", "DEPENDENT", "INLINE"})
    rows, seen = [], set()

    def add(service, method, phase):
        if (service, method) not in seen:
            seen.add((service, method))
            rows.append({"service": service, "method": method, "phase": phase})

    for phase in ("GLOBAL", "REGIONAL", "DEPENDENT"):
        for service, methods in values[phase].items():
            for method in methods:
                add(service, method, phase)
    for service, method in values["INLINE"]:
        add(service, method, "ORGANIZATION" if service == "organizations" else "DEPENDENT")
    for service, method in inline_calls(tree):
        add(service, method, "DEPENDENT")
    for service, method, _why in SETUP:
        add(service, method, "SETUP")
    return rows


def probe_calls() -> list[tuple[str, str]]:
    if not PROBE.is_file():
        return []
    values = literal(ast.parse(PROBE.read_text(encoding="utf-8")), {"FAMILIES"})
    return [(f[1], f[2]) for f in values.get("FAMILIES", ())]


def iam_action(service: str, method: str) -> str:
    from offline_analyzer.contracts.aws_operation_names import API_OPERATIONS

    key = f"{service}.{method}"
    if key in ACTION:
        return ACTION[key]
    if service == "sts" and method == "get_caller_identity":
        return "sts:GetCallerIdentity"
    api = API_OPERATIONS.get(key)
    if not api:
        raise SystemExit(f"No API name for {key}; regenerate contracts/aws_operation_names.py")
    return f"{PREFIX.get(service, service)}:{api}"


def snapshot() -> dict:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


def grants(action: str, patterns: list[str]) -> str | None:
    """The first Allow pattern matching the action (IAM actions are case-insensitive)."""
    return next(
        (p for p in patterns if fnmatch.fnmatchcase(action.lower(), p.lower())),
        None,
    )


def matrix() -> list[dict]:
    policies = snapshot()["policies"]
    rows = []
    for call in collector_calls():
        action = iam_action(call["service"], call["method"])
        row = {**call, "action": action}
        for name in MANAGED:
            row[name] = grants(action, policies[name]["actions"])
        row["requires_permission"] = action != "sts:GetCallerIdentity"
        rows.append(row)
    return rows


def supplement_actions(rows) -> list[str]:
    """Actions SecurityAudit does not grant: the member role's custom read-only policy."""
    return sorted(
        {r["action"] for r in rows if r["requires_permission"] and not r["SecurityAudit"]}
    )


def statement(sid, actions, effect="Allow"):
    return {"Sid": sid, "Effect": effect, "Action": sorted(actions), "Resource": "*"}


def documents(rows) -> dict[str, dict]:
    supplement = {
        "Version": "2012-10-17",
        "Statement": [
            statement("CloSecReadOnlySupplement", supplement_actions(rows)),
            statement("CloSecNoDataPlaneReads", DATA_PLANE_DENY, "Deny"),
        ],
    }
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloSecHubAssumeRole",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::HUB_ACCOUNT_ID:root"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "ArnLike": {"aws:PrincipalArn": "HUB_PRINCIPAL_ARN"},
                    "StringEquals": {"aws:PrincipalOrgID": "ORGANIZATION_ID"},
                },
            }
        ],
    }
    stackset = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "CloSec read-only evidence collection role (deploy with StackSets to "
        "member accounts). No write permissions.",
        "Parameters": {
            "RoleName": {
                "Type": "String",
                "Default": "CloSecEvidenceReadOnly",
                "AllowedPattern": "[A-Za-z0-9+=,.@_-]{1,64}",
            },
            "HubAccountId": {"Type": "String", "AllowedPattern": "[0-9]{12}"},
            "HubPrincipalArn": {
                "Type": "String",
                "Description": "Role ARN (or ARN pattern, for example an IAM Identity Center "
                "permission-set role) allowed to assume this role",
            },
            "OrganizationId": {"Type": "String", "AllowedPattern": "o-[a-z0-9]{10,32}"},
            "MaxSessionDuration": {
                "Type": "Number",
                "Default": 3600,
                "MinValue": 3600,
                "MaxValue": 43200,
            },
        },
        "Resources": {
            "CollectorRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleName"},
                    "Description": "CloSec read-only evidence collection",
                    "MaxSessionDuration": {"Ref": "MaxSessionDuration"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": {
                                        "Fn::Sub": "arn:${AWS::Partition}:iam::${HubAccountId}:root"
                                    }
                                },
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "ArnLike": {"aws:PrincipalArn": {"Ref": "HubPrincipalArn"}},
                                    "StringEquals": {
                                        "aws:PrincipalOrgID": {"Ref": "OrganizationId"}
                                    },
                                },
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/SecurityAudit"}
                    ],
                    "Policies": [
                        {"PolicyName": "CloSecReadOnlySupplement", "PolicyDocument": supplement}
                    ],
                    "Tags": [{"Key": "closec:purpose", "Value": "read-only-evidence"}],
                },
            }
        },
        "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["CollectorRole", "Arn"]}}},
    }
    hub = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloSecAssumeMemberRole",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::*:role/CloSecEvidenceReadOnly",
            },
            statement("CloSecAccountSearch", ["organizations:ListAccounts"]),
        ],
    }
    management = {
        "Version": "2012-10-17",
        "Statement": [statement("CloSecOrganizationsRead", MANAGEMENT)],
    }
    return {
        "member-supplement-policy.json": supplement,
        "member-trust-policy.json": trust,
        "member-role-stackset.cfn.json": stackset,
        "hub-operator-policy.json": hub,
        "management-organizations-read-policy.json": management,
    }


def table(rows) -> list[str]:
    lines = [
        "| Collector call | Phase | IAM action | SecurityAudit | ViewOnlyAccess | Supplement |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        if not r["requires_permission"]:
            sa = vo = "not required"
            extra = "—"
        else:
            sa = f"`{r['SecurityAudit']}`" if r["SecurityAudit"] else "**no**"
            vo = f"`{r['ViewOnlyAccess']}`" if r["ViewOnlyAccess"] else "no"
            extra = "**yes**" if not r["SecurityAudit"] else "—"
        lines.append(
            f"| {r['service']}.{r['method']} | {r['phase']} | `{r['action']}` | {sa} | {vo} | "
            f"{extra} |"
        )
    return lines


def doc(rows) -> str:
    snap = snapshot()
    meta = snap["policies"]
    supplement = supplement_actions(rows)
    from tools.collector_contract import aws_registry

    version = aws_registry()["version"]
    probes = probe_calls()
    probe_actions = sorted({iam_action(s, m) for s, m in probes})
    probe_uncovered = [
        a
        for a in probe_actions
        if a != "sts:GetCallerIdentity"
        and not grants(a, meta["SecurityAudit"]["actions"])
        and a not in supplement
    ]
    sa_only = sum(1 for r in rows if r["SecurityAudit"] and not r["ViewOnlyAccess"])
    vo_only = [r["action"] for r in rows if r["ViewOnlyAccess"] and not r["SecurityAudit"]]
    neither = sorted(
        {
            r["action"]
            for r in rows
            if r["requires_permission"] and not r["SecurityAudit"] and not r["ViewOnlyAccess"]
        }
    )
    lines = [
        "# AWS collection access (generated)",
        "",
        "Generated by `tools/aws_access_policy.py` from `collectors/aws/assessment.py` "
        f"{version} (registries and literal calls, read by AST, never executed) and a dated "
        "snapshot of the AWS-managed policies. Do not edit by hand; "
        "`tests/test_aws_collection_access.py` fails on drift.",
        "",
        "Managed-policy snapshot (`tools/data/aws_managed_policies.json`, retrieved "
        f"{snap['retrieved']} from the AWS Managed Policy Reference):",
        "",
    ]
    for name in MANAGED:
        m = meta[name]
        lines.append(
            f"- `{m['arn']}` {m['version']}, edited {m['edited']}: {len(m['actions'])} Allow "
            "action patterns, no Deny."
        )
    lines += [
        "",
        "AWS revises these policies; re-check the snapshot before each engagement "
        "(`--refresh-snapshot`). An organization SCP or permissions boundary can still deny an "
        "allowed action: the pre-flight probe (`collectors/aws/preflight.py`) tests the "
        "effective result per account.",
        "",
        "## 1. Recommendation",
        "",
        "Member accounts: one role (default name `CloSecEvidenceReadOnly`) with",
        "",
        "1. AWS-managed **SecurityAudit**;",
        "2. the inline **CloSecReadOnlySupplement** "
        "(`collectors/aws/policies/member-supplement-policy.json`): "
        + ", ".join(f"`{a}`" for a in supplement)
        + ", plus an explicit Deny of data-plane reads the collector never needs (object "
        "bodies, secret values, parameters, decryption, table items, function code, image "
        "layers, log events);",
        "3. the trust policy in section 3 (hub principal, organization-bound).",
        "",
        f"Of {sum(r['requires_permission'] for r in rows)} permission-bearing calls, "
        f"SecurityAudit grants all but {len(supplement)}; {sa_only} are granted by "
        "SecurityAudit only. ViewOnlyAccess adds "
        + (", ".join(f"`{a}`" for a in vo_only) or "nothing")
        + " and is not needed with the supplement. Granted by neither managed policy: "
        + (", ".join(f"`{a}`" for a in neither) or "none")
        + ". No call needs a write, tag, put, create, delete or update permission (static test "
        "`test_collector_calls_are_read_only`).",
        "",
        "## 2. Every API action the collector uses",
        "",
        "Phases: GLOBAL and REGIONAL registries; DEPENDENT per-resource calls after a complete "
        "parent listing; ORGANIZATION the SCP/RCP chain; SETUP session and Region discovery. "
        "Cells name the managed-policy pattern that grants the action.",
        "",
        *table(rows),
        "",
        "## 3. Member role, trust policy and StackSet",
        "",
        "- `collectors/aws/policies/member-role-stackset.cfn.json`: CloudFormation (JSON) "
        "template for a service-managed StackSet targeting the member OUs. Parameters: "
        "`RoleName`, `HubAccountId`, `HubPrincipalArn`, `OrganizationId`, "
        "`MaxSessionDuration` (default 3600). It attaches SecurityAudit and the supplement "
        "inline. Service-managed StackSets do not deploy to the management account; create "
        "the role there separately if the management account is in scope.",
        "- `collectors/aws/policies/member-trust-policy.json`: the same trust as a standalone "
        "document. Replace `HUB_ACCOUNT_ID`, `HUB_PRINCIPAL_ARN` (for example "
        "`arn:aws:iam::<hub>:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_<set>_*` for "
        "an IAM Identity Center permission set) and `ORGANIZATION_ID`.",
        "- The trust binds `aws:PrincipalOrgID`, so CloSec's own R1-IAM-ROLE-TRUST-CONDITIONS "
        "does not report the collection role as an unconditioned cross-account trust.",
        "",
        "## 4. Hub (operator) permissions",
        "",
        "`collectors/aws/policies/hub-operator-policy.json`, attached to the identity that "
        "runs the collector, the probe or the batch orchestrator:",
        "",
    ]
    lines += [f"- `{a}`: {why}." for a, why in HUB]
    lines += [
        "",
        "## 5. Management account: Organizations, SCPs and RCPs",
        "",
        "Organizations read APIs other than `DescribeOrganization` answer only in the "
        "management account or an Organizations delegated administrator; member-account "
        "collection receives AccessDenied, which the collector journals and the analyzer "
        'reports as "organization controls not assessed" (never as "no SCP"). For SCP and '
        "RCP content, run the collector once against the management account (or a delegated "
        "administrator) with these actions "
        "(`collectors/aws/policies/management-organizations-read-policy.json`; SecurityAudit "
        "already grants `organizations:Describe*` and `organizations:List*`):",
        "",
    ]
    lines += [f"- `{a}`" for a in MANAGEMENT]
    lines += [
        "",
        "The collector records the organization ID and management account ID from "
        "`DescribeOrganization` (available to members) in the manifest, and states "
        "explicitly when organization policy access is missing.",
        "",
        "## 6. Session duration",
        "",
        "Recommended: **3600 s** (`DurationSeconds=3600`, role `MaxSessionDuration` 3600). "
        "When the hub identity is itself an assumed role (IAM Identity Center or another "
        "role), AWS limits the chained session to one hour regardless of "
        "`MaxSessionDuration`. The collector uses refreshable assume-role credentials and the "
        "batch orchestrator re-assumes before expiry, so longer sessions are not required; "
        "raise `MaxSessionDuration` only when the hub uses long-term credentials and the "
        "operator wants fewer AssumeRole calls.",
        "",
        "## 7. Pre-flight probe coverage",
        "",
        f"`collectors/aws/preflight.py` makes {len(probes)} read-only calls per account "
        "(global families once, regional families per Region), all within SecurityAudit plus "
        "the supplement"
        + (
            "."
            if not probe_uncovered
            else "; not covered: " + ", ".join(f"`{a}`" for a in probe_uncovered) + "."
        ),
        "",
        "## 8. Not verified",
        "",
        "- No real AWS account was used. Coverage is computed from the policy snapshot, not "
        "from an IAM policy simulation; SCPs, permission boundaries and service opt-in can "
        "still deny an allowed action (the probe reports that per account).",
        "- IAM action names come from the Service Authorization Reference naming; the table "
        "`ACTION` in the generator lists every name that differs from the API operation.",
        "",
    ]
    return "\n".join(lines)


def outputs() -> dict[Path, str]:
    rows = matrix()
    text = doc(rows)
    # The same generated document ships in the collector kit.
    result = {DOC: text, AWS / "AWS_COLLECTION_ACCESS.md": text}
    for name, value in documents(rows).items():
        result[POLICIES / name] = json.dumps(value, indent=2) + "\n"
    return result


def refresh(folder: Path) -> None:
    data = {"retrieved": None, "source": "AWS Managed Policy Reference", "policies": {}}
    for name in MANAGED:
        page = (folder / f"{name}.html").read_text(encoding="utf-8")
        document = None
        for block in re.findall(r"<pre[^>]*>(.*?)</pre>", page, re.S):
            text = html.unescape(re.sub(r"<[^>]+>", "", block))
            if '"Statement"' in text:
                document = json.loads(text)
                break
        if document is None:
            raise SystemExit(f"No policy document in {name}.html")
        if any(s.get("Effect") != "Allow" or "NotAction" in s for s in document["Statement"]):
            raise SystemExit(f"{name}: unexpected Deny/NotAction; review manually")
        actions = []
        for s in document["Statement"]:
            value = s["Action"]
            actions += [value] if isinstance(value, str) else value
        version = re.search(r"(v[0-9]+) \(default\)", page)
        edited = re.search(r"Edited time:</b>\s*([^<]+?)\s*<", page)
        data["policies"][name] = {
            "arn": "arn:aws:iam::aws:policy/"
            + ("job-function/" if name == "ViewOnlyAccess" else "")
            + name,
            "version": version[1] if version else "UNKNOWN",
            "edited": edited[1].strip() if edited else "UNKNOWN",
            "url": f"https://docs.aws.amazon.com/aws-managed-policy/latest/reference/{name}.html",
            "actions": sorted(set(actions)),
        }
    SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--refresh-snapshot", type=Path)
    parser.add_argument("--retrieved", help="date the reference pages were saved (YYYY-MM-DD)")
    args = parser.parse_args()
    if args.refresh_snapshot:
        refresh(args.refresh_snapshot)
        if args.retrieved:
            data = snapshot()
            data["retrieved"] = args.retrieved
            SNAPSHOT.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    for path, text in outputs().items():
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                raise SystemExit(f"{path.relative_to(ROOT)} is stale; regenerate it")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    print("AWS access design " + ("verified" if args.check else "written"))


if __name__ == "__main__":
    main()
