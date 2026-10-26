#!/usr/bin/env python3
"""CloSec AWS pre-flight access probe (read-only, Python 3.9+, boto3).

For each approved account: assume the member role, then make one read-only call per API
family the collector needs (global families once, Regional families per Region) and report
ALLOWED, DENIED, REGION_NOT_ENABLED, SERVICE_NOT_IN_USE, THROTTLED, CREDENTIALS_EXPIRED,
TIMEOUT, CONNECTION_ERROR or ERROR. Writes a per-account table and a fleet summary of
repeated denials, so access can be fixed centrally (StackSet, SCP) before collection.

No evidence is written: only call outcomes and error codes, never response bodies. Account
IDs are masked in terminal output; the files written to --output keep full IDs because the
access owner needs them. Credentials are never printed or stored.

    python preflight.py --accounts accounts.csv --role CloSecEvidenceReadOnly \
        --regions ap-south-1 eu-west-1 --output preflight-results
"""

import argparse
import datetime
import pathlib
import sys
import threading
import time
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import assessment  # noqa: E402  (same folder; the collector's classifier and sessions)
import fleet  # noqa: E402

# (family, service, method, scope, parameters, IAM action). Parameters are the collector's
# own (read-only); "{account}" is replaced by the account ID. Read by
# tools/aws_access_policy.py, which checks every IAM action against the access design.
FAMILIES = [
    ("identity", "sts", "get_caller_identity", "global", {}, "sts:GetCallerIdentity"),
    ("regions", "ec2", "describe_regions", "global", {"AllRegions": True}, "ec2:DescribeRegions"),
    ("iam", "iam", "get_account_authorization_details", "global", {"MaxItems": 1},
     "iam:GetAccountAuthorizationDetails"),
    ("iam-summary", "iam", "get_account_summary", "global", {}, "iam:GetAccountSummary"),
    ("s3", "s3", "list_buckets", "global", {}, "s3:ListAllMyBuckets"),
    ("s3-account-bpa", "s3control", "get_public_access_block", "global",
     {"AccountId": "{account}"}, "s3:GetAccountPublicAccessBlock"),
    ("cloudfront", "cloudfront", "list_distributions", "global", {},
     "cloudfront:ListDistributions"),
    ("route53", "route53", "list_hosted_zones", "global", {}, "route53:ListHostedZones"),
    ("organizations", "organizations", "describe_organization", "global", {},
     "organizations:DescribeOrganization"),
    ("organizations-policies", "organizations", "list_policies_for_target", "global",
     {"TargetId": "{account}", "Filter": "SERVICE_CONTROL_POLICY"},
     "organizations:ListPoliciesForTarget"),
    ("ec2", "ec2", "describe_vpcs", "regional", {}, "ec2:DescribeVpcs"),
    ("rds", "rds", "describe_db_instances", "regional", {}, "rds:DescribeDBInstances"),
    ("kms", "kms", "list_keys", "regional", {}, "kms:ListKeys"),
    ("cloudtrail", "cloudtrail", "describe_trails", "regional", {}, "cloudtrail:DescribeTrails"),
    ("config", "config", "describe_configuration_recorders", "regional", {},
     "config:DescribeConfigurationRecorders"),
    ("guardduty", "guardduty", "list_detectors", "regional", {}, "guardduty:ListDetectors"),
    ("securityhub", "securityhub", "describe_hub", "regional", {}, "securityhub:DescribeHub"),
    ("access-analyzer", "accessanalyzer", "list_analyzers", "regional", {},
     "access-analyzer:ListAnalyzers"),
    ("elb", "elbv2", "describe_load_balancers", "regional", {},
     "elasticloadbalancing:DescribeLoadBalancers"),
    ("lambda", "lambda", "list_functions", "regional", {}, "lambda:ListFunctions"),
    ("ecs", "ecs", "list_clusters", "regional", {}, "ecs:ListClusters"),
    ("eks", "eks", "list_clusters", "regional", {}, "eks:ListClusters"),
    ("ecr", "ecr", "describe_repositories", "regional", {}, "ecr:DescribeRepositories"),
    ("dynamodb", "dynamodb", "list_tables", "regional", {}, "dynamodb:ListTables"),
    ("efs", "efs", "describe_file_systems", "regional", {},
     "elasticfilesystem:DescribeFileSystems"),
    ("fsx", "fsx", "describe_file_systems", "regional", {}, "fsx:DescribeFileSystems"),
    ("secretsmanager", "secretsmanager", "list_secrets", "regional", {},
     "secretsmanager:ListSecrets"),
    ("logs", "logs", "describe_log_groups", "regional", {}, "logs:DescribeLogGroups"),
    ("cloudwatch", "cloudwatch", "describe_alarms", "regional", {}, "cloudwatch:DescribeAlarms"),
    ("events", "events", "list_rules", "regional", {}, "events:ListRules"),
    ("wafv2", "wafv2", "list_web_acls", "regional", {"Scope": "REGIONAL"}, "wafv2:ListWebACLs"),
    ("network-firewall", "network-firewall", "list_firewalls", "regional", {},
     "network-firewall:ListFirewalls"),
    ("inspector", "inspector2", "list_findings", "regional", {"maxResults": 100},
     "inspector2:ListFindings"),
    ("macie", "macie2", "get_macie_session", "regional", {}, "macie2:GetMacieSession"),
    ("apigateway", "apigateway", "get_rest_apis", "regional", {}, "apigateway:GET"),
    ("apigatewayv2", "apigatewayv2", "get_apis", "regional", {}, "apigateway:GET"),
    ("tagging", "resourcegroupstaggingapi", "get_resources", "regional",
     {"ResourcesPerPage": 100}, "tag:GetResources"),
    ("resource-explorer", "resource-explorer-2", "list_indexes", "regional", {},
     "resource-explorer-2:ListIndexes"),
    ("ram", "ram", "list_resources", "regional", {"resourceOwner": "SELF"}, "ram:ListResources"),
    ("ssm", "ssm", "describe_instance_information", "regional", {},
     "ssm:DescribeInstanceInformation"),
    ("route53resolver", "route53resolver", "list_resolver_endpoints", "regional", {},
     "route53resolver:ListResolverEndpoints"),
]  # fmt: skip
# Organizations policy reads are answered only by the management account or a delegated
# administrator; denial in a member account is expected and reported separately.
EXPECTED_MEMBER_DENIAL = {"organizations-policies"}
STATUS = {
    "COMPLETE": "ALLOWED",
    "PARTIAL": "ALLOWED",
    "NOT_ENABLED": "ALLOWED",  # AWS answered "not configured": the permission works
    "ACCESS_DENIED": "DENIED",
    "THROTTLED": "THROTTLED",
    "CREDENTIALS_EXPIRED": "CREDENTIALS_EXPIRED",
    "TIMEOUT": "TIMEOUT",
    "CONNECTION_ERROR": "CONNECTION_ERROR",
    "SERVICE_NOT_IN_USE": "SERVICE_NOT_IN_USE",
}
FIELDS = [
    "account_id",
    "business_group",
    "family",
    "iam_action",
    "region",
    "status",
    "code",
    "attempts",
]


def probe_call(session, family, account, region, options, throttle):
    """One bounded probe call (first page only), retried on throttling and transient errors."""
    name, service, method, scope, params, action = family
    params = {k: (v.replace("{account}", account) if isinstance(v, str) else v)
              for k, v in params.items()}  # fmt: skip
    client = session.client(
        service,
        region_name=None if scope == "global" else region,
        config=assessment.client_config(options),
    )
    status, code = "ALLOWED", ""
    for attempt in range(1, options["max_attempts"] + 1):
        throttle.wait()
        try:
            getattr(client, method)(**params)
            status, code = "ALLOWED", ""
        except Exception as exc:
            raw, code = assessment.classify(exc)
            status = STATUS.get(raw, "ERROR")
            if raw in assessment.RETRYABLE and attempt < options["max_attempts"]:
                if raw == "THROTTLED":
                    throttle.signal()
                time.sleep(assessment.backoff(options, attempt))
                continue
        return {"status": status, "code": code, "attempts": attempt}
    return {"status": status, "code": code, "attempts": options["max_attempts"]}


def probe_account(entry, args, options, throttle, master):
    account = entry["account_id"]
    base = {"account_id": account, "business_group": entry.get("business_group") or ""}
    rows = []
    try:
        session, _role = assessment.account_session(
            master,
            account,
            args.role,
            args.regions[0],
            duration=options["session_duration"],
            config=assessment.client_config(options),
        )
        session.client("sts", config=assessment.client_config(options)).get_caller_identity()
    except Exception as exc:
        status, code = assessment.classify(exc)
        verdict = "CREDENTIALS_EXPIRED" if status == "CREDENTIALS_EXPIRED" else "DENIED"
        return [{**base, "family": "assume-role", "iam_action": "sts:AssumeRole",
                 "region": "global", "status": verdict, "code": code, "attempts": 1}]  # fmt: skip
    enabled = None
    for family in FAMILIES:
        if family[3] != "global":
            continue
        result = probe_call(session, family, account, args.regions[0], options, throttle)
        rows.append({**base, "family": family[0], "iam_action": family[5], "region": "global",
                     **result})  # fmt: skip
        if family[0] == "regions" and result["status"] == "ALLOWED":
            try:
                regions = session.client(
                    "ec2", region_name=args.regions[0], config=assessment.client_config(options)
                ).describe_regions(AllRegions=True)["Regions"]
                enabled = {
                    r["RegionName"]
                    for r in regions
                    if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")
                }
            except Exception:
                enabled = None  # opt-in state unknown: probe every requested Region
        if result["status"] == "CREDENTIALS_EXPIRED":
            return rows
    for region in args.regions:
        for family in FAMILIES:
            if family[3] != "regional":
                continue
            if enabled is not None and region not in enabled:
                result = {"status": "REGION_NOT_ENABLED", "code": "", "attempts": 0}
            else:
                result = probe_call(session, family, account, region, options, throttle)
            rows.append({**base, "family": family[0], "iam_action": family[5], "region": region,
                         **result})  # fmt: skip
            if result["status"] == "CREDENTIALS_EXPIRED":
                return rows
    return rows


def account_verdict(rows):
    """READY (every needed family allowed or not applicable), ACCESS GAP (a needed family is
    denied or the role cannot be assumed) or RE-PROBE (transient failures only)."""
    needed = [r for r in rows if r["family"] not in EXPECTED_MEMBER_DENIAL]
    if any(r["status"] == "DENIED" for r in needed):
        return "ACCESS GAP"
    if any(r["status"] in ("THROTTLED", "TIMEOUT", "CONNECTION_ERROR", "ERROR",
                           "CREDENTIALS_EXPIRED") for r in needed):  # fmt: skip
        return "RE-PROBE"
    return "READY"


def fleet_summary(rows, accounts):
    """Repeated non-allowed families across accounts, most widespread first."""
    by_family = defaultdict(set)
    statuses = Counter()
    for r in rows:
        statuses[r["status"]] += 1
        if r["status"] not in ("ALLOWED", "REGION_NOT_ENABLED"):
            by_family[(r["family"], r["iam_action"], r["status"], r["code"])].add(r["account_id"])
    repeated = [
        {
            "family": f,
            "iam_action": action,
            "status": status,
            "code": code,
            "accounts": len(ids),
            "account_ids": sorted(ids),
            "expected_in_member_accounts": f in EXPECTED_MEMBER_DENIAL,
        }
        for (f, action, status, code), ids in by_family.items()
    ]
    repeated.sort(key=lambda r: (-r["accounts"], r["family"], r["status"]))
    return {"accounts": len(accounts), "row_statuses": dict(statuses), "repeated": repeated}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--accounts", required=True, help="CSV (account_id,business_group,name) or text")
    p.add_argument("--role", required=True, help="member role name, e.g. CloSecEvidenceReadOnly")
    p.add_argument("--regions", nargs="+", required=True)
    p.add_argument("--output", default="preflight-results")
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--max-attempts", type=int, default=3)
    p.add_argument("--profile", help="named profile for the hub identity (optional)")
    args = p.parse_args(argv)
    accounts, problems = fleet.read_accounts(args.accounts)
    for problem in problems:
        print(f"Account list line {problem['line']}: {problem['problem']}")
    if not accounts:
        print("No valid account IDs; nothing probed.")
        return 2
    options = assessment.resolve_options({}, {"max_attempts": args.max_attempts})
    throttle = assessment.Throttle()
    master = assessment.boto3.Session(profile_name=args.profile, region_name=args.regions[0]) \
        if args.profile else assessment.boto3.Session(region_name=args.regions[0])  # fmt: skip
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = pathlib.Path(args.output) / f"preflight-{stamp}"
    stop = threading.Event()
    results = fleet.run_pool(
        accounts, lambda e: probe_account(e, args, options, throttle, master), args.concurrency,
        stop,
    )  # fmt: skip
    rows, verdicts = [], {}
    for entry, account_rows, error in results:
        if error:
            account_rows = [{"account_id": entry["account_id"],
                             "business_group": entry.get("business_group") or "",
                             "family": "probe", "iam_action": "", "region": "global",
                             "status": "ERROR", "code": error[:120], "attempts": 0}]  # fmt: skip
        rows += account_rows
        verdicts[entry["account_id"]] = account_verdict(account_rows)
    rows.sort(key=lambda r: (r["account_id"], r["region"], r["family"]))
    summary = fleet_summary(rows, accounts)
    summary["verdicts"] = dict(Counter(verdicts.values()))
    summary["account_verdicts"] = verdicts
    fleet.write_csv(out / "accounts.csv", rows, FIELDS)
    fleet.write_json(out / "accounts.json", {"rows": rows, "list_problems": problems})
    fleet.write_json(out / "fleet-summary.json", summary)
    print(f"\nPre-flight: {len(accounts)} accounts, verdicts {summary['verdicts']}")
    for account in sorted(verdicts):
        bad = Counter(r["status"] for r in rows
                      if r["account_id"] == account and r["status"] != "ALLOWED")  # fmt: skip
        print(f"  {fleet.mask(account)}  {verdicts[account]:<11} {dict(bad) or ''}")
    print("\nRepeated non-allowed families (fix centrally):")
    for item in summary["repeated"][:25]:
        note = " (expected for member accounts)" if item["expected_in_member_accounts"] else ""
        print(f"  {item['accounts']:>4} accounts  {item['status']:<19} {item['iam_action']}"
              f" {item['code']}{note}")  # fmt: skip
    print(f"\nResults: {out}")
    return 0 if set(verdicts.values()) <= {"READY"} else 1


if __name__ == "__main__":
    sys.exit(main())
