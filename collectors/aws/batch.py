#!/usr/bin/env python3
"""CloSec AWS batch collector (read-only, Python 3.9+, boto3; Windows, macOS and Linux).

Collects many accounts with the unchanged single-account collector (assessment.py), one
package per account:

    python batch.py --accounts accounts.csv --role CloSecEvidenceReadOnly \
        --regions ap-south-1 eu-west-1 --output batch-2026-10 --assessment-id ACME-2026

* per account: assume the member role (refreshed before expiry by botocore), collect, write
  `<name>__<account>__<run>.zip` plus `.zip.sha256`, and a result row (status, duration,
  retries, datasets by status, collector version, health verdict);
* concurrency (default 4) with one throttle-aware backoff shared by every worker;
* one account's failure never stops the batch; a checkpoint (`batch-checkpoint.json`) is
  written after every account, so a restart skips accounts that finished;
* `--retry-failed` re-runs only accounts that failed, were interrupted or are not READY, and
  resumes their previous run so only failed or missing operations are collected again;
* an expired hub sign-in (SSO session) stops scheduling new accounts, finalizes the running
  ones as INTERRUPTED and tells the operator to sign in and rerun with `--retry-failed`.

Outputs in --output: batch-manifest.json, accounts-result.csv, fleet-rollup.json and
fleet-limitations.md (repeated non-success datasets, the basis of the report's limitations
section). Account IDs are masked in terminal output; credentials are never printed.

Health verdict (metrics only, same inputs as a triage of the package: status histogram,
defect datasets, Region coverage, collector version):
READY      every evaluated dataset complete or AWS-defined absent, every Region collected;
ACCESS GAP an evaluated dataset (or the role itself) was denied: fix access centrally;
RE-COLLECT transient failures, partial Regions, interruption or an older collector.
"""

import argparse
import hashlib
import json
import pathlib
import sys
import threading
import time
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import assessment  # noqa: E402
import fleet  # noqa: E402

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
TRANSIENT = {"THROTTLED", "TIMEOUT", "CONNECTION_ERROR", "API_ERROR", "CREDENTIALS_EXPIRED",
             "PARTIAL"}  # fmt: skip
DEFINITIVE = {"COMPLETE", "NOT_ENABLED"}
# Organizations policy reads are expected to be denied in member accounts; they are
# reported as "organization controls not assessed", not as an access gap of the account.
ORGANIZATION_OPS = {"organizations.list_roots", "organizations.list_policies_for_target",
                    "organizations.list_parents", "organizations.describe_policy"}  # fmt: skip
RESULT_FIELDS = [
    "account_id",
    "business_group",
    "name",
    "state",
    "verdict",
    "reasons",
    "duration_seconds",
    "retries",
    "datasets_by_status",
    "collector_version",
    "regions_succeeded",
    "regions_not_enabled",
    "zip",
    "zip_sha256",
    "resumed_from",
]


def evaluated_datasets():
    """`service.method` datasets an analyzer rule consumes (collector-analyzer contract
    shipped beside this script); None when the contract is not available."""
    for candidate in (SCRIPT_DIR / "collector-analyzer-contract.json",
                      SCRIPT_DIR.parent / "collector-analyzer-contract.json"):  # fmt: skip
        if candidate.is_file():
            contract = json.loads(candidate.read_text(encoding="utf-8"))
            aws = next(p for p in contract["providers"] if p["provider"] == "AWS")
            return {d["dataset"] for d in aws["datasets"] if d["lifecycle"] == "EVALUATED"}
    return None


def triage(run_directory, evaluated=None):
    """Metrics-only health of one package: never reads evidence values."""
    root = pathlib.Path(run_directory)
    manifest = assessment.read_json(root / "manifest.json")
    summary = assessment.read_json(root / "collection-summary.json")
    rows = [json.loads(line) for line in (root / "operations.jsonl").read_text(
        encoding="utf-8").splitlines() if line.strip()]  # fmt: skip
    facts = manifest.get("collection_facts") or {}
    histogram = Counter(r["outcome"] for r in rows)
    defects = defaultdict(set)
    for r in rows:
        dataset = f"{r['service']}.{r['operation']}"
        if r["outcome"] in DEFINITIVE or r["service"] in assessment.SCANNERS:
            continue
        if evaluated is not None and dataset not in evaluated:
            continue
        defects[dataset].add(r["outcome"])
    reasons = []
    denied = sorted(d for d, s in defects.items() if "ACCESS_DENIED" in s and d not in ORGANIZATION_OPS)
    transient = sorted(d for d, s in defects.items() if s & TRANSIENT)
    if denied:
        reasons.append("denied: " + ", ".join(denied[:8]))
    if summary.get("status") in ("INTERRUPTED", "FAILED_VALIDATION"):
        reasons.append("collection " + summary["status"].lower())
    if transient:
        reasons.append("transient or partial: " + ", ".join(transient[:8]))
    if facts.get("regions_partial"):
        reasons.append("partial Regions: " + ", ".join(facts["regions_partial"]))
    version = manifest.get("collector_version")
    if version != assessment.VERSION:
        reasons.append(f"collector {version} (current {assessment.VERSION})")
    if denied:
        verdict = "ACCESS GAP"
    elif reasons:
        verdict = "RE-COLLECT"
    else:
        verdict = "READY"
    return {
        "verdict": verdict,
        "reasons": reasons,
        "histogram": dict(sorted(histogram.items())),
        "defect_datasets": {d: sorted(s) for d, s in sorted(defects.items())},
        "regions_succeeded": facts.get("regions_succeeded", manifest.get("regions", [])),
        "regions_partial": facts.get("regions_partial", []),
        "regions_not_enabled": facts.get("regions_not_enabled", []),
        "collector_version": version,
        "retries": (facts.get("retries") or {}).get("total", 0),
        "organization_access": (facts.get("organization") or {}).get("access"),
    }


def rollup(rows, evaluated=None):
    """Repeated non-success datasets across the fleet (the report's limitations input)."""
    by_item = defaultdict(set)
    organization = Counter()
    verdicts = Counter(r.get("verdict") or "NOT COLLECTED" for r in rows)
    for row in rows:
        for dataset, statuses in (row.get("defect_datasets") or {}).items():
            for status in statuses:
                by_item[(dataset, status)].add(row["account_id"])
        if row.get("organization_access"):
            organization[row["organization_access"]] += 1
    repeated = sorted(
        ({"dataset": d, "status": s, "accounts": len(ids), "account_ids": sorted(ids)}
         for (d, s), ids in by_item.items()),
        key=lambda x: (-x["accounts"], x["dataset"], x["status"]),
    )  # fmt: skip
    return {
        "accounts": len(rows),
        "verdicts": dict(sorted(verdicts.items())),
        "repeated": repeated,
        "organization_access": dict(sorted(organization.items())),
        "not_collected": sorted(r["account_id"] for r in rows if r.get("state") != "DONE"),
    }


def limitations_text(roll, total):
    lines = [
        "# Fleet collection limitations (generated by batch.py)",
        "",
        f"Accounts in scope: {total}. Verdicts: "
        + ", ".join(f"{k} {v}" for k, v in roll["verdicts"].items()) + ".",
        "",
    ]  # fmt: skip
    if roll["not_collected"]:
        lines += [f"- {len(roll['not_collected'])} account(s) have no complete package "
                  "(failed, interrupted or not started); see accounts-result.csv.", ""]  # fmt: skip
    denied_org = roll["organization_access"].get("ACCESS_DENIED", 0)
    if denied_org:
        lines += [f"- Organization controls (SCPs, RCPs) not assessed in {denied_org} account(s): "
                  "Organizations policy access is available only to the management account or "
                  "a delegated administrator.", ""]  # fmt: skip
    if roll["repeated"]:
        lines += ["Repeated non-success datasets (evidence gaps, never compliant):", ""]
        for item in roll["repeated"]:
            lines.append(f"- {item['accounts']} of {total} accounts: `{item['dataset']}` "
                         f"{item['status']}")  # fmt: skip
    else:
        lines.append("No repeated evidence gaps.")
    return "\n".join(lines) + "\n"


def prior_run(row):
    path = row and row.get("run_directory")
    if path and pathlib.Path(path, "manifest.json").is_file():
        try:
            manifest = assessment.read_json(pathlib.Path(path) / "manifest.json")
        except ValueError:
            return None
        if manifest.get("collector_version") == assessment.VERSION:
            return path
    return None


def selected(accounts, checkpoint, retry_failed):
    """Accounts to run now: not finished (restart), or also not READY (--retry-failed)."""
    chosen = []
    for entry in accounts:
        row = checkpoint.get(entry["account_id"])
        if row is None:
            chosen.append((entry, None))
        elif row.get("state") != "DONE":
            chosen.append((entry, prior_run(row)))
        elif retry_failed and row.get("verdict") != "READY":
            chosen.append((entry, prior_run(row)))
    return chosen


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--accounts", required=True, help="CSV (account_id,business_group,name) or text")
    p.add_argument("--role", help="member role name (default: spoke_role_name in --config)")
    p.add_argument("--regions", nargs="+", help="default: approved_regions in --config")
    p.add_argument("--output", required=True, help="batch folder (reused on restart)")
    p.add_argument("--config", help="collector config.json (allowlists, timeouts, retries)")
    p.add_argument("--assessment-id")
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--session-duration", type=int, help="AssumeRole seconds (default 3600)")
    p.add_argument("--max-attempts", type=int)
    p.add_argument("--connect-timeout", type=float)
    p.add_argument("--read-timeout", type=float)
    p.add_argument("--operation-timeout", type=float)
    p.add_argument("--retry-failed", action="store_true")
    p.add_argument("--profile", help="named profile for the hub identity (optional)")
    args = p.parse_args(argv)
    out = pathlib.Path(args.output).expanduser().resolve()
    cfg = assessment.load_config(args.config) if args.config else {"_config_dir": str(out)}
    cfg["spoke_role_name"] = args.role or cfg.get("spoke_role_name")
    cfg["approved_regions"] = args.regions or cfg.get("approved_regions")
    cfg["assessment_id"] = args.assessment_id or cfg.get("assessment_id")
    cfg["output_directory"] = str(out / "evidence")
    cfg.setdefault("dataset_origin", "TOOL_GENERATED")
    if not cfg["spoke_role_name"] or not cfg["approved_regions"] or not cfg["assessment_id"]:
        p.error("--role, --regions and --assessment-id are required (or set them in --config)")
    if args.concurrency < 1 or args.concurrency > 32:
        p.error("--concurrency must be 1-32")
    options = assessment.resolve_options(cfg, {
        "max_attempts": args.max_attempts, "connect_timeout": args.connect_timeout,
        "read_timeout": args.read_timeout, "operation_timeout": args.operation_timeout,
        "session_duration": args.session_duration,
    })  # fmt: skip
    accounts, problems = fleet.read_accounts(args.accounts)
    for problem in problems:
        print(f"Account list line {problem['line']}: {problem['problem']}")
    allow = None
    if cfg.get("approved_accounts") or cfg.get("approved_accounts_file"):
        allow = set(assessment.load_approved_accounts(cfg))
    out.mkdir(parents=True, exist_ok=True)
    checkpoint = fleet.Checkpoint(out / "batch-checkpoint.json")
    for entry in accounts:
        if allow is not None and entry["account_id"] not in allow:
            checkpoint.put(entry["account_id"], {**entry, "state": "REFUSED",
                                                 "verdict": None,
                                                 "reasons": ["not in approved account list"]})  # fmt: skip
    runnable = [e for e in accounts if allow is None or e["account_id"] in allow]
    todo = selected(runnable, checkpoint, args.retry_failed)
    evaluated = evaluated_datasets()
    throttle = assessment.Throttle()
    master = (assessment.boto3.Session(profile_name=args.profile, region_name=cfg["approved_regions"][0])
              if args.profile else assessment.boto3.Session(region_name=cfg["approved_regions"][0]))  # fmt: skip
    stop = threading.Event()
    done = Counter()
    lock = threading.Lock()
    print(f"Batch: {len(accounts)} accounts, {len(todo)} to collect now "
          f"({len(runnable) - len(todo)} already finished), concurrency {args.concurrency}")  # fmt: skip

    def work(item):
        entry, resume = item
        account = entry["account_id"]
        started, t0 = assessment.UTC(), time.monotonic()
        row = {**entry, "state": "FAILED", "verdict": "RE-COLLECT", "reasons": [],
               "started_at": started, "resumed_from": None}  # fmt: skip
        try:
            result = assessment.collect_account(
                cfg, account, cfg["approved_regions"], account_name=entry.get("name") or "",
                business_group=entry.get("business_group"), options=options,
                throttle=throttle, resume=resume, master=master, log=lambda *_: None,
            )  # fmt: skip
            health = triage(result["run_directory"], evaluated)
            summary = result["summary"]
            row.update(
                state="INTERRUPTED" if summary["status"] == "INTERRUPTED" else
                "DONE" if result["zip"] else "FAILED",
                verdict=health["verdict"], reasons=health["reasons"],
                run_directory=result["run_directory"], zip=result["zip"],
                zip_sha256=result["zip_sha256"], datasets_by_status=health["histogram"],
                defect_datasets=health["defect_datasets"],
                regions_succeeded=health["regions_succeeded"],
                regions_not_enabled=health["regions_not_enabled"],
                collector_version=health["collector_version"], retries=health["retries"],
                organization_access=health["organization_access"], resumed_from=resume,
            )  # fmt: skip
            if summary.get("interruption_reason") == "CREDENTIALS_EXPIRED":
                stop.set()
                row["reasons"].append("hub sign-in expired during collection")
        except assessment.CredentialsExpired as exc:
            stop.set()
            row.update(state="INTERRUPTED", reasons=[f"credentials expired ({exc.code})"])
        except assessment.AssumeRoleFailed as exc:
            row.update(verdict="ACCESS GAP", reasons=[f"role not assumable ({exc.code})"])
        except assessment.NoEnabledRegion:
            row.update(reasons=["none of the requested Regions is enabled in this account"])
        except Exception as exc:  # isolation: the batch continues
            row.update(reasons=[f"{type(exc).__name__}: {str(exc)[:160]}"])
        row["duration_seconds"] = round(time.monotonic() - t0, 1)
        row["completed_at"] = assessment.UTC()
        checkpoint.put(account, row)
        with lock:
            done["n"] += 1
            print(f"[{done['n']}/{len(todo)}] {fleet.mask(account)} {row['state']:<11} "
                  f"{row.get('verdict') or '':<10} {row['duration_seconds']:>7}s")  # fmt: skip
        return row

    try:
        results = fleet.run_pool(todo, work, args.concurrency, stop)
    except KeyboardInterrupt:
        print("\nInterrupted: finished accounts are checkpointed; rerun the same command.")
        results = []
    for (entry, _resume), row, error in results:
        if row is None:
            state = "NOT_STARTED" if error == "NOT_STARTED" else "FAILED"
            checkpoint.put(entry["account_id"], {**entry, "state": state, "verdict": None,
                                                 "reasons": [error or "not started"]})  # fmt: skip
    rows = [checkpoint.get(e["account_id"]) or {**e, "state": "NOT_STARTED"} for e in accounts]
    roll = rollup(rows, evaluated)
    batch_manifest = {
        "schema": "closec-aws-batch-1",
        "collector_version": assessment.VERSION,
        "updated_at": assessment.UTC(),
        "assessment_id": cfg["assessment_id"],
        "role_name": cfg["spoke_role_name"],
        "regions": cfg["approved_regions"],
        "concurrency": args.concurrency,
        "options": options,
        "input": {"file": pathlib.Path(args.accounts).name,
                  "sha256": hashlib.sha256(pathlib.Path(args.accounts).read_bytes()).hexdigest(),
                  "list_problems": problems},  # fmt: skip
        "accounts": rows,
        "throttle_events": throttle.events,
    }
    fleet.write_json(out / "batch-manifest.json", batch_manifest)
    fleet.write_json(out / "fleet-rollup.json", roll)
    (out / "fleet-limitations.md").write_text(limitations_text(roll, len(accounts)),
                                              encoding="utf-8", newline="\n")  # fmt: skip
    flat = [{**r, "reasons": "; ".join(r.get("reasons") or []),
             "datasets_by_status": json.dumps(r.get("datasets_by_status") or {}, sort_keys=True),
             "regions_succeeded": " ".join(r.get("regions_succeeded") or []),
             "regions_not_enabled": " ".join(r.get("regions_not_enabled") or [])}
            for r in rows]  # fmt: skip
    fleet.write_csv(out / "accounts-result.csv", flat, RESULT_FIELDS)
    print(f"\nVerdicts: {roll['verdicts']}")
    if stop.is_set():
        print("The hub sign-in expired. Sign in again, then rerun with --retry-failed; finished "
              "accounts are kept and interrupted ones resume.")  # fmt: skip
    print(f"Results: {out}")
    return 0 if roll["verdicts"].get("READY", 0) == len(accounts) else 1


if __name__ == "__main__":
    sys.exit(main())
