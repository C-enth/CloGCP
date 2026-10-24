"""Synthetic collector-style packages (closec-collector-1) from an existing r0.1 package.

Test/demo tooling only: output is SYNTHETIC and never counts as real-export compatibility.
Splits the source package per account, as the boto3 collector writes one package per
account/run, and optionally adds failed, truncated and unsupported operation records.
"""

import argparse
import json
import shutil
from pathlib import Path

from offline_analyzer.ingestion.safety import sha256_file


def convert(source: Path, output: Path, extras: bool = True) -> list[Path]:
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    accounts: dict[str, list[dict]] = {}
    for item in manifest["sources"]:
        accounts.setdefault(item["account_id"], []).append(item)
    packages = []
    for account, items in sorted(accounts.items()):
        target = output / f"collector-{account}"
        target.mkdir(parents=True)
        operations = []
        for item in items:
            record = {
                "operation": item["operation"],
                "region": item["region"] or "global",
                "format": item["format"],
                "started_at": item["collected_at"],
                "completed_at": item["collected_at"],
                "request_parameters": item.get("request_parameters") or {},
            }
            if item["path"]:
                name = f"responses/{len(operations):04d}.json"
                (target / "responses").mkdir(exist_ok=True)
                shutil.copyfile(source / item["path"], target / name)
                record.update(path=name, sha256=sha256_file(target / name))
            coverage = item["coverage"]
            if coverage in {"COMPLETE", "PARTIAL"}:
                record.update(
                    status="SUCCEEDED",
                    pages=1,
                    pagination="TRUNCATED" if coverage == "PARTIAL" else "ALL_PAGES_MERGED",
                )
            elif coverage == "ERROR":
                record.update(status="FAILED", error_code=item["errors"][0])
            else:
                record.update(status="SKIPPED")
            if item["format"] != "aws-json-v1":
                record.pop("request_parameters")
                record["tool_version"] = "5.10.0"
            operations.append(record)
        stamp = min(o["started_at"] for o in operations)
        if extras and account == sorted(accounts)[0]:
            (target / "responses").mkdir(exist_ok=True)
            unsupported = target / "responses/unsupported-securityhub.json"
            unsupported.write_text(json.dumps({"Findings": []}))
            operations.append(
                {
                    "operation": "securityhub:GetFindings",
                    "region": "us-east-1",
                    "status": "SUCCEEDED",
                    "path": "responses/unsupported-securityhub.json",
                    "sha256": sha256_file(unsupported),
                    "started_at": stamp,
                    "completed_at": stamp,
                    "pages": 1,
                    "pagination": "ALL_PAGES_MERGED",
                }
            )
            operations.append(
                {
                    "operation": "cloudtrail:DescribeTrails",
                    "region": "us-east-1",
                    "status": "FAILED",
                    "error_code": "AccessDenied",
                    "started_at": stamp,
                    "completed_at": stamp,
                }
            )
        (target / "collector-manifest.json").write_text(
            json.dumps(
                {
                    "schema": "closec-collector-1",
                    "package_id": f"synthetic-{account}",
                    "collector": {"name": "synthetic-collector-fixture", "version": "1.0.0"},
                    "account_id": account,
                    "partition": "aws",
                    "dataset_origin": "SYNTHETIC",
                    "started_at": stamp,
                    "completed_at": max(o["completed_at"] for o in operations),
                    "regions": sorted({o["region"] for o in operations}),
                    "operations": operations,
                },
                indent=1,
            ),
            encoding="utf-8",
        )
        packages.append(target)
    return packages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="r0.1 package directory")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for package in convert(args.source, args.output):
        print(package)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
