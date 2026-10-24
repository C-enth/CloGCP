"""Synthetic R0 demonstration; never opens private customer material."""

import argparse
import json
from pathlib import Path

from offline_analyzer.cli import summary
from offline_analyzer.contracts.r0 import Package, Scope, Source
from offline_analyzer.ingestion.importer import import_package, single_file_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import sha256_file
from offline_analyzer.reporting.excel import export_excel
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store

TIME = "2026-10-09T08:00:00+00:00"
A, B = "111111111111", "222222222222"


def build_package(directory: Path) -> Package:
    directory.mkdir(parents=True, exist_ok=False)
    sources = []

    def add(name, data, operation, account, region, coverage="COMPLETE", format="aws-json-v1"):
        path = directory / name
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        sources.append(
            Source(
                path=name,
                sha256=sha256_file(path),
                format=format,
                operation=operation,
                account_id=account,
                region=region,
                collected_at=TIME,
                coverage=coverage,
                collector_version="synthetic-r0",
                request_parameters={} if format == "aws-json-v1" else None,
            )
        )

    for account, tokens in [(A, "required"), (B, "optional")]:
        region = "us-east-1" if account == A else "eu-west-1"
        instance = dict(
            InstanceId="i-0000000000000000" + ("1" if account == A else "2"),
            State={"Name": "running"},
            MetadataOptions={"HttpTokens": tokens, "HttpEndpoint": "enabled", "State": "applied"},
            Tags=[{"Key": "Name", "Value": '=HYPERLINK("https://invalid.example")'}],
        )
        # Duplicate resource: two raw occurrences, one canonical observation.
        add(
            f"ec2-{account}.json",
            {"Reservations": [{"Instances": [instance, instance] if account == B else [instance]}]},
            "ec2:DescribeInstances",
            account,
            region,
        )
        db = {
            "DBInstanceArn": f"arn:aws:rds:{region}:{account}:db:synthetic-db",
            "DBInstanceIdentifier": "synthetic-db",
            "Engine": "postgres",
            "StorageEncrypted": account == A,
        }
        add(
            f"rds-{account}.json", {"DBInstances": [db]}, "rds:DescribeDBInstances", account, region
        )
    add(
        "trails.json",
        {
            "trailList": [
                {
                    "TrailARN": f"arn:aws:cloudtrail:eu-west-1:{B}:trail/synthetic",
                    "HomeRegion": "eu-west-1",
                    "LogFileValidationEnabled": False,
                }
            ]
        },
        "cloudtrail:DescribeTrails",
        B,
        "eu-west-1",
    )
    add(
        "incomplete.json",
        {"Reservations": [], "NextToken": "synthetic-page-2"},
        "ec2:DescribeInstances",
        B,
        "ap-south-1",
    )
    sources.append(
        Source(
            format="aws-json-v1",
            operation="rds:DescribeDBInstances",
            account_id=B,
            region="ap-south-1",
            collected_at=TIME,
            coverage="ERROR",
            errors=("AccessDenied",),
        )
    )
    scanner = {
        "class_uid": 2004,
        "time_dt": TIME,
        "status_code": "PASS",
        "status_id": 1,
        "status": "New",
        "finding_info": {"uid": "synthetic-finding-001", "desc": "Synthetic source-format fixture"},
        "severity": "High",
        "status_detail": "=MALICIOUS_DISPLAY_STRING",
        "metadata": {
            "event_code": "rds_instance_storage_encrypted",
            "product": {"name": "Prowler", "version": "5.10.0"},
        },
        "cloud": {"provider": "aws", "account": {"uid": B}, "region": "eu-west-1"},
        "resources": [
            {
                "uid": f"arn:aws:rds:eu-west-1:{B}:db:synthetic-db",
                "region": "eu-west-1",
                "type": "AwsRdsDbInstance",
                "cloud_partition": "aws",
            }
        ],
        "unrecognized_extension": {"retained": "synthetic raw detail"},
    }
    insufficient = json.loads(json.dumps(scanner))
    insufficient["cloud"]["account"]["uid"] = A
    insufficient["cloud"]["region"] = "us-east-1"
    insufficient["resources"] = [
        {
            "uid": f"arn:aws:rds:us-east-1:{A}:db:scanner-only",
            "region": "us-east-1",
            "type": "AwsRdsDbInstance",
            "cloud_partition": "aws",
        }
    ]
    unsupported = json.loads(json.dumps(insufficient))
    unsupported["metadata"]["event_code"] = "synthetic_unsupported_check"
    unsupported["resources"][0]["uid"] = None
    add(
        "prowler.json",
        [scanner, scanner, insufficient, unsupported],
        "prowler:Scan",
        None,
        None,
        coverage="PARTIAL",
        format="prowler-ocsf-5.10",
    )
    package = Package(
        targets=(
            Scope(account_id=A, region="us-east-1"),
            Scope(account_id=B, region="eu-west-1"),
            Scope(account_id=B, region="ap-south-1"),
        ),
        sources=tuple(sources),
    )
    (directory / "manifest.json").write_text(package.model_dump_json(indent=2), encoding="utf-8")
    return package


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New output directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    build_package(args.output / "input")
    with Store(args.output / "workspace") as store:
        run = import_package(store, args.output / "input")
        assess(store, run)
        assert import_package(store, args.output / "input") == run
        assess(store, run)
        malicious = args.output / "malformed.json"
        malicious.write_text('{"Reservations": [], "Reservations": []}')
        invalid = single_file_package(
            malicious,
            format="aws-json-v1",
            operation="ec2:DescribeInstances",
            account_id=A,
            region="us-east-1",
            collected_at=TIME,
        )
        try:
            import_package(store, malicious.parent, invalid)
        except InputError as exc:
            assert str(exc) == "DUPLICATE_JSON_KEY"
        else:
            raise AssertionError("Malformed input was accepted")
        report = args.output / "R0-assessment.xlsx"
        export_excel(store, run, report)
        print(
            json.dumps(
                {
                    **summary(store, run),
                    "rejected_malformed_inputs": 1,
                    "excel_output": str(report.resolve()),
                    "compatibility": (
                        "synthetic-tested; actual Prowler/AWS export validation pending"
                    ),
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
