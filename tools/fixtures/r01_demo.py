"""R0.1 synthetic source-format demonstration, including CloudTrail shadows."""

import argparse
import json
from pathlib import Path

from offline_analyzer.cli import summary
from offline_analyzer.contracts.r0 import Package
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.safety import sha256_file
from offline_analyzer.reporting.excel import export_excel
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store
from offline_analyzer.verification import verify_package
from tools.fixtures.demo import TIME, A, build_package


def build_source_format_package(directory: Path) -> Package:
    """All contents synthetic; structure follows cited public API/emitter contracts."""
    package = build_package(directory)
    sources = []
    for source in package.sources:
        if source.path:
            path = directory / source.path
            body = json.loads(path.read_text())
            if source.operation == "ec2:DescribeInstances":
                for reservation in body["Reservations"]:
                    reservation["OwnerId"] = source.account_id
                    reservation["ReservationId"] = "r-0123456789abcdef0"
            elif source.operation == "cloudtrail:DescribeTrails":
                for trail in body["trailList"]:
                    trail.update(
                        IsOrganizationTrail=True,
                        IsMultiRegionTrail=True,
                        Name="synthetic-organization-trail",
                    )
            if source.format == "aws-json-v1":
                body["ResponseMetadata"] = {"HTTPStatusCode": 200, "RequestId": "synthetic-request"}
            else:
                for index, row in enumerate(body):
                    # The deliberately duplicated result keeps the same finding UID.
                    row["finding_info"]["uid"] = "synthetic-finding-" + str(max(1, index))
                    row["finding_info"]["created_time_dt"] = TIME
                    row["metadata"].update(version="1.3.0", profiles=["cloud", "datetime"])
                    row["message"] = "Synthetic source-format observation"
                    for resource in row["resources"]:
                        resource["data"] = {
                            "details": "synthetic metadata",
                            "metadata": {"encrypted": False},
                        }
            path.write_text(json.dumps(body, indent=2))
            source = source.model_copy(update={"sha256": sha256_file(path)})
        sources.append(source)
    home = next(s for s in sources if s.operation == "cloudtrail:DescribeTrails")
    shadow_path = directory / "organization-shadow.json"
    shadow_path.write_bytes((directory / home.path).read_bytes())
    sources.append(
        home.model_copy(
            update={
                "path": shadow_path.name,
                "sha256": sha256_file(shadow_path),
                "account_id": A,
                "region": "us-east-1",
                "request_parameters": {"includeShadowTrails": True},
            }
        )
    )
    package = package.model_copy(update={"sources": tuple(sources)})
    (directory / "manifest.json").write_text(package.model_dump_json(indent=2))
    return package


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    build_source_format_package(args.output / "input")
    diagnostics = verify_package(args.output / "input")
    assert all(s["parser_accepted"] for s in diagnostics["sources"])
    (args.output / "compatibility.json").write_text(json.dumps(diagnostics, indent=2))
    with Store(args.output / "workspace") as store:
        run = import_package(store, args.output / "input")
        assess(store, run)
        assert import_package(store, args.output / "input") == run
        assess(store, run)
        report = args.output / "R0.1-synthetic-assessment.xlsx"
        export_excel(store, run, report)
        print(
            json.dumps(
                {
                    **summary(store, run),
                    "excel_output": str(report.resolve()),
                    "evidence_origin": "SYNTHETIC_SOURCE_FORMAT_FIXTURES",
                    "actual_tool_generated_evidence_tested": False,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
