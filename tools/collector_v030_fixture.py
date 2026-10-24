"""Generate a SYNTHETIC v0.3.0 field-profile fixture; never proof of real compatibility."""

import argparse
import json
import shutil
from pathlib import Path

from offline_analyzer.ingestion.safety import sha256_file


def checksums(directory: Path) -> None:
    paths = sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "checksums.sha256")
    (directory / "checksums.sha256").write_text(
        "".join(f"{sha256_file(p)}  {p.relative_to(directory).as_posix()}\n" for p in paths),
        encoding="utf-8",
    )


def convert(source: Path, destination: Path) -> Path:
    metadata = json.loads((source / "collector-manifest.json").read_text())
    destination.mkdir(parents=True, exist_ok=False)
    rows = []
    for original in metadata["operations"]:
        row = dict(original)
        row["status"] = {
            "SUCCEEDED": "COMPLETE",
            "FAILED": "API_ERROR",
            "SKIPPED": "NOT_COLLECTED",
        }[row["status"]]
        if row.get("pagination") == "TRUNCATED":
            row["status"] = "PARTIAL"
        if row.get("path"):
            target = destination / row["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / row["path"], target)
        rows.append(row)
    (destination / "manifest.json").write_text(
        json.dumps(
            {
                "collector_version": "0.3.0",
                "collection_id": "synthetic-v030-" + metadata["account_id"],
                "account_id": metadata["account_id"],
                "dataset_origin": "SYNTHETIC",
                "assessment_id": "SYNTHETIC",
                "regions": metadata["regions"],
                "started_at": metadata["started_at"],
                "completed_at": metadata["completed_at"],
            }
        ),
        encoding="utf-8",
    )
    (destination / "operations.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
    )
    for name in ("collection-summary.json", "retry-requests.json"):
        (destination / name).write_text("{}", encoding="utf-8")
    scanners = destination / "scanners/prowler/synthetic"
    scanners.mkdir(parents=True)
    (scanners / "execution.log").write_text("Synthetic partial scanner execution only\n")
    (scanners / "observations.csv").write_text("synthetic,not imported\n")
    checksums(destination)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    convert(args.source, args.output)


if __name__ == "__main__":
    main()
