"""Customer-local bounded pilot preflight and optional existing assessment pipeline.

No AWS connection, report approval or customer upload. The compatibility JSON contains
only counts, registered parser diagnostics, operation identifiers and fixed error codes.
Private workbook and collection requests stay in the operator-specified output directory.
"""

import argparse
import json
import tempfile
import time
from collections import Counter
from pathlib import Path

from openpyxl import load_workbook

from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.ingestion.archive import unpack_package
from offline_analyzer.ingestion.collector import (
    has_collector_manifest,
    inspect_collector,
    sanitized,
)
from offline_analyzer.ingestion.collector_v030 import probe, verify_checksums
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.environment import (
    enterprise_origin,
    record_run_origin,
    set_environment,
)
from offline_analyzer.release_audit import audit
from offline_analyzer.reporting.collection import collection_readiness
from offline_analyzer.reporting.excel import export_excel
from offline_analyzer.storage.store import Store
from offline_analyzer.verification import verify_package


def execute(root: Path, workspace: Path, output: Path, origin: str) -> dict:
    set_environment(workspace, "SYNTHETIC" if origin == "synthetic" else "ASSESSMENT")
    timings = {}
    with Store(workspace) as store:
        started = time.perf_counter()
        imported = import_package(store, root)
        record_run_origin(workspace, imported, origin)
        timings["import_seconds"] = time.perf_counter() - started
        started = time.perf_counter()
        combined_origin = enterprise_origin(store, None)
        run = assess_enterprise(store)
        record_run_origin(workspace, run, combined_origin)
        timings["assessment_correlation_seconds"] = time.perf_counter() - started
        counts = {
            "resources": store.db.execute(
                "SELECT count(DISTINCT resource_id) FROM observations WHERE run_id=?", [run]
            ).fetchone()[0],
            "evaluations": store.db.execute(
                "SELECT count(*) FROM evaluations WHERE run_id=?", [run]
            ).fetchone()[0],
            "candidate_findings": store.db.execute(
                "SELECT count(*) FROM findings WHERE run_id=?", [run]
            ).fetchone()[0],
            "relationships": store.db.execute(
                "SELECT count(*) FROM enterprise_edges WHERE run_id=?", [run]
            ).fetchone()[0],
        }
        outcomes = dict(sorted(Counter(str(r.outcome) for r in store.results(run)).items()))
        readiness = collection_readiness(store, run)
        (output / "CloSec-evidence-requests.private.json").write_text(
            json.dumps(
                {
                    "schema": "closec-evidence-request-1",
                    "run_id": run,
                    "requests": readiness["evidence_requests"],
                    "manual_validation": readiness["manual_validation"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        # A bounded private queue is a review aid, never automatic confirmation.
        candidates = sorted(
            store.candidates(run),
            key=lambda c: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                    str(c.suggested_severity), 4
                ),
                c.finding_id,
            ),
        )
        (output / "CloSec-review-queue.private.json").write_text(
            json.dumps(
                {
                    "run_id": run,
                    "classification": "CANDIDATES_REQUIRE_ANALYST_VERIFICATION",
                    "candidate_count": len(candidates),
                    "findings": [c.model_dump(mode="json") for c in candidates[:100]],
                    "evaluation_samples": [
                        r.model_dump(mode="json")
                        for outcome in ("FAIL", "PASS", "UNKNOWN", "COLLECTION_ERROR")
                        for r in list(r for r in store.results(run) if str(r.outcome) == outcome)[
                            :5
                        ]
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        started = time.perf_counter()
        workbook_path = output / "CloSec-enterprise.private.xlsx"
        export_excel(store, run, workbook_path)
        timings["excel_seconds"] = time.perf_counter() - started
        with workbook_path.open("rb") as stream:
            workbook = load_workbook(stream, read_only=True)
            rows = {
                name: sum(1 for _ in workbook[name].rows) - 3
                for name in (
                    "Findings Register",
                    "Control Assessment",
                    "Cross-Account Relationships",
                )
            }
            workbook.close()
        reconciled = rows == {
            "Findings Register": counts["candidate_findings"],
            "Control Assessment": counts["evaluations"],
            "Cross-Account Relationships": counts["relationships"],
        }
        gaps = Counter(r["operation"] for r in readiness["evidence_requests"] if r.get("operation"))
    audit_result = audit(workspace, run)
    return {
        "counts": counts,
        "evaluation_outcomes": outcomes,
        "timings": timings,
        "evidence_gap_operations": dict(sorted(gaps.items())),
        "excel_reconciled": reconciled,
        "excel_row_counts": rows,
        "release_audit": {
            "result": audit_result["result"],
            "invariant_violations": audit_result["invariant_violations"],
        },
        "analyst_acceptance": "NOT_ESTABLISHED",
        "approvals_created": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package", type=Path, required=True, help="Original directory or ZIP; never modified"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="New private local output directory"
    )
    parser.add_argument("--origin", required=True, choices=["synthetic", "tool-generated"])
    parser.add_argument("--expected-attempts", type=int)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Import, assess enterprise, export Excel; no analyst approvals",
    )
    parser.add_argument("--workspace", type=Path)
    args = parser.parse_args(argv)
    if args.execute and not args.workspace:
        parser.error("--execute requires --workspace")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    result = {
        "schema": "closec-pilot-compatibility-1",
        "declared_origin": args.origin,
        "raw_values_included": False,
        "sharing_status": "LOCAL_ONLY_REQUIRES_HUMAN_APPROVAL",
        "result": "INCOMPLETE",
        "real_export_validation": "NOT_ESTABLISHED",
    }
    code = 2
    try:
        with tempfile.TemporaryDirectory() as temporary:
            root = (
                unpack_package(args.package, Path(temporary))
                if args.package.is_file()
                else args.package
            )
            if (root / "operations.jsonl").is_file():
                verify_checksums(root)
                result["transport_integrity"] = "PASS"
                result["index_probe"] = probe(root)
                if (
                    args.expected_attempts is not None
                    and result["index_probe"]["attempts"] != args.expected_attempts
                ):
                    raise InputError("COLLECTION_ATTEMPT_COUNT_MISMATCH")
            if has_collector_manifest(root):
                _, summary = inspect_collector(root)
                result["collector_package"] = sanitized(summary)
            verification = verify_package(root, origin=args.origin)
            result["verification"] = verification
            result["real_export_validation"] = verification["real_export_validation"]
            if not all(s["parser_accepted"] for s in verification["sources"]):
                raise InputError("SUPPORTED_SOURCE_PARSER_REJECTED")
            result["result"] = "PREFLIGHT_PASS"
            code = 0
            if args.execute:
                result["assessment"] = execute(root, args.workspace, args.output, args.origin)
                if (
                    not result["assessment"]["excel_reconciled"]
                    or result["assessment"]["release_audit"]["result"] != "PASS"
                ):
                    raise InputError("PILOT_RECONCILIATION_OR_AUDIT_FAILED")
                result["result"] = "PIPELINE_PASS_REQUIRES_ANALYST_ACCEPTANCE"
    except (OSError, ValueError, RuntimeError) as exc:
        # Imported paths, validation values and DB details must never enter a shareable report.
        result["error_category"] = (
            str(exc) if isinstance(exc, InputError) else "LOCAL_EXECUTION_OR_PROFILE_ERROR"
        )
        result["result"], code = "INCOMPLETE", 2
    (args.output / "CloSec-pilot-compatibility.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "result": result["result"],
                "error_category": result.get("error_category"),
                "raw_values_included": False,
            }
        )
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
