"""Generate the shared collector-to-analyzer contract and the coverage matrix.

Everything is derived from source registries: the AWS collector's operation registry
(parsed, never executed), the botocore-generated name table, the analyzer's parsers and
rule registry, and the GCP expanded dataset catalog. A test fails if the committed files
drift from this output. Lifecycle: COLLECTED -> RECOGNIZED -> NORMALIZED -> EVALUATED ->
DISPLAYED -> REPORTABLE. "Recognized" never implies coverage or a security conclusion.
"""

import argparse
import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWS_COLLECTOR = ROOT / "collectors/aws/assessment.py"
GCP_COLLECTOR = ROOT / "collectors/gcp/GCP_Security_Evidence_Collector.ps1"


def aws_registry() -> dict[str, list[tuple[str, str]]]:
    tree = ast.parse(AWS_COLLECTOR.read_text())
    values = {
        n.targets[0].id: ast.literal_eval(n.value)
        for n in tree.body
        if isinstance(n, ast.Assign)
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id in {"GLOBAL", "REGIONAL", "DEPENDENT", "VERSION"}
    }
    inline = [
        ("iam", "get_policy_version"),
        ("elbv2", "describe_listeners"),
        ("elbv2", "describe_rules"),
        ("ec2", "get_transit_gateway_route_table_associations"),
        ("ec2", "get_transit_gateway_route_table_propagations"),
        ("ec2", "search_transit_gateway_routes"),
        ("ecs", "describe_clusters"),
        ("eks", "describe_cluster"),
        ("dynamodb", "describe_table"),
        ("organizations", "list_policies_for_target"),
        ("organizations", "describe_policy"),
        ("organizations", "list_parents"),
    ]
    return {
        "version": values["VERSION"],
        "GLOBAL": [(s, o) for s, ops in values["GLOBAL"].items() for o in ops],
        "REGIONAL": [(s, o) for s, ops in values["REGIONAL"].items() for o in ops],
        "DEPENDENT": [(s, o) for s, ops in values["DEPENDENT"].items() for o in ops] + inline,
    }


def aws_contract() -> dict:
    from offline_analyzer.contracts.aws_operation_names import API_OPERATIONS, BOTOCORE_VERSION
    from offline_analyzer.contracts.r0 import AWS_OPERATIONS
    from offline_analyzer.ingestion.collector_v030_native import (
        OUTCOMES,
        PROFILE,
        SCHEMA,
        VERSIONS,
        canonical,
    )
    from offline_analyzer.rules.registry import ALL_RULES, rule_operations

    registry = aws_registry()
    rows = []
    for phase in ("GLOBAL", "REGIONAL", "DEPENDENT"):
        for service, method in registry[phase]:
            operation, recognized = canonical(service, method)
            rules = sorted(r.rule_id for r in ALL_RULES if operation in rule_operations(r))
            normalized = operation in AWS_OPERATIONS
            rows.append(
                {
                    "dataset": f"{service}.{method}",
                    "operation": operation,
                    "phase": phase,
                    "collected": True,
                    "recognized": recognized,
                    "normalized": normalized,
                    "evaluated_by": rules,
                    "displayed": "Evidence Explorer and Assessment Coverage"
                    if normalized
                    else "Collection summary (retained, unparsed)",
                    "reportable": "Findings and coverage sheets" if rules else "Coverage only",
                    "lifecycle": "EVALUATED"
                    if rules
                    else "NORMALIZED"
                    if normalized
                    else "RECOGNIZED_RETAINED_UNPARSED",
                }
            )
    return {
        "provider": "AWS",
        "collector": "collectors/aws/assessment.py",
        "collector_version": registry["version"],
        "manifest_schema": SCHEMA,
        "accepted_collector_versions": sorted(VERSIONS),
        "analyzer_adapter": PROFILE,
        "operation_names": f"botocore {BOTOCORE_VERSION} model table ({len(API_OPERATIONS)})",
        "journal": {
            "file": "operations.jsonl",
            "required_fields": [
                "account_id",
                "collection_id",
                "region",
                "service",
                "operation",
                "outcome",
                "started_at",
                "completed_at",
                "files",
            ],
            "outcomes": sorted(OUTCOMES),
            "outcome_mapping": {
                "COMPLETE": "SUCCEEDED; residual pagination token -> PARTIAL coverage",
                "PARTIAL": "SUCCEEDED with TRUNCATED pagination -> PARTIAL coverage",
                "NOT_ENABLED": "AWS-defined absence code -> derived absence evidence; "
                "otherwise FAILED (coverage ERROR)",
                "ACCESS_DENIED": "FAILED (coverage ERROR); never PASS",
                "API_ERROR": "FAILED (coverage ERROR); never PASS",
                "NOT_COLLECTED": "SKIPPED (coverage NOT_COLLECTED)",
            },
            "multi_page_responses": "merged into .closec-derived/ with source page SHA-256s",
        },
        "integrity": "checksums.sha256 must list every file; mismatch or omission fails closed",
        "datasets": rows,
    }


def gcp_contract() -> dict:
    from offline_analyzer.contracts.gcp_expanded_catalog import (
        DATASETS,
        EXTENSIONS_22,
        VERSION,
        VERSION_22,
    )
    from offline_analyzer.ingestion.gcp_legacy import ADAPTERS
    from offline_analyzer.rules.registry import GCP_RULES, rule_operations

    rows = []
    for row in DATASETS + EXTENSIONS_22:
        rules = sorted(r.rule_id for r in GCP_RULES if row["operation"] in rule_operations(r))
        rows.append(
            {
                "domain": row["domain"],
                "dataset_pattern": row["pattern"],
                "operation": row["operation"],
                "resource_type": row["resource_type"],
                "method": row["method"],
                "since_schema": VERSION_22 if row in EXTENSIONS_22 else VERSION,
                "analysis_support": row["analysis_support"],
                "evaluated_by": rules,
                "lifecycle": "EVALUATED"
                if rules
                else "NORMALIZED"
                if row["analysis_support"] != "UNSUPPORTED_PARSER"
                else "RECOGNIZED",
            }
        )
    return {
        "provider": "GCP",
        "collector": "collectors/gcp/GCP_Security_Evidence_Collector.ps1",
        "collector_version": "2.2.5",
        "accepted_manifest_schemas": sorted(
            name for name in ADAPTERS if name.startswith("assessment-expanded")
        ),
        "legacy_manifest_schemas": sorted(
            name for name in ADAPTERS if not name.startswith("assessment-expanded")
        ),
        "gap_statuses_never_pass": [
            "FAILED",
            "API_DISABLED",
            "ACCESS_DENIED",
            "QUOTA_PROJECT_DENIED",
            "COMMAND_ERROR",
            "AUTH_ERROR",
            "TIMEOUT",
            "RATE_LIMITED",
            "NOT_FOUND",
            "HTTP_ERROR",
            "SERVER_ERROR",
            "UNEXPECTED_SCHEMA",
            "INVALID_OUTPUT",
            "UNSUPPORTED_ENDPOINT",
        ],
        "partial_statuses": ["TRUNCATED", "PARTIAL"],
        "integrity": "2.2 requires checksums.sha256; 2.1 and pilot packages require an "
        "explicit acknowledgment that no source checksums exist",
        "datasets": rows,
    }


def contract() -> dict:
    return {
        "contract": "closec-collector-analyzer",
        "contract_version": "2.0.0",
        "lifecycle": [
            "COLLECTED",
            "RECOGNIZED",
            "NORMALIZED",
            "EVALUATED",
            "DISPLAYED",
            "REPORTABLE",
        ],
        "rule": "Missing, denied or failed evidence never yields PASS; recognition is not "
        "coverage; a scanner or SCC finding is never an approved vulnerability.",
        "providers": [aws_contract(), gcp_contract()],
    }


def matrix(data: dict) -> str:
    aws, gcp = data["providers"]
    lines = [
        "# Assessment coverage matrix (generated)",
        "",
        "Generated by `tools/collector_contract.py` from the collector registry, parsers and",
        "rules; do not edit by hand. A dataset is EVALUATED only when an executable rule",
        "consumes it. RECOGNIZED_RETAINED_UNPARSED datasets are verified and preserved, shown",
        "in collection coverage, and never evaluated or reported as compliant.",
        "",
        f"## AWS — collector {aws['collector_version']} ({aws['manifest_schema']})",
        "",
    ]
    counts: dict[str, int] = {}
    for row in aws["datasets"]:
        counts[row["lifecycle"]] = counts.get(row["lifecycle"], 0) + 1
    lines.append(
        "Summary: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + ".",
    )
    lines += ["", "| Dataset | Operation | Lifecycle | Evaluated by |", "|---|---|---|---|"]
    for row in aws["datasets"]:
        lines.append(
            f"| {row['dataset']} | {row['operation']} | {row['lifecycle']} | "
            f"{', '.join(row['evaluated_by']) or '—'} |"
        )
    lines += [
        "",
        f"## GCP — collector {gcp['collector_version']} "
        f"({', '.join(gcp['accepted_manifest_schemas'])})",
        "",
    ]
    counts = {}
    for row in gcp["datasets"]:
        counts[row["lifecycle"]] = counts.get(row["lifecycle"], 0) + 1
    lines.append("Summary: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + ".")
    lines += [
        "",
        "| Domain | Dataset | Operation | Lifecycle | Evaluated by |",
        "|---|---|---|---|---|",
    ]
    for row in gcp["datasets"]:
        lines.append(
            f"| {row['domain']} | `{row['dataset_pattern']}` | {row['operation']} | "
            f"{row['lifecycle']} | {', '.join(row['evaluated_by']) or '—'} |"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if committed files drift")
    args = parser.parse_args()
    data = contract()
    outputs = {
        ROOT / "collectors/collector-analyzer-contract.json": json.dumps(data, indent=2) + "\n",
        ROOT / "docs/ASSESSMENT_COVERAGE.md": matrix(data),
    }
    for path, text in outputs.items():
        if args.check:
            if not path.is_file() or path.read_text() != text:
                raise SystemExit(f"{path.relative_to(ROOT)} is stale; regenerate it")
        else:
            path.write_text(text)
    print("contract and coverage matrix " + ("verified" if args.check else "written"))


if __name__ == "__main__":
    main()
