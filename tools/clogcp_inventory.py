"""Generate the public criterion inventory and dataset mapping; no client data."""

import csv
import json
from pathlib import Path

from offline_analyzer.findings.clogcp_reconcile import History
from offline_analyzer.reporting.clogcp_assurance import coverage_matrix
from offline_analyzer.rules.gcp_domains import SPECS
from offline_analyzer.rules.registry import PROVIDER_RULES


def main() -> None:
    out = Path("docs/clogcp")
    out.mkdir(parents=True, exist_ok=True)
    rules = [r for r in PROVIDER_RULES if r.provider == "GCP"]
    inventory = [
        {
            "rule_id": r.rule_id,
            "version": r.version,
            "domain": r.domain,
            "title": r.title,
            "resource_type": r.resource_type,
            "operation": r.operation,
            "new_in_clogcp": r.rule_id in SPECS,
            "qualification": (
                "Named criterion only; outcome, evidence limits and review remain authoritative."
            ),
        }
        for r in rules
    ]
    for name, rows in [("RULE_INVENTORY", inventory), ("DATASET_RULE_MATRIX", coverage_matrix())]:
        (out / (name + ".json")).write_text(json.dumps(rows, indent=2) + "\n")
        with (out / (name + ".csv")).open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            for row in rows:
                writer.writerow(
                    {
                        k: json.dumps(v, sort_keys=True) if isinstance(v, dict) else v
                        for k, v in row.items()
                    }
                )
    (out / "HISTORY_SCHEMA.json").write_text(
        json.dumps(History.model_json_schema(), indent=2) + "\n"
    )
    print(f"Generated {len(rules)} criteria and {len(coverage_matrix())} dataset-family rows.")


if __name__ == "__main__":
    main()
