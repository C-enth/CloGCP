"""Generate the reviewed collector inventory and concise documentation, not evidence."""

import argparse
import json
from pathlib import Path

from offline_analyzer.contracts.gcp_expanded import ExpandedManifest
from offline_analyzer.contracts.gcp_expanded_catalog import COLLECTOR_SHA256, DATASETS, VERSION
from offline_analyzer.rules.gcp import GCP_RULES


def inventory() -> dict:
    rows = []
    for definition in DATASETS:
        row = dict(definition)
        kinds = {row["resource_type"]}
        if row["resource_type"] == "GCP::IAMPolicy":
            kinds.add("GCP::IAMBinding")
        row["rule_consumers"] = [rule.rule_id for rule in GCP_RULES if rule.resource_type in kinds]
        rows.append(row)
    return {
        "schema_version": VERSION,
        "collector_sha256": COLLECTOR_SHA256,
        "definitions": rows,
        "manifest_schema": ExpandedManifest.model_json_schema(),
    }


def markdown() -> str:
    lines = [
        "# GCP collector contract",
        "",
        "Generated from `contracts/gcp_expanded_catalog.py`; "
        f"collector SHA256 `{COLLECTOR_SHA256}`.",
        "",
        (
            "115 definitions: 90 fixed, 25 bounded dynamic families. The "
            "supplied collector is unchanged."
        ),
        (
            "Supported versions: `closec-gcp-1`, `pilot-1.2.2`, `pilot-1."
            "5`, `assessment-expanded-2.1`."
        ),
        (
            "Unknown versions remain rejected. ZIP and browser-folder imp"
            "orts share the same adapter."
        ),
        "",
        (
            "The table describes implementation support, not field accept"
            "ance. Expanded 2.1 actual exports"
        ),
        (
            "and real AWS packages remain unverified. Native observations"
            " retain original locators/hashes."
        ),
        ("Cloud Asset search/list snapshots remain distinct from detailed service configurations."),
        "",
        "## Transport and collection semantics",
        "",
        (
            "gcloud lists are arrays; describes and IAM policies are obje"
            "cts. REST outputs are flattened"
        ),
        "arrays, including singleton GETs. Aggregated Compute items contain explicit scope maps.",
        (
            "Transport counts are checked before normalization; IAM bindi"
            "ng expansion and nested scopes"
        ),
        "can yield different observation counts. Malformed and unexpected shapes fail explicitly.",
        (
            "Indexed child names never identify a parent: canonical names"
            " or recorded read-only context do."
        ),
        (
            "Zero collector page/detail limits mean unlimited collection;"
            " analyzer bounds still apply."
        ),
        "",
        (
            "SUCCESS/EMPTY retain partial provenance: the collector decla"
            "res no source hashes or provable"
        ),
        "pagination completeness. EMPTY REST output cannot prove the source array field existed.",
        "TRUNCATED retains partial observations and blocks positive conclusions from that source.",
        "FAILED, API_DISABLED, ACCESS_DENIED, COMMAND_ERROR, AUTH_ERROR, RATE_LIMITED, NOT_FOUND,",
        (
            "HTTP_ERROR and SERVER_ERROR preserve failure metadata; faile"
            "d output is never configuration."
        ),
        "API_DISABLED and ACCESS_DENIED never establish absence or a control PASS.",
        "",
        "## Dataset support",
        "",
        (
            "All listed families are recognized and normalize typed metad"
            "ata when their shape/identity is valid."
        ),
        (
            "`NOT_EVALUATED` means no existing rule consumes that resourc"
            "e type. Evidence and coverage are"
        ),
        (
            "displayed/reportable; this does not imply a finding or repor"
            "t approval. Unknown families are"
        ),
        (
            "retained as unsupported observations. Read permission requir"
            "ements must be reviewed for the"
        ),
        (
            "recorded source operation; exact permission mappings are not"
            " inferred from command success."
        ),
        "",
        "| Domain | Dataset / bounded pattern | Source | Resource type | Rule consumers |",
        "|---|---|---|---|---|",
    ]
    for row in inventory()["definitions"]:
        source = row["source_expression"].replace("|", "&#124;").replace("`", "")
        lines.append(
            f"| {row['domain']} | `{row['pattern']}` | {source} | {row['resource_type']} | "
            f"{', '.join(row['rule_consumers']) or 'NOT_EVALUATED'} |"
        )
    lines.extend(
        [
            "",
            "## Application consumers and limitations",
            "",
            (
                "Each definition exposes `COLLECTED → RECOGNIZED → NORMALIZED"
                " → EVALUATED → DISPLAYED → REPORTABLE`"
            ),
            (
                "states in the machine-readable inventory. Account Explorer u"
                "ses project scope; IAM Intelligence"
            ),
            (
                "shows observed identities/policies and qualified structural "
                "relationships. Evidence Explorer"
            ),
            (
                "retains unsupported observations and collection outcomes. Ne"
                "twork Analysis shows only collected"
            ),
            "network metadata; missing datasets and unsupported controls are coverage limitations.",
            "Dashboard coverage denominators are declared operations "
            "and actual persisted evaluations,",
            (
                "never inferred cloud-resource totals or a security score. Re"
                "ports use the selected run."
            ),
            "",
            "## Collector reliability review",
            "",
            "The 2.1 script had an unbounded gcloud WaitForExit(), no pagination-token cycle "
            "guard,",
            "no source integrity hashes, and could turn a missing REST array field into EMPTY.",
            "Collector 2.2.0 (`collectors/gcp/`, schema `assessment-expanded-2.2`) bounds "
            "commands,",
            "retries REST calls, guards pagination, records UNEXPECTED_SCHEMA/PARTIAL/TIMEOUT/",
            "QUOTA_PROJECT_DENIED/UNSUPPORTED_ENDPOINT gaps and writes verified checksums. "
            "2.1 packages",
            "remain accepted with their limitations; the analyzer cannot recover uncollected "
            "records.",
            "",
            (
                "Regenerate: `PYTHONPATH=src python -m tools.gcp_collector_co"
                "ntract --doc docs/GCP_COLLECTOR_CONTRACT.md`."
            ),
            (
                "Machine inventory: add `--json <local-output.json>`; tests i"
                "mport the same authoritative definitions."
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--doc", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.doc:
        args.doc.write_text(markdown(), encoding="utf-8")
    if args.json:
        args.json.write_text(json.dumps(inventory(), indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
