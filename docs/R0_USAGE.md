# CloSec offline CLI

The CLI uses the same importer, rules, DuckDB and reports as the GUI. No cloud calls
are performed. Obtain current command options with python -m offline_analyzer --help.
Windows CloSec.exe dispatches these commands through its cli subcommand.

## Local evidence-to-findings workflow

Use approved evidence outside the repository. Set the workspace environment once;
ASSESSMENT rejects explicitly synthetic packages. Keep the actual returned run ID:

```sh
.venv/bin/python -m offline_analyzer --workspace /approved/workspace environment set --label assessment
.venv/bin/python -m offline_analyzer --workspace /approved/workspace import /approved/evidence/package
.venv/bin/python -m offline_analyzer --workspace /approved/workspace assess --run RETURNED_RUN_ID
.venv/bin/python -m offline_analyzer --workspace /approved/workspace summary --run RETURNED_RUN_ID
.venv/bin/python -m offline_analyzer --workspace /approved/workspace export --run RETURNED_RUN_ID --output /approved/reports/new-assessment.xlsx
```

Package folders and bounded ZIPs are supported. r0.1, closec-collector-1 and
closec-gcp-1 contracts retain source identity, scope, UTC time, SHA-256, operation,
coverage/status and limitations. Guided source import requires explicit source operation
and scope; it is partial/unverified. Generate public schemas with:

```sh
.venv/bin/python -m offline_analyzer.contracts.schema artifacts/schemas-new
```

Use the registered profiles shown by the contracts, rather than inventing an operation.
See collectors/collector-analyzer-contract.json, GCP_USAGE.md and EVIDENCE_SCHEMA.md. Unknown or denied
sources cannot yield PASS. Complete empty inventories are NOT_APPLICABLE, not secure
scope claims. Native configuration determines candidates; scanner observations remain
supplementary. No source is automatically confirmed or approved for customer reporting.

## Deterministic development exercise

There is no committed assessment evidence. Generate the historical AWS scenario and
its report in a new ignored directory from trusted development tooling:

```sh
PYTHONPATH=src .venv/bin/python -m tools.fixtures.r12_demo --output artifacts/aws-demo-new
PYTHONPATH=src .venv/bin/python -m tools.multicloud_scale --help
```

Tests generate in pytest temporary directories; generated evidence, registries, DBs,
reports and logs are never tracked. Synthetic packages come from tools/fixtures. These exercise the real importer/rules; they do not prove
actual-export compatibility, exploitation or Windows execution.

## Review, persistence and export

Use review --help for explicit finding CONFIRMED/REJECTED/NEEDS_VALIDATION/EXCEPTION
updates. Decisions bind to evidence and rule versions and survive reimport; changed
evidence requires revalidation. Recommendation/narrative approvals and report inclusion
are separate shared services exposed by the Findings Workbench. Only approved current
revisions enter client-ready RTF/text; comprehensive Excel also lists candidates/gaps.
See REPORT_FINDINGS_USAGE.md and REPORTING_ALIGNMENT.md.

One process owns the workspace writer. Finish the GUI before running CLI mutation,
backup or restore. Exports and generated output directories refuse overwrites. Keep
raw input unchanged; do not relabel or edit customer evidence to bypass integrity checks.
