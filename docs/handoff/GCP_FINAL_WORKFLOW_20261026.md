# CloGCP final workflow handoff — 2026-10-26

Branch: `feature/offline-security-analyzer`. No commits, pushes or history changes.
Prior edits were retained. Customer material was not uploaded or included in releases.

Implemented: verified side-by-side recovery and non-migrating app preflight; independent
stored-evidence **Recalculate Attack Paths** with immutable versions/comparison; a separate
approved-scope multi-project delta collector; immutable native delta import; reference-based
versioned evidence composition with timestamps, precedence/conflicts, reconciliation and
new-run-only broader IAM evaluation; independent finalizer with the approved 40-column
schema, focused evidence, deterministic domain guidance, preserved ratings/reviews/source
records, conservative consolidation and separate Assessor QA / Exceptions register.

Operating instructions: `docs/GCP_FINAL_WORKFLOW.md`. Delivery index and verification report
are under ignored `artifacts/CloGCP-final-delivery-20261026/`. Extract updated application
beside the old release. Use its verified copy tool before changing a working workspace.
No opening/recalculation requires rebuilding prior enterprise assessments or reimporting
existing evidence. Import supplementary evidence first, then create a new analysis version.
Shared IAM context currently requires existing security evaluators in that new version;
the frozen baseline and completed evidence-bound reviews remain intact.

Final application package:
`delivery-application/CloSec-0.8.4-update-20261026-sprint-9baf32112ca5-portable-source.zip`
SHA-256: `af4ae2e5cf6b028fe6b57dc4f33a7114022b38fef10db3c50da68585c4895dea`.
It truthfully retains application version 0.8.4 and identifies the updated candidate by
source snapshot/build; attack-path engine version is 2.0.1. It is a source candidate,
not a native Windows executable.

Separate collector:
`delivery-collector/clogcp-delta-1.0.0rc1-source.zip`
SHA-256: `083df8d7c8efcacf6227e82807604796f22efa49c021ae0c65601baf976c5003`.

Separate finalizer:
`delivery-finalizer/clogcp-report-finalizer-1.0.0rc1-source.zip`
SHA-256: `7e2a70ca63567d9e852ceb8eeb49c4dfa9d4b9b4e50024b7cf4f13a00b1e4da7`.
Each standalone package contains its own source, hashed offline dependency subsets,
verification script, launchers and instructions. `CLOGCP_PYTHON` can select the existing
compatible CloGCP Python; the finalizer requires no analyzer reinstall/backend/database.

Actual validation: selected regression 200 passed; final focused run 66 passed; additional
fault/retry and legacy-scope inventory tests passed; final export/finalizer/methodology checks 16 passed; new and
existing GUI workflows 2 passed, then final exact-source browser acceptance 1 passed; extracted application engine/workflow checks 45 passed;
Vitest 5 passed, TypeScript/build/lint/schema/dependency checks passed. The expanded export/register regression passed 81 tests. See TEST_PLAN.md for
scope, timings, corrected earlier failures and warnings. ZIP CRC/member hashes and exact
runtime-source equality passed. Fresh offline macOS application setup and independent
finalizer environment passed. The original RC1 ZIP SHA-256 remains unchanged.

The synthetic sample retains 14 original rows and protected cell values, groups 13 issues
with one exact supporting duplicate, and exposes 12 QA entries/47 focused parts. Source
hashes, every row's reconciliation, internal links and formula safety passed. All 16 selected
worksheet previews rendered locally; these do not establish native Office acceptance.
The finalizer never approves findings or overrides ratings/path classifications. Its
`--final` gate requires an explicitly selected acceptance record and matching report hash.

Limits/next task: authorized customer field validation, exact approved bucket/Discovery
resource scopes, actual read-only collector execution and tool-generated input verification.
Optional IAM recommendation collection is unsupported. Unknown roles/CEL/deny/PAB/network
context and mixed collection dates remain qualified; configuration never verifies execution.
Native Windows build/execution, native Excel and Tk dialog testing remain pending. Legacy
incompatible/interrupted workspaces stop for explicit recovery rather than auto-migrating.
The full repository suite was not rerun for this integration; no production acceptance is
claimed. No customer findings or exploitation results were fabricated.
