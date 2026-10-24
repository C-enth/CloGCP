# Permanent engineering contract
Build an offline, evidence-backed enterprise AWS assessment platform. Read this file,
README.md, ARCHITECTURE.md, METHODOLOGY_COVERAGE.md, EVIDENCE_SCHEMA.md,
IMPLEMENTATION_ROADMAP.md, TEST_PLAN.md and the latest Git state before changes.

## Security and reasoning
Never upload customer material without explicit authorization. Never expose private
contents in tool output absent authorization. Keep evidence and derived artifacts in
ignored data/private or artifacts. Use synthetic tests. Never store credentials.
Missing evidence cannot produce PASS. Preserve source requirements and IDs; record
ambiguities separately. Methodology inspection was authorized for local model processing
on 2026-10-10; keep its text in data/private or artifacts only. Tracked specs hold IDs,
link metadata and engineering paraphrases (methodology/coverage_spec.py,
rules/methodology_links.py, attack_paths/specs.py). Any mapping change updates those
specs, bumps the rule version and must pass the private reconciliation test. A rule
evaluating a subset of criteria never yields a control-level Pass; configuration
evidence never marks an exploitation prerequisite verified. Rule outcomes answer the
source clause; finding class (baseline deviation / potential exposure / supported gap)
and technical severity follow evidence and are documented in docs/RULE_SPECIFICATIONS.md.
Real-export compatibility is claimed only from the local verifier run with
`--origin tool-generated` on actual collector files; synthetic fixtures never count. Never fabricate findings, edges or confirmed exploitation.
Confidence, severity and analyst approval are independent.
Treat imports as untrusted: bounded input, no execution, pickle or unsafe YAML,
no archive extraction outside approved roots, no external links or formula execution.
No telemetry, AWS SDK calls, remote assets or hosted AI in the runtime.

## Architecture and conventions
Use Python >=3.11, src layout, type annotations, Pydantic v2 versioned contracts,
small functions and explicit errors. Use pathlib, UTC-aware timestamps and stable
identifiers. Parsers only normalize; control logic belongs in rules. Analysis must
not depend on API/UI. Follow all module boundaries in ARCHITECTURE.md.
Do not add frameworks or change decisions without an ADR. Empty module namespaces
are boundaries, not implemented functionality.

## Workflow and handoff
One agent may modify this working tree at a time; do not delegate concurrent edits.
Inspect status and preserve existing changes. Work on feature/offline-security-analyzer.
No commits, pushes, history rewrites or destructive cleanup without explicit authority.
Update documentation with implemented versus planned status and actual test results.
Handoff includes branch, changes, checks, blockers and next task; no customer content.

## Definition of Done
Run relevant synthetic tests, lint and schema validation; document failures and
platform limitations. Verify private paths ignored and source integrity unchanged.
Review diff for secrets and unintended changes. Windows artifacts must be built and
validated on Windows. No false completion claims, invented counts, silent methodology
repairs, scanner severity copied into business risk, or generic compliance substitution.
