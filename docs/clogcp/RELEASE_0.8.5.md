# CloGCP 0.8.5-clogcp.1 prerelease — 2026-10-26

Application version: `0.8.5rc1`; attack-path engine: `2.0.1`; separate collector/finalizer:
`1.0.0rc1`. Supersedes the download recommendation for `v0.8.4-clogcp.2` without changing
that release, its tag or assets. CloSec's repository is not a publication target.

The corrected prerequisite engine distinguishes direct token creation, actAs, workload
creation and network/identity requirements. Unknown permissions, unsupported conditions,
deny/PAB and mixed-date context remain qualified. Historical blockers cannot masquerade
as current blockers after supplementary evidence. Configuration never proves execution.

Existing assessments now expose independent **Recalculate Attack Paths**, with immutable
versions and old/new comparisons. Batch 1 frozen records, Batch 2 findings and analyst/SRE
history are retained. New IAM evidence enters through bounded native delta import and
resource/date-qualified composition, followed by a separate analysis version. Shared IAM
context currently uses broader evaluation in that new version; fine-grained caching is pending.

The multi-project collector provides explicit scope/approval binding, shared-folder dedup,
skipping of complete operations, bounded pacing/retries/pagination and partial-access status.
No permission mutation/API enablement occurs. Optional IAM recommendations are unsupported.
The external finalizer preserves all 40 original columns and protected values, creates
focused excerpts and conservative issue grouping, and writes a separate QA register.

CloGCP-specific domain corrections, isolated profile, Windows file-based preflight and
verified clone bootstrap remain. New explicit copy-only additive upgrading supports the
previous workspace schema while preserving every original row and file. CloGCP opening
performs read-only preflight and refuses implicit recovery/migration. Installation runs no
assessment or finalization. See [upgrade/rollback](UPGRADE_0.8.5.md).

The original development candidate passed 66 focused tests, full browser acceptance and
45 packaged-source tests. Those results do not by themselves validate this merged release.
Publication-specific results are recorded in TEST_PLAN.md and the release verification asset,
including the CloGCP correction/isolation/bootstrap regression and new copy-only upgrade test.

Packages contain compiled UI and hash-locked offline dependencies, with no developer paths
or virtual environment. CPython 3.12 remains a system prerequisite. Collector additionally
requires approved gcloud credentials; finalizer can reuse the compatible CloGCP Python.
Native Windows execution, desktop Excel/Tk, approved real collector execution and customer
acceptance remain pending. This is a prerelease, with no production or human engine sign-off.
