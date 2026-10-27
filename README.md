# CloGCP 0.8.5-clogcp.3 (candidate)

GCP finalization readiness: evidence-consistent claims, checkable expected states, a register
that follows the owner's column rules, finalizer QA additions, faster dashboard/Finalized
views and a clone that equals the release. Display and export text only; stored findings,
IDs, fingerprints, decisions and frozen editions are unchanged. See the
[changelog](CHANGELOG.md) and the [one-page validation workflow](docs/GCP_VALIDATION_WORKFLOW.md).
The 0.8.5-clogcp.2 recovery hotfix is retained ([notes](docs/clogcp/HOTFIX_0.8.5_2.md)).

Offline, evidence-backed GCP assessment prerelease. This update adds attack-path engine
2.0.1, independent **Recalculate Attack Paths**, immutable supplementary IAM evidence
composition, frozen Batch 1/ongoing Batch 2 reconciliation, an approved-scope delta
collector and a separate Excel Report Finalizer. Existing CloGCP rule corrections,
workspace isolation and Windows file-based preflight are retained. The reused interface
continues to display CloSec branding; its application version is `0.8.5rc2`.

Download [the new prerelease](https://github.com/C-enth/CloGCP/releases/tag/v0.8.5-clogcp.2).
This repository is private; sign in with an authorized GitHub account.

- [CloGCP.zip](https://github.com/C-enth/CloGCP/releases/download/v0.8.5-clogcp.2/CloGCP.zip): complete application source, compiled GUI, launchers and hash-locked offline wheels.
- [CloGCP-Delta-Collector.zip](https://github.com/C-enth/CloGCP/releases/download/v0.8.5-clogcp.2/CloGCP-Delta-Collector.zip): separate explicitly approved collection tool.
- [CloGCP-Report-Finalizer.zip](https://github.com/C-enth/CloGCP/releases/download/v0.8.5-clogcp.2/CloGCP-Report-Finalizer.zip): separate offline report utility.
- [Checksums](https://github.com/C-enth/CloGCP/releases/download/v0.8.5-clogcp.2/SHA256SUMS.txt), source archive, verification and upgrade notes are release assets.

A compatible **CPython 3.12** installation is required (Windows x64; macOS arm64/x86_64).
All application Python dependencies are bundled; installation uses no package-index access.
Python itself is a system prerequisite, not an embedded executable. The collector additionally
requires an authorized gcloud session. The analyzer and finalizer require no cloud credentials,
gcloud, Node, Docker, internet or hosted AI. Node is needed only to rebuild the frontend.

See [upgrade and rollback](docs/clogcp/HOTFIX_0.8.5_2.md) before opening an existing workspace.
Installing does not open a workspace or run analysis. The explicit verified-copy command
can add only missing empty consolidation tables in a **new copy**; the original database,
raw evidence and decisions remain intact. Opening refuses pending recovery/incompatible
schemas. Recalculation never imports evidence, rebuilds enterprise assessment, reruns
security rules or approves findings. Additional IAM uses a separate analysis version.

Windows: extract `CloGCP.zip` into a new folder and run `CloGCP.cmd`.
macOS: run `sh CloGCP.command` (`CLOGCP_PYTHON` may select installed Python 3.12).
A source clone runs the same runtime files as the release: `RUNTIME_MANIFEST.json` lists
them with SHA-256 and `verify.py` checks them before every launch. Release archives are tag
assets, never committed. The clone has no wheels: set `CLOGCP_WHEELHOUSE` to the `wheelhouse`
folder of the matching release ZIP; setup installs only the committed hash-locked wheels.
The old release remains available
at [v0.8.4-clogcp.2](https://github.com/C-enth/CloGCP/releases/tag/v0.8.4-clogcp.2).

Read [the exact workflow](docs/GCP_FINAL_WORKFLOW.md), [release notes](docs/clogcp/RELEASE_0.8.5.md),
[architecture](ARCHITECTURE.md), [coverage](METHODOLOGY_COVERAGE.md) and [test record](TEST_PLAN.md).
Source and synthetic tests are under `src/`, `tests/` and `tools/fixtures/`.

This prerelease has synthetic acceptance only. Native Windows execution, desktop Excel/Tk
and authorized client validation remain pending. Configuration evidence never verifies
exploitation; missing evidence never produces PASS. No client material is distributed.
