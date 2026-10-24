# CloGCP

CloGCP **0.8.4-clogcp.1** is an independent, offline GCP assessment **release candidate**
based on the validated CloSec application. It reuses the working import, investigation,
review and reporting interface, with corrected GCP evaluation, additional criteria,
coverage reporting and read-only historical comparison. The reused GUI retains CloSec branding.

## Download the application

This repository is public. Open the
[release candidate](https://github.com/C-enth/CloGCP/releases/tag/v0.8.4-clogcp.1), and download
**CloGCP.zip** and **CloGCP.zip.sha256** from its assets. GitHub's green
**Code → Download ZIP** button downloads development source, not the complete offline application.

[Download CloGCP.zip](https://github.com/C-enth/CloGCP/releases/download/v0.8.4-clogcp.1/CloGCP.zip)

This build is a prerelease. A `releases/latest` stable-release link is intentionally not used.
Native Windows execution and Microsoft Excel desktop acceptance remain pending.

Verify before extraction:

```sh
# macOS
shasum -a 256 CloGCP.zip
```

```powershell
# Windows PowerShell
Get-FileHash .\CloGCP.zip -Algorithm SHA256
```

Expected SHA-256:

```text
abb87926e119dad60d533d3d8f52aaf9e5a404d709f1acea9d14e261719b22ed
```

## Start and update safely

Extract the application ZIP into a **new folder**. Do not overwrite CloSec, install into
its Python environment, or select its workspace as the CloGCP writable workspace.
Python 3.12 is required. On macOS run `sh CloGCP.command`; Windows source entry point is
`CloGCP.cmd`, pending native validation. Setup installs the bundled hash-locked wheels offline.
For updates, extract into a fresh application folder and continue using the separate
**CloGCP** workspace. Existing CloSec settings, assessments and reports stay separate.

See [operations](docs/clogcp/OPERATIONS.md) for analysis against already collected project
packages and optional read-only export from a closed historical workspace. No further
collection is required for the implemented criteria. Never automatically transfer approvals.

## Scope and validation

There are **77 GCP criteria**: 48 existing plus 29 additional, including seven new
review-only criteria. All 118 catalog entries are documented: 45 criterion-backed,
11 review-only, 10 context consumers and 52 without automated assessment. These counts
include aliases and do not mean complete service or compliance coverage.

- Full GCP regression: 705 passed, 4 skipped.
- Final history/end-to-end checks: 12 passed.
- Final extracted-package regression: 287 passed.
- Packaged Chromium workflow, macOS launcher and clean offline setup passed.
- AWS comparison matched 97 evaluations, 8 findings, 1 review and all workbook members
  except the document timestamp.
- Five broader legacy test failures also reproduce on the validated baseline.
- Ten synthetic projects completed in 60.99 seconds; no real customer assessment or
  historical client finding was validated or reconciled in development.

Read [corrections and limitations](docs/clogcp/CORRECTIONS.md),
[criterion inventory](docs/clogcp/RULE_INVENTORY.csv),
[dataset-to-rule matrix](docs/clogcp/DATASET_RULE_MATRIX.csv),
[test results](docs/clogcp/VALIDATION.md),
[release verification](docs/clogcp/RELEASE_VERIFICATION.json) and
[exact package changes](docs/clogcp/EXACT_PACKAGE_CHANGES.json).

## Source checkout

The repository contains source, synthetic tests and development tools. Runtime implementation
matches the verified release candidate; repository documentation and Git metadata are separate.
The portable release additionally supplies offline dependencies and its integrity manifest.
For reproducible offline execution, use the release application. Do not run the source
checkout's `CloGCP.command` until the portable dependencies/manifest have been supplied.

For an isolated development environment with package-index access:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev,application]'
PYTHONPATH=src .venv/bin/python -m offline_analyzer.clogcp --environment synthetic
```

Use a new synthetic workspace for tests and the CloGCP entry module for execution.
Do not use the legacy generic launcher to open the installed CloSec workspace.
Production assessment approval and the outstanding platform gates require local acceptance.
