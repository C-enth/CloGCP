# CloSec repository and release policy

The feature branch holds maintained application code, security specifications/contracts,
dependency locks, packaging, automated tests/generators and current technical documentation.
Every current tracked file is classified by tools/source_release.py; its JSON inventory
lists all paths, categories, bytes and hashes. Unknown paths or index/worktree mismatches
fail publication review. Values matched by credential/account scans are never printed.

## Data and history

No assessment JSON collections, registries, databases, reports, screenshots, logs,
browser traces, binaries, wheels, runtimes or private workbooks are tracked. Tests create
synthetic inputs under temporary directories; manually generated outputs belong in ignored
artifacts or outside the checkout. Fixture hashes in test source pin legacy bytes without
retaining evidence files. Source generators are development code, not imported evidence.

Cleanup preserves the local examples tree (now ignored) and archives obsolete documentation
locally under ignored artifacts/cleanup-050. Customer evidence/workspaces/private methodology
and uncommitted user work are not deleted. Never use git clean -fdx or destructive resets.

104 reviewed synthetic JSON files remain in older commits and unchanged main. They are
non-sensitive test examples, not customer exports. Cleanup is not history erasure.
The security audit still scans their bytes; only their exact prior-reviewed historical
paths receive a non-sensitive legacy classification. Newly introduced evidence and
private paths remain blocked. No automatic rewrite or force push is authorized. If a
material secret is ever discovered, block publication, revoke/rotate it, restrict access
and coordinate an approved history-remediation plan with collaborators.

## Retained non-Python resources

- frontend/src: React/TypeScript/CSS and frontend/index.html: maintained GUI source.
- frontend/package.json, package-lock.json, tsconfig.json, vite.config.ts and .npmrc:
  locked build/test configuration; public registry addresses are dependency metadata.
- tests/gcp_rule_outcomes_baseline.json: expected per-rule outcome counts for the named
  synthetic fixture generators. It contains only fixture names, rule IDs, outcome labels
  and integer counts; no collected observations, resource configurations or customer data.
- pyproject.toml and .gitignore: Python build/dependency/package-data settings and exclusions.
- src/offline_analyzer/contracts/schemas/*.json: 31 public versioned contracts; generated
  from Pydantic and verified for equality in tests, required by packaging/operators.
- collectors/: versioned read-only AWS (Python) and GCP (PowerShell) collectors and the
  generated collector-analyzer contract; no credentials or account data.
- packaging/portable: macOS/Windows setup/start scripts, README and stdlib integrity
  verifier for the portable application (ADR-007). Wheels are release artifacts, not Git.
- src/offline_analyzer/api/assets/index.html, build-info.json, one JS and one CSS bundle: the only
  retained generated runtime assets. They allow Python-only installs on macOS and
  Windows without npm/Node. frontend/package-lock.json and npm run build reproduce them. Browser
  tests exercise these assets against real APIs; no remote assets are loaded.
- Markdown under the root and docs: current architecture, evidence/rule/methodology
  specifications, operator/build/test instructions, ADRs and release record. Historical
  sprint/recovery reports are removed from the current branch and remain in Git history.

The exact categorized list, including every non-source path, is emitted by the source audit.
There are no binary-data exceptions or assessment-dataset exceptions in the current tree.

Private methodology-input documents and rendered UI-review screenshots remain local and
are explicitly ignored. The synthetic outcome-count baseline above is test source, not
an assessment dataset. Root launchers, Git line-ending attributes and their historical
portable launcher copies are maintained delivery source. The older source-review tool's
path/mode/signature diagnostics still need review; they are not automatically waived by
being present in a private repository.

## macOS and Windows distribution boundary

`tools/portable_release.py` builds one portable ZIP from a clean commit: source, compiled
GUI, collectors, operator documents, offline wheelhouses and hash locks for Windows x64 and
macOS (`tools/build_wheelhouse.py`), but no evidence. SHA256SUMS, archives and wheels are
release artifacts outside Git. Actual Windows execution is required before claiming
Windows validation; preparation and hash checks on macOS are not Windows validation.
