# CloGCP attack-path engine handoff — 2026-10-25

Branch: `feature/offline-security-analyzer`, base checkpoint `d232bb5`. No commit or
push was made in the project repository. Original working releases and client histories
were not replaced, migrated, reassessed or published.

## Deliverable

[Isolated portable source candidate](../../artifacts/CloGCP-attack-path-engine-2.0.0rc1/CloGCP-attack-path-engine-2.0.0rc1-portable-source.zip)
is engine **2.0.0**, candidate **2.0.0rc1**, inside the existing CloSec **0.8.4** application.
Its manifest truthfully identifies an uncommitted working-tree snapshot. It is not a
native Windows build or a production/field-acceptance certification.

Final ZIP SHA-256:
`89dad7c0fe8e41f386b06f2024e35d27a15d93756a13bc41c22dca4df4989e2e`.

The ignored candidate directory contains the source/verification manifests, hash list,
offline setup logs, packaged tests and a clearly named synthetic evaluation. The final
extraction is `verified-app/`; earlier packaging attempts are retained separately.

## Changes

- Traced XP-01 to `attack_paths/cross.py`, not the UNKNOWN finding investigations in
  `gcp.py`. It conflated actAs and token minting, then hop summarization produced PROVEN
  while possession stayed outside that conclusion. Corrected GCP/cross-cloud projections
  require qualified IAM/service/execution context; historical editions are unchanged.
- Shared GCP permission semantics separate access tokens, ID tokens, signing, actAs,
  attachment and Compute/Run execution mechanisms. Custom-role details, inactive/conflicting
  roles, scope, known ancestors, conditions, denies, PAB uncertainty and managed identity
  restrictions fail closed. Role names do not substitute for effective permissions.
- Finding-independent bounded discovery covers the six requested priority families:
  service-account token/workload paths; cross-project chains; VM-to-identity; serverless
  runtime identity; GKE identity investigations; and public/identity-mediated data access.
  Several mechanisms remain investigations because mandatory evidence is uncollected.
- Versioned five-state register with independent execution/validation/review fields,
  source provenance, original finding references, prerequisites, blockers, severity rationale,
  remediation and remaining verification. Root-cause groups preserve individual chains.
  BLOCKED variants remain in history and are excluded from active candidates.
- Read-only reanalysis opens existing runs without recovery, migrations or assessment
  writes, verifies raw hashes, and emits a new JSON/CSV register. Legacy matches preserve
  previous status and reasons; unmatched identities/mechanisms remain explicit ambiguities.
  New evaluations never inherit old path approval. The existing GUI keeps its qualified
  projection; the new independent register is an opt-in CLI artifact.
- Regression fixes: optional Git metadata timeouts no longer stop startup; grouped
  register projections are rebuilt after merging linked frozen findings. A stale browser
  expectation now includes the baseline's three existing GCP evidence sheets. No old
  report file, finding decision, SRE validation or frozen edition was rewritten.

## Checks and results

- Broad existing suite: **1,264 passed, 2 failed**, 1,814.81 s. This was not a clean sweep.
  The frozen-register failure was corrected; the folder-upload timeout passed in isolation.
- Final acceptance after corrections: **75 passed**, 98.36 s; private methodology
  reconciliation included. Fresh final AWS/GCP GUI reruns: **2 passed**, 76.48 s.
- Final packaged-source engine tests: **27 passed**, 6.25 s. Fresh final offline macOS
  x86_64 setup, pip check, runtime identity and packaged read-only reanalysis passed.
- Frontend **5 tests passed**, TypeScript passed; compiled assets are unchanged. Ruff,
  formatting, compileall, collector contract, 42-schema equality and diff checks passed.
- ZIP CRC/hash and **360** manifest entries verified. **64** existing platform wheels
  were hash-verified; no new dependencies or Windows binary were built.
- Confirmed analyst/SRE history and all database tables were preserved in synthetic
  tests. The durable synthetic workspace retained **103** original file hashes through
  checkout and packaged reanalysis. Its **8** candidates are unreviewed/unverified.
- **2 synthetic legacy conclusions → 8 mechanism records**: 4 CONDITIONAL,
  3 INSUFFICIENT_EVIDENCE, 1 UNSUPPORTED. No actual Batch 1 reclassification is claimed.
- Final bounded benchmark: **1,002 resources → 1,000 candidates in 0.571 s**, explicit
  truncation. This is not a comprehensive reachability or estate-capacity benchmark.

Full and focused logs, benchmark source hashes, preservation and packaging metadata are
under ignored `artifacts/`. The broad suite's failures are retained rather than described
as a passing full rerun. One existing Starlette deprecation warning remains in API tests.
The changed-file scan is clean; private paths stay ignored. Source methodology mappings
and IDs are unchanged. No private methodology text or customer material was copied into
tracked files or uploaded.

## Remaining limits and next task

The permission catalogue is deliberately partial. Full CEL, inherited deny/PAB applicability,
groups/federation, generic privileged-role expansion, key creation, signing-to-token exchange,
GKE/KSA/RBAC mapping, service agents, image/network/quota/organization constraints and actual
workload execution remain incomplete or unsupported. Structural topology, public addresses,
IAM grants and runtime identity references never verify exploitation. VPC denies are
potential blockers; the engine does not claim comprehensive network reachability.

No authorized client dataset was supplied to this run. **Actual Batch 1 correction,
native Windows execution and native Office acceptance remain unverified.**

Next task: stop the application using the selected authorized workspace and execute the
[documented read-only command](../GCP_ATTACK_ENGINE.md) from this isolated candidate, choosing
a new private output directory and optionally supplying the original legacy path array.
Review canonical matches and unmatched history before accepting the new register. Retain
the original reports, approvals and evidence. Validate native Windows separately before
describing a Windows release as accepted.
