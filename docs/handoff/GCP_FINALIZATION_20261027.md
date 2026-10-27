# GCP finalization handoff — 2026-10-27

Branch `feature/gcp-finalization` in the CloGCP clone (`artifacts/clogcp-publication-20261026`
of the CloSec tree), created from `main` `8f535dd`. **Nothing committed or pushed.** The
staged deletions (`CloGCP.zip`, `CloGCP.zip.sha256`, `run-portable.py`,
`tests/test_clone_launcher.py`) are index changes only; the zip files remain on disk and the
published v0.8.5-clogcp.2 assets are unchanged.

What changed, results and limits: [status](../GCP_FINALIZATION_STATUS.md),
[changelog](../../CHANGELOG.md), [test record](../../TEST_PLAN.md),
[validation workflow](../GCP_VALIDATION_WORKFLOW.md).

Candidate (working-tree snapshot, `source_kind` WORKING_TREE_SNAPSHOT) in
`artifacts/CloGCP-0.8.5-clogcp.3-candidate-20261027/` of the CloSec tree, with `SHA256SUMS.txt`.
The installed CloSec.zip and earlier releases were not touched.

No customer workspace, evidence or export was opened or copied. The only local workspace
(a 2026-10-14 pilot) was not opened.

Next: run `tools/workspace_counts.py` on the B1/B2 workspace (app closed). Validate on
Windows and in desktop Excel. Run the finalizer on a real export. Then commit and tag on
approval, and publish the ZIPs as tag assets.
