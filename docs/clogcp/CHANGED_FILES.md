# Exact application changes versus the validated ZIP

The original repository is untouched. These files change only in the isolated
CloGCP source. Files restored from the validated release can differ from the isolated
Git base without being new sprint edits. The source ZIP includes the synthetic test
suite and fixture tools; the portable ZIP excludes development tools and tests.

Modified runtime files:

- `src/offline_analyzer/findings/explanations.py`
- `src/offline_analyzer/findings/gcp_recommendations.py`
- `src/offline_analyzer/launcher.py`
- `src/offline_analyzer/normalization/gcp.py`
- `src/offline_analyzer/rules/gcp.py`
- `src/offline_analyzer/rules/gcp_config.py`
- `src/offline_analyzer/rules/gcp_identity.py`
- `src/offline_analyzer/rules/gcp_org.py`
- `src/offline_analyzer/storage/location.py`
- `src/offline_analyzer/storage/store.py`

New runtime files:

- `src/offline_analyzer/clogcp.py`
- `src/offline_analyzer/clogcp_profile.py`
- `src/offline_analyzer/findings/clogcp_reconcile.py`
- `src/offline_analyzer/reporting/clogcp_assurance.py`
- `src/offline_analyzer/rules/gcp_context.py`
- `src/offline_analyzer/rules/gcp_domains.py`
- `src/offline_analyzer/rules/gcp_public_context.py`

Distribution additions: `CloGCP.cmd`, `CloGCP.command`, independent portable manifest/
verifier/version metadata, `README.md`, `docs/ADR-CLOGCP-001.md`, and `docs/clogcp/*`.
Generated `docs/GCP_COLLECTOR_CONTRACT.md` reflects the executable inventory.

New tests: `tests/test_clogcp_{domains,corrections,rule_matrix,reconcile,isolation,public_context,end_to_end,profile_browser}.py`.
Existing GCP tests updated for the corrected agent, source-completeness, version and
running-state semantics: `test_gcp_config.py`, `test_gcp_identity.py`,
`test_gcp_ownership.py`, `test_gcp_principal_context.py`, `test_gcp_collector_227.py`.
Development tools added: `tools/fixtures/clogcp.py`, `tools/clogcp_inventory.py`,
`tools/build_clogcp_release.py`. GCP regression tests/fixtures from the current source
checkpoint are included for testing the validated runtime; the unpublished frozen-feed
test is excluded because its runtime feature is absent from the validated baseline.

AWS rules, collectors, frontend, database schemas and methodology mappings are byte-
identical to the validated release. Launcher, Store and workspace-open modifications
only guard the explicitly active CloGCP profile; existing behavior remains unchanged
when that profile is absent. No commits, pushes or publication were made.
