# P0 workspace recovery hotfix — 0.8.5-clogcp.2

The previous recovery inventory reused the evidence-ingestion SHA helper. Its intentional
64 MiB file budget rejected legitimate large workspace databases/artifacts before recovery
could proceed. This hotfix introduces workspace-specific SHA-256 with 1 MiB reads and no
total file-size cap. Every file byte remains verified. Ingestion limits and implementation,
attack-path engine 2.0.1, reporting, rules and methodology mappings remain unchanged.
Application version is 0.8.5rc2. The previous 0.8.5-clogcp.1 tag/release is retained.

Recovery copies into a new private container on the destination drive. It requires free
space of twice the workspace file bytes plus 16 MiB for the copy/optional database backup
and metadata. Copy, hash, table-row and explicit additive-upgrade verification finish
before the destination is published by rename. A new recovery manifest includes source
and destination hashes; existing historical recovery manifests are retained. The source
workspace is only read. A failed copy is never published as the requested destination.

Symlinks, Windows reparse points/junctions, traversal paths and special files are refused.
File changes during hashing are detected. Controlled interrupts and I/O failures attempt to remove
only the newly created staging container. Cleanup failure or a hard process kill can leave a private
`.clogcp-recovery-*` container with `.workspace-recovery-incomplete`; opening it or its
payload is refused. There is no automatic resume, recovery, reassessment or finalization.
Do not use a half-copied folder as a source or select it in the application.

## Safe retry on Windows

1. Close the old application normally and retain/back up the entire original healthy B1/B2
   workspace. If its database needs shutdown recovery, use the previous compatible version
   first. Do not select an earlier failed destination as the source.
2. Download this new prerelease's `CloGCP.zip` and checksum. Verify SHA-256, then extract
   into a new installation folder beside the existing version. CPython 3.12 x64 is required;
   all application dependency wheels are bundled. Run `setup-windows.ps1` using your
   organization's approved PowerShell execution policy.
3. In Command Prompt in the new extracted `CloGCP` folder, use the original workspace
   and a **new, nonexistent destination** (replace these example paths):

   ```bat
   set "PYTHONPATH=%CD%\src"
   .venv\Scripts\python.exe -m offline_analyzer.storage.side_by_side --source "D:\Assessments\original-workspace" --target "D:\Assessments\workspace-v0852" --upgrade-additive
   CloGCP.cmd --workspace "D:\Assessments\workspace-v0852"
   ```

4. Require `recovery_verified: true`. The CLI names the new manifest. Check B1/B2 finding
   IDs/counts and analyst/SRE decisions. All pre-existing rows and evidence remain intact.
   No evidence import, Bulk Enterprise rebuild or attack-path recalculation is needed to open.
5. Retain the original workspace and installation for rollback. Close the new application
   before returning to the old version with its original workspace. Never open an upgraded
   copy with older software. Do not delete unidentified recovery containers automatically;
   retain any hard-killed partial copy for diagnosis, or remove only that identified container
   after confirming the original is intact and neither application is using it.

macOS uses the same module with `PYTHONPATH=src .venv/bin/python -m ...` and
`sh CloGCP.command --workspace /path/to/new-copy`. Native Excel/full GUI and actual
customer acceptance remain separate gates. Synthetic tests cover large files, failure
injection, hard termination, disk space, links/junctions and recovered-workspace opening.
Actual validation results and Windows CI evidence are included with the release.
