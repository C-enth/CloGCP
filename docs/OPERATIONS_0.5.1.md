# CloSec 0.5.1rc3 operational recovery

P0 GCP correction: a legitimate `pilot-1.5` folder was rejected by the earlier rc3
build's `pilot-1.2.2`-only adapter. The corrected source has a separate strict pilot-1.5
contract and uses the same dispatch for ZIP and folder. Manifest-detection details are
recorded before evidence parsing and shown on rejection. Preserve the original files;
do not rename the manifest or rewrite its version. Earlier portable archives do not
contain this correction; no replacement kit is prepared during this P0 repair.

This release keeps the existing offline monolith, AWS/GCP engines, DuckDB, analyst
workbench and report approval system. No new runtime dependency or cloud access is added.
Engineering demonstrations use temporary synthetic evidence, not the customer archive.

## Current recovery behavior

Restart the launcher after updating source. The GUI displays application/Git/build identity
and refuses mismatched or changed running code instead of silently using an older backend.
Select a supported package, click the visible **Validate evidence** action, inspect coverage
and any integrity acknowledgment, then **Import validated evidence** and **Run assessment**.
File selection alone is not an import. **Build enterprise assessment** is on the Dashboard.

Validation starts a local job before transfer and runs parsing on the existing serialized
worker. The UI shows actual stage, counts where available, elapsed time and job ID. Upload
percentage describes local byte transfer only. No overall processing percentage is invented.
**View Import Details** shows local provider/scope/manifest context; **Export Sanitized
Diagnostic Report** excludes customer identities, configuration values, paths and raw logs.

Job sidecars use PENDING/RUNNING/COMPLETED/FAILED/CANCELLED/INTERRUPTED; older API status
names QUEUED/SUCCEEDED remain compatible. Health/progress remain independent of DuckDB.
Other database views return WORKSPACE_OPERATION_IN_PROGRESS while the writer is occupied.
Cancellation is cooperative before publication and rolls back the import/assessment
transaction; publication closes cancellation. Enterprise snapshot publication closes
cancellation before downstream finalization. Execution budget is 3,600 seconds; idle
transfer limits are 30 seconds without received bytes and 300 seconds without transfer
progress. Preserve the workspace and use sanitized diagnostics for a time/disk-limit failure.

On restart, unfinished journals become INTERRUPTED. Only reserved job-owned scratch
directories are cleaned; previous raw evidence, imports, approvals and reports are retained.
Retry the unchanged package or selected run. A completed but interrupted publication can
be revalidated idempotently. Backup/restore includes journals. Generated Excel files are
published only after success; cancelled worksheet/ZIP streams are closed and discarded.

Engineering acceptance uses actual launcher children, compiled production assets, real
FastAPI/DuckDB/adapters/engines and explicit synthetic evidence. Original AWS/GCP customer
packages were not available and are NOT validated. Follow the local real-export procedure
below in the authorized client environment; share only allowlisted diagnostics if needed.

## GCP ZIP import

The previous archive validator rejected backslashes in member names and converted path
validation exceptions into CORRUPT_OR_UNSAFE_ARCHIVE. It also did not recognize
collection_manifest.json or legacy stderr files. These code-level incompatibilities are
reproduced with synthetic packages. The exact first rejection of the customer archive
must still be confirmed locally; passing CRC does not establish acceptable evidence.

Supported packages remain AWS R0, native AWS collector contracts/v0.3.0 and closec-gcp-1.
An explicit gcp-pilot-1.2.2-adapter-1 profile adds collection_manifest.json with declared
schema_version pilot-1.2.2. No unknown version silently inherits this profile.

ZIP validation canonicalizes both separators, rejecting traversal, absolute/drive/UNC
paths, links, special/encrypted entries, Windows reserved names, trailing dots/spaces and
canonical/case collisions. Limits remain 1,100 entries, 1,025 files, 64 MiB per entry,
256 MiB expanded bytes and a maximum 1,000:1 expansion ratio. CRC is checked while reading.
Extraction never executes evidence, overwrites a file or writes beyond private staging.
The managed original ZIP is retained byte-for-byte alongside its canonicalized extraction.
UTF-8 BOM JSON is accepted without changing stored bytes.

Legacy source checksums and collector authenticity are NOT established. Local SHA-256
hashes are recorded for evidence/error files; GUI import/replacement requires explicit
acknowledgment of the limitation. Pagination and completeness are unverified, so SUCCESS
and EMPTY remain original statuses with internally PARTIAL completeness. Failed attempts
are ERROR, never empty inventories or evidence of a security weakness. Security criteria
may still identify a directly observed insecure configuration; missing prerequisites stay
UNKNOWN. Original commands/errors are preserved locally, but diagnostics display only
fixed categories, not raw stderr or credential contents.

The profile routes project/API/service-account/IAM/custom-role evidence, enabled services,
logging sinks/buckets/exclusions, storage and supported compute/network files to existing
parsers. New Cloud Asset resource/IAM search and organization-policy list profiles retain
inventory only. IAM search is not an effective-permission proof; policy listing is not an
effective organization-policy evaluation. Unknown dataset paths remain coverage entries
and retained raw evidence. Unsupported services, missing parent policies, monitoring
permissions, disabled APIs and incorrect collector commands remain explicit limitations.
Command failures produce a collection correction request. No failed operation is edited.

The synthetic 33-member acceptance package has 32 datasets: 8 SUCCESS, 5 EMPTY, 19 FAILED.
It imports, assesses and produces qualified IAM candidates, missing-evidence evaluations
and collection gaps through the real compiled GUI/API. These counts are a test assertion,
not a claim about a locally verified customer import.

## Manage Assessment Data

Open **Manage Assessment Data** in application navigation. Search and select the exact
provider/account ID or project ID. The list shows scope metadata, datasets/regions,
collection time, snapshots, resource/finding counts and related investigations.

**Replace Assessment Data** is preferred for refresh: verify a scope-specific ZIP/folder,
check exact provider and canonical identity (and project number when known), acknowledge
legacy integrity if applicable, then replace. A new immutable import and consolidated
snapshot are fully assessed before activation. Older evidence and approvals remain
historical; changed evidence requires revalidation. Other scopes remain in the active
snapshot. Failure keeps the previous database/active snapshot available.

**Delete Account Data / Delete Project Data** provides a fresh deletion preview of exact
managed files, snapshots, resources, findings, graph edges, reviews and report revisions.
Type the exact 12-digit AWS ID or exact case-sensitive GCP project ID; also check the
independent final confirmation before clicking Delete. API validation independently
checks both confirmations and the preview token. No wildcard, approximation or autofill.

Deletion removes only selected-scope logical records and owned managed files, fully
reassesses affected snapshots, recomputes relationships, clears view caches and invalidates
stale report approvals. Draft revisions owned by the scope are deleted; consolidated drafts
that also cover other scopes are kept without the scope's snapshots (text re-rendered,
analyst-written sections unchanged) and require a new review; other affected revisions
require a new review.

Purge (2026-10-17): the preview lists **Will be removed** (snapshot rows, resources, findings,
reviews, exclusions, drafts, path reviews, display labels, evidence files, collection
summaries, generated exports, job records naming the scope) and **Affected but kept**
(consolidated drafts, drafts marked for review, rebuilt snapshots, frozen editions). A
workspace backup is taken first to `<workspace>-backups/pre-purge-<UTC time>` beside the
workspace (checkbox, on by default; restorable with `restore`). Pre-purge backups hold the
purged data and need the same handling, retention and deletion rules as the evidence. The
result reports a separated verification (see OPERATOR_GUIDE.md): references removed,
cross-account references retained in other scopes' evidence, analyst-written drafts still
mentioning the identifier (redacted titles), superseded frozen editions retained, other;
CLEAN only when nothing remains. Audit events name the purged scope by a one-way digest.
Job records naming the scope and matching session diagnostics are removed. **Finalised
(frozen) editions are never altered or deleted**: scope deletion and single-file removal
are refused (`FROZEN_EDITION_DECISION_REQUIRED`) unless the explicit "Purge and mark
edition superseded" override is used (typed account/project ID, reason, verified backup
containing the edition); the edition record is kept and marked superseded. Shared methodology and
configuration remain. Cross-scope raw files containing multiple owned configurations
block permanent scoped deletion rather than rewriting evidence or deleting another
scope's configurations. Scope-specific packages are needed to resolve that limitation.

An OS lock and the existing serialized API writer protect lifecycle changes. Database
work is staged and compacted, then published with a journal and temporary rollback
checkpoint. Startup recovers an interrupted publication before exposing data. Failed
replacement stages discard only newly created uncommitted raw files on recovery.
Checkpoint files are removed after completion. A minimal audit retains identity, action,
time and counts, without deleted configuration contents. Expected-scope registries are
assessment scope definitions; they can still show the removed scope as not imported.

External source ZIPs, downloaded reports and retained backups are NOT deleted or recalled.
Logical deletion is not forensic media erasure. Follow authorized retention procedures
for external audit records/backups; never delete files outside the managed workspace.
Stop the process before backing up or restoring; use the existing backup/restore commands.

## Interface and local validation

The pilot-1.2.2 adapter in fe9cd6a supports the original collection_manifest.json,
including a 65-file folder with stdout and stderr for all 32 operations. The previous
synthetic browser record covered ZIP import; it did not establish the folder-picker
workflow or diagnose the reported customer UNSUPPORTED_MANIFEST_VERSION failure.
The new browser regression selects that complete synthetic folder through the real
GCP file chooser and also imports the Windows-separator ZIP, preserving original
bytes and manifest. No manual JSON restructuring is required for the supported format.

0.5.1rc2 fixes a separate job-submission race: while an import POST was pending, the
previous active run could still be assessed. The GUI now disables run selection,
assessment, repeated import and report submission from the first click through job
completion and persisted-run selection. This does not broaden accepted manifest
versions or establish compatibility with the original customer evidence.

AWS, GCP and Consolidated use persistent selected borders/underlines, readable stable
hover, visible keyboard focus and ARIA selected states. Provider tabs support arrows,
Home and End and retain the selected provider after reload. Domain/workbench tabs share
stable selected/focus styles; reduced-motion preferences disable transitions.

On the authorized workstation, preserve the original archive and run the packaged
verifier without extraction or upload. The output path must be new:

```powershell
.\CloSec\CloSec.exe verify --package 'D:\ApprovedEvidence\original-gcp.zip' --origin tool-generated --output 'D:\PrivateDiagnostics\gcp-051-verification.json'
$LASTEXITCODE
```

Exit 0 means the package adapter accepted its declared operations; it does not mean all
operations succeeded, all parsers are supported, or the environment is secure. Exit 2
indicates rejected source parsing; exit 1 means verification failed. Inspect status totals,
parser_supported, effective_coverage and integrity_assurance locally. Diagnostics may
include project identity and must not be shared without approval. If an exception occurs,
the verifier withholds private paths/values. The GUI presents a fixed error code, explanation
and action; keep the archive unchanged for local investigation.

Then import the original ZIP into an ASSESSMENT workspace, acknowledge legacy limitations,
assess, check all 32 operations and identity, review actual source evidence and validate
applicable findings. Verify 8/5/19 only if those remain the original manifest's counts.
Review collection corrections/permissions separately from candidate security findings.
This is the required real-evidence acceptance step; synthetic tests do not satisfy it.

## Build and release gates

See packaging/portable/README.md for the macOS/Windows portable install from bundled,
hash-locked wheels (ADR-007). Production distributions contain no synthetic
assessment data. Source/wheel kits and browser evidence remain ignored release artifacts.
Windows execution, real AWS/GCP evidence, analyst acceptance and production readiness
remain independent unachieved gates until their actual acceptance is recorded.

## Recorded engineering verification — 2026-10-12

628 Python/API tests passed, including seven actual Chromium workflows using compiled
assets and real APIs (one existing test-client deprecation warning). Frontend 3 tests,
TypeScript production build, Ruff lint/format, dependency/compile checks and public schema
equality passed. Private methodology reconciliation passed without modifying the source
workbook or mappings. The staged source/security audit passed for 246 required files and
447 historical blobs; no credentials, customer evidence or generated test evidence was
staged. Older reviewed non-sensitive synthetic examples remain in shared history.

A separate three-project synthetic AWS/GCP assessment reconciled 44 unified findings,
193 evaluations and 105 inventory resources in Excel and passed release audit. This is
a smoke check, not a large-estate performance certification. All 30 pinned Windows wheels
passed hash verification. The Windows executable and genuine customer archive were not
executed/verified here. Analyst and production acceptance remain pending.

Ignored local evidence: artifacts/operational-051-tests.xml, operational-051-browser/
(synthetic screenshots/results), operational-051-multicloud/ and source audit records.
Generated packages/databases/reports remain outside Git and production runtime bundles.

## Recorded complete Mac workflow verification — 2026-10-13

0.5.1rc2 passed the complete 632-test suite in 235.24 seconds, with nine real Chromium
workflows and zero failures/skips. The compiled GUI selected the complete 65-file
pilot folder and its ZIP through the GCP import buttons, created the same persisted
run across transports, normalized 9 supported observations, assessed 20 evaluations,
reviewed its candidate and exported Excel. Those counts describe this synthetic
fixture only. AWS ZIP/folder workflows retained 78 observations, 97 evaluations and
8 candidates, with report rows tied to the newly selected AWS run. All provider
dashboards, consolidated snapshots, existing approvals/exports and restart workflows
passed. Source bytes stayed unchanged; browser external requests/page errors were zero.

Frontend tests/build, Ruff, compile/dependency checks, 29 bundled contract comparisons,
private methodology reconciliation and 30 approved wheel hashes passed. The existing
Starlette/httpx warning remains. Original customer-evidence processing and native
Windows executable testing were not performed. The owner will test Windows manually
in the client environment; no agent access to that environment is authorized.
