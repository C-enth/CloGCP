# CloSec 0.8.4 operator guide

Collect → transfer → start CloSec → **Import and analyze** → review → approve → export.
Evidence never leaves approved systems; CloSec makes no cloud calls and uses no hosted AI.

## 0. Get the collectors

Start CloSec (section 4) and open **Evidence import → 1. Collect evidence**. Download
`CloSec_AWS_Collector_v0.3.2.zip` and `CloSec_GCP_Collector_v2.2.8.zip`; each unzips to one
folder with the script, its README, the analyzer contract and the working subfolders (AWS
`evidence/`; GCP `organization/`, `projects/`). The table shows each SHA-256. The same files are in the release ZIP under `collectors/`.

## 1. Collect AWS evidence (collector 0.3.2)

On the approved collection host (Linux/SSM or Windows, Python 3.9+ with boto3), in the
unzipped collector folder:

```sh
cp config.example.json config.json                       # approved Regions and spoke role
cp approved_accounts.example.txt approved_accounts.txt   # authorized account IDs
python assessment.py collect --no-prowler
```

Type a search (account name or ID), pick the account number, type YES. The collector
lists accounts from AWS Organizations, refuses accounts outside the allowlist and writes
`evidence/<AccountName>__<AccountID>__<run>.zip` beside the script. A PARTIAL summary is
normal: denied or unavailable APIs are recorded, never hidden. Repeat per account.

## 2. Collect GCP evidence (collector 2.2.8)

On the authorized Windows workstation with Google Cloud SDK authenticated:

```powershell
cd D:\CloSec_GCP_Collector
powershell -NoProfile -File .\GCP_Security_Evidence_Collector.ps1
```

Projects are listed from `organization\projects.json`; if it is missing or not JSON the
collector (2.2.x) discovers accessible projects read-only and saves the list there. Evidence
is written to `projects\`. Select the project number, type YES. Use `-QuotaProject <id>` only when its owner approved
it; the script asks you to retype it. The output folder and ZIP contain
`collection_manifest.json` and `checksums.sha256`; 2.2.6 and later print the ZIP SHA-256 and write
it to `<package>.zip.sha256` beside the ZIP.

With user credentials, use an owner-approved `-QuotaProject`: otherwise APIs such as
Discovery Engine are refused and show as QUOTA_PROJECT_DENIED (insufficient coverage, with
the reason in the Coverage tab). In the Coverage tab, "Service not enabled (per
enabled-services evidence)" (API_DISABLED), "denied access" (ACCESS_DENIED) and "quota/billing
project was refused" (QUOTA_PROJECT_DENIED) are different gaps; none is a pass. EMPTY means
the call succeeded and returned no resources.

**Do not use `-MaxDetailItems` during an engagement.** Any non-zero value stops the
service-account, bucket, API-key, custom-role, KMS, Discovery Engine and BigQuery detail
loops early. CloSec then marks those datasets Partial with the reason
(`DETAIL_LIMIT_REACHED_*`) and the skipped items are never assessed. Keep the default (0).

**Organization-wide IAM rows need `-IncludeOrganizationSearch`.** The GCP-ORG-* collection rows
(public data, basic roles, privileged or cross-project service accounts, impersonation,
deleted principals) PASS only from a complete organization-scope Cloud Asset IAM search with no
match. Without the switch, or when that search is denied, truncated or refused, the rows are
UNKNOWN; a project search alone is never an organization pass. Organization and folder IAM
policies (collected for every ancestor) are also needed for GCP-KEY-PRIVILEGED and
GCP-LOG-AUDIT to PASS; a denied ancestor policy keeps them UNKNOWN.

## 3. Transfer

Copy the ZIPs (or complete run folders) unchanged through the customer-approved channel.
Do not rename, edit, re-zip or restructure. Never place evidence in source control, chat or
hosted AI tools.

## 4. Install and start CloSec

Extract `CloSec-0.8.4-portable-source.zip`. Python 3.12 (64-bit) is the only prerequisite;
dependencies install offline from the bundled, hash-locked wheelhouse.

- macOS: `bash setup-macos.sh` once, then `bash start-macos.sh`.
- Windows x64: `.\setup-windows.ps1` once, then `.\start-windows.ps1` (under your approved
  PowerShell execution policy).

The browser opens on a local loopback address. Use **Stop app** before closing.
For a clean pilot, start with an empty workspace folder (pass it to the start script);
existing workspaces and analyst work are never wiped.

### Workspace location

With nothing chosen, CloSec keeps using its default workspace exactly as before
(macOS `~/Library/Application Support/OfflineAWSAnalyzer/workspace`, Windows
`%LOCALAPPDATA%\OfflineAWSAnalyzer\workspace`). The active path is shown in the header with
**Copy path**. Order of precedence when starting: a folder given to the start script
(`CloSec.command <folder>`, `CloSec.cmd "<folder>"`, `start-windows.ps1 -Workspace <folder>`),
then the `CLOSEC_WORKSPACE` environment variable, then the location chosen in CloSec, then
the default. Quote paths with spaces; non-ASCII names are supported.

**Workspace location** (left menu) offers, each only after **Check location** and an
explicit confirmation:
- **Use current (default)** — or **Return to the default location** if you chose another.
- **Open existing workspace (recovery)** — read-only check first (database present, journal
  kept with it, `workspace-environment.json` readable, schema version, lock), with counts.
- **Create new workspace** — a new or empty folder, owner-only permissions.
- **Move this workspace to a new location (copy)** — copies everything (database and journal
  included), verifies sizes, SHA-256 and counts, then switches. The old folder is never
  modified or deleted; its path is shown so you can remove it yourself.
- **Back up now** — verified copy into a new timestamped subfolder; never overwrites.
  Backups hold client data: store and delete them under the same rules as the evidence.

Switching applies after **Restart CloSec now** (a new browser tab opens). Location checks
warn — and need an explicit acceptance — for git repositories (including a home folder that
is a repository), cloud-synced folders (iCloud Drive, Dropbox, OneDrive, Google Drive),
network or removable drives, folders that are not writable, low free space, long Windows
paths and world-readable folders. Locations inside the CloSec source tree or a CloSec
release/application folder are refused. The chosen location is remembered in a small file
in your user configuration folder (macOS `~/Library/Application Support/CloSec/`, Windows
`%APPDATA%\CloSec\`) holding only the path and a timestamp; if it becomes invalid CloSec
shows the location screen instead of failing. Logs record only a one-way hash of a path.

## 5. Import and analyze

1. **Evidence import** → **Import AWS Evidence ZIP** (or GCP ZIP/Folder) → choose the file.
2. **Validate evidence**. Review the preview: collection outcomes, unsupported datasets,
   limitations. For GCP 2.1/pilot packages tick the no-source-checksum acknowledgment.
3. **Import and analyze**. The stepper shows Validate → Import → Analyze; the job panel shows
   live stages. When complete CloSec selects the new run and opens its dashboard.
4. If you navigated away, **Open assessment results** brings you back to that run.

A validated package that was not imported is restored on **Evidence import**, under
**Assessment workflow**, with **Import and analyze**. The dashboard omits this card.
Validation alone never creates an assessment. An imported but
not analyzed run shows **Run security analysis**.

The **Active evidence run** list names runs by provider, account/project, time and finding
count. Repeat for each AWS account and GCP project.

**GCP coverage is decided at import.** A collector 2.2 dataset with verified checksums and
status SUCCESS or EMPTY is complete (EMPTY gives Not applicable); TRUNCATED, PARTIAL,
interrupted collections and every failure status stay incomplete and never pass. Only
complete evidence lets CloSec read a field the Google API omits (an API key without
restrictions fails; a KMS key with no rotation schedule fails). Runs imported with an earlier
CloSec keep their recorded coverage: re-import the GCP package to apply this. Re-running the
analysis alone is not enough. Finding IDs do not change; work recorded on the earlier run stays
on that run. A false-positive disposition is carried over to the new import of the same
project (marked "carried over") only when the finding ID and its principals match exactly.

## 6. Consolidated view

Select the **Consolidated** tab → **Build enterprise assessment** (all imports, or tick
specific ones), at the bottom of **Dashboard**. Review **Enterprise build validation**:
source/artifact/observation/reference counts and scope identities must match; omitted
imports are reported. A PASS here validates the selected union, not collection or
security completeness. AWS accounts and GCP projects stay distinct; no cross-cloud path is
inferred without evidence.

The account summary always describes active imported scope, independently of the
selected run. The findings chart opens the matching severity filter. Posture and STRIDE
coverage show evidence limitations; missing evidence cannot establish a security Pass.

## 7. Review findings

- **Dashboard → Security Findings**, or **Findings workbench**: open a finding (**View**).
- Inspect evidence (source dataset, locator, collection status) in the detail panel and
  **Evidence explorer**.
- **Technical Analysis** is read-only. Open **Client Reporting** to record your decision
  (**Confirm** / reject / needs validation) with your identity.
- Edit the recommendation and narrative in the **Report finding editor**, **Save report
  draft**, **Approve recommendation**, **Approve report narrative**, **Copy Report Finding**.
  Saved drafts display their local database, record key and revision.

Candidate findings are not vulnerabilities until you confirm them. Coverage pages show
evidence gaps (denied, disabled, failed, unsupported); they are not compliance results.

## 8. Export and reconcile

Report scope (2026-10-19): Word and report Excel default to **analyst-confirmed findings
only**. "Exclude not valid / BAU" and "All findings" remain explicit choices; the Report center
shows a warning and the cover prints a "Report scope notice" for them. **Custom scope
limitations** (Report center) adds your own lines to "Coverage and limitations" after the fixed
limitations; the text is kept per run and frozen editions keep theirs. Excluded findings (any
reason) are not counted in any finding or risk count; evaluation listings show "excluded
(reason)". Consolidated snapshots include, by default, the latest import of each project or
account (older imports are listed as superseded and can be selected explicitly); refresh and
staleness work for GCP projects and AWS accounts. A path interpretation you confirmed applies
in every run where the path is identical.

Root-cause groups (Findings workbench → "Root-cause groups"): findings sharing a rule and, where
declared, a principal, firewall/security-group rule or organization node are listed once, with
findings, affected resources/scopes, highest severity and status mix; Mark valid, Send to SRE and
Exclude group act on every member (at most 2,000). In a finding's Client Reporting tab,
"Use root-cause group members" fills the consolidation with the group, so one edit (description,
immediate mitigation, permanent remediation, validation) covers the group; a member whose
evidence changes needs review on its own while the text stays for the others. Word and report
Excel render one entry per group with an affected-resources table ("Group findings by root
cause", on by default; untick for one entry per finding); the cover states "N grouped findings /
M affected resources" and totals still count member findings.

**Report center** → **Generate Excel** (complete workbook) and **Export all approved
findings (Word DOCX)**. **Assessment report** downloads a ZIP containing a native
`.docx` report and `.xlsx` workbook, scoped to GCP only, AWS only or both, with all
imports included in the selected enterprise snapshot. Both follow one template: cover,
executive summary, coverage and limitations (including UNKNOWN areas and why attack-path
kinds were or were not formed), attack surface by STRIDE, attack paths with a hop table
(the workbook has one row per hop and a STRIDE matrix), STRIDE and direction
justification, findings and appendix. Every workbook table has a frozen header row and
filters. PDF output is not offered. Legacy RTF endpoints remain compatible.

Attack paths include proposed STRIDE mappings and evidence limitations. Confirming
a path interpretation never confirms exploitation. The Findings Validation worksheet
includes a path only after that interpretation is confirmed by the analyst.

**Finalized findings → Freeze finalised assessment** requires an explicit checkbox
and a complete all-import enterprise snapshot with confirmed findings. This stores an
immutable edition, including cloud-specific and overall report content. Later edits
require a new assessment snapshot. Existing drafts are never frozen automatically.

The **Assessment reconciliation** table shows, for the selected run,
collector operations → imported evidence → normalized resources → evaluations → candidate
findings → API/GUI findings → exported Excel rows. Every stage should read PASS; any
difference states its exact reason. CLI equivalent:
`python -m offline_analyzer.cli --workspace <dir> reconcile --run <run> --markdown`.

If an import reports `GCP_PROJECT_IDENTITY_MISMATCH`, inspect the current job's identity
details: file, declared project, conflicting field and observed identity. Project IDs
and numbers are compared to their respective metadata; display labels are not identity.
Details are session-only and excluded from saved/exported diagnostics. A genuine
cross-project conflict requires correctly scoped collection metadata for each project.
`GCP_PROJECT_NUMBER_REQUIRED` means a file names the project by number but none was
declared; for a guided JSON import, enter the project number and import again.

Removing a local file selection does not delete an import. The removal panel offers
**Manage Assessment Data** for a separate account/project deletion preview with counts,
typed scope and explicit confirmation. **Delete One Imported File** previews one file
by content digest (every imported copy, all affected snapshots and scopes, findings,
reviews, reports and managed files) and requires the first 12 digest characters plus a
confirmation checkbox. Affected snapshots are fully reassessed; a retained transport ZIP
holding the file is removed in full. Path reviews of affected snapshots are removed.

**Finalised (frozen) editions** are never altered or deleted automatically. If one
includes the data, account/project deletion and single-file removal are blocked
(`FROZEN_EDITION_DECISION_REQUIRED`). The only override is **Purge and mark edition
superseded**: type the account/project ID (for a file, the ID of its account/project),
give a reason (10-2000 characters) and keep the pre-purge backup, which is then required.
CloSec confirms the backup contains each edition before removing anything. The edition
record is kept unchanged and marked superseded with time and reason; the audit entry
names the scope by a one-way digest. Unfreezing is not offered.

Account/project deletion takes a pre-purge backup to `<workspace>-backups/pre-purge-<time>`
(on by default; required for the override). **Pre-purge backups hold the purged data.**
Store, protect, retain and delete them under the same handling and deletion rules as the
evidence itself; deleting data from the workspace does not delete it from the backups.

After deletion the result shows a verification search of every database table, the
database files and the workspace, in separate groups, as counts only (never values):
references removed; cross-account references retained in other accounts' evidence (for
example an Organizations account list or a policy naming the account; kept because
removing them would alter other accounts' evidence); analyst-written drafts that still
mention the identifier (draft title with the identifier redacted, and revision count);
superseded frozen editions retained by decision; anything else. It reads "clean" only
when no reference remains at all.

**Exclude from report** (Client Reporting tab of a finding) hides a finding from client
reporting: Finalized findings, counts, the dashboard criticality pie (an "N excluded"
line keeps totals reconcilable), SRE workbooks, approved narratives and Word/Excel
exports, including attack-path and hop finding references. A reason is required (OTHER needs a note). Evidence and the evaluated finding
are unchanged; **Excluded findings** under Finalized findings lists them with **Undo**.
Exclusions are keyed by the stable finding ID (rule + canonical resource), so they
survive re-evaluation, enterprise rebuilds and restarts. Frozen editions keep their
preserved content. Single findings are not hard-deleted.

**Mark as false positive** (Client Reporting tab of a finding, or the bulk bar on a
filtered selection of up to 2,000 findings) records a false-positive disposition with a
mandatory reason: the preset "Google-managed service agent (platform-managed)" or free
text. It uses the same append-only exclusion log (reason False positive) and records the
reason, time, analyst, the finding's previous analyst state and the principals the finding
names. The rule result stays FAIL. The finding leaves confirmed and finalized lists,
severity totals, Word/Excel finding sections and the report's attack-path sections; it stays
visible in the Findings workbench with an **FP** tag through the **False positives** filter
(hidden by default, "N excluded as false positive"). Attack paths that rely on it are
flagged "depends on a false-positive finding". Word and both Excel outputs carry an
**Excluded findings** appendix grouped by rule and reason (the workbook lists finding IDs).
**Restore** (single or bulk) removes the disposition; the finding returns to its previous
state, which was never changed.

Authority: the workspace exclusion log, keyed by the stable finding ID, is the single
authoritative record. A disposition made in an import applies there and in every
enterprise snapshot that includes it; one made in a snapshot applies to its member imports.
For a new import of the same project it is carried over only when the finding ID (rule +
project + native resource) and the principals named by the finding match exactly, and is
shown as "carried over from <import>" for review. Different projects never share a finding
ID, so nothing carries across projects. Restore applies to every view of that finding.

The header **Theme** selector offers Dark (default; pitch-black), Light and System; the
choice is kept in this browser only. Generated reports do not depend on the theme.

## 9. Close and reopen

Stop the app; restart with the same workspace. The selected provider and run are restored;
interrupted jobs are marked INTERRUPTED and can be retried. Back up from **Workspace
location → Back up now** while running, or with
`python -m offline_analyzer.cli --workspace <dir> backup --output <file>` while stopped.

## 10. Recover after a crash

1. Do not move, rename or delete anything in the workspace folder. Keep
   `assessment.duckdb` and `assessment.duckdb.wal` (if present) together.
2. Start CloSec normally. On opening it checks the workspace: a leftover journal from an
   unclean shutdown is recovered by the database, the result is checkpointed and its
   integrity checked, and **Workspace location** shows "not closed cleanly … recovered" with
   counts (runs, sources, findings, confirmations, exclusions, drafts, finalised editions,
   path reviews). Compare them with what you expect.
3. If CloSec says the workspace is in use by another CloSec process, stop that window (its
   process id is shown). The lock is released automatically when that process ends; there
   is no force-unlock.
4. If the workspace lives elsewhere (or you restored a backup), use **Open existing
   workspace (recovery)**, check it, confirm, then restart.
5. A workspace written by a newer CloSec is refused (never downgraded). One from an older
   CloSec is backed up beside it (`<workspace>-backups/pre-migration-*`, verified) before the
   additive upgrade.
