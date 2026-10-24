# CloSec GCP collector 2.2.8

Windows PowerShell 5.1 collector using native `gcloud` and authenticated read-only REST,
for one selected project. Emits `assessment-expanded-2.2` (analyzer adapter
`gcp-expanded-2.2-adapter-1`); CloSec continues to accept 2.1 and pilot packages.

## Corrections over the 2.1 HostFix build

| Defect | Effect | Correction |
|---|---|---|
| Unbounded `WaitForExit()` | a hung gcloud command stalls collection forever | `-CommandTimeoutSeconds` (default 300) then the process tree is terminated: TIMEOUT |
| No REST retry; token used for whole run | 429/5xx and token expiry become failures | bounded retries with backoff; one token refresh on 401 |
| Pagination trusts every token | repeating tokens loop indefinitely | repeated token or `-PageHardCap` stops with TRUNCATED |
| Missing list property recorded as EMPTY | unrecognized responses looked like "no resources" | UNEXPECTED_SCHEMA (property names only are recorded) |
| Unreachable locations ignored | partial `locations/-` listings looked complete | PARTIAL |
| 403 SERVICE_DISABLED / quota-project errors labelled ACCESS_DENIED | wrong remediation | API_DISABLED and QUOTA_PROJECT_DENIED |
| Discovery Engine GET on the global host for every CAI name | 404 for `us`/`eu` resources, collections and other types | location endpoints (`{location}-discoveryengine`), dataStores/engines only, per-location lists, unsupported types recorded without requests |
| No quota-project option | user credentials fail with `serviceusage.services.use` | optional `-QuotaProject`, typed confirmation, `X-Goog-User-Project`/`--billing-project`, recorded in the manifest |
| Non-atomic writes; no manifest on Ctrl+C; no checksums | partial files, lost status, no integrity | atomic writes, manifest always written (`collection_status`), `checksums.sha256` |
| (2.2.8) Custom role details were requested with the full resource name | `gcloud iam roles describe projects/<id>/roles/<role>` is rejected ("The role id should not include any 'projects/' or 'organizations/' prefix"), so every `custom_role_detail_*` failed and custom-role permissions stayed unresolved | the bare role ID is passed with `--project=<id>` or `--organization=<number>`; unrecognised names are skipped with a console note; that gcloud message is COMMAND_ERROR if it recurs |
| (2.2.7) The enabled-services pre-check skipped identity/governance/security calls that would have answered | e.g. `project_org_policy_v2` and `service_account_keys_inventory` recorded API_DISABLED although the related calls succeeded | `iam`, `orgpolicy`, `recommender`, `accesscontextmanager`, `securitycenter`, `cloudasset` and `logging` are always attempted and classified from the response; resource services keep the pre-check |
| (2.2.7) Effective org policies required a `constraints/` prefix | `gcloud org-policies list` returns bare names, so no `effective_policy_*` dataset was produced | bare, `constraints/x` and `.../policies/x` names are normalised, unioned with an 11-constraint baseline (key creation/upload, member domains, OS Login, serial port, external IP, default network, bucket PAP and UBLA, SQL public IP, resource locations) and described with `--effective` |
| (2.2.7) A "service disabled" error from the quota project was recorded as API_DISABLED | user credentials bill a quota project; its disabled API looked like the target's | when the error names another project number than the target's, the status is QUOTA_PROJECT_DENIED (gcloud and REST); if the target number is unknown, API_DISABLED is kept with a note |
| (2.2.7) A fallback was recorded for an API_DISABLED Run/Functions list | a misleading fallback warning | no fallback is recorded or printed when the list was API_DISABLED |
| (2.2.7) `argument --x: Must be specified` and `not enabled on project` were unclassified | generic FAILED | COMMAND_ERROR and API_DISABLED / QUOTA_PROJECT_DENIED |
| (2.2.6) API-key and bucket detail loops piped the list through `ConvertFrom-Json` | under Windows PowerShell 5.1 a list of 2+ items became one item: one failed `api_key_detail_1` / `bucket_iam_1` / `bucket_details_1` instead of one per key or bucket | lists read with `Read-EvidenceArray` (items kept separate); counters advance only for named items |
| (2.2.6) Run/Functions IAM depended only on the REST lists | a failed REST list silently produced no `run_iam_*` / `function_iam_*` | targets taken from the gcloud `cloud_run` / `functions` lists instead; recorded in the manifest's `dependency_fallbacks` with both statuses |
| (2.2.6) gcloud failures: rate limits and expired sign-in unclassified; a bare `403`/`404` anywhere in stderr matched | wrong or generic statuses | RATE_LIMITED, AUTH_ERROR and SERVER_ERROR; 403/404 matched only beside HTTP/status/code/error, a reason phrase or brackets; up to 3 retries with backoff for RATE_LIMITED and SERVER_ERROR only (same read-only command) |
| (2.2.6) gcloud output decoded with the console code page | non-ASCII names could be mangled | stdout/stderr read as UTF-8 (`PYTHONIOENCODING=utf-8`, `PYTHONUTF8=1`) |
| (2.2.6) `Compress-Archive` packaging | Windows PowerShell 5.1 can write backslash entry names | entries written one by one with forward-slash names and verified; ZIP SHA-256 printed and written to `<package>.zip.sha256` |
| (2.2.6) `-MaxDetailItems` stops were invisible for service accounts, buckets, API keys, custom roles and KMS | a limited run looked complete | `detail_limits_reached` in the manifest; the limit now also bounds custom-role and KMS key-ring/key expansion (0, the default, means no limit) |
| (2.2.6) Hierarchy metadata written with `Set-Content -Encoding UTF8` | BOM, single object instead of array, non-atomic | atomic UTF-8 without BOM, always a JSON array |
| (2.2.5) Cloud Run service and Cloud Functions IAM policies: PowerShell joined `'--region='+$region` as two arguments | every per-service IAM call failed with `unrecognized arguments` (COMMAND_ERROR) | arguments grouped; each flag is one argument |
| (2.2.5) Cloud Run jobs and Artifact Registry REST lists used the `locations/-` wildcard | always HTTP 400 INVALID_ARGUMENT, recorded as a gap | invalid requests removed; the same inventory is collected by `cloud_run_jobs` and `artifact_repositories` (`--location=all`) |
| (2.2.4) `compute images list` included Google's public image catalog | import stopped with `GCP_PROJECT_IDENTITY_MISMATCH` (`compute/images.json`, `selfLink`, e.g. `debian-cloud`) | `--no-standard-images`: only the project's own images; CloSec also drops public images from earlier outputs |
| (2.2.4) Workforce pools and access policies listed without an organization parent | always HTTP 400, recorded as a gap | `parent=organizations/<id>` when the project's organization is visible |
| (2.2.3) Folder/organization IAM search ran by default | IAM bindings of every project in the organization were collected | project-only by default; `-IncludeOrganizationSearch` with typed confirmation when org-level review is authorized |
| (2.2.2) Expired gcloud sign-in not detected | every dataset FAILED/AUTH_ERROR, package still marked COMPLETE | read-only `gcloud auth print-access-token` check before collection stops with the fix; a warning if sign-in expires during collection |

**Discovery Engine and other APIs with user credentials need `-QuotaProject`.** User
credentials bill API calls to a quota project. Without an owner-approved `-QuotaProject`,
calls such as Discovery Engine fail with a "service disabled" error that names the quota
project's number; 2.2.7 records these as QUOTA_PROJECT_DENIED (not API_DISABLED) and CloSec
shows them as insufficient coverage. Recollect with `-QuotaProject <approved-project>`.

**`-MaxDetailItems`: leave it at 0 (no limit) during an engagement.** A non-zero value
stops detail collection early for service accounts, buckets, API keys, custom roles, KMS
key rings/keys, Discovery Engine and BigQuery; CloSec then marks those datasets Partial
(`DETAIL_LIMIT_REACHED_*` in the Coverage tab and report limitations) and the skipped items
are not assessed. Use it only for quick test runs.

The collector never enables APIs, changes IAM, switches projects silently or retrieves
secret values or data content. Evidence can still contain VM startup scripts and instance
metadata, Cloud Run and Cloud Functions environment variables and Cloud Build substitutions,
which may hold secrets: handle every package as sensitive.

## If the collector says "gcloud sign-in check failed"

gcloud sessions expire (organizations often enforce re-authentication every 16-24 hours)
and the collector runs gcloud non-interactively, so it cannot prompt. Run `gcloud auth
login`, complete the browser sign-in, confirm `gcloud auth print-access-token --quiet`
prints a token, then run the collector again. If a run warns that datasets failed because
the sign-in expired, collect again; do not import that package.

## Run

Unzip `CloSec_GCP_Collector_v2.2.8.zip` (for example to `D:\`), then:

```powershell
gcloud auth login            # or the approved service identity
cd D:\CloSec_GCP_Collector
powershell -NoProfile -File .\GCP_Security_Evidence_Collector.ps1
# Only if the quota-project owner approved it:
#   ... -QuotaProject approved-quota-project-id
# Only if organization-level review is authorized (returns other projects' IAM bindings):
#   ... -IncludeOrganizationSearch
```

Folder layout (defaults, beside the script):

| Path | Purpose |
|---|---|
| `organization\projects.json` | project inventory; if missing or not JSON, the collector discovers accessible projects read-only (`gcloud projects list --format=json`) and saves it here |
| `projects\` | one evidence folder and ZIP per collected project |

Pick the project number from the list and type YES. `-ProjectsFile` and `-OutputRoot`
still override the defaults (the 2.2.0 layout `D:\GCP_Assessment\...` keeps working).

Use your organization's approved execution policy; the script does not change it. Import
the resulting ZIP or folder unchanged with **Import GCP Evidence ZIP/Folder**.

## Permissions

Viewer-level read access on the project (for example `roles/viewer`,
`roles/iam.securityReviewer`, `roles/cloudasset.viewer`, `roles/securitycenter.findingsViewer`,
`roles/discoveryengine.viewer`), plus `roles/serviceusage.serviceUsageConsumer` on the quota
project when one is used. Missing permissions are recorded per dataset and never treated as
compliant.

## Validation status

Parsed with PowerShell 7.4 on macOS. It has **not** been executed against GCP APIs or on
Windows PowerShell 5.1 by the developer; run it in the authorized Windows environment and
review the dataset status distribution before relying on it.
