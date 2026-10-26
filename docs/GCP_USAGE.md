# CloSec GCP operations

The analyzer remains one offline application. Start it with
`.venv/bin/python -m offline_analyzer.launcher`. Use **AWS | GCP | Consolidated**.
Import through **Import GCP Evidence ZIP** or **Import GCP Evidence Folder**, validate,
then **Import and analyze**. Combine explicitly selected original imports with
**Build enterprise assessment** to investigate both providers in one immutable snapshot.
The existing AWS collector contract, IDs, IAM and network engines are retained.

## Native collection, separately on the authorized host

Use the GCP collector 2.2.8 (`collectors/gcp/GCP_Security_Evidence_Collector.ps1`, also
downloadable from **Evidence import → Collect evidence**). It runs on Windows PowerShell 5.1
with the operator's authenticated gcloud and emits `assessment-expanded-2.2` with checksums;
see [collectors/gcp/README.md](../collectors/gcp/README.md) for parameters, permissions,
the optional approved quota project and its limitations. CloSec itself needs neither
PowerShell nor gcloud. Real GCP execution of 2.2.0 remains a field-acceptance gate.

## Contract and guided native JSON

Generate the machine-readable contract locally:

```sh
.venv/bin/python -m offline_analyzer.ingestion.gcp --output artifacts/gcp-contract.json
```

`closec-gcp-1` records expected and collected project scopes, assessment identity,
collector version, project ID/number, optional organization/folder, operation,
noncredential parameters, timestamps, location, status, original record count, path,
checksum, pagination, errors, parser profile and declared resource/rule metadata.
Manifest declarations never determine actual rule availability: the executable registry
does. All nine collection statuses are retained. Complete empty inventories become
NOT_APPLICABLE scope results, never project-wide PASS. Denied, failed and uncollected
operations become unresolved assessment gaps. Checksums prove byte consistency only.

For individually exported JSON, open Advanced options, choose **Guided JSON provider:
GCP**, select the registered operation and project ID (and project number if native
resource names contain it), enter a known timestamp and request parameters, and select
the JSON. A missing operation/project is rejected. For resource IAM policies supply
`subject`; for effective policy supply `constraint` and `effective: "true"`.
All files in one guided import must represent the specified operation/project.
If a file names resources by project number (`projects/<number>/...`) and no number
was entered, the import stops with `GCP_PROJECT_NUMBER_REQUIRED`; enter the number
and import again.
Manual imports are `manual-unverified`, always partial; unknown collection times are
shown as unrecorded. Raw bytes are preserved without rewriting.

## Security interpretation and reports

Implemented high-value rules cover API-key application/API restrictions, combined
unrestricted keys, persistent/aged/privileged service-account keys, basic Owner/Editor,
sensitive public principals, broad impersonation and cross-project basic-role bindings,
effective key-governance flags, explicit audit exemptions, exact Data Access logging exclusions,
context-qualified public Cloud Storage bindings and active
SCC observations. Rule outcomes are per observed criterion, not whole-control compliance.
SCC is supplementary; source severity does not determine technical/business severity.

Allow bindings are observed configuration. Missing inherited allow/deny policies,
conditions and principal access boundaries remain uncertainties. Static evidence never
proves credential theft, workload compromise or exploitation. GCP candidate paths retain
unverified attacker-control prerequisites. No cross-cloud edge is invented.

Use Security Findings or the shared Findings workbench to confirm/reject/request
validation, edit report sections and approve recommendations and narratives independently.
Select Include in client report. Copy and Word-compatible RTF/text export require current
evidence, technical confirmation and the separate approvals. Unapproved findings remain
candidate rows in comprehensive Excel, never final client narrative text. Client action,
remarks and target-date columns remain separate from technical sections.

Cloud-specific reports use the corresponding original/provider-only enterprise snapshot;
consolidated reports use the combined snapshot. Existing AWS worksheets and streaming
export remain; mixed/GCP runs add provider-labelled overview, domains, register, inventory,
evaluations, coverage, relationships, investigations, methodology and collection requests.

GCP methodology source-control mappings remain UNRESOLVED. The matrix retains all 204
original IDs and the unchanged source hash, existing AWS mappings, implemented domains
and explicit unsupported GCP objectives. Domain alignment is not mapped-control coverage.

Supported native profiles are enumerated by `/api/gcp/contract`. Broader workload profiles
are inventory-only unless an explicit rule is documented. Full effective IAM, general
network reachability, vulnerability analysis, trends, drift and cross-cloud federation
evaluation are not established by this release candidate.

SCC/native candidate deduplication is deliberately narrow: SERVICE_ACCOUNT_KEY_NOT_ROTATED,
an exact project and key resource, a 90-day native policy and a 24-hour event window.
All original SCC observations remain available; stale/contradictory states are explicit.
This category/threshold was reviewed against
[Google SCC definitions](https://docs.cloud.google.com/security-command-center/docs/how-to-remediate-security-health-analytics-findings).

Synthetic GCP packages for testing come from tools/fixtures (pytest temporary
directories); import synthetic data only into a SYNTHETIC workspace.
The Windows acceptance script still performs the AWS CLI smoke flow; GCP and consolidated
GUI acceptance, helper execution and native Word/Excel verification remain operator gates.

Logging exclusions are normalized directly from native sink JSON collected with
[the supported sinks list command](https://docs.cloud.google.com/sdk/gcloud/reference/logging/sinks/list).
The legacy exclusions API profile remains available for authorized JSON imports; the helper
does not assume a gcloud exclusions command exists. Raw sink bytes and nested locators are
retained without transformation.
