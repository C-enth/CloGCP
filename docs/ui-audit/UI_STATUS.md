# CloSec UI status (audit, 2026-10-17)

Scope: `frontend/src` as built today (0.8.4 working tree). Inspected source, the compiled
app and 44 screenshots captured from a **synthetic** workspace (`tools/fixtures/r12_demo`
AWS accounts plus the `demo-alpha` / `demo-beta` GCP fixture projects, one frozen edition).
No live workspace, evidence, draft or edition was opened. Note (later the same day): PDF exports listed below were withdrawn;
reports are Word and Excel only. Screenshots:
`docs/ui-audit/screenshots/{light,dark}-<screen>.jpg` (1440 px wide, full page), plus
drawer, deletion-preview, empty-workspace and 390 px / 1000 px captures.

Ratings: **Good** (fit for purpose, minor polish), **Needs work** (usable, clear
friction), **Poor** (hinders the task or misleads).

## 1. Inventory

The app is a single page with 13 screens selected from the sidebar (`main.tsx` `screens`,
state `screen`, no URL routing), a provider tablist (AWS / GCP / Consolidated) and two
drawers. Every screen sits below the same shell: topbar (environment badge, OFFLINE, Theme,
Refresh, Stop app), run bar (Active evidence run, Run assessment), page heading,
environment/origin banners, compatibility notice, workflow stepper, job details and the
revision line.

| Screen | Component (file) | Purpose | API calls | Filters | Actions | Browser tests that use it |
|---|---|---|---|---|---|---|
| Shell | `App` (main.tsx), `WorkflowPanel` (Workflow.tsx), `JobDetails`, `ThemeToggle` (Theme.tsx) | Session, run selection, jobs, workflow, theme | `/environment`, `/runs`, `/workflow`, `/jobs`, `/jobs/{id}`, `/jobs/{id}/cancel`, `/profiles`, `/collectors`, `/shutdown`, `/runs/{r}/assess`, `/import`, `/enterprise/assess`, `/enterprise/refresh` | Provider tabs; Active evidence run | Run assessment; Refresh; Stop app; theme; Import / Import and analyze; Open assessment results; cancel job; diagnostic export | All browser tests (label "Active evidence run" ×34, "Local operation details" ×8, "Assessment workflow", "Application revision", "Colour theme") |
| Dashboard | `CloudDashboard` (CloudDashboard.tsx) with `FindingsPie`, `PostureSummary` (incl. coverage legend), `EstateSummary` (Posture.tsx), `PathDiagrams` (PathDiagram.tsx); "Detailed metrics" `EnterpriseMetrics` (Enterprise.tsx), legacy `Dashboard`, `SecurityCoverage`, `Collection`/`Readiness`; enterprise builder (main.tsx) | Per-cloud and consolidated posture, findings by severity, STRIDE, reconciliation, 8 sub-tabs | `/runs/{r}/cloud/dashboard`, `/cloud/paths`, `/cloud/relationships`, `/cloud/scc`, `/path-review/{id}`, `/records/{kind}`, `/workspace/scope-summary`, `/enterprise/dashboard`, `/dashboard`, `/security-coverage`, `/collection`, `/reconciliation` | Sub-tabs (Overview, Assessment Coverage, Inventory, Security Findings, Attack Paths, Cross Account Explorer, Recommendations, Security Command Center); domain/severity/search dropdowns | Pie slice → findings; confirm path interpretation; build/refresh enterprise assessment | gui, guided_workflow, gcp, gcp_expanded, sre, integrated_acceptance, pilot_import, enterprise_api, theme ("Security Findings", "Attack Paths", "Assessment Coverage" tabs; `.cloud-records tbody tr`; labels "AWS/GCP scope summary", "Security domain comparison", "Cloud Search", "Cloud severity", "Criticality pie chart", "Observed findings by criticality"; text "Detailed metrics and collection records") |
| Evidence import | `ImportScreen`, `CollectorDownloads`, `CollectorPackage`, `Collection`→`Readiness` (main.tsx, Readiness.tsx), `ImportedRemoval` (ManageData.tsx) | Download collectors, choose/validate/import packages, readiness | `/uploads/start`, `/uploads` (XHR), `/collectors/{id}/download`, `/reports/{id}/download`, `/runs/{r}/evidence-requests.{csv,json}` | Origin declaration; advanced import options | Import AWS/GCP Evidence Folder/ZIP; Validate evidence; Import validated evidence; Import and analyze; remove/replace data | 12 browser files ("Select package folder", "Validate evidence", "Import validated evidence", heading "Validation preview", "Manifest detection details", "Collector package") |
| Findings workbench | `FindingsWorkbench`, `RecordTable`, `BulkBar`, `IncludeSelect` (main.tsx), `FindingsByAccount` (FindingsOverview.tsx), `SharedInvestigations` (Enterprise.tsx), `ChoiceFilter` (Filters.tsx) | Triage candidate findings, bulk marking, SRE workbooks | `/runs/{r}/records/findings`, `/finding-facets`, `/record-facets/{kind}`, `/review-bulk`, `/sre`, `/sre-workbook(s)`, `/reports`, `/enterprise/investigations`, `/enterprise/review/{id}` | Search; outcome; finding class; security domain; checklist control; region; evidence confidence; validation status; stage; account/project; Priority review queue; Clear filters | View; bulk Mark valid / not valid / Send to SRE / SRE verdicts; Show findings by account; Excel + Word report; Remove / replace data; review shared investigation | gui, guided_workflow, gcp_expanded, sre, integrated_acceptance, enterprise_api, theme (`locator("table").last … "View"` ×17, "Stage", "Filter findings", "Finding account", "Bulk marking", "Bulk note", "Mark not valid", `re.compile("Show findings by account")`) |
| Finding details (drawer) | `FindingDetail` → `Detail`, `FindingAnalysis` (FindingView.tsx), `SreSection` (SreReview.tsx), `ExcludeControl` (Exclusion.tsx), `ReportFinding` (ReportFinding.tsx) | Technical Analysis (read-only) and Client Reporting (decision, exclusion, SRE, report draft/approval) | `/findings/{f}/detail`, `/identity`, `/review/{f}`, `/sre`, `/exclusions(/{f})`, `/report-findings/{f}(/approve)`, `/records/findings` | — | Confirm / Reject / Mark for validation / Record exception; Exclude from report / Undo; SRE verdict; save draft; approve; copy | gui, gcp, gcp_expanded, sre, integrated_acceptance, operational, pilot_import, theme (tab "Client Reporting" ×23, "Close details" ×12, dialog "Finding details", "Analyst identity", "Analyst remarks", "Report finding editor", "Report reviewer", "Include in client report", "Quick summary", `.evidence-snippet`, `.sre-section`, "Exclude from report", "Exclusion reason/note") |
| Finalized findings | `Finalized` (SreReview.tsx), `ExcludedFindings` (Exclusion.tsx) | Confirmed vulnerabilities, freeze, finalised exports, excluded findings with Undo | `/runs/{r}/finalized`, `/finalize`, `/finalized.{xlsx,docx,pdf}`, `/exclusions` | Account / project | Freeze; 9 per-cloud export links + 3 per-account downloads; View; Undo | gcp, sre, theme ("Confirm freeze assessment", heading "Confirmed vulnerabilities", `.finalized-detail`, `.metric`, `.excluded-count`, links "Download Excel"/"Download Word report"/"GCP PDF", "Excluded findings list", "Undo") |
| Report center | `Reports`, `downloadReport` (main.tsx), `ApprovedReports` (ReportFinding.tsx) | Assessment report, approved client narratives, technical exports, report history | `/runs/{r}/reports` (POST), `/reports`, `/reports/{id}/download`, `/report-findings`, `/records/findings` | Report contents; account/project | Download assessment report; export approved findings (docx/pdf/text); Generate Excel / findings / accounts / coverage / evidence | 9 files ("Generate Excel" ×10, link "Download" ×20, "Export all approved findings (Word DOCX)", "Download assessment report (Excel + Word)") |
| Assessment checklist | `Checklist` (Checklist.tsx) | Approved checklist with per-cloud control outcomes | `/runs/{r}/checklist` | Search controls; domain; outcome; cloud-only | Open findings for a control | gcp ("Checklist controls", "Search controls") |
| Account explorer | `EnterpriseAccounts` (Enterprise.tsx), `Accounts` (main.tsx) | Account selection and per-account records | `/enterprise/accounts`, `/enterprise/filter-choices`, `/records/accounts` | Account/alias; group/OU; region; severity; coverage | Select displayed/matching accounts; per-account tabs | none by name (theme screenshot loop only) |
| IAM intelligence | `CrossAccount initialDomain="IAM"` (Enterprise.tsx), `Iam` (main.tsx), `GcpIdentity` (main.tsx) | IAM investigations, roles, policies, relationships, gaps | `/iam-context`, `/records/{iam kinds}`, `/enterprise/graph`, `/enterprise/relationships` | 9 explorer filters + record search | Tabs: investigations, roles, policies, relationships, gaps; graph | none by name |
| Network analysis | `Network` (main.tsx) | Network configuration and network candidate findings | `/records/network`, `/records/network_findings` | Record search; project; dataset; domain; support; finding filters | View | none by name |
| Cross-account explorer | `CrossAccount` (Enterprise.tsx), `GcpIdentity` for GCP | Typed relationships, bounded graph, register | `/enterprise/graph`, `/enterprise/relationships`, `/enterprise/filter-choices` | Source/destination account; relationship type; group/OU; search; domain; status; node budget; 3 checkboxes | Zoom; reset; select node/edge; Inspect relationship | enterprise_api ("Source account", "Relationship type", img "Enterprise relationship graph", "Zoom in graph", `.graph-node`, `.graph-edge`) |
| Evidence explorer | `Records kind=evidence/coverage` (main.tsx) | Normalised evidence and collection coverage | `/records/evidence`, `/records/coverage`, `/evidence/{oid}` | Search; outcome; project; dataset; collection domain; support | Inspect evidence (drawer) | workspace_selection ("Search evidence"; heading "Evidence traceability", "Integrity and source locators") |
| Security investigations | `Records kind=security_investigations` (main.tsx) | Investigation records (AWS and GCP) | `/records/security_investigations` | Search | View (record drawer) | none by name |
| Manage Assessment Data | `ManageData`, `FileRemoval`, `SupersedeOverride`, `PurgeResult` (ManageData.tsx) | Replace, purge account/project, remove one file | `/assessment-data/scopes`, `/delete-preview`, `/delete`, `/files`, `/file-delete-preview`, `/file-delete`, `/replace`, `/uploads` | Search canonical scope | Replace; Delete Project/Account Data; Delete One Imported File; typed ID; backup; supersede override | file_deletion, gcp_expanded, operational, purge_override, theme ("Deletion preview", "Deletion confirmation identifier", "Removed data", "Affected but kept", "Frozen edition decision", "Supersede confirmation identifier", "Supersede reason", "Purge result", "File deletion preview", "Imported files", table "Assessed scopes") |
| Record / evidence drawers | `Detail` (main.tsx); second drawer implementation in `SharedInvestigations` (Enterprise.tsx) | Raw record and evidence traceability | `/evidence/{oid}` | — | Inspect related evidence | gui, enterprise_api ("Typed relationship qualification", "Evidence traceability") |

## 2. Audit per screen

| Screen | Rating | Evidence (one line) |
|---|---|---|
| Shell (all screens) | **Poor** | Heading, two full-width banners, notice, workflow stepper and revision line take ≈510 px of a 900 px viewport on every screen before any content; 11 of 13 screens share the subtitle "Inspect source-backed records and preserve the evidence trail." |
| Dashboard | Needs work | Pie, posture and coverage legend are clear, but the page is ≈5,500 px, the 8 sub-tabs wrap to two rows, and the reconciliation details show raw JSON (`<pre>`). |
| Evidence import | Needs work | Numbered "1. Collect / 2. Import" sections work, but the global stepper repeats the same steps above them and the page is ≈1,800 px. |
| Findings workbench | **Poor** | The first finding row appears ≈1,230 px down: shared-root investigations come first, then 12 filter controls in 3 rows and a 7-control bulk bar. |
| Finding details drawer | Needs work | Technical Analysis is read-only as required, but on a frozen run Confirm / Reject / Exclude / SRE stay enabled (only the report editor is disabled) and fail on click; no Escape, focus move, focus return or `aria-modal`. |
| Finalized findings | Needs work | Two export toolbars (9 per-cloud links, then 3 per-account buttons) for the same documents; severity tiles and detail cards read well. |
| Report center | Needs work | Three report areas with overlapping purposes; the empty "Approved client findings" table shows headers with no empty-state message. |
| Assessment checklist | **Poor** | Shows "0 controls / No results" until data arrives (verified: 0 → 142 after ≈0.3 s), then renders 142 unpaginated rows (≈10,500 px). |
| Account explorer | Needs work | Coverage cells render raw JSON arrays (`["COMPLETE","PARTIAL"]`); two tables for one task. |
| IAM intelligence | **Poor** | ≈7,900 px: renders the full AWS cross-account explorer (same as Cross-account explorer) before the IAM tabs. |
| Network analysis | Good | Two compact tables with a clear empty state; AWS rows show "Unresolved" in the Project column. |
| Cross-account explorer | Needs work | Graph legible in both themes, but 9 filters and 3 checkboxes precede it and the page is ≈5,300 px. |
| Evidence explorer | Needs work | The evidence table is wider than its panel (Parser support / Operation cut off), with two stacked registers (≈4,700 px). |
| Security investigations | Good | One compact table with View per row; AWS rows show "Unresolved" Project. |
| Manage Assessment Data | Good | Scope table, removed/kept preview, typed ID, default-on backup, frozen override and separated verification are explicit; the preview with override is long (≈3,000 px) but every part is safety-relevant. |
| Record / evidence drawers | **Poor** | Primary content is raw JSON dumps (`Json` component) with no summary. |
| Empty workspace | Good | Single clear message and "Go to Evidence import" action. |

### Cross-cutting findings

**Layout and hierarchy.** Repeated shell chrome (above). Page heights: Dashboard ≈5,500,
Cross-account ≈5,300, Evidence explorer ≈4,700, IAM ≈7,900, Checklist ≈10,500 px. There
is no in-page navigation or sticky table header (`position: sticky` is used once, not on
tables).

**Tables and scannability.** 29 hand-rolled `<table>` blocks across 13 files; no shared
table component, no sticky header, no column alignment for numbers; some cells hold
JSON or `Unresolved` placeholders; wide tables cut off inside panels.

**Consistency.** Two drawer implementations (`Detail` in main.tsx, a second in
Enterprise.tsx). Badges are built ad hoc in 7 files (`<Badge>`, `StageBadge`,
hand-written `span.badge`). Filters mix `ChoiceFilter` (10 uses) with 29 raw `<select>`s;
filter bars differ per screen. Metric tiles exist as `.metric`, `.finalized-metrics`,
posture tiles and cloud cards.

**States.** Loading text appears in 7 components; elsewhere data-less components render
zeros (checklist). Six error renderings have no `role="alert"` (Checklist.tsx:93,
FindingView.tsx:109, SecurityCoverage.tsx:27, ReportFinding.tsx:383, main.tsx:1570 and
:2226), so screen readers do not announce them. Empty states exist (`Empty`, `.empty`) but some tables show headers
only.

**Accessibility.** Good: visible `:focus-visible` rings; `aria-current="page"` in the
nav; WCAG AA colour tokens (tested); keyboard pie slices and graph nodes. Gaps: drawers
lack `aria-modal`, Escape, initial focus, focus trap and focus return; tablists have no
`tabpanel`/`aria-controls`, and only the provider tablist supports arrow keys; disabled
controls use `opacity: 0.45` (exempt from contrast rules, but hard to read in dark).

**Responsiveness.** At 1000 px the layout holds (nav labels wrap). At 390 px the
13-item sidebar stacks above the content (content starts below the first screen) and the
topbar badges break one letter per line ("SY NT HE TIC"). Breakpoints are 700, 900,
1000 and 1450 px (900 and 1000 overlap in purpose).

**Themes.** Light and dark use the same tokens; no hardcoded colours (enforced by
`tests/test_theme_contrast.py`); severity colours identical across themes; diagrams
legible in both. No theme-specific defects found beyond the disabled-control legibility
above. Generated reports do not depend on the theme.

## 3. Design system today (`frontend/src/style.css`, 1,746 lines, 314 rules)

| Category | Current state |
|---|---|
| Colour | 73 tokens in `:root` (65 colour + 8 type), 42 dark overrides: surfaces (5), border (3), text (4), accent (4), focus, status sets (danger/warning/caution/success), severity badge and chart sets (fixed), diagram (4) and edge (5) colours, sidebar `--nav-*` (12, theme-independent). |
| Type | 8 size tokens `--text-xs … --text-hero` (12–48 px). Font weights are not tokens: 400, 500, 600, 650, 700, 750. |
| Spacing | No tokens. 40+ distinct `padding` values (e.g. 19, 21, 22, 26, 27 px), 16 distinct `gap` values (3–24 px), 30+ distinct `margin` values. |
| Radius | No tokens. 4, 5, 6, 7, 8, 9, 12 px and 50 %. |
| Shadow | Two colour tokens; geometry varies (`0 2px 4px`, `-10px 0 40px`). |
| Breakpoints | 700, 900, 1000, 1450 px; not tokens. |

Duplicated or one-off styles: card surfaces repeated in `.panel`/`.records`, `.metric`,
`.job`, `.path-node`, `.analysis-section`, `.empty`, `.file-button`; per-screen table
overrides (`.cloud-dashboard table`, `.finalized-detail td`, `.selected-row td`); toolbar
variants (`.toolbar`, `.cloud-records .toolbar`, `.review-actions`, `.exclusion-fields`);
two status-message styles (`.error`, `.success`) used both as banners and inline text.

## 4. Safety-critical behaviours to preserve

Read-only Technical Analysis tab; exclusion with required reason, note for OTHER,
tooltip and Undo; typed-ID account/project purge, default-on backup, frozen-edition block
and the explicit supersede override; separated verification wording ("not clean" when
anything remains); coverage legend ("Effective Coverage, Partial and Error explained");
frozen-edition banner and preserved exports; fixed severity colours; synthetic,
unlabelled and origin warnings always visible; no-flash theme initialisation.
