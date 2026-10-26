# CloSec UI redesign plan (proposal, not implemented)

Status: **awaiting owner approval.** Nothing below is implemented. The audit behind it is
`docs/ui-audit/UI_STATUS.md`.

Boundaries for every step: frontend only (`frontend/src`, `frontend/index.html`,
`frontend/public`, rebuilt assets). No backend, API contract, schema, config or collector
change. Synthetic data only. Each step ships separately, with the full suite (browser
tests on), Ruff, Prettier, typecheck, build and `tests/test_theme_contrast.py` passing.

## Invariants (must not change in any step)

| Behaviour | Where | Guarded by |
|---|---|---|
| Technical Analysis is read-only; edits and decisions only in Client Reporting | `FindingDetail` (main.tsx), `FindingView.tsx` | gui, gcp, sre, integrated_acceptance browser tests |
| Exclusion needs a reason (note for OTHER), shows the no-hard-delete tooltip, has Undo | `Exclusion.tsx` | `tests/test_exclusions.py`, theme browser test |
| Typed-ID purge, default-on backup, frozen-edition block, explicit supersede override (typed ID, reason, enforced backup), separated verification ("not clean" when anything remains) | `ManageData.tsx` | `tests/test_scope_purge.py`, purge_override, file_deletion, theme browser tests |
| Coverage legend "Effective Coverage, Partial and Error explained" on the dashboard | `Posture.tsx` | gcp browser test, readiness report |
| Frozen-edition banner and preserved exports | `SreReview.tsx`, `ReportFinding.tsx` | `tests/test_assessment_sprint.py`, gcp browser test |
| Severity colours fixed across themes | `--sev-chart-*`, badge tokens | `tests/test_theme_contrast.py` |
| Synthetic / unlabelled / origin warnings always visible | shell (main.tsx) | browser tests ("Active run origin: synthetic") |
| No-flash theme, CSP-compatible (no inline script/style) | `public/theme-init.js`, `index.html` | theme browser test |
| Accessible names used by tests (labels, roles, button text) | all | 216 distinct locators in 16 browser files |

## Proposed minimal tokens (additions only; colour tokens unchanged)

```css
/* spacing: 4 px base */
--space-1: 4px; --space-2: 8px; --space-3: 12px; --space-4: 16px;
--space-5: 20px; --space-6: 24px; --space-8: 32px;
/* radius */
--radius-sm: 4px;  /* badges, small controls */
--radius-md: 6px;  /* inputs, buttons, messages */
--radius-lg: 8px;  /* cards, panels, drawers */
/* elevation */
--elevation-1: 0 2px 4px var(--shadow-soft);
--elevation-2: -10px 0 40px var(--shadow-strong);
/* weight */
--weight-regular: 400; --weight-medium: 600; --weight-bold: 700;
/* layout */
--content-max: 1400px; --sidebar-width: 240px; --header-height: 64px;
```

Breakpoints collapse to three, used as literal media queries (CSS cannot use custom
properties in media queries): 700 px (single column, collapsible nav), 1000 px (narrow
sidebar), 1450 px (wide). Existing one-off values map to the nearest token; any visible
shift is at most 3 px.

## Proposed shared components (presentation only; same props, data and API calls)

| Component | Replaces | Behaviour kept |
|---|---|---|
| `DataTable` (aria-label required, sticky header, numeric alignment, horizontal scroll with visible edge, optional row action column, built-in loading/empty/error rows) | 29 hand-rolled tables | Existing columns, pagination, selection and "View" buttons; `.records` / `.cloud-records` classes retained as aliases so existing selectors keep working |
| `Badge` (one component; variants severity / status / stage / environment) | `Badge`, `StageBadge`, hand-written `span.badge` in 7 files | Same class names (`badge critical`, `badge stage-with_sre` …) and same colours |
| `Card` and `MetricTile` | `.panel`, `.records`, `.metric`, `.finalized-metrics`, posture tiles, cloud cards | Same headings and aria-labels |
| `FilterBar` (primary filters inline, the rest in a "More filters (n active)" disclosure, Clear filters) | per-screen toolbars and 29 raw selects | Same labels and option values; `ChoiceFilter` stays the control |
| `Dialog` / `Drawer` (role="dialog", `aria-modal`, title, Escape, initial focus, focus trap, focus return, scroll lock) | `Detail` (main.tsx) and the second drawer in Enterprise.tsx | Same titles ("Finding details", "Record details", "Evidence traceability") and "Close details" button |
| `StateMessage` (loading = `role="status"`, error = `role="alert"`, empty with optional action) | 7 loading texts, error paragraphs, `Empty`, `.empty` | Same message texts used by tests ("No assessment imported.") |
| `Tabs` (tablist + tabpanel + `aria-controls`, arrow keys, scrollable single row) | provider tabs, dashboard sub-tabs, finding view tabs | Same tab names and roles |

## Plan, ordered by user impact

| # | Step | Files touched | Regression risk | Tests to update |
|---|---|---|---|---|
| 1 | **Frozen-run consistency in the finding drawer.** On a frozen run, disable Confirm / Reject / Mark for validation / Record exception, Exclude / Undo and SRE verdict with the existing frozen notice, as the report editor already does. The backend already refuses these actions; this only stops misleading enabled buttons. | main.tsx (`FindingDetail`), Exclusion.tsx, SreReview.tsx (`SreSection`) | Low | Add assertions to the gcp browser frozen flow; no selector changes |
| 2 | **Loading, empty and error states.** `StateMessage`; checklist shows "Loading checklist…" instead of 0 controls; `role="alert"` on the six unannounced errors; empty messages for header-only tables (Report center approved findings). | Filters.tsx (new export or new `States.tsx`), Checklist.tsx, FindingView.tsx, SecurityCoverage.tsx, ReportFinding.tsx, main.tsx | Low | theme browser loading wait (`^Loading`) keeps working; add one checklist-loading assertion |
| 3 | **Compact shell.** One status strip for the environment, origin and compatibility warnings (same text, always visible, still announced); workflow stepper shown on Evidence import and Dashboard only, collapsed to a one-line progress elsewhere; revision line moved to the footer; a specific subtitle per screen. Content starts ≈250 px higher. | main.tsx, Workflow.tsx, style.css | Medium | Keep "Assessment workflow", "Open assessment results", "Application revision" and the warning texts; tests that click "Open assessment results" from non-dashboard screens need checking (guided_workflow, pilot_import, integrated_acceptance) |
| 4 | **Accessible drawer.** Shared `Dialog` for both drawer implementations. | main.tsx (`Detail`), Enterprise.tsx | Low–medium | Keep titles and "Close details"; add an Escape/focus-return browser assertion |
| 5 | **Findings workbench order and filters.** Findings table first; shared-root investigations collapsed below; `FilterBar` with search, severity, stage and account inline and the remaining 8 filters under "More filters"; bulk bar appears only when rows are selected (the action buttons stay present and disabled when nothing is selected if tests require it). | main.tsx (`FindingsWorkbench`, `RecordTable`, `BulkBar`), Enterprise.tsx (`SharedInvestigations`), FindingsOverview.tsx, Filters.tsx | **High** | Positional `locator("table").last` (×17 "View"), `.records tbody tr`, "Stage", "Filter findings", "Finding account", "Bulk marking", `Show findings by account`: replace positional selectors with labelled ones (same assertions) in gui, guided_workflow, gcp_expanded, sre, integrated_acceptance, enterprise_api, theme |
| 6 | **Tables.** `DataTable` everywhere; arrays as chips instead of JSON (Account explorer coverage); "Unresolved" placeholders rendered as muted "—" with a title; wide tables scroll inside their card; checklist grouped by domain with collapsible groups (or 50 rows per page, see decisions). | main.tsx, CloudDashboard.tsx, Enterprise.tsx, Checklist.tsx, Posture.tsx, SecurityCoverage.tsx, Readiness.tsx, ReportFinding.tsx, SreReview.tsx, Exclusion.tsx, FindingsOverview.tsx, ManageData.tsx, style.css | Medium–high | `tbody tr` counts (×35) must keep counting data rows only (loading/empty rows rendered outside `tbody`); `.cloud-records tbody tr`, cell role "NEEDS_VALIDATION", `get_by_text(f"{api_total} records")` kept |
| 7 | **IAM intelligence de-duplication.** IAM tabs first; the cross-account graph replaced by a link to Cross-account explorer pre-filtered to IAM (or collapsed; see decisions). | main.tsx | Medium | No test references IAM intelligence by name; add a smoke assertion |
| 8 | **Dashboard length.** Sub-tabs as one scrollable tablist with panels; reconciliation shown as a table, raw JSON in a collapsed "Raw data" disclosure; detailed metrics unchanged in their disclosure; enterprise builder stays at the bottom (sprint B1). Coverage legend unchanged. | CloudDashboard.tsx, Posture.tsx, Enterprise.tsx, style.css | Medium | Tab names unchanged; "Detailed metrics and collection records" text kept |
| 9 | **One export panel on Finalized findings.** Scope (GCP / AWS / both / one account) + format (Excel / Word; PDF withdrawn 2026-10-17) in one control group replacing two toolbars; frozen exports unchanged. | SreReview.tsx | Medium | Links "GCP DOCX", "Download Excel", "Download Word report" in gcp and sre browser tests change unless names are kept (see decisions) |
| 10 | **Report center grouping.** Three titled sections: Client assessment report, Approved narratives, Technical exports, plus report history; each with an empty state. | main.tsx (`Reports`), ReportFinding.tsx | Medium | Button names ("Generate Excel", "Download assessment report (Excel + Word)", "Export all approved findings (Word DOCX)") kept; link "Download" ×20 kept |
| 11 | **Record and evidence drawers.** Key–value summary first, raw JSON in a collapsed "Raw record" disclosure. | main.tsx (`Detail` uses), Enterprise.tsx | Low | Headings "Typed relationship qualification", "Evidence traceability", "Integrity and source locators" kept |
| 12 | **Responsive and tokens.** Spacing/radius/elevation/weight tokens; collapsible nav (menu button) below 700 px; topbar badges never wrap per letter; three breakpoints. | style.css, main.tsx (nav toggle) | Low–medium | Add 390 px screenshot check to the theme browser test; contrast test extended to new tokens if any colours are touched (none planned) |

Order rationale: 1–2 fix misleading UI with almost no risk; 3–5 remove the largest
friction for the daily triage path; 6–11 are consistency work; 12 is polish. Steps 5 and 6
carry most of the test churn and should land as separate changes.

## Test strategy

- Prefer accessible names over structure: add `aria-label` to every table (DataTable
  requires one) and update positional selectors (`table.last`, `.records`) to those labels
  with identical assertions. No assertion is weakened or removed.
- Keep existing labels/texts listed in UI_STATUS.md §1 unless a decision below changes
  them; any renamed accessible name updates its tests in the same change.
- Extend `tests/test_theme_browser.py` screenshots to the changed screens (both themes,
  1440 and 390 px) and keep `tests/test_theme_contrast.py` passing.
- Screens with no named browser coverage today (Account explorer, IAM intelligence,
  Network analysis, Security investigations) get a smoke assertion before they change.

## Decisions needed from the owner

1. **Warnings strip (step 3):** may the synthetic/unlabelled banner, the origin banner and
   the compatibility notice be merged into one compact, always-visible strip with the same
   texts, or must they stay as separate full-width banners?
2. **Workflow stepper (step 3):** show it in full only on Evidence import and Dashboard
   (one-line progress elsewhere), or keep it full on every screen?
3. **Findings workbench (step 5):** findings table first with shared-root investigations
   collapsed below, and 8 of 12 filters under "More filters": approved?
4. **IAM intelligence (step 7):** remove the duplicated cross-account explorer and link to
   Cross-account explorer pre-filtered to IAM, or keep it collapsed on the IAM screen?
5. **Finalized exports (step 9):** one scope + format panel. Keep the current link names
   (tests unchanged, slightly longer labels) or rename and update the gcp and sre tests?
6. **Checklist (step 6):** group by domain with collapsible groups, or paginate 50 rows?
7. **Narrow screens (step 12):** support 390 px phones for review/reading only, or set a
   minimum supported width (e.g. 1000 px) and only fix the breakage?
8. **Test selectors:** approve replacing positional selectors with labelled-region
   selectors (same assertions) where layout order changes?
9. **Delivery:** one change per step with the full suite and a rebuilt `CloSec.zip` after
   each, or batch steps 1–4 and 5–8 and rebuild the archive only at the end?
10. **Audit screenshots:** keep the 44 synthetic JPEGs (11 MB) in `docs/ui-audit/screenshots/`
    or move them to the ignored `artifacts/` folder and link them from the docs?
