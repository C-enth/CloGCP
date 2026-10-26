# CloSec report findings workflow

Release candidate 0.4.2rc1 implements the workflow below. Runtime remains offline; no
AWS calls, credentials, remote AI, second frontend or additional database are required.

1. Launch `.venv/bin/python -m offline_analyzer.launcher`. For approved collector
   evidence use a separate workspace, for example
   `.venv/bin/python -m offline_analyzer.launcher --workspace artifacts/assessment --environment assessment`.
   Keep demonstrations in SYNTHETIC workspaces. An ASSESSMENT label does not establish
   real-export compatibility or analyst acceptance.
2. **Evidence import**: select the collector ZIP, validate checksums/source shapes,
   inspect supported/unsupported operations, completeness and account/Region identity,
   then import supported evidence. Keep each approved collector run immutable.
3. Run assessment or explicitly select original imports and **Build enterprise
   assessment**. Dashboard **Security assessment coverage** distinguishes persisted
   collection files, normalized evidence occurrences, resources, implemented checks,
   evaluated records, candidates and current analyst confirmations. Domain and operation
   tables identify gaps; there are no coverage percentages.
4. Open **Findings workbench**. Filter by account/project, severity, class, domain,
   checklist control, region, confidence or validation status (options and counts come
   from the run), or use **Show findings by account** for per-account severity and review
   counts. Each finding opens with Why this is flagged, How it can be misused (a potential
   scenario, never evidence of exploitation), Impact and Recommendation; the same text is in
   the Excel register, the assessment report and new report drafts. Inspect evidence and
   missing dependencies, enter analyst
   identity and independently Confirm, Reject or Mark for validation. Confirmation does
   not approve remediation or a client narrative. **Security investigations** exposes
   additional IAM/KMS observations; their methodology mapping remains UNRESOLVED.
4. (0.8.2) **Review flow.** Open a finding: the Quick summary states what is wrong, how
   it can be misused, the impact and the recommended action; **Copy technical finding**
   copies a report-ready entry. Click **Confirm** (valid: listed in Finalized findings) or
   **Reject** (not valid: excluded from reports); remarks are optional. No name is asked;
   the local login name is recorded and can be edited under "Recorded as". **Technical
   analysis** expands to the collected configuration at the evidence path (credentials
   masked, responsible fields highlighted), actual versus expected values, the security gap,
   misuse prerequisites, remediation and read-only verification commands (shown for
   review, never run) and evidence completeness. SRE responses are optional.
4a. **SRE validation (0.8.0, ADR-008).** In **Show findings by account**, download an
   account's **SRE workbook** (or all accounts as a ZIP) and share it with the owning SRE
   team. Each workbook has a Read me sheet with definitions and one row per finding still
   open for SRE, with Why flagged, How it can be misused, Impact, Recommendation, How to
   validate, evidence references and SRE columns (verdict dropdown, name, date, comments).
   Enter your analyst identity and **Mark N sent to SRE**. When SRE replies, open each
   finding and **Record SRE verdict**: Gap confirmed, No gap (BAU) (justification required),
   or Needs info. Returned workbooks are not imported. A gap confirmed by SRE becomes a
   **Confirmed vulnerability** only after the analyst clicks **Confirm as vulnerability**
   (an analyst CONFIRMED decision). Stages are shown as coloured badges, a Stage filter and
   per-account counts; changed evidence moves a finding to "Evidence changed: revalidate
   with SRE".
4a2. **Faster marking (0.8.1).** Tick findings (or **Select all N matching** the current
   filters), enter your analyst identity and use the bulk bar: **Mark valid**, **Mark not
   valid** (reason required, for known or accepted issues), **Send to SRE**, **SRE: gap
   confirmed** or **SRE: no gap (BAU)**. Each bulk action is all-or-nothing. A finding
   marked not valid is shown as "Rejected by analyst" even if it was with SRE.
4a3. **Reports follow your marking.** Every assessment report download asks for **Report
   contents**: exclude findings marked not valid / No gap (BAU) (default), only findings
   marked valid, or all findings; the report states which rule applied. Download it for all
   accounts in **Report center** or for one account with **Excel + Word report** on its row
   in **Show findings by account**. To re-upload an account, use **Remove / replace data**
   on its row, which opens Manage Assessment Data with that account selected.
4a5. **Report template (0.8.4).** Assessment reports (all or one account) and Finalized
   downloads share one Word/Excel layout: title page with document control, 1. Executive
   summary, 2. Technical findings, 3. Attack paths. Coverage matrices and the roadmap are in
   the comprehensive register (Report center > Generate Excel).
4a4. **Attack path diagrams.** Dashboard > Attack Paths and Finalized findings draw each
   path as Start -> Step -> Step: the starting resource, each resource or prerequisite, what
   allows the step (role, binding, trust) and, for AWS, the evidence status and rule. The
   Excel and Word reports carry the same chain as text. Paths describe configuration
   prerequisites; exploitation is not performed.
4b. **Finalized findings** lists only confirmed vulnerabilities, consolidated by severity
   and account, each with its four explanations and SRE/analyst confirmation, plus the
   attack paths (including cross-account and cross-project paths from an enterprise
   assessment) that involve them. **Download Excel** and **Download Word report** export
   exactly this list. Attack paths describe configuration prerequisites; exploitation is not
   performed.
5. In **Client report finding**, review the versioned service-specific guidance, edit
   title, severity/rationale and each narrative section. Root cause and exploitation
   remain unestablished until justified by the analyst. Enter **Report reviewer**, set
   inclusion and **Save report draft**. Saving any edit resets report approvals.
6. Independently **Approve recommendation** and **Approve report narrative**. Narrative
   approval requires current technical confirmation for every selected member. A
   recommendation can remain unapproved while the finding is confirmed. Risk acceptance
   requires a rationale and is recorded independently; it does not automatically approve
   remediation or narrative.
7. **Copy Report Finding** copies the exact saved, approved 13-section plain text. It
   is disabled for unsaved edits, candidates, rejected/needs-validation decisions,
   excluded scope, missing approvals or changed evidence. Browser clipboard denial is
   reported; approved text export provides a local alternative. No HTML is inserted.
8. **Report center** exports selected or all eligible report findings as Word-compatible
   RTF or plain text, with preserved report IDs/revisions and account/resource/evidence
   references. RTF escapes source text and includes no executable fields or objects.
   Existing Excel remains comprehensive, including candidates and open investigations.
   Approved-only exports do not replace that workbook.

## Consolidation and revisions

Use **Consolidate related findings** only after validating a shared root cause and
remediation scope. Choose members (first 100 current choices, or known finding IDs),
author the combined narrative and rationale, save, confirm every member and explicitly
**Approve consolidation** in addition to recommendation/narrative approvals. A shared
rule ID does not consolidate findings automatically. Affected account/resource rows and
per-member collection/evidence snapshots remain attached. Overlapping individual and
consolidated scopes are rejected at export; exclude the redundant individual report.

Every edit or approval appends a new revision. Previous narratives, severities,
recommendations, reviewer identities, timestamps, inclusion and evidence fingerprints
remain in historical revisions and backup/restore. A refresh never overwrites them.
Current candidate identity/fingerprint and analyst confirmation gate new copy/exports.
Changed conclusions show NEEDS_REVIEW; vanished findings show SUPERSEDED_OR_OUTSIDE_RUN.
Unrelated account approvals remain usable when their evidence-bound conclusion remains
unchanged. Previously downloaded reports are immutable historical files; consult the
current report register before issuing a new client report.

## Evidence gaps and limits

Mark incomplete findings for validation and export targeted requests from Dashboard
collection readiness. Registered operations, concrete IAM policy/version parameters,
account/Region scope, priorities and missing manual validation are retained. Additional
investigation IDs join the related evaluation IDs. The separate collector independently
enforces approved scope and permissions. Manual needs never become invented AWS operations.

Existing IAM and cross-account explorer views show supported, potential, blocked and
unknown transitions with evidence and missing dependencies. AP-04/05/06 constituent
prerequisites are implemented; configuration cannot verify exploitation or support an
entire path. General application reachability, NACL/firewall traversal, vulnerability
exploitability and crown-jewel classification are not implemented. Lambda/ECS exports
produce identity references, not complete workload security assessments. Deployed real
Prowler 5.26.1 and actual AWS collector exports remain unverified.

## Reproduce without customer material

```sh
.venv/bin/python -m offline_analyzer.reporting.capabilities --output artifacts/security-capabilities/SECURITY_ASSESSMENT_CAPABILITIES.json
.venv/bin/python -m offline_analyzer.contracts.schema artifacts/my-0.4.2-schemas
```

The demonstration creates five SYNTHETIC collector ZIPs, verifies/imports/correlates,
confirms a synthetic finding, approves its recommendation/narrative, exports RTF/text,
generates evidence requests, reimports and reconciles all report counts. Browser tests
exercise editing, independent approvals, actual clipboard text and downloading RTF/Excel.
These tests do not establish analyst acceptance or Microsoft Word/Windows execution.
