# Reporting alignment with the approved tracker

The approved workbook (private) contains the live tracker sheets. The analyzer **never
opens, edits or overwrites** that workbook. It writes a standalone report whose
*Tracker Staging* sheet uses the tracker's per-account control result columns, so an
analyst can review and transfer rows. Automated transfer into the customer workbook is
not implemented (see "Remaining requirements").

Write policy: **KEY** row identity written by the analyzer; **SCANNER** written by the
analyzer (the tracker permits imports to write only `Scanner_*`); **ANALYST** never
written; **FORMULA** preserved, never written; **REF** analyzer reference column placed
after the tracker columns; **GAP** no approved field exists.

## Account Control Results (Tracker Staging, columns A–O, then references)
| Tracker field | Policy | Analyzer source |
|---|---|---|
| Result ID | KEY | `OA-` + SHA-256(account, control)[:16]; stable across runs |
| Account ID | KEY | Approved key from the private workspace registry (`accounts load`), or an explicit `--account-keys` file at export; blank with a mapping-required status otherwise; never guessed |
| Control ID | KEY | Original methodology control ID (`methodology_id`) |
| Scanner_Status | SCANNER | Fail if any mapped rule FAILs; Not Applicable if all N/A; otherwise Not Assessed. Pass only if every rule fully covers the control's criteria (none currently), so sub-criterion PASS never becomes control Pass |
| Scanner_Severity | SCANNER | Highest analyzer *technical* suggested severity among FAIL candidates; never scanner or methodology severity |
| Scanner_Source | SCANNER | Engine version and `rule@version` list |
| Scan_Date | SCANNER | Latest collection date (UTC) of the evidence used |
| Analyst_Status, Analyst_Validated, Finding_ID, Assessed_By, Assessed_Date, Analyst_Notes | ANALYST | Left empty |
| Evidence Ref, Resource ARN / ID | STAGING (authorized 2026-10-10) | For Fail rows: raw evidence references (`raw/<sha256>.json<locator>`) and failing resource IDs; empty otherwise. The customer tracker itself is never written |
| REF: AWS account, key status, control coverage (criteria evaluated / not evaluated), rule outcomes, affected resources, candidate finding IDs, evidence artifact IDs, run ID | REF | Analyzer provenance |

Every in-scope registry account gets a row per mapped control; accounts without evidence
show `Not Assessed` with "no evidence for this control in the run", so coverage gaps are
never hidden. REF columns add finding classes, technical observations and evidence needed.
The *Assessment Coverage* sheet lists, per account and evidence family, the Regions and
coverage states; summary metrics count registry accounts with and without evidence.
Findings are additionally split into *Security Gaps*, *Potential Exposures*, *Baseline
Deviations* (all unconfirmed candidates), *Incomplete Investigations* (UNKNOWN, MANUAL,
COLLECTION_ERROR) and *Confirmed Findings* (analyst decisions only).

Granularity: one row per account and control. Per-resource detail stays in *Control
Assessment*, *Findings Register* and *Evidence Register*.

## Findings Register (confirmed findings only)
| Field | Policy | Source / requirement |
|---|---|---|
| Finding ID | ANALYST | Assigned at confirmation; analyzer candidate ID kept as reference |
| Title, Precondition / Weakness, Remediation | Proposal | Candidate title, technical observation, remediation; analyst edits |
| Domain | Proposal | Control Library domain of `methodology_id` |
| Asset / Component | Proposal | Resource type and native ID |
| STRIDE | Proposal | Source STRIDE category of the mapped control |
| CVSS v4.0 Base / Severity / Vector | ANALYST | Never derived from suggested severity, scanner severity or inherent severity |
| Status | ANALYST | Only analyst-CONFIRMED candidates are eligible for this sheet |
| Affected Accounts | FORMULA | Counts Account Control Results rows carrying the Finding ID; never written |
| Linked Control IDs | Proposal | `methodology_id` |
| Linked Attack Path | Proposal | Source-linked attack paths of the control |
| SEBI Ref | GAP | Empty at control level in the source (AUD-03); scenario-level refs only |
| Business Impact, Remediation Owner/Due, Identified By/Date, Notes | ANALYST | |
| Evidence Ref | Proposal | Technical Evidence IDs once evidence rows are created (below) |

## Technical Evidence
Evidence Type `CLI / API Output (JSON)`; Collection Tool/Method = operation and collector
version; File/Artifact Reference = `raw/<sha256>.json`; Integrity Hash = artifact SHA-256;
Collected Date = declared collection time. Linked IDs come from findings. Storage location,
sensitivity and collector identity are ANALYST fields.

## STRIDE / Attack Path Validation
The analyzer supplies prerequisite evidence only (*Attack Path Prerequisites*). Validation
Status, Chain Viability, Exploitability Confirmed and Entry/Escalation/Detection Validated
are ANALYST fields: configuration evidence never sets them.

## Requested fields absent from the approved tracker (GAP)
Customer action, customer remarks and reassessment status have no columns. The nearest
existing field is the finding Status vocabulary (Open, In Remediation, Remediated, Risk
Accepted, False Positive, Pending Validation). The owner must approve a tracker extension
or a separate customer-response sheet before the analyzer can populate them.

## Remaining requirements
1. The approved registry file built from the customer's account inventory (AUD-15 / MR-H11);
   the mechanism exists (`offline-analyzer --workspace W accounts load registry.json`).
2. Owner decision on per-resource rows and whether imports may write Evidence Ref /
   Resource ARN (MR-H10).
3. A merge tool that writes only KEY/SCANNER cells into a copy of the tracker, preserves
   analyst/customer edits, formulas, validations and formatting, and is tested against a
   synthetic replica of the layout. Not implemented in this increment.
