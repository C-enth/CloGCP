# GCP Excel observation register — 2026-10-23

Implemented on `feature/offline-security-analyzer`: a read-only Excel appendix in the
assessment report ZIP and the comprehensive Report Center Excel export. The owner supplied
the exact forty headers in chat; layout whitespace is normalized to spaces. No reference
workbook observations, FortiGate conclusions, hint rows or example values were imported.
The existing worksheets and report model are retained. AWS-only exports take the unchanged
writer path and receive no additional sheets.

`GCP_Observation_Register` has the owner's forty columns, in order. Each row retains its
persisted candidate/evaluation ID. Existing candidate classifications remain verbatim;
evaluations without a candidate are observations, existing gaps or evidence limitations.
UNKNOWN and collection errors have no invented security severity. PASS, when present,
is a stored criterion outcome in the automatic evidence-result column, never a control
assurance claim. Findings excluded by the assessor and their evaluations are omitted.

| Reference fields | Persisted source / behavior |
| --- | --- |
| Record ID; observation; affected asset/scope; affected objects/services | Candidate or evaluation ID, project, native resource and recorded source operations |
| Criticality; rationale; rating confidence | Existing finding severity/rationale and independent evidence confidence; report-applied edits stay applied |
| Possible business impact | Blank: technical severity is not business impact |
| Recommended action | Existing finding remediation, or the remediation already applied by the report model |
| Assessor record type | Original finding class; otherwise observation, existing gap or evidence limitation |
| What the evidence shows | Concise redacted actual JSON values, with an explicit shortening notice when needed |
| Evidence reference | Original relative file plus JSON pointer; internal link to its first index entry |
| Expected control/requirement; control area | Recorded control/criteria IDs; an evidence-current analyst revision can supply expected posture |
| Evidence at assessment | Recorded collection completeness/status; never a configuration snippet |
| What evidence does not establish; evidence limits/data quality | Persisted missing dependencies/limits, plus explicit file/path/integrity availability limitations |
| Possible attack scenario; conditions | Evidence-current saved analyst scenario and persisted validation requirements; no invented exploitation |
| Source-reported result | Source-native finding status when recorded (e.g. SCC); CLI transport success is not a security result |
| Domain/tool; evidence type | Existing domain, GCP and source operations; configuration or unavailable evidence |
| Assessor conclusion/evidence basis | Stored technical observation and assessor note, without automatically confirming it |
| Related observations; issue group/summary title | Existing root-cause grouping IDs and visible member IDs; no new relationships |
| Attack-path evidence level | Existing report path IDs/states only; source-methodology path links are not verified paths |
| Automatic evidence result; report sequence; record count | Stored evaluation outcome; deterministic ID sort; one persisted record per row |
| Common asset reference | Existing native resource identifier |
| Risk rating decision | Evidence-current saved risk approval and reviewer/time, otherwise pending |
| Show in Overall? | Evidence-current saved report-revision inclusion flag, otherwise pending |
| Shown in Overall (automatic) | Membership in the existing selected report model; comprehensive export lists all nonexcluded candidates. It does not change saved inclusion flags or approvals |
| Applicability (SPOC) | Blank: there is no separate persisted applicability decision |
| SPOC assessment; justification/comments | Existing SRE verdict/reason, or pending; no SPOC identity/decision is invented |
| Supporting evidence/reference | References in an evidence-current analyst revision, otherwise blank |
| Reviewed by; review date; final review conclusion | Recorded assessor identity/time and existing effective status/stage; otherwise assessor review remains pending |

`GCP_Evidence_Index` maps each record to its artifact, project, native resource, original
file, JSON pointer, operation, dataset and collection time when recorded. SHA-256 and
availability are explicit. The stable mapping ID depends on record ID + artifact ID +
pointer. Each entry links to `GCP_Evidence_Details`; details link back to the index. Excerpts
come only from hash-verified retained original JSON at that pointer. Embedded JSON is
decoded before secret masking. Credentials and environment values are masked; no command,
external link or spreadsheet formula is executed. There are no raw-file hyperlinks.

Long excerpts are split into numbered, adjacent parts without dropping content. Main-sheet
text is deliberately concise. Very long narrative cells may require Excel's formula bar
or row expansion; Excel limits row height. All three sheets have native Excel tables,
filters, wrapped text and frozen headers. Filter project in Affected asset/scope, resource
in Common asset reference, operation/service in Affected objects/services, domain in
Domain/tool, and the dedicated criticality, type, confidence, review and inclusion columns.

Missing artifacts, invalid pointers, changed hashes, absent collection times/datasets and
failed collections remain explicit or blank as appropriate. A classification-only imported
frozen GCP feed has no original configuration: its rows say so and never borrow AWS data.
Lookup is bounded to the importer's 64 MiB per-file limit. No analyzer, collector, rule,
normalizer, schema, API, GUI, launcher, workspace resolver or deployment script is changed.
Existing built reports and frozen editions are not rewritten. Standalone historical
Finalized/SRE workbook downloads retain their existing formats.

Optional future work: expose this register in the GUI and extend the standalone Finalized/
SRE download formats. That would require a separately scoped design and, for live GUI
querying, API/React work. None is implemented here.

Validation and release results are recorded in TEST_PLAN.md and the ignored sprint
artifacts. Native Windows and native Microsoft Excel execution require their own hosts;
OOXML table/filter/hyperlink checks are not a claim of native Office execution.
