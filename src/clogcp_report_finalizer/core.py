"""Standalone finalization of explicitly selected files. No analyzer/database imports."""

import hashlib
import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from .evidence import exported_evidence, focus, table
from .formatting import add_table, chunks, link
from .narratives import narrative
from .safety import FinalizerError, digest, literal, read_json, workbook
from .schema import CLIENT_REGISTER, COLUMNS, REGISTER, VERSION


class Acceptance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: str = "clogcp-engine-acceptance-1"
    engine_version: str = Field(pattern=r"^2\.[0-9]+\.[0-9]+$")
    status: str = Field(pattern=r"^ACCEPTED$")
    accepted_by: str = Field(min_length=1, max_length=200)
    accepted_at: AwareDatetime
    verification_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def stable(prefix: str, data: object) -> str:
    return (
        prefix
        + hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()[:24]
    )


def _guidance(path: Path | None) -> dict:
    if not path:
        return {}
    data = read_json(path)
    if not isinstance(data, dict) or data.get("schema_version") != "clogcp-finalizer-guidance-1":
        raise FinalizerError("UNSUPPORTED_GUIDANCE_SCHEMA")
    records = data.get("records")
    if not isinstance(records, dict) or len(records) > 50000:
        raise FinalizerError("INVALID_GUIDANCE_RECORDS")
    return records


def _optional(paths: list[Path], name: str) -> list[dict]:
    result = []
    for path in paths:
        data = read_json(path)
        rows = (
            data
            if isinstance(data, list)
            else data.get(name, [])
            if isinstance(data, dict)
            else None
        )
        if (
            not isinstance(rows, list)
            or len(rows) > 50000
            or any(not isinstance(r, dict) for r in rows)
        ):
            raise FinalizerError("INVALID_OPTIONAL_INPUT")
        result.extend(rows)
    return result


def _neutralize(book) -> list[list]:
    changes = []
    for sheet in book:
        for row in sheet:
            for cell in row:
                if cell.data_type == "f":
                    changes.append(
                        [
                            sheet.title,
                            cell.coordinate,
                            "Formula retained as literal text; never evaluated",
                        ]
                    )
                if isinstance(cell.value, str):
                    literal(cell, cell.value)
                if cell.hyperlink:
                    target = cell.hyperlink.location or (cell.hyperlink.target or "").removeprefix(
                        "#"
                    )
                    if "!" in target:
                        name, address = target.rsplit("!", 1)
                        name = name.strip("'").replace("''", "'")
                        try:
                            destination = book[name][address] if name in book else None
                            if destination is None or destination.value is None:
                                if (
                                    destination is not None
                                    and book[name].cell(destination.row, 1).value
                                ):
                                    link(cell, name, destination.row)
                                else:
                                    cell.hyperlink = None
                                changes.append(
                                    [
                                        sheet.title,
                                        cell.coordinate,
                                        (
                                            "Broken source hyperlink repaired to its source row, "
                                            "or removed when "
                                            "unresolved; source values preserved"
                                        ),
                                    ]
                                )
                        except (ValueError, KeyError, TypeError):
                            cell.hyperlink = None
                            changes.append(
                                [
                                    sheet.title,
                                    cell.coordinate,
                                    "Unresolved source hyperlink removed; source value preserved",
                                ]
                            )
    return changes


def _consolidation(row: dict, context: dict, selected: list[dict]) -> tuple[str, str]:
    canonical = context.get("canonical") or {}
    required = (
        "project",
        "resource",
        "root_cause",
        "principal_or_workload",
        "evidence_scope",
        "mechanism",
    )
    if (
        not all(isinstance(canonical.get(k), str) and canonical[k] for k in required)
        or not selected
    ):
        return "", "ANALYST_REVIEW_REQUIRED"
    # All source values except IDs, evidence locators, sequence and related-record text
    # must agree. This keeps conflicting decisions/ratings in separate issues.
    ignored = {COLUMNS[i] for i in (0, 10, 11, 23, 26, 32, 36)}
    values = {k: v for k, v in row.items() if k not in ignored}
    evidence = [
        {"selected": e["selected"], "qualifying_controls": e["qualifying_controls"]}
        for e in selected
    ]
    return stable("issue-", [canonical, values, evidence]), "EXACT_EQUIVALENCE"


def _qa(
    register_rows: list[dict],
    focused: list,
    narratives: list[dict],
    paths: list[dict],
    history: list[dict],
) -> list[list]:
    issues = []
    possible_duplicates = defaultdict(list)

    def add(record, category, detail, state="OPEN_ASSESSOR_REVIEW"):
        issues.append(
            [
                stable("qa-", [record, category, detail]),
                record,
                category,
                state,
                detail,
                "Resolve technical corrections in CloGCP; no decision is changed by this tool.",
            ]
        )

    for row, evidence, text in zip(register_rows, focused, narratives, strict=True):
        record = str(row[COLUMNS[0]])
        key, _basis = _consolidation(row, evidence.context, evidence.entries)
        possible_duplicates[
            (row.get(COLUMNS[1]), row.get(COLUMNS[2]), row.get(COLUMNS[27]))
        ].append((record, key))
        if not evidence.context.get("canonical"):
            add(
                record,
                "UNCERTAIN_CONSOLIDATION",
                "Canonical root-cause, principal, evidence-scope and mechanism mapping "
                "unavailable; no automatic merge.",
            )
        if not row.get(COLUMNS[11]):
            add(
                record,
                "MISSING_SOURCE_REFERENCE",
                "Original evidence reference is missing; resolve traceability in CloGCP.",
            )
        if not evidence.entries:
            add(
                record,
                "MISSING_FOCUSED_EVIDENCE",
                "Evidence detail unavailable; supply precise exported evidence and selectors.",
            )
        for limitation in evidence.limitations:
            add(record, "EVIDENCE_LIMITATION", limitation)
        if not row.get(COLUMNS[2]) or not row.get(COLUMNS[27]):
            add(
                record,
                "MISSING_RESOURCE_ATTRIBUTION",
                "Project or canonical affected resource is missing.",
            )
        if row.get(COLUMNS[4]) and not row.get(COLUMNS[5]):
            add(
                record,
                "SEVERITY_WITHOUT_RATIONALE",
                "Original severity retained; a justification is required.",
            )
        if not row.get(COLUMNS[37]) or "pending" in str(row.get(COLUMNS[39]) or "").lower():
            add(
                record,
                "MISSING_REVIEW",
                "No complete assessor review record was exported. No approval has been invented.",
            )
        if text["verification"].startswith("Verification procedure required"):
            add(record, "MISSING_VERIFICATION", text["verification"])
        if "PROVEN" in str(row.get(COLUMNS[24]) or "").upper():
            add(
                record,
                "LEGACY_PATH_CONCLUSION",
                "Legacy PROVEN is retained in the source; it is not converted to SUPPORTED.",
            )
        if str(row.get(COLUMNS[25]) or "").upper() == "PASS":
            add(
                record,
                "PASS_SCOPE_REVIEW",
                (
                    "A source criterion PASS does not establish a control-level Pass or an "
                    "approved exception."
                ),
            )
        if any(
            w in str(row.get(COLUMNS[23]) or "").lower()
            for w in ("confirmed exploitation", "successfully exploited", "no risk")
        ):
            add(
                record,
                "NARRATIVE_EXCEEDS_EVIDENCE",
                "Review the original narrative's execution/safety claim against supplied evidence.",
            )
        if row.get(COLUMNS[14]) or row.get(COLUMNS[21]):
            add(
                record,
                "UNRESOLVED_SOURCE_LIMITATIONS",
                str(row.get(COLUMNS[14]) or row.get(COLUMNS[21])),
            )
        for assertion in evidence.context.get("assertions", []):
            matches = [
                entry for entry in evidence.entries if entry["mapping"] == assertion.get("mapping")
            ]
            if not matches or assertion.get("pointer") not in matches[0]["selected"]:
                add(
                    record,
                    "ASSERTION_EVIDENCE_UNAVAILABLE",
                    "Exact assertion field was not reconstructed.",
                )
            elif matches[0]["selected"][assertion["pointer"]] != assertion.get("observed_value"):
                add(
                    record,
                    "OBSERVATION_EVIDENCE_CONTRADICTION",
                    (
                        "Exported actual value conflicts with the supplied source-observation "
                        "assertion; resolve in CloGCP."
                    ),
                )
        source_text = str(row.get(COLUMNS[22]) or "").lower()
        if (
            "approved compensating" in source_text or "approved exception" in source_text
        ) and "approved by" not in str(row.get(COLUMNS[29]) or "").lower():
            add(
                record,
                "UNSUPPORTED_COMPENSATING_CONTROL",
                "An approval claim lacks an identifiable exported approval record.",
            )
    for members in possible_duplicates.values():
        if len(members) > 1:
            exact = bool(members[0][1]) and len({m[1] for m in members}) == 1
            add(
                "; ".join(m[0] for m in members),
                "DUPLICATE_REPORTABLE_OBSERVATIONS",
                "Exact equivalent entries grouped in Consolidated_Issues; "
                "every source row retained."
                if exact
                else "Potential duplicate entries have differing or incomplete material context; "
                "assessor review required.",
                "EXACT_EQUIVALENCE_GROUPED" if exact else "OPEN_ASSESSOR_REVIEW",
            )
    for p in paths:
        state = p.get("classification", p.get("proof_status", ""))
        if state == "PROVEN" or (
            state == "SUPPORTED"
            and (
                not p.get("prerequisites")
                or any(c.get("state") != "AVAILABLE" for c in p.get("prerequisites", []))
            )
        ):
            add(
                p.get("path_id", ""),
                "UNSUPPORTED_ATTACK_CONCLUSION",
                (
                    "Supplied path conclusion lacks complete mandatory configuration "
                    "support. Preserved for assessor review."
                ),
            )
        if p.get("exploitation_verification") not in {None, "UNVERIFIED"}:
            add(
                p.get("path_id", ""),
                "EXECUTION_CLAIM_REQUIRES_REVIEW",
                "The finalizer cannot verify successful exploitation.",
            )
    for h in history:
        if h.get("match_status") in {"UNMATCHED", "AMBIGUOUS"} or not h.get("new_paths"):
            add(
                h.get("legacy_path_id", ""),
                "INCOMPLETE_HISTORY_RECONCILIATION",
                "Original historical record has no unambiguous reconciled chain.",
            )
    return issues


def finalize(
    source: Path,
    output: Path,
    *,
    evidence_files: list[Path] | None = None,
    guidance: Path | None = None,
    attack_paths: list[Path] | None = None,
    coverage: list[Path] | None = None,
    history: list[Path] | None = None,
    acceptance: Path | None = None,
    verification_report: Path | None = None,
    release: bool = False,
    origin: str = "UNSPECIFIED",
) -> dict:
    evidence_files, attack_paths, coverage, history = (
        evidence_files or [],
        attack_paths or [],
        coverage or [],
        history or [],
    )
    inputs = [
        p.resolve()
        for p in [
            source,
            *evidence_files,
            *attack_paths,
            *coverage,
            *history,
            *([guidance] if guidance else []),
            *([acceptance] if acceptance else []),
            *([verification_report] if verification_report else []),
        ]
    ]
    if len(inputs) > 20 or len(set(inputs)) != len(inputs):
        raise FinalizerError("INPUT_COUNT_OR_DUPLICATE_SELECTION")
    hashes = {p: digest(p) for p in inputs}
    if sum(p.stat().st_size for p in inputs) > 128 * 1024 * 1024:
        raise FinalizerError("TOTAL_INPUT_BYTE_LIMIT")
    accepted = False
    if acceptance and verification_report:
        record = Acceptance.model_validate(read_json(acceptance))
        accepted = record.verification_report_sha256 == hashes[verification_report.resolve()]
        if not accepted:
            raise FinalizerError("ENGINE_VERIFICATION_HASH_MISMATCH")
    if release and not accepted:
        raise FinalizerError("FINAL_RELEASE_REQUIRES_ENGINE_ACCEPTANCE")
    if output.exists() or output.resolve() in inputs:
        raise FinalizerError("NEW_OUTPUT_DIRECTORY_REQUIRED")
    book = workbook(source)
    extra_books = []
    try:
        if REGISTER not in book or tuple(c.value for c in book[REGISTER][1]) != COLUMNS:
            raise FinalizerError("APPROVED_40_COLUMN_SCHEMA_REQUIRED")
        reserved = {
            CLIENT_REGISTER,
            "Assessment_Summary",
            "Finding_Analysis",
            "Focused_Evidence",
            "QA_Register",
            "Evidence_Limitations",
            "Source_Reconciliation",
            "Consolidated_Issues",
            "Input_Provenance",
            "Presentation_Changes",
            "Finalizer_Attack_Paths",
            "Finalizer_Coverage",
            "History_Reconciliation",
        }
        if reserved.intersection(book.sheetnames):
            raise FinalizerError("FINALIZER_SHEET_NAME_COLLISION")
        sanitized = _neutralize(book)
        original = table(book[REGISTER])
        if len(original) > 50000:
            raise FinalizerError("REGISTER_ROW_LIMIT")
        extra_books = [workbook(p) for p in evidence_files]
        evidence = exported_evidence([book, *extra_books])
        guides = _guidance(guidance)
        focused = [
            focus(
                str(r[COLUMNS[0]]),
                evidence.get(str(r[COLUMNS[0]]), []),
                guides.get(str(r[COLUMNS[0]])),
            )
            for r in original
        ]
        narratives = [narrative(r, e) for r, e in zip(original, focused, strict=True)]
        paths = _optional(attack_paths, "paths")
        histories = _optional(history, "reconciliation")
        coverages = _optional(coverage, "coverage")
        qa = _qa(original, focused, narratives, paths, histories)
        for number, change in enumerate(sanitized):
            if "hyperlink" in change[2].lower():
                qa.append(
                    [
                        f"qa-source-navigation-{number}",
                        "",
                        "BROKEN_SOURCE_NAVIGATION",
                        "REPAIRED_COPY_REVIEW_REQUIRED",
                        change[2],
                        "Review Presentation_Changes; original input remains unchanged.",
                    ]
                )
        if not accepted:
            qa.append(
                [
                    "qa-engine-acceptance",
                    "",
                    "ENGINE_ACCEPTANCE_NOT_SUPPLIED",
                    "OPEN_ASSESSOR_REVIEW",
                    "Engine acceptance is not established by this finalizer run.",
                    (
                        "Provide a signed-off acceptance record and its explicitly selected "
                        "verification report before final release."
                    ),
                ]
            )
        changes, prepared, analysis, details, reconciliation = [], [], [], [], []
        group_members, group_rows = defaultdict(list), {}
        for number, (row, e, text) in enumerate(zip(original, focused, narratives, strict=True), 2):
            record = str(row[COLUMNS[0]] or "")
            snippet = (
                json.dumps(
                    [
                        {"selected": v["selected"], "qualifying_controls": v["qualifying_controls"]}
                        for v in e.entries
                    ],
                    ensure_ascii=True,
                    sort_keys=True,
                )
                if e.entries
                else "Evidence detail unavailable"
            )
            values = [row.get(c) for c in COLUMNS]
            replacement = snippet[:900] + (
                "\nSee Focused_Evidence for all parts." if len(snippet) > 900 else ""
            )
            if values[10] != replacement:
                changes.append(
                    [
                        record,
                        COLUMNS[10],
                        f"'{REGISTER}'!K{number}",
                        "Focused exported configuration only; no security conclusion changed",
                    ]
                )
                values[10] = replacement
            prepared.append(values)
            analysis.append(
                [
                    record,
                    text["domain"],
                    text["observed"][:1800],
                    text["why"],
                    text["scenario"],
                    text["exception"],
                    text["remediation"],
                    text["verification"],
                    text["expected"],
                    text["supports"],
                    text["contradicts"],
                    text["challenge"],
                    text["unresolved"],
                ]
            )
            for entry in e.entries:
                serialized = json.dumps(entry, ensure_ascii=True, sort_keys=True, indent=2)
                for part, chunk in enumerate(chunks(serialized), 1):
                    details.append(
                        [
                            record,
                            entry["mapping"],
                            part,
                            chunk,
                            entry["reference"],
                            entry["locator"],
                            entry["collected"],
                            entry["source_sha256"],
                            (
                                "Original raw hash is a source declaration; exported JSON verified "
                                "against selected file only"
                            ),
                        ]
                    )
            key, basis = _consolidation(row, e.context, e.entries)
            key = key or stable("issue-", [record, number])
            group_members[key].append(record)
            group_rows.setdefault(
                key,
                [key, row[COLUMNS[1]], row[COLUMNS[2]], row[COLUMNS[27]], row[COLUMNS[4]], basis],
            )
            reconciliation.append(
                [
                    record,
                    REGISTER,
                    number,
                    CLIENT_REGISTER,
                    number,
                    key,
                    basis,
                    "Original cells preserved; only focused evidence presentation is refined",
                ]
            )
        client = add_table(
            book,
            CLIENT_REGISTER,
            COLUMNS,
            prepared,
            [27, 46, 25, 46, 17, 42, 20, 44, 44, 23, 60, 38] + [38] * 28,
        )
        add_table(
            book,
            "Finding_Analysis",
            [
                "Record ID",
                "Domain",
                "What was observed?",
                "Why was it flagged?",
                "What could go wrong?",
                "When might it be acceptable?",
                "What should change?",
                "Read-only verification",
                "Expected secure result",
                "Supports the observation",
                "Contradicts the observation",
                "Exception evidence requested",
                "Unresolved conditions",
            ],
            analysis,
        )
        detail_sheet = add_table(
            book,
            "Focused_Evidence",
            [
                "Record ID",
                "Evidence mapping ID",
                "Part",
                "Focused configuration and qualifying controls",
                "Original reference",
                "Source JSON path",
                "Assessment / collection timestamp",
                "Declared source SHA-256",
                "Verification limitation",
            ],
            details,
            [27, 28, 9, 110, 42, 35, 27, 35, 50],
        )
        first_detail = {}
        original_rows = {}
        for n, row in enumerate(original, 2):
            original_rows.setdefault(str(row[COLUMNS[0]]), n)
        for r in range(2, detail_sheet.max_row + 1):
            first_detail.setdefault(str(detail_sheet.cell(r, 1).value), r)
            record = str(detail_sheet.cell(r, 1).value)
            if record in original_rows:
                link(detail_sheet.cell(r, 1), CLIENT_REGISTER, original_rows[record])
        for r in range(2, client.max_row + 1):
            record = str(client.cell(r, 1).value)
            if record in first_detail:
                link(client.cell(r, 11), "Focused_Evidence", first_detail[record])
            link(client.cell(r, 1), REGISTER, r)
        add_table(
            book,
            "QA_Register",
            ["QA ID", "Record ID", "Category", "Resolution state", "Issue", "Required action"],
            qa,
        )
        limitations = [
            [str(row[COLUMNS[0]]), value, "OPEN_ASSESSOR_REVIEW"]
            for row, e in zip(original, focused, strict=True)
            for value in e.limitations
        ]
        add_table(
            book,
            "Evidence_Limitations",
            ["Record ID", "Evidence limitation", "Resolution state"],
            limitations,
        )
        add_table(
            book,
            "Source_Reconciliation",
            [
                "Source record ID",
                "Source sheet",
                "Source row",
                "Client sheet",
                "Client row",
                "Consolidated ID",
                "Consolidation basis",
                "Preservation",
            ],
            reconciliation,
        )
        add_table(
            book,
            "Consolidated_Issues",
            [
                "Consolidated ID",
                "Observation",
                "Project",
                "Resource",
                "Criticality",
                "Basis",
                "Supporting source IDs",
                "Source record count",
            ],
            [
                v + ["; ".join(group_members[k]), len(group_members[k])]
                for k, v in group_rows.items()
            ],
        )
        add_table(
            book,
            "Presentation_Changes",
            [
                "Record ID / source sheet",
                "Column / cell",
                "Original location / reason",
                "Transformation",
            ],
            changes + sanitized,
        )
        add_table(
            book,
            "Input_Provenance",
            ["Selected input", "SHA-256", "Original modified?"],
            [[p.name, h, "No"] for p, h in hashes.items()],
        )
        for title, records in (
            ("Finalizer_Attack_Paths", paths),
            ("Finalizer_Coverage", coverages),
            ("History_Reconciliation", histories),
        ):
            if records:
                add_table(
                    book,
                    title,
                    ["Source row", "Original exported record"],
                    [
                        [i, chunk]
                        for i, record in enumerate(records, 1)
                        for chunk in chunks(json.dumps(record, ensure_ascii=True, sort_keys=True))
                    ],
                    [14, 115],
                )
        duplicate_count = sum(len(v) - 1 for v in group_members.values())
        summary = {
            "schema_version": "clogcp-report-finalizer-1",
            "version": VERSION,
            "generated_at": datetime.now(UTC).isoformat(),
            "origin": origin,
            "source_observations": len(original),
            "client_observations": len(prepared),
            "consolidated_issues": len(group_rows),
            "equivalent_source_duplicates": duplicate_count,
            "qa_issues": len(qa),
            "focused_evidence_parts": len(details),
            "engine_acceptance": "SUPPLIED_AND_HASH_MATCHED" if accepted else "NOT_ESTABLISHED",
            "release_status": "ASSESSOR_REVIEW_REQUIRED" if qa else "PREPARED_FOR_CLIENT_REVIEW",
            "input_hashes": {p.name: h for p, h in hashes.items()},
            "native_excel_rendering": "PENDING",
            "analyzer_invoked": False,
            "database_accessed": False,
            "source_register_columns_unchanged": True,
        }
        add_table(
            book,
            "Assessment_Summary",
            ["CloGCP Report Finalizer", "Assessment preparation result"],
            [
                ["Dataset origin", origin],
                ["Report status", summary["release_status"]],
                ["Engine acceptance", summary["engine_acceptance"]],
                ["Original observations", len(original)],
                ["Client observations", len(prepared)],
                ["Consolidated issues", len(group_rows)],
                ["Equivalent supporting duplicates", duplicate_count],
                [
                    "Primary issue view",
                    "Consolidated_Issues groups exact equivalents. The 40-column register "
                    "retains every source record and original ID.",
                ],
                ["QA items requiring review", len(qa)],
                [
                    "Security ratings and reviews",
                    "Retained. Proposed technical corrections must be resolved in CloGCP.",
                ],
                [
                    "Evidence verification",
                    (
                        "Focused excerpts reconstructed from selected exported files; raw source "
                        "authenticity is not reverified."
                    ),
                ],
                [
                    "Batch 1 and Batch 2",
                    (
                        "Source records retained. Batch attribution is not inferred when it was "
                        "not exported."
                    ),
                ],
                [
                    "Native desktop Excel rendering",
                    "Pending. Workbook structures, values and internal links checked offline.",
                ],
            ],
            [38, 110],
        )
        # Retain every original tab. New reader-facing views precede the source sheets.
        order = [
            "Assessment_Summary",
            "Consolidated_Issues",
            CLIENT_REGISTER,
            "Finding_Analysis",
            "Focused_Evidence",
        ]
        book._sheets = [book[n] for n in order] + [s for s in book if s.title not in order]
        book.active = 0
        # Reconciliation checks independent of presentation transformations.
        protected = [i for i in range(40) if i != 10]
        for n, source_row in enumerate(original, 2):
            if any(client.cell(n, i + 1).value != source_row.get(COLUMNS[i]) for i in protected):
                raise FinalizerError("PROTECTED_VALUE_RECONCILIATION_FAILED")
        if any(digest(p) != h for p, h in hashes.items()):
            raise FinalizerError("INPUT_CHANGED_DURING_FINALIZATION")
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        target = output / "CloGCP-client-report.xlsx"
        book.save(target)
        verify_output(target)
        summary["output_sha256"] = digest(target)
        (output / "Assessor-QA-Exceptions.json").write_text(
            json.dumps(
                {
                    "schema_version": "clogcp-assessor-qa-1",
                    "columns": [
                        "QA ID",
                        "Record ID",
                        "Category",
                        "State",
                        "Detail",
                        "Required action",
                    ],
                    "exceptions": qa,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        (output / "qa-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        if any(digest(p) != h for p, h in hashes.items()):
            raise FinalizerError("INPUT_CHANGED_DURING_FINALIZATION")
        return summary
    finally:
        book.close()
        for extra in extra_books:
            extra.close()


def verify_output(path: Path) -> None:
    book = workbook(path)
    try:
        if tuple(c.value for c in book[CLIENT_REGISTER][1]) != COLUMNS:
            raise FinalizerError("OUTPUT_SCHEMA_RECONCILIATION_FAILED")
        for sheet in book:
            for row in sheet:
                for cell in row:
                    if cell.data_type == "f":
                        raise FinalizerError("ACTIVE_FORMULA_IN_OUTPUT")
                    if cell.hyperlink:
                        target = cell.hyperlink.location or (
                            cell.hyperlink.target or ""
                        ).removeprefix("#")
                        if "!" in target:
                            name, address = target.rsplit("!", 1)
                            name = name.strip("'").replace("''", "'")
                            if name not in book or book[name][address].value is None:
                                raise FinalizerError("BROKEN_INTERNAL_LINK")
    finally:
        book.close()
