"""Literal, self-contained Word OOXML. No input markup, links, fields or remote assets."""

import re
import zipfile
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, register_namespace, tostring

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
register_namespace("w", W)


def tag(name: str) -> str:
    return f"{{{W}}}{name}"


def paragraph(parent, text: object, style: str = "Normal", bold: bool = False):
    p = SubElement(parent, tag("p"))
    props = SubElement(p, tag("pPr"))
    SubElement(props, tag("pStyle"), {tag("val"): style})
    if bold:
        SubElement(props, tag("keepNext"))
    for i, line in enumerate(str(text if text is not None else "").split("\n")):
        run = SubElement(p, tag("r"))
        if bold:
            SubElement(SubElement(run, tag("rPr")), tag("b"))
        if i:
            SubElement(run, tag("br"))
        t = SubElement(run, tag("t"), {"{http://www.w3.org/XML/1998/namespace}space": "preserve"})
        t.text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", line)
    return p


def save(body, path: Path) -> None:
    document = Element(tag("document"))
    document.append(body)
    section = SubElement(body, tag("sectPr"))
    SubElement(section, tag("pgSz"), {tag("w"): "11906", tag("h"): "16838"})
    SubElement(section, tag("pgMar"), {tag(k): "1134" for k in ("top", "bottom", "left", "right")})
    styles = Element(tag("styles"))
    for name, size in (
        ("Normal", "22"),
        ("Title", "40"),
        ("Subtitle", "28"),
        ("Heading1", "30"),
        ("Heading2", "26"),
        ("Heading3", "23"),
        ("TableText", "17"),
    ):
        style = SubElement(styles, tag("style"), {tag("type"): "paragraph", tag("styleId"): name})
        SubElement(style, tag("name"), {tag("val"): name})
        p = SubElement(style, tag("pPr"))
        spacing = {tag("after"): "140", tag("line"): "276", tag("lineRule"): "auto"}
        if name == "TableText":
            spacing = {tag("after"): "20", tag("line"): "240", tag("lineRule"): "auto"}
        elif name not in {"Normal", "Subtitle"}:
            SubElement(p, tag("keepNext"))
            spacing[tag("before")] = "240"
        SubElement(p, tag("spacing"), spacing)
        r = SubElement(style, tag("rPr"))
        SubElement(r, tag("rFonts"), {tag("ascii"): "Calibri", tag("hAnsi"): "Calibri"})
        SubElement(r, tag("sz"), {tag("val"): size})
        SubElement(r, tag("color"), {tag("val"): "000000"})
        if name not in {"Normal", "Subtitle", "TableText"}:
            SubElement(r, tag("b"))
    types = (
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        "</Types>"
    )
    rel_header = (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    )
    rel_type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
    root_rels = (
        rel_header
        + '<Relationship Id="rId1" Type="'
        + rel_type
        + 'officeDocument" Target="word/document.xml"/></Relationships>'
    )
    doc_rels = (
        rel_header
        + '<Relationship Id="rId1" Type="'
        + rel_type
        + 'styles" Target="styles.xml"/></Relationships>'
    )
    with zipfile.ZipFile(path, "x", zipfile.ZIP_DEFLATED) as archive:
        for name, value in (
            ("[Content_Types].xml", types),
            ("_rels/.rels", root_rels),
            ("word/_rels/document.xml.rels", doc_rels),
            ("word/document.xml", tostring(document, encoding="utf-8", xml_declaration=True)),
            ("word/styles.xml", tostring(styles, encoding="utf-8", xml_declaration=True)),
        ):
            archive.writestr(name, value)


TEXT_WIDTH = 11906 - 2 * 1134  # A4 portrait text width in twips
GRID = {tag(k): v for k, v in (("val", "single"), ("sz", "4"), ("space", "0"), ("color", "BFBFBF"))}


def page_break(parent) -> None:
    SubElement(SubElement(SubElement(parent, tag("p")), tag("r")), tag("br"), {tag("type"): "page"})


def table(parent, rows: list[list], widths: list[int], header: bool = True) -> None:
    """Grid table; the header row repeats on every page and rows do not split."""
    scale = TEXT_WIDTH / sum(widths)
    widths = [int(w * scale) for w in widths]
    tbl = SubElement(parent, tag("tbl"))
    props = SubElement(tbl, tag("tblPr"))
    SubElement(props, tag("tblW"), {tag("w"): str(sum(widths)), tag("type"): "dxa"})
    borders = SubElement(props, tag("tblBorders"))
    for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
        SubElement(borders, tag(side), GRID)
    SubElement(props, tag("tblLayout"), {tag("type"): "fixed"})
    margins = SubElement(props, tag("tblCellMar"))
    for side in ("left", "right"):
        SubElement(margins, tag(side), {tag("w"): "70", tag("type"): "dxa"})
    grid = SubElement(tbl, tag("tblGrid"))
    for width in widths:
        SubElement(grid, tag("gridCol"), {tag("w"): str(width)})
    for index, row in enumerate(rows):
        head = header and index == 0
        tr = SubElement(tbl, tag("tr"))
        tr_props = SubElement(tr, tag("trPr"))
        SubElement(tr_props, tag("cantSplit"))
        if head:
            SubElement(tr_props, tag("tblHeader"))
        for width, value in zip(widths, row, strict=True):
            tc = SubElement(tr, tag("tc"))
            tc_props = SubElement(tc, tag("tcPr"))
            SubElement(tc_props, tag("tcW"), {tag("w"): str(width), tag("type"): "dxa"})
            if head:
                SubElement(
                    tc_props,
                    tag("shd"),
                    {tag("val"): "clear", tag("color"): "auto", tag("fill"): "EAECEF"},
                )
            paragraph(tc, value, "TableText", bold=head)
    paragraph(parent, "")


def labelled(parent, rows: list[tuple[str, str]]) -> None:
    table(parent, [["Item", "Detail"], *[[k, v] for k, v in rows]], [2600, 7000])


def document_body(data: dict) -> Element:
    """Cover, executive summary, coverage and limitations (UNKNOWN areas), attack surface,
    attack paths with hop tables, STRIDE and direction justification, findings, appendix."""
    from offline_analyzer.attack_paths.model import EDGE_STRIDE
    from offline_analyzer.reporting.report_document import (
        BASIS,
        COVERAGE_HEADERS,
        EDGE_MEANING,
        GLOSSARY,
        LIMITATIONS,
        NOTE_HEADERS,
        PATH_LIMIT,
        SEVERITIES,
        STRIDE,
        _finding_rows,
        _ordered_paths,
        _path_name,
        checklist_rows,
        coverage_rows,
        custom_lines,
        hop_evidence,
        note_rows,
        path_detail_rows,
        provider_scope,
        stride_surface,
        summary,
        unknown_rows,
    )

    s = summary(data)
    paths = _ordered_paths(data["paths"])
    body = Element(tag("body"))
    # Cover
    for _ in range(4):
        paragraph(body, "")
    paragraph(body, s["title"], "Title")
    paragraph(body, f"Cloud scope: {provider_scope(data)}", "Subtitle")
    labelled(body, s["control"])
    paragraph(body, BASIS)
    page_break(body)
    # 1 Executive summary
    paragraph(body, "1 Executive summary", "Heading1")
    paragraph(body, s["overview"])
    paragraph(body, "Findings by severity", "Heading2")
    table(
        body,
        [["Severity", "Findings"]]
        + [[x.title(), s["totals"].get(x, 0)] for x in SEVERITIES]
        + [["Total", sum(s["totals"].values())]],
        [5000, 4600],
    )
    paragraph(body, "Attack paths by proof status", "Heading2")
    table(
        body,
        [["Proof status", "Paths"]]
        + [[x, s["proof"].get(x, 0)] for x in ("PROVEN", "HYPOTHESIS", "BLOCKED")],
        [5000, 4600],
    )
    paragraph(body, "Findings by account / project", "Heading2")
    table(
        body,
        [["Account / project", "Name", *(x.title() for x in SEVERITIES), "Total"]]
        + [
            [
                f"{a['provider']} {a['scope']}",
                a["name"],
                *(a["severity"].get(x, 0) for x in SEVERITIES),
                a["total"],
            ]
            for a in s["accounts"]
        ],
        [2000, 2400, 800, 800, 800, 800, 800, 800],
    )
    paragraph(body, "Key risks", "Heading2")
    table(
        body,
        [["#", "Severity", "Finding", "Account / project"]]
        + (
            [
                [i, f["severity"], f["title"], f"{f['provider']} {f['scope']}"]
                for i, f in enumerate(s["key"], 1)
            ]
            or [["-", "-", "No findings", "-"]]
        ),
        [500, 1300, 5200, 2600],
    )
    page_break(body)
    # 2 Coverage and limitations
    paragraph(body, "2 Coverage and limitations", "Heading1")
    paragraph(body, "Evidence coverage by account / project", "Heading2")
    table(
        body,
        [COVERAGE_HEADERS, *coverage_rows(data)],
        [1700, 1500, 800, 1000, 700, 700, 900, 1200, 1100],
    )
    paragraph(body, "UNKNOWN and manual areas", "Heading2")
    paragraph(
        body,
        "Rules where evidence could not support an outcome (UNKNOWN or collection error) or a "
        "manual check is required. These areas are never reported as passing.",
    )
    unknown = unknown_rows(data)
    table(
        body,
        [["Account / project", "Name", "Rule", "Insufficient evidence", "Manual"]]
        + (unknown[:60] or [["None", "", "", 0, 0]]),
        [2200, 2000, 3000, 1300, 1100],
    )
    if len(unknown) > 60:
        paragraph(body, f"{len(unknown) - 60} further areas are listed in the Excel workbook.")
    paragraph(body, "Collection gaps and limitations", "Heading2")
    paragraph(
        body,
        "Why evidence is missing or partial: rate limits, expired sign-in, detail limits and "
        "IAM target-list fallbacks. Each is a collection gap, never a security result.",
    )
    notes = note_rows(data)
    table(
        body,
        [NOTE_HEADERS, *(notes[:60] or [["None", "", "", "", 0]])],
        [1700, 1300, 2000, 3800, 800],
    )
    if len(notes) > 60:
        paragraph(body, f"{len(notes) - 60} further rows are listed in the Excel workbook.")
    paragraph(body, "Attack-path coverage", "Heading2")
    table(
        body,
        [["Provider", "Path kind", "Formed", "Why"]]
        + [
            [r["provider"], r["kind"], r["formed"], r["reason"]]
            for r in data.get("path_coverage", [])
        ]
        + ([] if data.get("path_coverage") else [["-", "-", "-", "Not recorded for this edition"]]),
        [1000, 1800, 900, 5900],
    )
    paragraph(body, "Limitations", "Heading2")
    for text in LIMITATIONS:
        paragraph(body, "• " + text)
    for text in custom_lines(data):
        paragraph(body, "• " + text)
    page_break(body)
    # 3 Attack surface
    paragraph(body, "3 Attack surface", "Heading1")
    paragraph(
        body,
        "Every hop of every evaluated path counted under each STRIDE category its edge type "
        "maps to (proposed mapping). Entry points are where the paths start.",
    )
    table(
        body,
        [
            [
                "STRIDE category",
                "Paths",
                "Proven hops",
                "Hypothesis hops",
                "Blocked hops",
                "Entry points",
            ]
        ]
        + [
            [
                r["category"],
                r["paths"],
                r["proven"],
                r["hypothesis"],
                r["blocked"],
                f"{len(r['entries'])}: "
                + "; ".join(r["entries"][:5])
                + (f" (+{len(r['entries']) - 5})" if len(r["entries"]) > 5 else "")
                if r["entries"]
                else (
                    "No edge type maps to Repudiation" if r["category"] == "Repudiation" else "-"
                ),
            ]
            for r in stride_surface(paths)
        ],
        [1800, 700, 900, 1100, 900, 4200],
    )
    page_break(body)
    # 4 Attack paths
    paragraph(body, "4 Attack paths", "Heading1")
    paragraph(
        body,
        "Each path is a chain of directed hops from the entry point to the objective. A hop is "
        "PROVEN when the configuration creating it is cited from collected evidence, HYPOTHESIS "
        "when evidence is missing (named) and BLOCKED when evidence shows it does not exist. "
        "Configuration prerequisites only; exploitation was not performed.",
    )
    if not paths:
        paragraph(body, "No evaluated attack path matches this report scope.")
    for index, p in enumerate(paths[:PATH_LIMIT], 1):
        paragraph(body, f"4.{index} [{p['feasibility']}] {_path_name(p)}", "Heading2")
        labelled(body, path_detail_rows(p))
        hops = p.get("hops") or []
        if hops:
            paragraph(body, "Hops", "Heading3")
            table(
                body,
                [
                    [
                        "#",
                        "From",
                        "Edge",
                        "To",
                        "Status",
                        "STRIDE",
                        "Direction justification",
                        "Evidence",
                    ]
                ]
                + [
                    [
                        h["index"],
                        h["source"],
                        h["edge_type"],
                        h["target"],
                        h["status"],
                        ", ".join(h["stride"]),
                        h["justification"]
                        + (
                            " Missing: " + "; ".join(h["missing_evidence"])
                            if h.get("missing_evidence")
                            else ""
                        ),
                        hop_evidence(h),
                    ]
                    for h in hops
                ],
                [350, 1500, 1000, 1500, 900, 1100, 2100, 1350],
            )
        else:
            paragraph(body, "Hop model not recorded for this path (edition before hop model).")
    if len(paths) > PATH_LIMIT:
        paragraph(
            body, f"{len(paths) - PATH_LIMIT} further paths are listed in the Excel workbook."
        )
    page_break(body)
    # 5 STRIDE and direction justification
    paragraph(body, "5 STRIDE and direction justification", "Heading1")
    paragraph(
        body,
        "Each edge type has a fixed direction (source → target) and a proposed STRIDE mapping. "
        "Every hop in section 4 states why access flows in that direction. Repudiation is not "
        "mapped: no edge type removes audit evidence.",
    )
    table(
        body,
        [["Edge type", "Meaning (source → target)", "STRIDE"]]
        + [
            [edge, EDGE_MEANING.get(edge, ""), ", ".join(cats)]
            for edge, cats in EDGE_STRIDE.items()
        ],
        [2200, 4400, 3000],
    )
    paragraph(body, "STRIDE categories", "Heading2")
    paragraph(body, ", ".join(STRIDE))
    page_break(body)
    # 6 Findings
    paragraph(body, "6 Findings", "Heading1")
    if not data["findings"]:
        paragraph(
            body,
            "No findings match the selected review and cloud scope. "
            "This does not establish security assurance.",
        )
    number = 0
    grouped = data.get("grouped") and data.get("groups") is not None
    for severity in SEVERITIES:
        if grouped:
            # One entry per root-cause group; its members are listed as affected resources.
            entries = [g for g in data["groups"] if g["severity"] == severity]
            if not entries:
                continue
            paragraph(body, f"{severity.title()} findings ({len(entries)} groups)", "Heading2")
            for entry in entries:
                number += 1
                paragraph(
                    body,
                    f"6.{number} {entry['title']} ({entry['affected_resources']} affected "
                    "resource(s))",
                    "Heading3",
                )
                labelled(body, _finding_rows(entry["representative"]))
                table(
                    body,
                    [
                        ["Finding ID", "Account / project", "Resource", "Severity", "Status"],
                        *[
                            [
                                m["id"],
                                f"{m['provider']} {m['scope']}",
                                m["resource"],
                                m["severity"],
                                m["status"],
                            ]
                            for m in entry["members"]
                        ],
                    ],
                    [2400, 1800, 3000, 1000, 1400],
                )
            continue
        group = [f for f in data["findings"] if f["severity"] == severity]
        if not group:
            continue
        paragraph(body, f"{severity.title()} findings ({len(group)})", "Heading2")
        for finding in group:
            number += 1
            paragraph(body, f"6.{number} {finding['title']}", "Heading3")
            labelled(body, _finding_rows(finding))
    page_break(body)
    # Appendix
    paragraph(body, "Appendix A Glossary and evidence basis", "Heading1")
    paragraph(body, BASIS)
    table(body, [["Term", "Meaning"], *[[t, m] for t, m in GLOSSARY]], [2600, 7000])
    paragraph(body, "Appendix B Control coverage", "Heading1")
    table(
        body,
        [["Control", "Title", "AWS", "GCP"], *checklist_rows(data)]
        if data.get("checklist")
        else [["Control", "Title", "AWS", "GCP"], ["-", "Not recorded", "-", "-"]],
        [1000, 5000, 1800, 1800],
    )
    from offline_analyzer.reporting.report_document import EXCLUDED_NOTE, excluded_rows

    paragraph(body, "Appendix C Excluded findings", "Heading1")
    paragraph(body, EXCLUDED_NOTE)
    table(
        body,
        [["Rule", "Reason", "Detail", "Count"], *(excluded_rows(data) or [["None", "", "", 0]])],
        [2400, 2600, 3600, 1000],
    )
    return body


def write_docx(data: dict, path: Path) -> None:
    save(document_body(data), path)


def write_text_docx(title: str, text: str, path: Path) -> None:
    body = Element(tag("body"))
    paragraph(body, title, "Title")
    for line in text.split("\n"):
        paragraph(body, line)
    save(body, path)
