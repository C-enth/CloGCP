"""Offline Word-compatible RTF and text exports of immutable approved narratives."""

from pathlib import Path

from offline_analyzer.findings.report_ready import approved_revisions, verify_snapshots
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.environment import run_origins, workspace_environment
from offline_analyzer.storage.store import Store


def rtf_escape(text: str) -> str:
    """Emit literal text only: no fields, objects, links or RTF commands from input."""
    parts = []
    for char in text:
        if char in "\\{}":
            parts.append("\\" + char)
        elif char == "\n":
            parts.append("\\par\n")
        elif char == "\t":
            parts.append("\\tab ")
        elif 32 <= ord(char) < 127:
            parts.append(char)
        elif ord(char) >= 32:
            encoded = char.encode("utf-16-le")
            for i in range(0, len(encoded), 2):
                number = int.from_bytes(encoded[i : i + 2], "little")
                parts.append(f"\\u{number if number < 32768 else number - 65536}?")
    return "".join(parts)


def export_approved(
    store: Store, run: str, path: Path, kind: str, selected: list[str] | None = None, progress=None
) -> None:
    revisions = approved_revisions(store, run, selected)
    if not revisions:
        raise InputError("NO_APPROVED_REPORT_FINDINGS")
    verify_snapshots(store, revisions)
    environment = workspace_environment(store.workspace)
    label = environment.label if environment else "UNLABELED — NOT APPROVED FOR CUSTOMER REPORTING"
    dataset_origin = run_origins(store.workspace).get(run, "UNRECORDED")
    header = f"CloSec\nWorkspace: {label}\nRun: {run}\nOrigin: {dataset_origin}\n"
    if kind == "approved-docx":
        from offline_analyzer.reporting.docx import write_text_docx

        text = header + "\n\n".join(
            f"Report ID: {r.report_id} | Revision: {r.revision}\n{r.report_text}" for r in revisions
        )
        write_text_docx("Approved client findings", text, path)
        return
    with path.open("x", encoding="utf-8") as output:
        if kind == "approved-rtf":
            output.write("{\\rtf1\\ansi\\deff0\\uc1{\\fonttbl{\\f0 Calibri;}}\\f0\\fs22\n")
            output.write(rtf_escape(header))
        else:
            output.write(header)
        for index, revision in enumerate(revisions, 1):
            text = (
                f"\nReport ID: {revision.report_id} | Revision: {revision.revision}\n\n"
                f"{revision.report_text}\n"
            )
            output.write(rtf_escape(text) if kind == "approved-rtf" else text)
            if progress:
                progress("Writing approved findings", index, len(revisions))
        if kind == "approved-rtf":
            output.write("}")
