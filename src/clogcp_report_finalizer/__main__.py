"""CloGCP Report Finalizer CLI and optional native local file-selection window."""

import argparse
import json
from pathlib import Path

from .core import finalize
from .safety import FinalizerError


def gui() -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox

    root = tk.Tk()
    root.title("CloGCP Report Finalizer")
    root.geometry("850x420")
    entries = {}
    labels = {
        "source": "Exported GCP Excel",
        "evidence": "Evidence workbook (optional)",
        "guidance": "Verification / selection guidance (optional)",
        "paths": "Attack paths JSON (optional)",
        "history": "Reconciliation JSON (optional)",
        "output": "New output folder",
    }
    for n, (key, label) in enumerate(labels.items()):
        tk.Label(root, text=label, anchor="w").grid(row=n, column=0, padx=12, pady=10, sticky="w")
        value = tk.StringVar()
        entries[key] = value
        tk.Entry(root, textvariable=value, width=65).grid(row=n, column=1)

        def select(k=key, variable=value):
            path = (
                filedialog.askdirectory()
                if k == "output"
                else filedialog.askopenfilename(
                    filetypes=[("Selected local files", "*.xlsx *.json")]
                )
            )
            if path:
                # Choose a new child directory; existing folders are never overwritten.
                variable.set(str(Path(path) / "CloGCP-finalized-report") if k == "output" else path)

        tk.Button(root, text="Browse", command=select).grid(row=n, column=2, padx=8)

    def run():
        try:
            values = {k: Path(v.get()) for k, v in entries.items() if v.get()}
            result = finalize(
                values["source"],
                values["output"],
                evidence_files=[values["evidence"]] if "evidence" in values else [],
                guidance=values.get("guidance"),
                attack_paths=[values["paths"]] if "paths" in values else [],
                history=[values["history"]] if "history" in values else [],
            )
            messagebox.showinfo(
                "Report prepared",
                f"{result['client_observations']} observations retained. "
                f"{result['qa_issues']} QA items. Review the summary before client release.",
            )
        except Exception:
            messagebox.showerror(
                "Unable to prepare report",
                (
                    "Check the selected workbook, optional files and new output folder. Use "
                    "the CLI for a fixed diagnostic code."
                ),
            )

    tk.Label(
        root,
        text=(
            "Offline files only. Source ratings and decisions are retained. No "
            "commands are executed."
        ),
    ).grid(row=7, column=0, columnspan=3, pady=10)
    tk.Button(root, text="Prepare review copy", command=run).grid(row=8, column=1)
    root.mainloop()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CloGCP Report Finalizer — offline exported-file utility"
    )
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    for name in ("evidence", "attack-paths", "coverage", "history"):
        parser.add_argument("--" + name, type=Path, action="append", default=[])
    parser.add_argument("--guidance", type=Path)
    parser.add_argument("--engine-acceptance", type=Path)
    parser.add_argument("--verification-report", type=Path)
    parser.add_argument("--final", action="store_true")
    parser.add_argument(
        "--origin", choices=["SYNTHETIC", "ASSESSMENT", "UNSPECIFIED"], default="UNSPECIFIED"
    )
    args = parser.parse_args()
    if args.gui:
        gui()
        return
    if not args.input or not args.output:
        parser.error("--input and --output are required")
    result = finalize(
        args.input,
        args.output,
        evidence_files=args.evidence,
        guidance=args.guidance,
        attack_paths=args.attack_paths,
        coverage=args.coverage,
        history=args.history,
        acceptance=args.engine_acceptance,
        verification_report=args.verification_report,
        release=args.final,
        origin=args.origin,
    )
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "source_observations",
                    "client_observations",
                    "qa_issues",
                    "release_status",
                )
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except FinalizerError as exc:
        raise SystemExit(str(exc)) from None
    except (ValueError, TypeError, KeyError, OSError):
        raise SystemExit("FINALIZER_INVALID_INPUT_OR_UNAVAILABLE") from None
