"""Stable offline R0 CLI. Runtime contains no AWS or hosted service calls."""

import argparse
import json
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from offline_analyzer.contracts.r0 import AWS_OPERATIONS
from offline_analyzer.findings.generate import record_decision
from offline_analyzer.ingestion.importer import import_package, single_file_package
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.inventory.accounts import install_registry, workspace_registry
from offline_analyzer.inventory.environment import (
    check_origin,
    record_run_origin,
    set_environment,
    workspace_environment,
)
from offline_analyzer.reporting.excel import export_excel
from offline_analyzer.reporting.metrics import assessment_metrics
from offline_analyzer.reporting.tracker import load_account_keys
from offline_analyzer.rules.engine import assess
from offline_analyzer.storage.store import Store


def summary(store: Store, run_id: str) -> dict:
    return assessment_metrics(store, run_id)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--workspace", required=True, type=Path)
    commands = root.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser(
        "import", help="Import a package directory (manifest.json or collector-manifest.json)"
    )
    ingest.add_argument("package", type=Path)
    origin_help = "Declared dataset origin; ASSESSMENT workspaces require tool-generated"
    ingest.add_argument("--origin", choices=["synthetic", "tool-generated"], help=origin_help)
    file = commands.add_parser(
        "import-file", help="Import supported JSON with explicit source context"
    )
    file.add_argument("file", type=Path)
    file.add_argument("--format", required=True, choices=["aws-json-v1", "prowler-ocsf-5.10"])
    file.add_argument("--operation", required=True, choices=[*AWS_OPERATIONS, "prowler:Scan"])
    file.add_argument("--account")
    file.add_argument("--region")
    file.add_argument("--collected-at", required=True, help="ISO 8601 with timezone")
    file.add_argument("--origin", choices=["synthetic", "tool-generated"], help=origin_help)
    environment = commands.add_parser(
        "environment", help="Label the workspace SYNTHETIC or ASSESSMENT (once) or show it"
    )
    environment.add_argument("action", choices=["set", "show"])
    environment.add_argument("--label", choices=["synthetic", "assessment"])
    environment.add_argument("--name", default="")
    contract = commands.add_parser(
        "contract", help="Write the analyzer/collector contract JSON (no workspace data)"
    )
    contract.add_argument("--output", required=True, type=Path)
    reconcile = commands.add_parser(
        "reconcile", help="Stage-by-stage counts for one run (collector to exported report)"
    )
    reconcile.add_argument("--run", required=True)
    reconcile.add_argument("--markdown", action="store_true")
    backup = commands.add_parser("backup", help="Consistent workspace backup (stop the GUI first)")
    backup.add_argument("--output", required=True, type=Path)
    restore = commands.add_parser("restore", help="Restore a verified backup into --workspace")
    restore.add_argument("--from", dest="source", required=True, type=Path)
    enterprise = commands.add_parser(
        "enterprise", help="Build an enterprise assessment from imported runs"
    )
    enterprise.add_argument("--members", nargs="*", help="Run IDs; omit for all original imports")
    accounts = commands.add_parser(
        "accounts", help="Install or summarize the private approved account registry"
    )
    accounts.add_argument("action", choices=["load", "show"])
    accounts.add_argument("file", nargs="?", type=Path)
    for name in ("assess", "summary", "export", "review"):
        command = commands.add_parser(name)
        command.add_argument("--run", required=True)
        if name == "export":
            command.add_argument("--output", required=True, type=Path)
            command.add_argument(
                "--account-keys",
                type=Path,
                help="JSON map of 12-digit account IDs to approved tracker account keys",
            )
        if name == "review":
            command.add_argument("--finding", required=True)
            command.add_argument(
                "--status", required=True, choices=["CONFIRMED", "REJECTED", "NEEDS_VALIDATION"]
            )
            command.add_argument("--analyst", required=True)
            command.add_argument("--note", default="")
    return root


def import_origin(workspace: Path, declared: str | None) -> str:
    environment = workspace_environment(workspace)
    if declared is None:
        if environment and environment.label == "ASSESSMENT":
            raise InputError("ORIGIN_REQUIRED_FOR_ASSESSMENT_WORKSPACE")
        declared = "synthetic"
    check_origin(workspace, declared)
    return declared


@contextmanager
def private_copy(workspace: Path, source: Path):
    """Import from a workspace-private copy: ZIPs are unpacked safely and native collector
    folders are never modified by adapter-derived artifacts."""
    import shutil
    import tempfile

    from offline_analyzer.ingestion.archive import unpack_package
    from offline_analyzer.ingestion.collector_v030_native import is_native

    if source.is_dir() and not is_native(source):
        yield source
        return
    with tempfile.TemporaryDirectory(prefix="cli-import-", dir=workspace) as temporary:
        root = Path(temporary) / "package"
        if source.is_file() and source.suffix.lower() == ".zip":
            root.mkdir(mode=0o700)
            yield unpack_package(source, root)
        else:
            shutil.copytree(source, root, symlinks=True)
            yield root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "contract":
            from offline_analyzer.ingestion.collector import main as write_contract

            return write_contract(["--output", str(args.output)])
        if args.command in {"backup", "restore", "environment"}:
            from offline_analyzer.storage.backup import backup, restore

            if args.command == "backup":
                result = backup(args.workspace, args.output)
            elif args.command == "restore":
                result = restore(args.source, args.workspace)
            else:
                if args.action == "set":
                    if not args.label:
                        raise InputError("ENVIRONMENT_LABEL_REQUIRED")
                    set_environment(args.workspace, args.label.upper(), args.name)
                current = workspace_environment(args.workspace)
                result = {
                    "label": current.label if current else "UNLABELED",
                    "name": current.name if current else "",
                }
            print(json.dumps(result, indent=2))
            return 0
        with Store(args.workspace) as store:
            if args.command == "import":
                origin = import_origin(store.workspace, args.origin)
                with private_copy(store.workspace, args.package) as package:
                    run = import_package(store, package)
                record_run_origin(store.workspace, run, origin)
                print(run)
            elif args.command == "reconcile":
                from offline_analyzer.api.services import Views
                from offline_analyzer.reporting.reconciliation import markdown

                result = Views(store.workspace).reconciliation(store, args.run)
                print(markdown(result) if args.markdown else json.dumps(result, indent=2))
            elif args.command == "enterprise":
                from offline_analyzer.enterprise.snapshot import assess_enterprise
                from offline_analyzer.inventory.environment import enterprise_origin

                origin = enterprise_origin(store, args.members or None)
                run = assess_enterprise(store, args.members or None)
                record_run_origin(store.workspace, run, origin)
                print(run)
            elif args.command == "import-file":
                package = single_file_package(
                    args.file,
                    format=args.format,
                    operation=args.operation,
                    account_id=args.account,
                    region=args.region,
                    collected_at=datetime.fromisoformat(args.collected_at.replace("Z", "+00:00")),
                )
                origin = import_origin(store.workspace, args.origin)
                run = import_package(store, args.file.parent, package)
                record_run_origin(store.workspace, run, origin)
                print(run)
            elif args.command == "accounts":
                if args.action == "load":
                    if not args.file:
                        raise InputError("ACCOUNT_REGISTRY_FILE_REQUIRED")
                    registry = install_registry(store.workspace, args.file)
                else:
                    registry = workspace_registry(store.workspace)
                # Counts and fingerprint only; account IDs are not printed.
                print(
                    json.dumps(
                        {
                            "registry_present": registry is not None,
                            "accounts": len(registry.entries) if registry else 0,
                            "in_scope": len(registry.in_scope) if registry else 0,
                            "with_tracker_key": len(registry.tracker_keys()) if registry else 0,
                            "sha256": registry.fingerprint() if registry else None,
                        },
                        indent=2,
                    )
                )
            elif args.command == "assess":
                assess(store, args.run)
                print(json.dumps(summary(store, args.run), indent=2))
            elif args.command == "summary":
                print(json.dumps(summary(store, args.run), indent=2))
            elif args.command == "export":
                keys = load_account_keys(args.account_keys)
                export_excel(store, args.run, args.output, keys)
                print("Excel report created locally.")
            else:
                print(
                    record_decision(
                        store, args.run, args.finding, args.status, args.analyst, args.note
                    )
                )
        return 0
    except Exception as exc:
        # DuckDB/Pydantic/parser exceptions may include customer contents. Never log them.
        code = str(exc) if isinstance(exc, InputError) else "OPERATION_FAILED"
        print(
            f"Error: {code}. No customer exception details logged.", file=__import__("sys").stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
