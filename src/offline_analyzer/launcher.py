"""One-command loopback application launcher; no Node server at runtime."""

import argparse
import os
import re
import secrets
import socket
import sys
import threading
import time
import webbrowser
from datetime import UTC, datetime
from pathlib import Path

from offline_analyzer import PRODUCT_NAME
from offline_analyzer.contracts.errors import InputError
from offline_analyzer.ingestion.safety import resolve_under

ASSETS = Path(__file__).parent / "api" / "assets"


def default_workspace() -> Path:
    """Frozen applications never write into their installation/current directory.

    The per-user folder keeps its pre-CloSec name so existing workspaces are found.
    """
    if not getattr(sys, "frozen", False):
        return Path("artifacts/gui-workspace")
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if not local or not Path(local).is_absolute():
            raise RuntimeError("LOCALAPPDATA must identify a user-writable directory")
        return Path(local) / "OfflineAWSAnalyzer" / "workspace"
    return Path.home() / "Library" / "Application Support" / "OfflineAWSAnalyzer" / "workspace"


LIFECYCLE_EVENTS = {
    "STARTED",
    "STOPPED",
    "STARTUP_FAILED",
    "WORKSPACE_OPENED",
    "WORKSPACE_RECOVERED",
    "WORKSPACE_MIGRATED",
    "WORKSPACE_BACKUP",
    "WORKSPACE_COPIED",
    "WORKSPACE_SELECTED",
}


def lifecycle_log(workspace: Path, event: str, path_hash: str = "") -> None:
    """Small local operational log: fixed events only, no paths/tokens/evidence. A location
    is identified only by a one-way hash (storage.location.path_hash)."""
    if event not in LIFECYCLE_EVENTS or not re.fullmatch(r"[0-9a-f]{0,16}", path_hash):
        raise ValueError("invalid lifecycle event")
    if path_hash:
        event = f"{event} location={path_hash}"
    try:
        path = resolve_under(workspace, "application.log")
        if path.exists() and path.stat().st_size > 256 * 1024:
            return  # Never truncate an existing log or allow unbounded growth.
        descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as output:
            os.chmod(path, 0o600)
            output.write(f"{datetime.now(UTC).isoformat()} {event}\n")
    except (OSError, ValueError):
        pass  # Logging failure must not prevent safe shutdown/startup diagnostics.


class WorkspaceLock:
    def __init__(self, workspace: Path, *, record_pid: bool = True):
        workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.pid_file = workspace / ".gui-owner.pid" if record_pid else None
        self.file = (workspace / ".gui-owner.lock").open("a+b")
        try:
            if __import__("sys").platform == "win32":
                import msvcrt

                self.file.seek(0)
                if self.file.read(1) == b"":
                    self.file.write(b"0")
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            raise RuntimeError("workspace already owned by another GUI") from None
        if self.pid_file:
            # Only the owner's process id, so another launcher can name it when refusing.
            self.pid_file.write_text(str(os.getpid()))

    def close(self):
        if self.pid_file:
            try:
                if self.pid_file.read_text().strip() == str(os.getpid()):
                    self.pid_file.unlink()
            except OSError:
                pass
        self.file.close()


def refusal_text(code: str) -> str:
    """Fixed reason for a refusal code; empty when no wording exists."""
    from offline_analyzer.clogcp_profile import REFUSALS
    from offline_analyzer.storage.location import ERRORS

    return REFUSALS.get(code) or ERRORS.get(code.removeprefix("WORKSPACE_"), "")


def resolve_workspace(explicit: Path | None, default: Path | None) -> tuple[str, Path | None]:
    """Where to open: command line, then CLOSEC_WORKSPACE, then the remembered location,
    then the default. ("SETUP", None) when a remembered location is invalid: the UI asks."""
    from offline_analyzer.storage.location import read_pointer

    if explicit:
        return "COMMAND_LINE", explicit
    if os.environ.get("CLOSEC_WORKSPACE"):
        return "ENVIRONMENT", Path(os.environ["CLOSEC_WORKSPACE"])
    status, remembered = read_pointer()
    if status == "VALID":
        return "REMEMBERED", remembered
    if status == "INVALID":
        return "SETUP", None
    return "DEFAULT", default or default_workspace()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Open this workspace (overrides CLOSEC_WORKSPACE and the remembered location)",
    )
    parser.add_argument(
        "--default-workspace",
        type=Path,
        default=None,
        help="Workspace used when nothing else is chosen (passed by the start scripts)",
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true", help="Service lifecycle testing only")
    parser.add_argument(
        "--environment",
        choices=["synthetic", "assessment"],
        help="Label a new workspace once; a labelled workspace refuses a different label",
    )
    parser.add_argument("--workspace-name", default="", help="Optional label shown in the GUI")
    args = parser.parse_args()
    # A restart (after choosing another workspace in the UI) re-resolves the location and
    # serves again; the previous lock is released first.
    while True:
        outcome = serve_once(args)
        if outcome != "RESTART":
            return outcome
        # The newly remembered location applies, not the old command-line/env override.
        args.workspace = None
        os.environ.pop("CLOSEC_WORKSPACE", None)


def serve_once(args) -> int | str:
    import tempfile

    lock, listener, server, setup_folder = None, None, None, None
    restart = {"requested": False}
    stage = "workspace selection"
    workspace = None
    refused = None
    try:
        source, workspace = resolve_workspace(args.workspace, args.default_workspace)
        if source == "REMEMBERED" and os.environ.get("CLOGCP_PROFILE") == "1":
            from offline_analyzer.clogcp_profile import open_refusal

            # A remembered folder this release refuses must not block every later launch:
            # show the location screen with the reason instead. Explicit choices still fail.
            refused = open_refusal(workspace.resolve())
            if refused:
                print(f"Remembered workspace refused: {refused}. {refusal_text(refused)}")
                source, workspace = "SETUP", None
        if source == "SETUP":
            # The remembered location is missing or invalid: serve the location screen from
            # a private empty folder that is removed on exit. No real workspace is opened.
            setup_folder = Path(tempfile.mkdtemp(prefix="closec-setup-"))
            workspace = setup_folder
        workspace = workspace.resolve()
        if os.environ.get("CLOGCP_PROFILE") == "1":
            from offline_analyzer.clogcp_profile import ensure_workspace

            ensure_workspace(workspace)
        if not (ASSETS / "index.html").is_file():
            raise RuntimeError(
                "compiled frontend missing; see docs/GUI_USAGE.md build instructions"
            )
        if not 0 <= args.port <= 65535:
            raise RuntimeError("invalid loopback port")
        stage = "workspace access or ownership"
        try:
            lock = WorkspaceLock(workspace)
        except RuntimeError:
            from offline_analyzer.storage.location import lock_holder

            stage = f"workspace in use by CloSec process {lock_holder(workspace) or 'unknown'}"
            raise
        if args.environment and source != "SETUP":
            stage = "workspace environment label"
            from offline_analyzer.inventory.environment import set_environment

            set_environment(workspace, args.environment.upper(), args.workspace_name)
        stage = "workspace check and recovery"
        from offline_analyzer.storage.location import path_hash, prepare_open

        report = prepare_open(workspace)
        location = {
            "source": source,
            "setup_required": source == "SETUP",
            "open_report": report,
            "default_path": str((args.default_workspace or default_workspace()).resolve()),
            "remembered_refusal": {"code": refused, "message": refusal_text(refused)}
            if refused
            else None,
        }
        if source != "SETUP":
            lifecycle_log(workspace, "WORKSPACE_OPENED", path_hash(workspace))
            if report.get("recovered"):
                lifecycle_log(workspace, "WORKSPACE_RECOVERED", path_hash(workspace))
            if report.get("migrated"):
                lifecycle_log(workspace, "WORKSPACE_MIGRATED", path_hash(workspace))
        stage = "loopback listener"
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sys.platform != "win32":
            # A stopped local server may leave TIME_WAIT connections. Permit a
            # same-port restart; an active listening owner still prevents bind.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", args.port))
        listener.listen(128)
        port = listener.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        bootstrap = secrets.token_urlsafe(32)
        import uvicorn

        from offline_analyzer.api.app import create_app

        def stop():
            if server:
                server.should_exit = True

        def request_restart():
            restart["requested"] = True
            stop()

        stage = "database and backend initialization"
        app = create_app(
            workspace,
            origin=origin,
            bootstrap=bootstrap,
            stop=stop,
            restart=request_restart,
            location=location,
        )
        server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, access_log=False, log_level="critical")
        )

        def open_when_ready():
            while not server.should_exit:
                if server.started:
                    lifecycle_log(workspace, "STARTED")
                    if not args.no_browser:
                        if webbrowser.open(origin + "/#token=" + bootstrap) is False:
                            print(
                                f"Default browser did not open for {PRODUCT_NAME}. "
                                "Configure it and restart the launcher."
                            )
                    return
                if server.should_exit:
                    return
                time.sleep(0.05)

        threading.Thread(target=open_when_ready, daemon=True).start()
        print(f"{PRODUCT_NAME} is running at {origin}. Ctrl+C stops the application.", flush=True)
        server.run(sockets=[listener])
        if not server.started:
            raise RuntimeError("backend initialization failed")
        return "RESTART" if restart["requested"] else 0
    except (Exception, SystemExit) as exc:
        # No exception text, paths, policy documents or bootstrap secrets in logs.
        if lock and not setup_folder:
            lifecycle_log(workspace, "STARTUP_FAILED")
        print(f"Startup stage: {stage}.")
        if isinstance(exc, InputError):
            # Refusal codes are fixed identifiers, never paths or workspace content.
            print(f"Refused: {exc}. {refusal_text(str(exc))}".rstrip())
        print(
            f"{PRODUCT_NAME} startup failed. Check dependencies, frontend build, "
            "port and workspace lock."
        )
        return 1
    finally:
        if lock and server and server.started and not setup_folder:
            lifecycle_log(workspace, "STOPPED")
        if listener:
            listener.close()
        if lock:
            lock.close()
        if setup_folder:
            import shutil

            shutil.rmtree(setup_folder, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
