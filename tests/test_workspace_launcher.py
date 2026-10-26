"""Real launcher with the workspace-location resolution (synthetic temporary folders; the
pointer lives in a temporary CLOSEC_CONFIG_DIR, never the user's configuration)."""

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import httpx
import pytest

REPO = Path.cwd()


class Launcher:
    """Starts the launcher without --workspace; captures each session URL (restarts too)."""

    def __init__(self, tmp_path: Path, *args: str):
        code = (
            "import runpy,sys,webbrowser; "
            "webbrowser.open=lambda url: print('CLOSEC_TEST_SESSION '+url,flush=True) or True; "
            "sys.argv=['closec',*sys.argv[1:]]; "
            "runpy.run_module('offline_analyzer.launcher',run_name='__main__')"
        )
        env = {
            **os.environ,
            "PYTHONPATH": str(REPO / "src"),
            "CLOSEC_CONFIG_DIR": str(tmp_path / "config"),
        }
        env.pop("CLOSEC_WORKSPACE", None)
        self.process = subprocess.Popen(
            [sys.executable, "-c", code, "--port", "0", *args],
            cwd=REPO,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        self.urls: queue.Queue[str | None] = queue.Queue()
        self.output: list[str] = []

        def read():
            for line in self.process.stdout:
                self.output.append(line)
                if line.startswith("CLOSEC_TEST_SESSION "):
                    self.urls.put(line.removeprefix("CLOSEC_TEST_SESSION ").strip())
            self.urls.put(None)

        threading.Thread(target=read, daemon=True).start()

    def session(self) -> httpx.Client:
        url = self.urls.get(timeout=30)
        assert url, "".join(self.output)
        origin = url.split("/#", 1)[0]
        client = httpx.Client(base_url=origin, trust_env=False, timeout=60)
        response = client.post(
            "/api/session",
            json={},
            headers={"Origin": origin, "X-Bootstrap-Token": url.split("token=", 1)[1]},
        )
        client.headers.update({"Origin": origin, "X-CSRF-Token": response.json()["csrf"]})
        return client

    def close(self, client: httpx.Client | None = None):
        if client and self.process.poll() is None:
            try:
                client.post("/api/shutdown", json={})
                self.process.wait(timeout=20)
            except (httpx.HTTPError, subprocess.TimeoutExpired):
                pass
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


@pytest.fixture(scope="module")
def other_workspace(tmp_path_factory) -> Path:
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.inventory.environment import set_environment
    from offline_analyzer.rules.engine import assess
    from offline_analyzer.storage.store import Store
    from tools.gcp_fixture import build

    root = tmp_path_factory.mktemp("launcher")
    workspace = root / "synthetic workspace"
    set_environment(workspace, "SYNTHETIC")
    with Store(workspace) as store:
        assess(store, import_package(store, build(root / "pkg", "demo-alpha", "123456789012")))
    return workspace


def test_nothing_chosen_opens_the_default_exactly_as_before(tmp_path):
    default = tmp_path / "default"
    launcher = Launcher(tmp_path, "--default-workspace", str(default))
    client = launcher.session()
    try:
        info = client.get("/api/workspace").json()
        assert info["source"] == "DEFAULT" and info["path"] == str(default.resolve())
        assert info["open_report"]["new_workspace"] and not info["setup_required"]
        assert client.get("/api/runs").json() == []
        assert not (tmp_path / "config").exists()  # nothing remembered unless chosen
    finally:
        launcher.close(client)
    assert (default / "assessment.duckdb").is_file()


def test_corrupt_pointer_shows_the_location_screen(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "workspace-location.json").write_text("{corrupt")
    default = tmp_path / "default"
    launcher = Launcher(tmp_path, "--default-workspace", str(default))
    client = launcher.session()
    try:
        info = client.get("/api/workspace").json()
        assert info["setup_required"] and info["source"] == "SETUP"
        assert not default.exists()  # no real workspace opened or created
    finally:
        launcher.close(client)


def test_open_existing_switches_after_restart(tmp_path, other_workspace):
    default = tmp_path / "default"
    launcher = Launcher(tmp_path, "--default-workspace", str(default))
    client = launcher.session()
    try:
        body = {"purpose": "open", "path": str(other_workspace)}
        check = client.post("/api/workspace/check", json=body).json()
        applied = client.post(
            "/api/workspace/apply",
            json={**body, "confirm": True, "accept_warnings": bool(check["checks"]["warnings"])},
        ).json()
        assert applied["restart_required"]
        assert client.post("/api/workspace/restart", json={}).json()["restarting"]
        client = launcher.session()  # the launcher reopens on the remembered location
        info = client.get("/api/workspace").json()
        assert info["source"] == "REMEMBERED" and info["path"] == str(other_workspace.resolve())
        assert info["open_report"]["counts"]["runs"] == 1
        assert len(client.get("/api/runs").json()) == 1
        pointer = json.loads((tmp_path / "config" / "workspace-location.json").read_text())
        assert set(pointer) == {"path", "updated_utc"}
        log = (other_workspace / "application.log").read_text()
        assert str(other_workspace) not in log and "WORKSPACE_OPENED location=" in log
    finally:
        launcher.close(client)
    output = "".join(launcher.output)
    assert str(other_workspace) not in output
