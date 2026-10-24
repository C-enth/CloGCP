"""Start the real launcher in a child; capture its browser URL only in test memory."""

import queue
import subprocess
import sys
import threading
from pathlib import Path

import httpx


class LauncherSession:
    def __init__(self, workspace: Path, *, checkout: Path | None = None, port: int = 0):
        self.workspace = workspace
        self.checkout = checkout or Path.cwd()
        code = (
            "import runpy,sys,webbrowser; "
            "webbrowser.open=lambda url: print('CLOSEC_TEST_SESSION '+url,flush=True) or True; "
            "sys.argv=['offline-analyzer-gui',*sys.argv[1:]]; "
            "runpy.run_module('offline_analyzer.launcher',run_name='__main__')"
        )
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                code,
                "--workspace",
                str(workspace),
                "--port",
                str(port),
                "--environment",
                "synthetic",
            ],
            cwd=self.checkout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**__import__("os").environ, "PYTHONPATH": str(self.checkout / "src")},
        )
        messages: queue.Queue[str | None] = queue.Queue()

        def read():
            for line in self.process.stdout:
                if line.startswith("CLOSEC_TEST_SESSION "):
                    messages.put(line.removeprefix("CLOSEC_TEST_SESSION ").strip())
            messages.put(None)

        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        try:
            self.url = messages.get(timeout=20)
        except queue.Empty:
            self.close(force=True)
            raise AssertionError("Real launcher failed to become ready in 20 seconds") from None
        if self.url is None:
            self.close(force=True)
            raise AssertionError("Real launcher exited before browser readiness")
        self.origin = self.url.split("/#", 1)[0]
        self.client = httpx.Client(base_url=self.origin, trust_env=False, timeout=30)
        response = self.client.post(
            "/api/session",
            json={},
            headers={"Origin": self.origin, "X-Bootstrap-Token": self.url.split("token=", 1)[1]},
        )
        assert response.status_code == 200
        self.headers = {"Origin": self.origin, "X-CSRF-Token": response.json()["csrf"]}

    def close(self, *, force: bool = False):
        if self.process.poll() is None and not force and hasattr(self, "client"):
            try:
                self.client.post("/api/shutdown", json={}, headers=self.headers)
                self.process.wait(timeout=20)
            except (httpx.HTTPError, subprocess.TimeoutExpired):
                force = True
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if hasattr(self, "client"):
            self.client.close()
        for stream in (self.process.stdout, self.process.stderr):
            stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
