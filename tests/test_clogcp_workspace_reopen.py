"""Reopen an existing CloGCP workspace copy through every selection method (synthetic only).

The real CloGCP entry runs in a child with a temporary HOME and CLOGCP_CONFIG_DIR, so the
default location and remembered pointer never reach the user's profile. Each check compares
every table's row hashes and the count-only snapshot with the original workspace.
"""

import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import duckdb
import httpx
import pytest

from offline_analyzer.storage.side_by_side import database_inventory, file_inventory

REPO = Path(__file__).resolve().parents[1]
COUNTS = REPO / "tools" / "workspace_counts.py"
WAL_WITHOUT_CHANGE = (
    "import duckdb,os,sys; db=duckdb.connect(sys.argv[1]); "
    "db.execute(\"SET checkpoint_threshold='10GB'\"); "
    "db.execute('CREATE TABLE zz_tmp(a INT)'); db.execute('DROP TABLE zz_tmp'); os._exit(0)"
)


class CloGCP:
    """Real `offline_analyzer.clogcp` child; session URLs captured in test memory only."""

    def __init__(self, sandbox: Path, *args: str, env: dict | None = None):
        code = (
            "import runpy,sys,webbrowser; "
            "webbrowser.open=lambda url: print('CLOGCP_TEST_SESSION '+url,flush=True) or True; "
            "sys.argv=['clogcp',*sys.argv[1:]]; "
            "runpy.run_module('offline_analyzer.clogcp',run_name='__main__')"
        )
        (sandbox / "home").mkdir(parents=True, exist_ok=True)
        environment = {
            k: v
            for k, v in os.environ.items()
            if k not in {"CLOSEC_WORKSPACE", "CLOGCP_WORKSPACE", "CLOSEC_CONFIG_DIR"}
        }
        environment.update(
            HOME=str(sandbox / "home"),
            CLOGCP_CONFIG_DIR=str(sandbox / "config"),
            PYTHONPATH=str(REPO / "src"),
            **(env or {}),
        )
        self.sandbox = sandbox
        self.process = subprocess.Popen(
            [sys.executable, "-c", code, "--port", "0", *args],
            cwd=REPO,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
        )
        self.urls: queue.Queue = queue.Queue()
        self.output: list[str] = []

        def read():
            for line in self.process.stdout:
                self.output.append(line)
                if line.startswith("CLOGCP_TEST_SESSION "):
                    self.urls.put(line.removeprefix("CLOGCP_TEST_SESSION ").strip())
            self.urls.put(None)

        threading.Thread(target=read, daemon=True).start()

    def session(self, timeout: float = 60) -> httpx.Client | None:
        url = self.urls.get(timeout=timeout)
        if not url:
            return None
        origin = url.split("/#", 1)[0]
        client = httpx.Client(base_url=origin, trust_env=False, timeout=120)
        response = client.post(
            "/api/session",
            json={},
            headers={"Origin": origin, "X-Bootstrap-Token": url.split("token=", 1)[1]},
        )
        client.headers.update({"Origin": origin, "X-CSRF-Token": response.json()["csrf"]})
        return client

    def close(self, client: httpx.Client | None = None) -> str:
        if client and self.process.poll() is None:
            try:
                client.post("/api/shutdown", json={})
                self.process.wait(timeout=30)
            except (httpx.HTTPError, subprocess.TimeoutExpired):
                pass
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        return "".join(self.output)

    @property
    def default_created(self) -> bool:
        return (self.sandbox / "home/Library/Application Support/CloGCP/workspace").exists()


def counts(workspace: Path) -> dict:
    result = subprocess.run(
        [sys.executable, "-I", str(COUNTS), str(workspace)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    data.pop("seconds")
    return data


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    """Two imports, confirmed findings, a false-positive exclusion, a report edit, a path
    review and one finalized edition, in a marked CloGCP workspace."""
    from offline_analyzer.attack_paths.feasibility import attack_paths
    from offline_analyzer.attack_paths.review import record as review_path
    from offline_analyzer.clogcp_profile import ensure_workspace
    from offline_analyzer.contracts.exclusion import ExclusionRequest
    from offline_analyzer.enterprise.snapshot import assess_enterprise
    from offline_analyzer.findings import exclusions
    from offline_analyzer.findings.finalisation import freeze
    from offline_analyzer.findings.generate import record_decision
    from offline_analyzer.findings.report_ready import save_revision
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.inventory.environment import set_environment
    from offline_analyzer.storage.store import Store
    from tests.test_report_ready import edit_for
    from tools.gcp_fixture import build

    root = tmp_path_factory.mktemp("reopen")
    work = root / "original workspace"
    ensure_workspace(work)
    set_environment(work, "SYNTHETIC")
    with Store(work) as store:
        imports = [
            import_package(store, build(root / "pkg-a", "demo-alpha", "111111111111")),
            import_package(store, build(root / "pkg-b", "demo-second", "222222222222")),
        ]
        run = assess_enterprise(store, imports)
        findings = sorted(
            (f for f in store.candidates(run) if f.provider == "GCP"), key=lambda f: f.finding_id
        )
        for finding in findings[:3]:
            record_decision(store, run, finding.finding_id, "CONFIRMED", "Synthetic", "reviewed")
        exclusions.record(
            store,
            run,
            findings[3].finding_id,
            ExclusionRequest(
                action="EXCLUDE", reason="FALSE_POSITIVE", note="Synthetic", analyst="Synthetic"
            ),
        )
        save_revision(store, run, findings[0].finding_id, edit_for(store, run, findings[0]))
        path = attack_paths(store, run)["items"][0]
        review_path(store, run, path["path_id"], "CONFIRMED", "Synthetic")
        freeze(store, run, "Synthetic", True)
    baseline = counts(work)
    latest = baseline["runs"][-1]
    assert latest["frozen_edition"] and latest["confirmed"] == 3 and baseline["run_count"] == 3
    return {
        "root": root,
        "work": work,
        "run": run,
        "tables": database_inventory(work),
        "counts": baseline,
    }


def copy_of(original, name: str) -> Path:
    return Path(shutil.copytree(original["work"], original["root"] / name, symlinks=True))


def assert_intact(original, workspace: Path) -> None:
    assert database_inventory(workspace) == original["tables"]
    assert counts(workspace) == original["counts"]


@pytest.mark.parametrize("method", ["argument", "environment", "pointer"])
def test_copy_opens_with_identical_data_by_every_method(original, method):
    copy = copy_of(original, f"copy {method}")
    sandbox = original["root"] / f"sandbox-{method}"
    args, env = [], {}
    if method == "argument":
        args = ["--workspace", str(copy)]
    elif method == "environment":
        env = {"CLOGCP_WORKSPACE": str(copy)}
    else:
        (sandbox / "config").mkdir(parents=True)
        (sandbox / "config/workspace-location.json").write_text(
            json.dumps({"path": str(copy.resolve()), "updated_utc": "2026-10-28T00:00:00+00:00"})
        )
    app = CloGCP(sandbox, *args, env=env)
    client = app.session()
    try:
        assert client, "".join(app.output)
        info = client.get("/api/workspace").json()
        run = original["run"]
        finalized = client.get(f"/api/runs/{run}/finalized?provider=GCP")
        assert info["path"] == str(copy.resolve())
        assert (
            info["source"]
            == {
                "argument": "COMMAND_LINE",
                "environment": "ENVIRONMENT",
                "pointer": "REMEMBERED",
            }[method]
        )
        assert finalized.status_code == 200 and len(finalized.json()["findings"]) == 3
        assert len(client.get(f"/api/runs/{run}/exclusions").json()["items"]) == 1
    finally:
        app.close(client)
    assert_intact(original, copy)
    assert not app.default_created


def refused(app: CloGCP) -> str:
    client = app.session(timeout=45)
    output = app.close(client)
    assert client is None, "the workspace must be refused"
    return output


def damaged(original, kind: str, name: str = "") -> Path:
    """A copy with one incompatibility; `name` only distinguishes the folder."""
    assert kind in {"leftover-wal", "newer-schema", "older-schema", "unmarked-closec"}, kind
    copy = copy_of(original, f"refused {kind} {name}".strip())
    if kind == "leftover-wal":
        subprocess.run(
            [sys.executable, "-c", WAL_WITHOUT_CHANGE, str(copy / "assessment.duckdb")], check=True
        )
        assert (copy / "assessment.duckdb.wal").exists()
    elif kind == "newer-schema":
        with duckdb.connect(str(copy / "assessment.duckdb")) as db:
            db.execute("UPDATE schema_info SET version=2")
            db.execute("CHECKPOINT")
    elif kind == "older-schema":
        with duckdb.connect(str(copy / "assessment.duckdb")) as db:
            db.execute("DROP TABLE enterprise_shards")
            db.execute("CHECKPOINT")
    elif kind == "unmarked-closec":
        (copy / "clogcp-workspace.json").unlink()
    return copy


REFUSAL = {
    "leftover-wal": ("workspace check and recovery", "CLOSE_OR_RECOVER_PREVIOUS_APPLICATION_FIRST"),
    "newer-schema": ("workspace check and recovery", "UNSUPPORTED_DATABASE_VERSION"),
    "older-schema": (
        "workspace check and recovery",
        "EXPLICIT_VERSIONED_WORKSPACE_UPGRADE_REQUIRED",
    ),
    "unmarked-closec": (
        "workspace selection",
        "CLOGCP_REFUSES_EXISTING_CLOSEC_OR_UNMARKED_WORKSPACE",
    ),
}


@pytest.mark.parametrize("kind", sorted(REFUSAL))
def test_incompatible_copies_are_refused_without_data_change(original, kind):
    """CloGCP never recovers, checkpoints or migrates on opening (README, ADR-CLOGCP-001)."""
    stage, code = REFUSAL[kind]
    copy = damaged(original, kind)
    before = file_inventory(copy)
    output = refused(CloGCP(original["root"] / f"sandbox-{kind}", "--workspace", str(copy)))
    assert f"Startup stage: {stage}." in output
    assert f"Refused: {code}." in output
    assert str(copy) not in output and str(original["root"]) not in output
    after = file_inventory(copy)
    # Only the lock file and the lifecycle log line are added; database and journal bytes
    # are untouched.
    assert {k: v for k, v in after.items() if k in before} == before
    assert set(after) - set(before) <= {".gui-owner.lock", "application.log"}


def test_older_schema_opens_after_explicit_verified_additive_copy(original):
    source = damaged(original, "older-schema", "upgrade")
    before = file_inventory(source)
    target = original["root"] / "older upgraded copy"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "offline_analyzer.storage.side_by_side",
            "--source",
            str(source),
            "--target",
            str(target),
            "--upgrade-additive",
        ],
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": str(REPO / "src")},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert file_inventory(source) == before
    app = CloGCP(original["root"] / "sandbox-upgraded", "--workspace", str(target))
    client = app.session()
    app.close(client)
    assert client is not None
    assert counts(target) == original["counts"]


def test_folder_that_is_not_a_workspace_is_refused_and_untouched(original):
    folder = original["root"] / "not a workspace"
    folder.mkdir()
    (folder / "notes.txt").write_text("synthetic")
    output = refused(CloGCP(original["root"] / "sandbox-not", "--workspace", str(folder)))
    assert "Startup stage: workspace selection." in output
    assert [p.name for p in folder.iterdir()] == ["notes.txt"]


def test_second_instance_is_refused_with_the_owner_process(original):
    copy = copy_of(original, "copy second instance")
    first = CloGCP(original["root"] / "sandbox-first", "--workspace", str(copy))
    client = first.session()
    try:
        output = refused(CloGCP(original["root"] / "sandbox-second", "--workspace", str(copy)))
        assert f"workspace in use by CloSec process {first.process.pid}" in output
    finally:
        first.close(client)
    assert_intact(original, copy)


@pytest.mark.parametrize(
    ("parent", "warning"), [("git", "GIT_REPOSITORY"), ("Dropbox", "SYNC_FOLDER")]
)
def test_risky_parent_folders_open_with_a_warning(original, parent, warning):
    base = original["root"] / f"{parent} parent"
    base.mkdir()
    if parent == "git":
        subprocess.run(["git", "init", "-q", str(base)], check=True)
    else:
        base = base / "Dropbox"
        base.mkdir()
    copy = Path(shutil.copytree(original["work"], base / "workspace", symlinks=True))
    app = CloGCP(original["root"] / f"sandbox-{parent}", "--workspace", str(copy))
    client = app.session()
    try:
        assert warning in client.get("/api/workspace").json()["checks"]["warnings"]
    finally:
        app.close(client)
    assert_intact(original, copy)


@pytest.mark.parametrize("kind", sorted(REFUSAL))
def test_gui_open_check_refuses_what_the_launcher_refuses(original, kind):
    """Formerly an expected failure: the screen accepted these and every launch then failed."""
    from offline_analyzer.clogcp_profile import REFUSALS
    from offline_analyzer.storage.location import ERRORS

    # The screen's own read-only inspection reports a newer schema precisely; every other
    # refusal comes from the launcher's checks.
    code = "NEWER_SCHEMA" if kind == "newer-schema" else REFUSAL[kind][1]
    expected = ERRORS[code].replace("CloSec", "CloGCP") if code in ERRORS else REFUSALS[code]
    good, bad = copy_of(original, f"gui good {kind}"), damaged(original, kind, "gui")
    before = file_inventory(bad)
    sandbox = original["root"] / f"sandbox-gui-{kind}"
    app = CloGCP(sandbox, "--workspace", str(good))
    client = app.session()
    try:
        body = {"purpose": "open", "path": str(bad)}
        inspection = client.post("/api/workspace/check", json=body).json()["inspection"]
        assert inspection["ok"] is False and inspection["code"] == code
        assert inspection["message"] == expected and "CloSec" not in inspection["message"]
        applied = client.post(
            "/api/workspace/apply", json={**body, "confirm": True, "accept_warnings": True}
        )
        assert applied.status_code >= 400 and applied.json()["error"] == "WORKSPACE_" + code
    finally:
        app.close(client)
    assert not (sandbox / "config/workspace-location.json").exists()
    assert file_inventory(bad) == before


def test_refusal_names_the_reason(original):
    """Formerly an expected failure: only the stage and a generic message were printed."""
    copy = damaged(original, "newer-schema", "message")
    output = refused(CloGCP(original["root"] / "sandbox-message", "--workspace", str(copy)))
    assert "Refused: UNSUPPORTED_DATABASE_VERSION. This CloGCP does not support" in output


@pytest.mark.parametrize("kind", ["leftover-wal", "unmarked-closec"])
def test_refused_remembered_location_falls_back_to_the_location_screen(original, kind):
    code = REFUSAL[kind][1]
    bad = damaged(original, kind, "remembered")
    before = file_inventory(bad)
    sandbox = original["root"] / f"sandbox-remembered-{kind}"
    (sandbox / "config").mkdir(parents=True)
    pointer = sandbox / "config/workspace-location.json"
    pointer.write_text(
        json.dumps({"path": str(bad.resolve()), "updated_utc": "2026-10-28T00:00:00+00:00"})
    )
    remembered = pointer.read_bytes()
    app = CloGCP(sandbox)
    client = app.session()
    try:
        assert client is not None, "".join(app.output)
        info = client.get("/api/workspace").json()
        assert info["setup_required"] is True and info["source"] == "SETUP"
        assert info["remembered_refusal"]["code"] == code
        assert client.get("/api/runs").json() == []
    finally:
        output = app.close(client)
    assert f"Remembered workspace refused: {code}." in output and str(bad) not in output
    # The refused folder and the pointer are left exactly as they were; nothing is created.
    assert file_inventory(bad) == before and pointer.read_bytes() == remembered
    assert not app.default_created


@pytest.fixture(scope="module")
def editable(tmp_path_factory):
    """An unfinalized CloGCP workspace (decisions may still be recorded)."""
    from offline_analyzer.clogcp_profile import ensure_workspace
    from offline_analyzer.enterprise.snapshot import assess_enterprise
    from offline_analyzer.findings.generate import record_decision
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.inventory.environment import set_environment
    from offline_analyzer.storage.store import Store
    from tools.gcp_fixture import build

    root = tmp_path_factory.mktemp("journal")
    work = root / "editable workspace"
    ensure_workspace(work)
    set_environment(work, "SYNTHETIC")
    with Store(work) as store:
        run = assess_enterprise(store, [import_package(store, build(root / "pkg"))])
        first = sorted(store.candidates(run), key=lambda c: c.finding_id)[0]
        record_decision(store, run, first.finding_id, "CONFIRMED", "Synthetic", "checkpointed")
    return {"root": root, "work": work, "run": run, "counts": counts(work)}


def journal_with_decision(editable, name: str) -> Path:
    """A copy left by a crash: one recorded decision exists only in the journal."""
    copy = Path(shutil.copytree(editable["work"], editable["root"] / name, symlinks=True))
    code = (
        "import os,sys; sys.path.insert(0, sys.argv[2]); "
        "from pathlib import Path; "
        "from offline_analyzer.storage.store import Store; "
        "from offline_analyzer.findings.generate import record_decision; "
        "s=Store(Path(sys.argv[1])); "
        "s.db.execute(\"SET checkpoint_threshold='10GB'\"); "
        "f=sorted(s.candidates(sys.argv[3]), key=lambda c: c.finding_id)[1]; "
        "record_decision(s, sys.argv[3], f.finding_id, 'REJECTED', 'Synthetic', 'in journal'); "
        "os._exit(0)"
    )
    subprocess.run(
        [sys.executable, "-c", code, str(copy), str(REPO / "src"), editable["run"]], check=True
    )
    assert (copy / "assessment.duckdb.wal").exists()
    return copy


def copy_tool(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "offline_analyzer.storage.side_by_side", *args],
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": str(REPO / "src")},
        capture_output=True,
        text=True,
    )


def test_journal_recovery_copies_replays_and_leaves_the_source_byte_identical(editable):
    from offline_analyzer.storage.side_by_side import _counts

    source = journal_with_decision(editable, "journal source")
    before_files = file_inventory(source)
    expected_tables = database_inventory(source)  # read-only replay, in memory only
    expected = _counts(source)
    assert expected["analyst_decisions"] == 2  # one checkpointed, one only in the journal
    target = editable["root"] / "journal recovered"
    result = copy_tool("--source", str(source), "--target", str(target), "--recover-journal")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["journal_replayed_in_copy"] and report["source_modified"] is False
    assert report["counts_before"] == report["counts_after"] == expected
    # Source: every byte identical, journal still present. Copy: journal folded in.
    assert file_inventory(source) == before_files
    assert not (target / "assessment.duckdb.wal").exists()
    assert database_inventory(target) == expected_tables
    app = CloGCP(editable["root"] / "sandbox-journal", "--workspace", str(target))
    client = app.session()
    try:
        assert client is not None, "".join(app.output)
        assert len(client.get("/api/runs").json()) == editable["counts"]["run_count"]
    finally:
        app.close(client)
    recovered = counts(target)
    status = recovered["runs"][-1]["by_status"]
    assert status["REJECTED"] == 1 and status["CONFIRMED"] == 1
    assert database_inventory(target) == expected_tables


@pytest.mark.parametrize("case", ["no-journal", "in-use", "two-modes", "target-exists"])
def test_journal_recovery_refusals_change_nothing(editable, case):
    source = (
        Path(shutil.copytree(editable["work"], editable["root"] / f"journal refusal {case}"))
        if case == "no-journal"
        else journal_with_decision(editable, f"journal refusal {case}")
    )
    target = editable["root"] / f"journal refusal target {case}"
    args = ["--source", str(source), "--target", str(target), "--recover-journal"]
    if case == "two-modes":
        args.append("--upgrade-additive")
    if case == "target-exists":
        target.mkdir()
    lock = None
    if case == "in-use":
        from offline_analyzer.launcher import WorkspaceLock

        lock = WorkspaceLock(source)  # held exactly as a running application holds it
    before = file_inventory(source)
    try:
        result = copy_tool(*args)
        after = file_inventory(source)  # compared while the test's own lock is still held
    finally:
        if lock:
            lock.close()
    assert result.returncode != 0
    assert {
        "no-journal": "NO_JOURNAL_TO_RECOVER",
        "in-use": "WORKSPACE_IN_USE_CLOSE_APPLICATION_FIRST",
        "two-modes": "ONE_RECOVERY_MODE_AT_A_TIME",
        "target-exists": "NEW_SIBLING_WORKSPACE_REQUIRED",
    }[case] in result.stderr
    assert after == before
    assert case == "target-exists" or not target.exists()


@pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in browser")
def test_gui_open_existing_restart_and_remembered_relaunch(original):
    from playwright.sync_api import expect, sync_playwright

    copy = copy_of(original, "gui copy")
    sandbox = original["root"] / "sandbox-gui"
    app = CloGCP(sandbox, "--workspace", str(original["root"] / "gui start empty"))
    url = app.urls.get(timeout=60)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url)
            page.get_by_role("button", name="Workspace location", exact=True).click()
            opening = page.get_by_label("Open existing workspace (recovery)", exact=True)
            opening.get_by_label("Existing workspace folder").fill(str(copy))
            opening.get_by_role("button", name="Check location").click()
            expect(opening.get_by_label("Counts in the selected workspace")).to_be_visible()
            accept = opening.get_by_label("I have read these warnings", exact=False)
            if accept.count():
                accept.check()
            opening.get_by_label("I confirm: open this workspace", exact=False).check()
            opening.get_by_role("button", name="Open this workspace").click()
            page.get_by_role("button", name="Restart CloSec now").click()
            page.goto(app.urls.get(timeout=90))
            header = page.get_by_label("Active workspace", exact=True).first
            expect(header).to_contain_text(str(copy.resolve()))
            page.get_by_role("tab", name="GCP", exact=True).first.click()
            page.get_by_role("button", name="Finalized findings", exact=True).click()
            expect(page.get_by_text("Frozen edition").first).to_be_visible(timeout=60000)
            expect(page.locator(".finalized-metrics").first).to_contain_text(
                re.compile(r"Total\s*3")
            )
            browser.close()
    finally:
        app.process.terminate()
        app.close()
    assert_intact(original, copy)
    again = CloGCP(sandbox)
    client = again.session()
    try:
        info = client.get("/api/workspace").json()
        assert info["source"] == "REMEMBERED" and info["path"] == str(copy.resolve())
    finally:
        again.close(client)
    assert not again.default_created
