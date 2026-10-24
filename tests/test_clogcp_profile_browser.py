"""Run the existing real GUI workflow through the independent CloGCP entry module."""

import os

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in browser")


def test_clogcp_entry_import_investigate_review_export_restart(monkeypatch, tmp_path):
    from tests import launcher_support
    from tests.test_gcp_expanded_browser import test_expanded_gui_modules_review_exports_and_restart

    original = launcher_support.subprocess.Popen

    def independent(args, **kwargs):
        # Reuse the unmodified workflow and real compiled frontend; select only the entry module.
        args = [
            s.replace("offline_analyzer.launcher", "offline_analyzer.clogcp")
            if isinstance(s, str)
            else s
            for s in args
        ]
        return original(args, **kwargs)

    monkeypatch.setenv("CLOGCP_CONFIG_DIR", str(tmp_path / "isolated-config"))
    monkeypatch.setattr(launcher_support.subprocess, "Popen", independent)
    test_expanded_gui_modules_review_exports_and_restart(tmp_path, "Folder", "chromium")
    assert (tmp_path / "workspace" / "clogcp-workspace.json").is_file()
