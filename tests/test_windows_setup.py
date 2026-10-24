"""Windows bootstrap regression; native PowerShell acceptance requires Windows."""

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def preflight():
    spec = importlib.util.spec_from_file_location(
        "clogcp_windows_preflight", ROOT / "check-windows.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "os_name,version,machine,bits,expected",
    [
        ("win32", (3, 12, 8), "AMD64", 64, True),
        ("win32", (3, 12, 8), "x86_64", 64, True),
        ("darwin", (3, 12, 8), "x86_64", 64, False),
        ("win32", (3, 11, 8), "AMD64", 64, False),
        ("win32", (3, 13, 0), "AMD64", 64, False),
        ("win32", (3, 12, 8), "AMD64", 32, False),
        ("win32", (3, 12, 8), "ARM64", 64, False),
    ],
)
def test_platform_prerequisites(os_name, version, machine, bits, expected):
    assert preflight().compatible(os_name, version, machine, bits) is expected


def test_preflight_exits_cleanly_without_name_error():
    result = subprocess.run(
        [sys.executable, str(ROOT / "check-windows.py")], capture_output=True, text=True
    )
    assert "NameError" not in result.stderr
    assert "Traceback" not in result.stderr
    expected = preflight().compatible(
        sys.platform,
        tuple(sys.version_info),
        __import__("platform").machine(),
        __import__("struct").calcsize("P") * 8,
    )
    assert result.returncode == (0 if expected else 1)


def test_setup_passes_python_file_instead_of_inline_native_code():
    setup = (ROOT / "setup-windows.ps1").read_text()
    assert "& py -3.12 (Join-Path $Root 'check-windows.py')" in setup
    assert " -c " not in setup


@pytest.mark.skipif(sys.platform != "win32", reason="Native Windows PowerShell required")
def test_native_powershell_preflight_with_spaces(tmp_path):
    if not shutil.which("py") or not shutil.which("powershell"):
        pytest.skip("Windows Python launcher and Windows PowerShell required")
    folder = tmp_path / "CloGCP setup with spaces"
    folder.mkdir()
    shutil.copy2(ROOT / "check-windows.py", folder / "check-windows.py")
    lines = (ROOT / "setup-windows.ps1").read_text().splitlines()
    stop = next(i for i, line in enumerate(lines) if "if ($LASTEXITCODE -ne 0)" in line)
    script = folder / "preflight.ps1"
    script.write_text("\n".join(lines[: stop + 1]) + "\n")
    result = subprocess.run(
        ["powershell", "-NoProfile", "-File", str(script)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
