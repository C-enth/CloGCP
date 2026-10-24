"""Launch the pinned application ZIP from a source checkout; never opens client data."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

EXPECTED_SHA256 = "e7e0be798760c50a2285de8c6634c64dd92c9a72c4ee87cd261dc6cdcaf50621"
MAX_BYTES = 256 * 1024 * 1024


def safe_relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        not path.parts
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or ":" in name
        or any(ord(c) < 32 for c in name)
    ):
        raise ValueError("Unsafe application archive path")
    return path


def verify_application(app: Path, manifest_bytes: bytes) -> None:
    """Check cached/extracted files against the manifest from the pinned archive."""
    manifest = json.loads(manifest_bytes)
    if manifest.get("product") != "CloGCP" or manifest.get("schema") != "clogcp-portable-1":
        raise ValueError("Invalid application manifest")
    expected = [
        ("portable-manifest.json", hashlib.sha256(manifest_bytes).hexdigest(), len(manifest_bytes))
    ]
    expected.extend((e["path"], e["sha256"], e["bytes"]) for e in manifest["files"])
    for name, digest, size in expected:
        relative = safe_relative(name)
        path = app.joinpath(*relative.parts)
        if not path.resolve().is_relative_to(app.resolve()) or any(
            parent.is_symlink() for parent in (path, *path.parents) if parent != app.parent
        ):
            raise ValueError("Unsafe application cache path")
        if not path.is_file() or path.stat().st_size != size:
            raise ValueError(f"Application file missing or changed: {name}")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError(f"Application file changed: {name}")


def prepare(root: Path) -> Path:
    root = root.resolve()
    archive = root / "CloGCP.zip"
    if archive.is_symlink() or archive.stat().st_size > MAX_BYTES:
        raise ValueError("Invalid application ZIP")
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != EXPECTED_SHA256:
            raise ValueError("CloGCP.zip checksum mismatch; download the verified release ZIP")
        stream.seek(0)
        with zipfile.ZipFile(stream) as zipped:
            infos = zipped.infolist()
            if len(infos) > 4096 or sum(i.file_size for i in infos) > MAX_BYTES:
                raise ValueError("Application archive exceeds extraction limits")
            seen = set()
            for info in infos:
                path = safe_relative(info.filename)
                key = info.filename.casefold()
                if (
                    path.parts[0] != "CloGCP"
                    or key in seen
                    or ((info.external_attr >> 16) & 0o170000 == 0o120000)
                ):
                    raise ValueError("Unsafe or duplicate application archive member")
                seen.add(key)
            manifest = zipped.read("CloGCP/portable-manifest.json")
            cache = root / ".portable"
            if cache.is_symlink():
                raise ValueError("Application cache must not be a symbolic link")
            cache.mkdir(exist_ok=True)
            if cache.resolve().parent != root:
                raise ValueError("Application cache must remain inside the checkout")
            target = cache / EXPECTED_SHA256
            app = target / "CloGCP"
            if not target.resolve().is_relative_to(root):
                raise ValueError("Application cache must remain inside the checkout")
            if target.exists() or target.is_symlink():
                if target.is_symlink():
                    raise ValueError("Application cache must not be a symbolic link")
                verify_application(app, manifest)
                return app
            print("Preparing verified CloGCP application from bundled ZIP...", flush=True)
            with tempfile.TemporaryDirectory(prefix="prepare-", dir=cache) as temporary:
                staging = Path(temporary) / "release"
                staging.mkdir()
                for info in infos:
                    path = staging.joinpath(*safe_relative(info.filename).parts)
                    if info.is_dir():
                        path.mkdir(parents=True, exist_ok=True)
                    else:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        with zipped.open(info) as source, path.open("xb") as destination:
                            shutil.copyfileobj(source, destination)
                verify_application(staging / "CloGCP", manifest)
                os.rename(staging, target)
            return app


def main() -> int:
    if sys.version_info[:2] != (3, 12):
        print("Python 3.12 is required; on Windows run CloGCP.cmd.", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true")
    args, forwarded = parser.parse_known_args()
    try:
        app = prepare(Path(__file__).resolve().parent)
        print(f"Verified application: {app}", flush=True)
        if args.prepare_only:
            return 0
        if sys.platform != "win32":
            raise ValueError(
                "Run the extracted platform launcher; automatic launch requires Windows"
            )
        return subprocess.call(["cmd.exe", "/d", "/c", "CloGCP.cmd", *forwarded], cwd=app)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        print(f"CloGCP package preparation failed: {exc}", file=sys.stderr)
        print("Assessment workspaces have not been opened or changed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
