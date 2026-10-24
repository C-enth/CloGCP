"""Startup-pinned source/frontend identity; no network, customer paths or credentials."""

import hashlib
import json
import platform
import re
import subprocess
import tomllib
from pathlib import Path

TRANSPORT_VERSION = "local-jobs-1"


class RuntimeIdentity:
    def __init__(self):
        self.package = Path(__file__).resolve().parents[1]
        self.root = self.package.parent.parent
        self.assets = self.package / "api/assets"
        self.frontend = self._frontend()
        self.version = self.frontend.get("application_version", "UNKNOWN")
        project = self.root / "pyproject.toml"
        if project.is_file():
            self.version = tomllib.loads(project.read_text())["project"]["version"]
        self.revision = None
        self.modified = None
        provenance = self.assets / "release-info.json"
        if provenance.is_file() and provenance.stat().st_size < 4096:
            data = json.loads(provenance.read_text())
            value = data.get("git_revision")
            if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40,64}", value):
                self.revision = value
            if type(data.get("working_tree_modified")) is bool:
                self.modified = data["working_tree_modified"]
        if (self.root / ".git").exists():
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=3,
            )
            value = result.stdout.strip()
            if re.fullmatch(r"[0-9a-f]{40,64}", value):
                self.revision = value
            status = subprocess.run(
                ["git", "status", "--porcelain"], cwd=self.root, capture_output=True, timeout=3
            )
            self.modified = bool(status.stdout)
        self.source_hash = self._source_hash()

    def _frontend(self):
        path = self.assets / "build-info.json"
        try:
            data = json.loads(path.read_text()) if path.stat().st_size < 4096 else {}
        except (OSError, ValueError):
            return {}
        return {
            key: data.get(key)
            for key in ("application_version", "frontend_build_id", "transport_version")
        }

    def _source_hash(self):
        digest = hashlib.sha256()
        for path in sorted(self.package.rglob("*.py")):
            digest.update(path.relative_to(self.package).as_posix().encode())
            digest.update(path.read_bytes())
        return digest.hexdigest()

    def status(self):
        current = self._frontend()
        stale = current != self.frontend or self._source_hash() != self.source_hash
        compatible = (
            not stale
            and self.frontend.get("application_version") == self.version
            and self.frontend.get("transport_version") == TRANSPORT_VERSION
        )
        return {
            "product": "CloSec",
            "application_version": self.version,
            "git_revision": self.revision,
            "working_tree_modified": self.modified,
            "backend_source_hash": self.source_hash,
            "frontend_build_id": self.frontend.get("frontend_build_id"),
            "transport_version": TRANSPORT_VERSION,
            "compatible": compatible,
            "source_changed_since_startup": stale,
            "operating_system": platform.system(),
            "operating_system_release": platform.release(),
        }
