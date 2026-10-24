"""Account/project display names from collector manifests (labels only, never identity)."""

import json
import re
from pathlib import Path

NAME = re.compile(r"^[^\x00-\x1f]{1,200}$")


def _manifest(directory: Path, name: str) -> dict:
    path = directory / name
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 16 * 1024 * 1024:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (ValueError, UnicodeError):
        return {}
    return value if isinstance(value, dict) else {}


def declared_labels(directory: Path) -> list[tuple[str, str, str]]:
    """(provider, scope_id, name) declared by the package's own manifest."""
    labels = []
    gcp = _manifest(directory, "collection_manifest.json")
    if gcp.get("project_id") and gcp.get("project_name"):
        labels.append(("GCP", str(gcp["project_id"]), str(gcp["project_name"])))
    aws = _manifest(directory, "manifest.json")
    if re.fullmatch(r"[0-9]{12}", str(aws.get("account_id", ""))) and aws.get("account_name"):
        labels.append(("AWS", str(aws["account_id"]), str(aws["account_name"])))
    return [label for label in labels if NAME.fullmatch(label[2])]


def record_labels(store, directory: Path) -> None:
    for provider, scope, name in declared_labels(directory):
        store.db.execute(
            "INSERT INTO scope_labels VALUES (?,?,?,?) ON CONFLICT(provider,scope_id) "
            "DO UPDATE SET name=excluded.name, source=excluded.source",
            [provider, scope, name, "collector-manifest"],
        )


def scope_names(store) -> dict[tuple[str, str], str]:
    return {
        (p, s): n for p, s, n in store.rows("SELECT provider, scope_id, name FROM scope_labels")
    }
