"""Bounded ZIP transport; portable names are checked before any extraction."""

import stat
import zipfile
import zlib
from pathlib import Path, PurePosixPath

from offline_analyzer.ingestion.json_input import (
    MAX_BYTES,
    MAX_PACKAGE_BYTES,
    MAX_PACKAGE_FILES,
    InputError,
)
from offline_analyzer.ingestion.safety import resolve_under, validate_relative_path
from offline_analyzer.ingestion.sidecars import check_metadata_size, is_os_metadata
from offline_analyzer.provenance.execution import checkpoint


def canonical_member(value: str) -> str:
    name = value.replace("\\", "/")
    try:
        validate_relative_path(name)
    except ValueError as exc:
        raise InputError("UNSAFE_ARCHIVE_PATH") from exc
    canonical = PurePosixPath(name).as_posix().rstrip("/")
    if name.rstrip("/") != canonical or any(
        any(ord(c) < 32 or c in '<>"|?*' for c in p)
        or p.endswith((".", " "))
        or p.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL"}
        or p.split(".")[0].upper() in {f"{s}{i}" for s in ("COM", "LPT") for i in range(1, 10)}
        for p in PurePosixPath(canonical).parts
    ):
        raise InputError("UNSAFE_ARCHIVE_PATH")
    return canonical


def unpack_package(archive: Path, destination: Path) -> Path:
    """Caller owns a new private staging directory. Never extractall or overwrite."""
    if destination.is_symlink():
        raise InputError("UNSAFE_ARCHIVE_MEMBER")
    destination = destination.resolve()
    try:
        with zipfile.ZipFile(archive) as package:
            members = package.infolist()
            if len(members) > MAX_PACKAGE_FILES + 75:
                raise InputError("ARCHIVE_MEMBER_LIMIT")
            checked, names = [], set()
            for member in members:
                name = canonical_member(member.filename)
                if name.casefold() in names:
                    raise InputError("DUPLICATE_ARCHIVE_PATH")
                names.add(name.casefold())
                mode = member.external_attr >> 16
                directory = member.filename.endswith(("/", "\\"))
                if stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise InputError("UNSAFE_ARCHIVE_MEMBER")
                if stat.S_ISDIR(mode) and not directory:
                    raise InputError("UNSAFE_ARCHIVE_MEMBER")
                if directory and member.file_size:
                    raise InputError("UNSAFE_ARCHIVE_MEMBER")
                if member.flag_bits & 1:
                    raise InputError("ENCRYPTED_ARCHIVE")
                if member.compress_type not in {
                    zipfile.ZIP_STORED,
                    zipfile.ZIP_DEFLATED,
                    zipfile.ZIP_BZIP2,
                    zipfile.ZIP_LZMA,
                }:
                    raise InputError("UNSUPPORTED_ARCHIVE_COMPRESSION")
                checked.append((member, name, directory))
            file_names = {name for _, name, directory in checked if not directory}
            roots = [
                PurePosixPath(n).parent
                for n in file_names
                if PurePosixPath(n).name
                in {"manifest.json", "collector-manifest.json", "collection_manifest.json"}
            ]
            if len(roots) != 1:
                raise InputError("ARCHIVE_MANIFEST_REQUIRED")
            root = roots[0]
            v030 = {
                (root / n).as_posix() for n in ("operations.jsonl", "checksums.sha256")
            } <= file_names
            legacy = (root / "collection_manifest.json").as_posix() in file_names
            total, files = 0, []
            for member, name, directory in checked:
                path = PurePosixPath(name)
                if directory and root.is_relative_to(path):
                    continue
                if not path.is_relative_to(root):
                    raise InputError("ARCHIVE_OUTSIDE_PACKAGE")
                if directory:
                    continue
                relative = path.relative_to(root)
                ancillary = (
                    v030
                    and (
                        relative.as_posix() in {"operations.jsonl", "checksums.sha256"}
                        or (relative.parts[0] == "scanners" and relative.suffix in {".csv", ".log"})
                    )
                ) or (legacy and name.endswith(".stderr.txt"))
                if is_os_metadata(name):
                    check_metadata_size(member.file_size)
                    ancillary = True
                if not name.endswith(".json") and not ancillary:
                    raise InputError("JSON_ONLY")
                total += member.file_size
                if member.file_size > MAX_BYTES or total > MAX_PACKAGE_BYTES:
                    raise InputError(
                        "ARCHIVE_BYTE_LIMIT",
                        limit={
                            "name": "file_bytes"
                            if member.file_size > MAX_BYTES
                            else "expanded_bytes",
                            "allowed": MAX_BYTES
                            if member.file_size > MAX_BYTES
                            else MAX_PACKAGE_BYTES,
                            "observed": member.file_size if member.file_size > MAX_BYTES else total,
                        },
                    )
                if member.file_size > max(1, member.compress_size) * 1000:
                    raise InputError("ARCHIVE_RATIO_LIMIT")
                files.append((member, name))
            if not files or len(files) > MAX_PACKAGE_FILES:
                raise InputError("ARCHIVE_MEMBER_LIMIT")
            for index, (member, name) in enumerate(files):
                checkpoint("ARCHIVE_VALIDATION", index, len(files))
                try:
                    target = resolve_under(destination, name)
                    # Reject pre-existing symlink parents even when they resolve inside staging.
                    if any(
                        p.is_symlink()
                        for p in [destination / name, *(destination / name).parents]
                        if p.is_relative_to(destination)
                    ):
                        raise InputError("UNSAFE_ARCHIVE_MEMBER")
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    received = 0
                    with package.open(member) as source, target.open("xb") as output:
                        while chunk := source.read(1024 * 1024):
                            checkpoint()
                            received += len(chunk)
                            if received > member.file_size or received > MAX_BYTES:
                                raise InputError("ARCHIVE_BYTE_LIMIT")
                            output.write(chunk)
                    if received != member.file_size:
                        raise InputError("CORRUPT_ARCHIVE")
                except ValueError as exc:
                    raise InputError("UNSAFE_ARCHIVE_PATH") from exc
            return destination / root
    except InputError:
        raise
    except (zipfile.BadZipFile, EOFError, zlib.error) as exc:
        raise InputError("CORRUPT_ARCHIVE") from exc
    except NotImplementedError as exc:
        raise InputError("UNSUPPORTED_ARCHIVE_COMPRESSION") from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise InputError("ARCHIVE_READ_FAILURE") from exc
