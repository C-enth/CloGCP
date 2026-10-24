"""Disk-backed transfers and worker-owned validation; no parsing on the HTTP loop."""

import asyncio
import json
import tempfile
from pathlib import Path

from offline_analyzer.contracts.r0 import Package, Source
from offline_analyzer.ingestion.archive import unpack_package
from offline_analyzer.ingestion.collector import (
    has_collector_manifest,
    inspect_collector,
    sanitized,
)
from offline_analyzer.ingestion.gcp import guided_manifest, is_gcp
from offline_analyzer.ingestion.importer import load_package, single_file_package
from offline_analyzer.ingestion.json_input import (
    MAX_BYTES,
    MAX_PACKAGE_BYTES,
    InputError,
    inspect_json,
)
from offline_analyzer.ingestion.safety import resolve_under, validate_relative_path
from offline_analyzer.inventory.environment import check_origin
from offline_analyzer.provenance.execution import checkpoint, committing
from offline_analyzer.verification import verify_package

MANIFESTS = {"manifest.json", "collector-manifest.json", "collection_manifest.json"}


class Uploads:
    def __init__(self, workspace, coordinator, published, report):
        self.workspace, self.coordinator, self.published, self.report = (
            workspace,
            coordinator,
            published,
            report,
        )
        # Recovered uploads remain untrusted: importing always repeats all validation.
        directory = workspace / "uploads"
        if directory.is_dir():
            for path in directory.iterdir():
                if (
                    len(path.name) == 32
                    and all(c in "0123456789abcdef" for c in path.name)
                    and path.is_dir()
                    and not path.is_symlink()
                ):
                    if (directory / f"{path.name}.origin").is_file():
                        published.add(path.name)

    def start(self, provider, import_mode, files_total):
        job = self.coordinator.prepare(
            "Package validation",
            context={"provider": provider, "import_mode": import_mode, "files_total": files_total},
            cancellable=True,
        )
        self.coordinator.transfer_progress(job["id"], 0, None)
        return self.coordinator.status(job["id"])

    def _copy(self, file, target, job_id, package_bytes):
        size = 0
        with target.open("xb") as output:
            while chunk := file.read(1024 * 1024):
                self.coordinator.check_cancelled(job_id)
                size += len(chunk)
                limit = MAX_PACKAGE_BYTES if target.suffix == ".zip" else MAX_BYTES
                if size > limit or package_bytes + size > MAX_PACKAGE_BYTES:
                    raise InputError(
                        "UPLOAD_BYTE_LIMIT",
                        limit={
                            "name": "file_bytes" if size > limit else "package_bytes",
                            "allowed": limit if size > limit else MAX_PACKAGE_BYTES,
                            "observed": size if size > limit else package_bytes + size,
                        },
                    )
                output.write(chunk)
        return size

    async def receive(self, files, paths, context, *, job_id=None):
        temporary = None
        scheduled = False
        try:
            if len(files) > 20000 or len(paths) > 4 * 1024 * 1024 or len(context) > 16000:
                raise InputError("UPLOAD_LIMIT")
            try:
                names, settings = json.loads(paths), json.loads(context)
            except (ValueError, TypeError) as exc:
                raise InputError("INVALID_UPLOAD_CONTEXT") from exc
            if (
                not isinstance(names, list)
                or len(names) != len(files)
                or not all(isinstance(n, str) for n in names)
                or len(set(names)) != len(names)
            ):
                raise InputError("INVALID_UPLOAD_PATHS")
            if not isinstance(settings, dict):
                raise InputError("INVALID_UPLOAD_CONTEXT")
            if job_id is None:
                mode = (
                    "ZIP"
                    if len(names) == 1 and names[0].endswith(".zip")
                    else "FOLDER"
                    if any(Path(n).name in MANIFESTS for n in names)
                    else "GUIDED_JSON"
                )
                provider = settings.get("provider", "UNRESOLVED")
                if provider not in {"AWS", "GCP", "UNRESOLVED"}:
                    raise InputError("INVALID_UPLOAD_CONTEXT")
                job_id = self.start(provider, mode, len(files))["id"]
            else:
                job = self.coordinator.status(job_id)
                if (
                    job["kind"] != "Package validation"
                    or job["status"] != "QUEUED"
                    or job["files_total"] != len(files)
                ):
                    raise InputError("UPLOAD_JOB_NOT_PENDING")
            self.coordinator.check_cancelled(job_id)
            collector = {"manifest.json", "operations.jsonl", "checksums.sha256"} <= {
                Path(n).name for n in names
            }
            legacy = any(Path(n).name == "collection_manifest.json" for n in names)
            for name in names:
                try:
                    validate_relative_path(name)
                except ValueError as exc:
                    raise InputError("INVALID_UPLOAD_PATHS") from exc
                ancillary = collector and (
                    Path(name).name in {"operations.jsonl", "checksums.sha256"}
                    or ("scanners" in Path(name).parts and Path(name).suffix in {".csv", ".log"})
                )
                from offline_analyzer.ingestion.sidecars import is_os_metadata

                ancillary = ancillary or is_os_metadata(name)
                if (
                    not name.endswith(".json")
                    and not (len(names) == 1 and name.endswith(".zip"))
                    and not ancillary
                    and not (legacy and name.endswith(".stderr.txt"))
                    and not (legacy and name == "checksums.sha256")
                ):
                    raise InputError("JSON_ONLY")
            staging = resolve_under(self.workspace, ".upload-staging")
            staging.mkdir(parents=True, mode=0o700, exist_ok=True)
            temporary = tempfile.TemporaryDirectory(prefix=f"upload-{job_id}-", dir=staging)
            root = Path(temporary.name)
            total = 0
            for index, (name, file) in enumerate(zip(names, files, strict=True)):
                target = resolve_under(root, name)
                target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                total += await asyncio.to_thread(self._copy, file.file, target, job_id, total)
                self.coordinator.transfer_progress(job_id, index + 1, len(names))
            initial = self.coordinator.schedule(
                job_id,
                lambda store: self.validate(root, names, settings, job_id),
                cancellable=True,
                cleanup=temporary.cleanup,
            )
            scheduled = True
            if settings.get("background_validation"):
                return initial
            return await self.coordinator.wait(job_id)
        except InputError as exc:
            if job_id:
                self.coordinator.transfer_failed(job_id, str(exc))
            raise
        except Exception as exc:
            if job_id:
                self.coordinator.transfer_failed(job_id, "UPLOAD_TRANSFER_FAILED")
            raise InputError("UPLOAD_TRANSFER_FAILED") from exc
        finally:
            if temporary and not scheduled:
                temporary.cleanup()
            for file in files:
                await file.close()

    def validate(self, root, names, settings, job_id):
        checkpoint("PACKAGE_VALIDATION")
        archive = None
        if len(names) == 1 and names[0].endswith(".zip"):
            archive = root / names[0]
            expanded = root / "expanded"
            expanded.mkdir(mode=0o700)
            root = unpack_package(archive, expanded)
            names = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
        else:
            manifests = [Path(n) for n in names if Path(n).name in MANIFESTS]
            if len(manifests) > 1:
                raise InputError("ARCHIVE_MANIFEST_REQUIRED")
            if manifests and manifests[0].parent != Path("."):
                prefix = manifests[0].parent
                if not all(Path(n).is_relative_to(prefix) for n in names):
                    raise InputError("ARCHIVE_OUTSIDE_PACKAGE")
                root = resolve_under(root, prefix.as_posix())
                names = [Path(n).relative_to(prefix).as_posix() for n in names]
        self.coordinator.describe(job_id, files_total=len(names))
        checkpoint("MANIFEST_IDENTIFICATION")
        if "collection_manifest.json" in names:
            from offline_analyzer.ingestion.gcp_legacy import manifest_detection

            detection = manifest_detection(root)
            self.coordinator.describe(
                job_id, manifest_version=detection["detected_version"], manifest_detection=detection
            )
        if not any(n in names for n in MANIFESTS) and settings.get("provider") == "GCP":
            guided_manifest(root, names, settings)
            names.append("manifest.json")
        collector = has_collector_manifest(root)
        if not any(n in names for n in MANIFESTS) and not collector:
            if len(names) != 1:
                raise InputError("MANIFEST_REQUIRED")
            path = resolve_under(root, names[0])
            shape = inspect_json(path)
            fmt = settings.get("format") or (
                "prowler-ocsf-5.10" if shape["root"] == "start_array" else "aws-json-v1"
            )
            operation = "prowler:Scan" if fmt.startswith("prowler-") else settings.get("operation")
            if operation is None:
                from offline_analyzer.normalization.adapters import AWS_SHAPES
                from offline_analyzer.normalization.enterprise_adapters import PROFILES

                matching = [
                    k for k, v in {**AWS_SHAPES, **PROFILES}.items() if v[0] in shape["fields"]
                ]
                if len(matching) == 1:
                    operation = matching[0]
            package = single_file_package(
                path,
                format=fmt,
                operation=operation,
                account_id=settings.get("account_id") or None,
                region=settings.get("region") or None,
                collected_at=settings.get("collected_at"),
            )
            data = package.sources[0].model_dump()
            data.update(
                request_parameters=settings.get("request_parameters"),
                collector_version=settings.get("collector_version") or "unspecified",
            )
            package = Package(sources=(Source.model_validate(data),))
            (root / "manifest.json").write_text(package.model_dump_json())
        origin = settings.get("origin", "synthetic")
        if origin not in {"synthetic", "tool-generated"}:
            raise InputError("INVALID_ORIGIN")
        check_origin(self.workspace, origin)
        gcp = is_gcp(root)
        checkpoint("EVIDENCE_PARSING")
        if collector:
            package, summary = inspect_collector(root)
        else:
            package, summary = load_package(root), None
        if gcp and package.sources[0].gcp_metadata["dataset_origin"] != origin:
            raise InputError("COLLECTOR_ORIGIN_CONFLICT")
        if summary and summary.get("dataset_origin"):
            declared = summary["dataset_origin"].lower().replace("_", "-")
            check_origin(self.workspace, declared)
            if origin != declared:
                raise InputError("COLLECTOR_ORIGIN_CONFLICT")
        self.coordinator.describe(
            job_id,
            provider="GCP" if gcp else "AWS",
        )
        manifest_name = (
            "collection_manifest.json"
            if gcp and "collection_manifest.json" in names
            else "collector-manifest.json"
            if "collector-manifest.json" in names
            else "manifest.json"
        )
        metadata = json.loads((root / manifest_name).read_bytes())
        version = (
            metadata.get("schema_version")
            or metadata.get("contract_version")
            or metadata.get("collector_version")
            or metadata.get("schema")
        )
        collection = metadata.get("collection_id") or metadata.get("package_id")
        self.coordinator.describe(
            job_id,
            manifest_version=version if isinstance(version, str) else None,
            collection_id=collection if isinstance(collection, str) else None,
        )
        result = verify_package(root, package=package, origin=origin)
        self.coordinator.describe(
            job_id,
            scopes=sorted(
                {
                    s.project_id or s.account_id
                    for s in package.sources
                    if s.project_id or s.account_id
                }
            ),
        )
        if summary:
            result = {**result, "collector_package": sanitized(summary)}
        can_import = all(s["parser_accepted"] for s in result["sources"])
        report_id = self.report(result, origin)
        if can_import:
            committing("PACKAGE_READY")
            destination = resolve_under(self.workspace, f"uploads/{job_id}")
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            root.rename(destination)
            if archive:
                archive.rename(destination.parent / f"{job_id}.zip")
            (destination.parent / f"{job_id}.origin").write_text(origin)
            self.published.add(job_id)
        return {
            "sources": [
                {
                    k: source.model_dump(mode="json").get(k)
                    for k in (
                        "account_id",
                        "region",
                        "operation",
                        "collected_at",
                        "coverage",
                        "collector_version",
                        "project_id",
                        "project_number",
                    )
                }
                for source in package.sources
            ],
            "upload_id": job_id,
            "diagnostics": result,
            "can_import": can_import,
            "compatibility_report": report_id,
            "collection": summary,
        }
