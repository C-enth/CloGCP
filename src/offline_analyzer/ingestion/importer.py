"""Transactional package/file import with immutable local raw snapshots."""

import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from offline_analyzer.contracts.r0 import NORMALIZATION_VERSION, VERSION, Package, Source, stable_id
from offline_analyzer.ingestion.coverage import collection_facts
from offline_analyzer.ingestion.json_input import (
    MAX_BYTES,
    MAX_PACKAGE_BYTES,
    InputError,
    inspect_json,
)
from offline_analyzer.ingestion.safety import resolve_under, sha256_file
from offline_analyzer.normalization.adapters import aws_records, prowler_records
from offline_analyzer.provenance.execution import checkpoint, committing, temporary_prefix


def snapshot(source: Path, target: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as incoming, target.open("xb") as outgoing:
        while chunk := incoming.read(1024 * 1024):
            checkpoint()
            size += len(chunk)
            if size > MAX_BYTES:
                raise InputError("INPUT_BYTE_LIMIT")
            digest.update(chunk)
            outgoing.write(chunk)
    return digest.hexdigest(), size


def load_package(directory: Path) -> Package:
    from offline_analyzer.ingestion.gcp import inspect_package, is_gcp

    if is_gcp(directory):
        return inspect_package(directory)[0]
    from offline_analyzer.ingestion.collector import has_collector_manifest, inspect_collector

    if has_collector_manifest(directory):
        return inspect_collector(directory)[0]
    manifest = resolve_under(directory, "manifest.json")
    if manifest.stat().st_size > 1024 * 1024:
        raise InputError("MANIFEST_BYTE_LIMIT")
    with manifest.open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise InputError("MANIFEST_BYTE_LIMIT")
    # Validate and decode the same bounded bytes, not two racing reads of an import.
    with tempfile.TemporaryDirectory() as temp:
        local = Path(temp) / "manifest.json"
        local.write_bytes(data)
        inspect_json(local)
    return Package.model_validate_json(data)


def import_package(store, directory: Path, package: Package | None = None) -> str:
    run_id = _import_any(store, directory, package)
    from offline_analyzer.ingestion.labels import record_labels

    record_labels(store, directory)
    return run_id


def _import_any(store, directory: Path, package: Package | None = None) -> str:
    checkpoint("MANIFEST_IDENTIFICATION")
    from offline_analyzer.ingestion.collector import (
        has_collector_manifest,
        inspect_collector,
        retain_unsupported,
        store_summary,
    )
    from offline_analyzer.ingestion.gcp import inspect_package, is_gcp

    if is_gcp(directory):
        gcp_package, _ = inspect_package(directory)
        from offline_analyzer.inventory.environment import check_origin

        check_origin(store.workspace, gcp_package.sources[0].gcp_metadata["dataset_origin"])
        return _import_package(store, directory, gcp_package)
    summary = None
    if package is None and has_collector_manifest(directory):
        package, summary = inspect_collector(directory)
        if summary.get("dataset_origin"):
            from offline_analyzer.inventory.environment import check_origin

            check_origin(store.workspace, summary["dataset_origin"].lower().replace("_", "-"))
    run_id = _import_package(store, directory, package or load_package(directory), summary)
    if summary:
        retain_unsupported(store.workspace, directory, summary)
        store_summary(store.workspace, run_id, summary)
    return run_id


def _import_package(store, directory: Path, package: Package, collection_identity=None) -> str:
    package_data = package.model_dump(mode="json")
    identity = [VERSION, NORMALIZATION_VERSION, package_data]
    if collection_identity:
        identity.append(collection_identity)
    run_id = stable_id("run", identity)
    # Even idempotent imports revalidate the supplied raw bytes and declared hashes.
    with tempfile.TemporaryDirectory(prefix=temporary_prefix(), dir=store.workspace) as temp:
        staging = Path(temp)
        staged = []
        total = 0
        for index, source in enumerate(package.sources):
            checkpoint("EVIDENCE_PARSING", index, len(package.sources))
            descriptor = source.model_dump(mode="json")
            artifact = stable_id("artifact", descriptor) if source.path else None
            local = None
            size = 0
            if source.path:
                local = staging / f"{index}.json"
                digest, size = snapshot(resolve_under(directory, source.path), local)
                total += size
                if total > MAX_PACKAGE_BYTES:
                    raise InputError("PACKAGE_BYTE_LIMIT")
                if digest != source.sha256:
                    raise InputError("ARTIFACT_CHECKSUM_MISMATCH")
                shape = inspect_json(local)
            else:
                shape = None
            staged.append((source, artifact, local, size, shape))
        with store.transaction():
            exists = store.db.execute("SELECT 1 FROM runs WHERE run_id=?", [run_id]).fetchone()
            if exists:
                from offline_analyzer.rules.engine import verify_raw

                verify_raw(store, run_id)
                # Still validate source format/record semantics; do not reinsert persisted rows.
                for source, artifact, local, _size, shape in staged:
                    if local:
                        adapter = adapter_for(source)
                        for _ in adapter(local, source, artifact, shape):
                            pass
                return run_id
            store.db.execute(
                "INSERT INTO runs VALUES (?, ?, ?)",
                [run_id, datetime.now(UTC).isoformat(), package.model_dump_json()],
            )
            for index, (source, artifact, local, size, shape) in enumerate(staged):
                checkpoint("RESOURCE_NORMALIZATION", index, len(staged))
                source_id = stable_id("source", source.model_dump(mode="json"))
                count = 0
                malformed = False
                if local:
                    adapter = adapter_for(source)
                    batch, batch_bytes = [], 0
                    for obs in adapter(local, source, artifact, shape):
                        count += 1
                        checkpoint()
                        malformed |= bool(obs.unresolved)
                        if count > 100000:
                            raise InputError("RECORD_LIMIT")
                        batch.append(obs)
                        batch_bytes += len(obs.model_dump_json().encode("utf-8"))
                        if len(batch) >= 128 or batch_bytes >= 2 * 1024 * 1024:
                            store.put_observations(run_id, batch)
                            batch, batch_bytes = [], 0
                    store.put_observations(run_id, batch)
                    store.db.execute(
                        "INSERT INTO artifacts VALUES (?, ?, ?, ?)",
                        [run_id, artifact, source.sha256, size],
                    )
                facts = collection_facts(source, shape, malformed)
                descriptor = source.model_dump(mode="json")
                descriptor.update(
                    artifact_id=artifact,
                    record_count=count,
                    **facts,
                )
                store.db.execute(
                    "INSERT INTO sources VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                    [run_id, source_id, json.dumps(descriptor)],
                )
            # Publish only validated bytes. Content-addressed orphans from an interrupted
            # commit are harmless and reusable; the DB transaction never references partial bytes.
            raw = resolve_under(store.workspace, "raw")
            raw.mkdir(mode=0o700, exist_ok=True)
            for source, _, local, _, _ in staged:
                if local:
                    destination = resolve_under(raw, f"{source.sha256}.json")
                    if destination.exists():
                        if sha256_file(destination) != source.sha256:
                            raise InputError("STORED_RAW_INTEGRITY_FAILURE")
                    else:
                        local.rename(destination)
            committing()
    return run_id


def single_file_package(path, *, format, operation, account_id, region, collected_at):
    source = Source(
        path=path.name,
        sha256=sha256_file(path),
        format=format,
        operation=operation,
        account_id=account_id,
        region=region,
        collected_at=collected_at,
    )
    return Package(sources=(source,))


def adapter_for(source: Source):
    if source.format == "gcp-json-v1":
        from offline_analyzer.normalization.gcp import gcp_records

        return gcp_records
    return prowler_records if source.format.startswith("prowler") else aws_records
