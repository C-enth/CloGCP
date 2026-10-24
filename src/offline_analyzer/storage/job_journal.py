"""Atomic private job sidecars; progress reads never queue behind DuckDB writes."""

import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from offline_analyzer.contracts.jobs import LocalJob
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import resolve_under

STATES = {"QUEUED": "PENDING", "SUCCEEDED": "COMPLETED"}


class JobJournal:
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.workspace_id = hashlib.sha256(str(workspace.resolve()).encode()).hexdigest()
        if (workspace / "jobs").is_symlink():
            raise InputError("JOB_JOURNAL_UNSAFE")
        self.directory = resolve_under(workspace, "jobs")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.is_symlink():
            raise InputError("JOB_JOURNAL_UNSAFE")
        self.logged_states = {}

    def save(self, job: dict) -> None:
        record = {
            **job,
            "workspace_id": self.workspace_id,
            "state": STATES.get(job["status"], job["status"]),
        }
        record.pop("deduplicated", None)
        data = LocalJob.model_validate(record).model_dump_json().encode()
        if len(data) > 4 * 1024 * 1024:
            raise InputError("JOB_JOURNAL_LIMIT")
        descriptor, name = tempfile.mkstemp(prefix=".job-", dir=self.directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if (self.directory / f"{job['id']}.json").is_symlink():
                raise InputError("JOB_JOURNAL_UNSAFE")
            destination = resolve_under(self.workspace, f"jobs/{job['id']}.json")
            os.replace(name, destination)
            state = (record["state"], record["stage"], record.get("error"))
            if self.logged_states.get(job["id"]) != state:
                log = self.directory / "operations.jsonl"
                if log.is_symlink():
                    raise InputError("JOB_JOURNAL_UNSAFE")
                if not log.exists() or log.stat().st_size < 1024 * 1024:
                    descriptor = os.open(log, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
                    with os.fdopen(descriptor, "w") as stream:
                        stream.write(
                            json.dumps(
                                {
                                    "at": record["updated_at"],
                                    "job_id": job["id"],
                                    "state": record["state"],
                                    "stage": record["stage"],
                                    "error_code": record.get("error"),
                                }
                            )
                            + "\n"
                        )
                self.logged_states[job["id"]] = state
        finally:
            Path(name).unlink(missing_ok=True)

    def load(self) -> dict[str, dict]:
        jobs = {}
        now = datetime.now(UTC).isoformat()
        for path in self.directory.glob("*.json"):
            if not re.fullmatch(r"[0-9a-f]{32}\.json", path.name) or path.is_symlink():
                continue
            if path.stat().st_size > 4 * 1024 * 1024:
                raise InputError("JOB_JOURNAL_LIMIT")
            try:
                job = LocalJob.model_validate_json(path.read_bytes()).model_dump(mode="json")
            except ValueError as exc:
                raise InputError("JOB_JOURNAL_INVALID") from exc
            if job["id"] != path.stem:
                raise InputError("JOB_JOURNAL_INVALID")
            if job["status"] in {"QUEUED", "RUNNING"}:
                job.update(
                    status="INTERRUPTED",
                    state="INTERRUPTED",
                    error="JOB_INTERRUPTED",
                    cancel_supported=False,
                    finished_at=datetime.now(UTC).timestamp(),
                    updated_at=now,
                )
                self.save(job)
                # Only job-owned scratch names under this workspace are eligible.
                # Persisted raw evidence, uploads and reports are never removed here.
                for parent, prefix in (
                    (self.workspace, f"work-{job['id']}-"),
                    (self.workspace / ".upload-staging", f"upload-{job['id']}-"),
                ):
                    if parent.is_dir() and not parent.is_symlink():
                        for scratch in parent.glob(prefix + "*"):
                            if scratch.is_dir() and not scratch.is_symlink():
                                shutil.rmtree(scratch)
            # Large validation results stay on disk; retain only progress metadata in RAM.
            job["result"] = None
            jobs[job["id"]] = job
        return jobs

    def result(self, job_id: str) -> dict | None:
        path = resolve_under(self.workspace, f"jobs/{job_id}.json")
        if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
            raise InputError("JOB_JOURNAL_UNSAFE")
        try:
            return LocalJob.model_validate_json(path.read_bytes()).result
        except ValueError as exc:
            raise InputError("JOB_JOURNAL_INVALID") from exc
