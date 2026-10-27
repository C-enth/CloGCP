"""One database owner, durable local jobs and independent progress/cancellation reads."""

import asyncio
import re
import secrets
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Any

from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.provenance.execution import Execution, WorkCancelled, executing
from offline_analyzer.storage.job_journal import STATES, JobJournal
from offline_analyzer.storage.store import Store

ACTIVE = {"QUEUED", "RUNNING"}


class Coordinator:
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="assessment-owner")
        self.journal = JobJournal(workspace)
        self.jobs = self.journal.load(persist_recovery=False)
        self.futures: dict[str, Future] = {}
        self.signals: dict[str, Execution] = {}
        self.connections = {}
        self.cleanups = {}
        self.last_saved = {}
        self.identity_details: dict[str, dict[str, str]] = {}
        self.lock = Lock()
        self.running: str | None = None
        self.exclusive_runs = 0
        self.closing = False
        self.stopped = Event()
        self.monitor = Thread(target=self._heartbeat, daemon=True, name="closec-job-heartbeat")
        self.monitor.start()

    @staticmethod
    def now():
        return datetime.now(UTC).isoformat()

    def _save(self, job):
        job["state"] = STATES.get(job["status"], job["status"])
        try:
            self.journal.save(job)
        except OSError as exc:
            raise InputError("JOB_JOURNAL_UNAVAILABLE") from exc

    async def call(self, action: Callable[[Store], Any]) -> Any:
        with self.lock:
            if self.running and self.jobs[self.running]["status"] == "RUNNING":
                raise InputError("WORKSPACE_OPERATION_IN_PROGRESS")

        def execute():
            with Store(self.workspace) as store:
                return action(store)

        return await asyncio.wrap_future(self.executor.submit(execute))

    async def exclusive(self, action: Callable[[], Any]) -> Any:
        """Run on the single database worker with no Store open (workspace copy/backup):
        nothing else reads or writes the database until it returns."""
        with self.lock:
            if self.running and self.jobs[self.running]["status"] == "RUNNING":
                raise InputError("WORKSPACE_OPERATION_IN_PROGRESS")
        try:
            return await asyncio.wrap_future(self.executor.submit(action))
        finally:
            with self.lock:
                self.exclusive_runs += 1

    @property
    def generation(self) -> tuple:
        """Changes when any job reaches a final state or an exclusive operation ends, so
        derived-view caches never outlive work done outside ordinary analyst writes."""
        with self.lock:
            finished = sorted(
                (job_id, job["status"])
                for job_id, job in self.jobs.items()
                if job["status"] not in ACTIVE
            )
            return self.exclusive_runs, len(finished), hash(tuple(finished))

    @property
    def job_running(self) -> bool:
        with self.lock:
            return bool(self.running and self.jobs[self.running]["status"] == "RUNNING")

    def _heartbeat(self):
        while not self.stopped.wait(1):
            with self.lock:
                for job in self.jobs.values():
                    if job["status"] not in ACTIVE:
                        continue
                    job["heartbeat_at"] = self.now()
                    if (
                        job["stage"] == "UPLOAD_LOCAL_TRANSFER"
                        and time.time()
                        - datetime.fromisoformat(job["last_progress_at"]).timestamp()
                        > 300
                    ):
                        job.update(
                            status="INTERRUPTED",
                            error="TRANSFER_IDLE_TIMEOUT",
                            finished_at=time.time(),
                            cancel_supported=False,
                        )
                    signal = self.signals.get(job["id"])
                    if signal and time.monotonic() - signal.started > signal.budget_seconds:
                        signal.cancelled.set()
                        connection = self.connections.get(job["id"])
                        if connection is not None:
                            try:
                                connection.interrupt()
                            except Exception:
                                pass
                    try:
                        self._save(job)
                    except InputError:
                        if signal and job["id"] in self.futures:
                            signal.abort_reason = "JOB_JOURNAL_UNAVAILABLE"
                        else:
                            job.update(
                                status="FAILED",
                                state="FAILED",
                                error="JOB_JOURNAL_UNAVAILABLE",
                                cancel_supported=False,
                                finished_at=time.time(),
                            )

    def _progress(self, job_id, stage, completed=None, total=None):
        with self.lock:
            job = self.jobs[job_id]
            previous = job["stage"]
            now = self.now()
            if stage != previous:
                job["timings"][previous] = job["timings"].get(previous, 0) + max(
                    0, time.time() - job["stage_started_at"]
                )
                job["stage_started_at"] = time.time()
            job.update(
                stage=stage,
                last_progress_at=now,
                updated_at=now,
                progress={"stage": stage, "completed": completed, "total": total},
            )
            if stage in {
                "DATABASE_COMMIT",
                "SNAPSHOT_COMMIT",
                "PACKAGE_READY",
                "REPORT_PUBLICATION",
            }:
                job["cancel_supported"] = False
            # File/record checkpoints remain cheap; stage transitions persist immediately.
            if stage != previous or time.monotonic() - self.last_saved.get(job_id, 0) >= 0.25:
                self._save(job)
                self.last_saved[job_id] = time.monotonic()

    def describe(self, job_id, **fields):
        allowed = {
            "provider",
            "files_total",
            "manifest_version",
            "manifest_detection",
            "collection_id",
            "scopes",
        }
        if set(fields) - allowed:
            raise ValueError("Unknown job context")
        with self.lock:
            self.jobs[job_id].update(fields)
            self._save(self.jobs[job_id])

    def progress(self, stage: str, completed: int, total: int | None) -> None:
        if self.running:
            self._progress(self.running, stage, completed, total)

    def prepare(self, kind: str, *, key=None, context=None, cancellable=False):
        with self.lock:
            if self.closing:
                raise InputError("APPLICATION_STOPPING")
            for existing in self.jobs.values():
                if key and existing.get("key") == key and existing["status"] in ACTIVE:
                    return {**existing, "deduplicated": True}
            if sum(j["status"] in ACTIVE for j in self.jobs.values()) >= 8:
                raise InputError("JOB_QUEUE_FULL")
            now = self.now()
            job_id = secrets.token_hex(16)
            context = context or {}
            job = {
                "schema_version": "local-job-1",
                "workspace_id": self.journal.workspace_id,
                "id": job_id,
                "kind": kind,
                "status": "QUEUED",
                "state": "PENDING",
                "stage": "PENDING",
                "result": None,
                "error": None,
                "error_class": None,
                "cancel_supported": cancellable,
                "key": key,
                "progress": None,
                "submitted_at": time.time(),
                "stage_started_at": time.time(),
                "started_at": None,
                "finished_at": None,
                "updated_at": now,
                "last_progress_at": now,
                "heartbeat_at": now,
                "recoverable": True,
                "timings": {},
                "limit": None,
                "provider": context.get("provider", "UNRESOLVED"),
                "import_mode": context.get("import_mode", "NONE"),
                "files_total": context.get("files_total"),
                "explanation": None,
                "manifest_version": context.get("manifest_version"),
                "manifest_detection": None,
                "collection_id": context.get("collection_id"),
                "scopes": context.get("scopes", []),
            }
            self.jobs[job_id] = job
            self.signals[job_id] = Execution(
                lambda stage, completed, total: self._progress(job_id, stage, completed, total),
                job_id=job_id,
            )
            try:
                self._save(job)
            except InputError:
                self.jobs.pop(job_id, None)
                self.signals.pop(job_id, None)
                raise
            return dict(job)

    def schedule(self, job_id, action, *, cancellable=False, cleanup=None):
        with self.lock:
            job = self.jobs[job_id]
            if job["status"] not in ACTIVE:
                raise InputError("JOB_NOT_PENDING")
            if job_id in self.futures:
                raise InputError("JOB_ALREADY_SCHEDULED")
            job["cancel_supported"] = True
            job.update(stage="PENDING", last_progress_at=self.now(), stage_started_at=time.time())
            self.cleanups[job_id] = cleanup

        def execute():
            signal = self.signals[job_id]
            signal.started = time.monotonic()
            completed = False
            result = None
            try:
                with self.lock:
                    job.update(
                        status="RUNNING",
                        cancel_supported=cancellable,
                        started_at=time.time(),
                        updated_at=self.now(),
                    )
                    self.running = job_id
                    self._save(job)
                with executing(signal), Store(self.workspace) as store:
                    with self.lock:
                        self.connections[job_id] = store.db if cancellable else None
                    signal.check()
                    result = action(store)
                completed = True
            except Exception as exc:
                code = str(exc) if isinstance(exc, InputError) else "JOB_FAILED"
                if signal.abort_reason:
                    code = signal.abort_reason
                elif isinstance(exc, WorkCancelled) or signal.cancelled.is_set():
                    code = (
                        "JOB_TIME_LIMIT"
                        if time.monotonic() - signal.started > signal.budget_seconds
                        else "JOB_CANCELLED"
                    )
                if not re.fullmatch(r"[A-Z_]{1,80}", code):
                    code = "JOB_FAILED"
                from offline_analyzer.ingestion.errors import explanation

                with self.lock:
                    if isinstance(exc, InputError) and exc.identity_context:
                        self.identity_details[job_id] = exc.identity_context
                    job.update(
                        status="CANCELLED" if code == "JOB_CANCELLED" else "FAILED",
                        error=code,
                        error_class=type(exc).__name__,
                        explanation=explanation(code),
                    )
                    job["limit"] = getattr(exc, "limit", None)
            finally:
                with self.lock:
                    if completed:
                        job.update(status="SUCCEEDED", result=result, error=None)
                    self.connections.pop(job_id, None)
                    self.running = None
                    now = self.now()
                    job["timings"][job["stage"]] = job["timings"].get(job["stage"], 0) + max(
                        0, time.time() - job["stage_started_at"]
                    )
                    job.update(
                        cancel_supported=False,
                        finished_at=time.time(),
                        updated_at=now,
                        heartbeat_at=now,
                    )
                    try:
                        self._save(job)
                        job["result"] = None
                    except (InputError, OSError):
                        from offline_analyzer.ingestion.errors import explanation

                        job.update(
                            status="FAILED",
                            state="FAILED",
                            error="JOB_JOURNAL_UNAVAILABLE",
                            error_class="JournalWriteFailure",
                            explanation=explanation("JOB_JOURNAL_UNAVAILABLE"),
                        )
                if cleanup:
                    cleanup()
                self.cleanups.pop(job_id, None)

        with self.lock:
            self.futures[job_id] = self.executor.submit(execute)
        return self.status(job_id)

    def submit(
        self,
        kind: str,
        action: Callable[[Store], Any],
        key=None,
        *,
        context=None,
        cancellable=False,
    ) -> dict:
        job = self.prepare(kind, key=key, context=context, cancellable=cancellable)
        if job.get("deduplicated"):
            return job
        return self.schedule(job["id"], action, cancellable=cancellable)

    async def wait(self, job_id):
        try:
            await asyncio.wrap_future(self.futures[job_id])
        except asyncio.CancelledError:
            raise WorkCancelled() from None
        job = self.status(job_id)
        if job["status"] == "SUCCEEDED":
            return job["result"]
        if job["status"] == "CANCELLED":
            raise WorkCancelled()
        raise InputError(
            job["error"] or "JOB_FAILED", identity_context=self.identity_details.get(job_id)
        )

    def status(self, job_id: str) -> dict:
        with self.lock:
            if job_id not in self.jobs:
                raise InputError("JOB_NOT_FOUND")
            job = deepcopy(self.jobs[job_id])
            if job_id in self.identity_details:
                job["identity_context"] = deepcopy(self.identity_details[job_id])
            if job["status"] == "SUCCEEDED" and job["result"] is None:
                job["result"] = self.journal.result(job_id)
            job["duration_seconds"] = max(
                0, (job["finished_at"] or time.time()) - job["submitted_at"]
            )
            return job

    def history(self):
        with self.lock:
            return [
                {
                    **deepcopy({key: value for key, value in job.items() if key != "result"}),
                    "result": None,
                    "duration_seconds": max(
                        0, (job["finished_at"] or time.time()) - job["submitted_at"]
                    ),
                }
                for job in sorted(
                    self.jobs.values(), key=lambda j: j["submitted_at"], reverse=True
                )[:100]
            ]

    def check_cancelled(self, job_id):
        signal = self.signals.get(job_id)
        if signal:
            signal.check()

    def transfer_progress(self, job_id, received, total):
        self.check_cancelled(job_id)
        self._progress(job_id, "UPLOAD_LOCAL_TRANSFER", received, total)

    def transfer_failed(self, job_id, code):
        with self.lock:
            job = self.jobs.get(job_id)
            if job and job["status"] in ACTIVE and job_id not in self.futures:
                job.update(
                    status="CANCELLED"
                    if code == "JOB_CANCELLED"
                    else "INTERRUPTED"
                    if code in {"TRANSFER_IDLE_TIMEOUT", "UPLOAD_TRANSFER_INTERRUPTED"}
                    else "FAILED",
                    error=code,
                    error_class="TransferFailure",
                    cancel_supported=False,
                    finished_at=time.time(),
                    updated_at=self.now(),
                )
                self._save(job)

    def cancel(self, job_id: str) -> dict:
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None:
                raise InputError("JOB_NOT_FOUND")
            future = self.futures.get(job_id)
            if job["status"] not in ACTIVE:
                return self.status_unlocked(job)
            if future is None or future.cancel():
                self.signals[job_id].cancelled.set()
                job.update(
                    status="CANCELLED",
                    cancel_supported=False,
                    error="JOB_CANCELLED",
                    finished_at=time.time(),
                    updated_at=self.now(),
                )
                self._save(job)
                cleanup = self.cleanups.pop(job_id, None)
                if cleanup:
                    cleanup()
            elif job["cancel_supported"]:
                self.signals[job_id].cancelled.set()
                connection = self.connections.get(job_id)
                if connection is not None:
                    try:
                        connection.interrupt()
                    except Exception:
                        pass
        return self.status(job_id)

    def status_unlocked(self, job):
        return {
            **deepcopy(job),
            "duration_seconds": max(0, (job["finished_at"] or time.time()) - job["submitted_at"]),
        }

    def close(self) -> None:
        self.closing = True
        for job in list(self.jobs.values()):
            if job["status"] in ACTIVE:
                self.cancel(job["id"])
        self.executor.shutdown(wait=True, cancel_futures=True)
        self.stopped.set()
        self.monitor.join(timeout=2)
