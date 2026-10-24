"""Optional local execution checkpoints; CLI reasoning has no API dependency."""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Event
from time import monotonic
from typing import BinaryIO

from offline_analyzer.contracts.errors import InputError


class WorkCancelled(InputError):
    def __init__(self) -> None:
        super().__init__("JOB_CANCELLED")


class Execution:
    def __init__(
        self,
        progress: Callable[[str, int | None, int | None], None],
        *,
        budget_seconds: float = 3600,
        job_id: str | None = None,
    ) -> None:
        self.cancelled = Event()
        self.progress = progress
        self.started = monotonic()
        self.budget_seconds = budget_seconds
        self.committing = False
        self.abort_reason = None
        self.job_id = job_id

    def check(self) -> None:
        if self.abort_reason:
            raise InputError(self.abort_reason)
        if monotonic() - self.started > self.budget_seconds:
            raise InputError("JOB_TIME_LIMIT")
        if self.committing:
            return
        if self.cancelled.is_set():
            raise WorkCancelled()


_current: ContextVar[Execution | None] = ContextVar("closec_execution", default=None)


@contextmanager
def executing(execution: Execution) -> Iterator[None]:
    token = _current.set(execution)
    try:
        yield
    finally:
        _current.reset(token)


def checkpoint(
    stage: str | None = None, completed: int | None = None, total: int | None = None
) -> None:
    execution = _current.get()
    if execution is not None:
        execution.check()
        if stage is not None:
            execution.progress(stage, completed, total)


def report(stage: str, completed: int | None = None, total: int | None = None) -> None:
    """Progress only, never a cancellation or time-limit check: for work after a commit."""
    execution = _current.get()
    if execution is not None:
        execution.progress(stage, completed, total)


def temporary_prefix() -> str:
    execution = _current.get()
    return f"work-{execution.job_id}-" if execution and execution.job_id else "work-local-"


class CheckpointWriter:
    """Checkpoint each compressed output chunk without buffering the workbook."""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.aborted = False

    def write(self, data: bytes) -> int:
        if not self.aborted:
            try:
                checkpoint()
            except BaseException:
                # ZIP's context manager may write a footer while closing after failure.
                # Permit bounded cleanup; the aborted report is still discarded.
                self.aborted = True
                raise
        return self.stream.write(data)

    def tell(self) -> int:
        return self.stream.tell()

    def seek(self, offset: int, whence: int = 0) -> int:
        return self.stream.seek(offset, whence)

    def flush(self) -> None:
        self.stream.flush()


def committing(stage: str = "DATABASE_COMMIT") -> None:
    """Cancellation is checked before commit; successful commits are never cancelled later."""
    execution = _current.get()
    if execution is not None:
        execution.check()
        execution.progress(stage, None, None)
        execution.check()
        execution.committing = True
