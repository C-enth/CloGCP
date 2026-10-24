"""Per-run cache of derived API views (dashboard, attack paths), invalidated by state.

A cached value is reused only while the run's state stamp is unchanged. The stamp combines
the row counts of every table an analyst action or assessment writes (decisions, exclusions,
path reviews, report revisions, SRE validations including severity overrides, limitations,
finalized editions, retired runs, labels, enterprise issue reviews), the run's evaluation and
finding counts and assessment time, the account-registry file and the coordinator's job
generation (any finished job, including re-assessment). Any decision, exclusion, path review,
report revision, severity override or re-assessment therefore changes the stamp; computing
it costs a handful of COUNT queries. The cache holds derived views only, never evidence.
"""

from collections import OrderedDict
from threading import Lock

MUTABLE_TABLES = (
    "decisions",
    "finding_exclusions",
    "path_reviews",
    "report_revisions",
    "sre_validations",
    "report_limitations",
    "finalized_assessments",
    "finalized_supersessions",
    "scope_retired_runs",
    "scope_labels",
    "enterprise_issues",
)
LIMIT = 64


def stamp(store, run: str, generation) -> tuple:
    parts = [generation]
    for table in MUTABLE_TABLES:
        parts.append(store.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
    for table in ("evaluations", "findings"):
        parts.append(
            store.db.execute(f"SELECT count(*) FROM {table} WHERE run_id=?", [run]).fetchone()[0]
        )
    assessed = store.db.execute(
        "SELECT assessed_at, engine_version FROM assessments WHERE run_id=?", [run]
    ).fetchone()
    parts.append(tuple(assessed) if assessed else None)
    registry = store.workspace / "account-registry.json"
    parts.append(registry.stat().st_mtime_ns if registry.is_file() else None)
    return tuple(parts)


class RunCache:
    def __init__(self):
        self.lock = Lock()
        self.values: OrderedDict = OrderedDict()
        self.hits = self.misses = 0

    def get(self, store, run: str, name: str, compute, generation=None, job_running=False):
        """`job_running`: writes are refused while a job runs, so a cached view is the last
        completed state and is served without recomputing the stamp (no extra database work
        competing with the job)."""
        key = (run, name)
        if job_running:
            with self.lock:
                entry = self.values.get(key)
                if entry:
                    self.hits += 1
                    return entry[1]
        current = stamp(store, run, generation)
        with self.lock:
            entry = self.values.get(key)
            if entry and entry[0] == current:
                self.values.move_to_end(key)
                self.hits += 1
                return entry[1]
        value = compute()
        with self.lock:
            self.misses += 1
            self.values[key] = (current, value)
            self.values.move_to_end(key)
            while len(self.values) > LIMIT:
                self.values.popitem(last=False)
        return value

    def clear(self):
        with self.lock:
            self.values.clear()
