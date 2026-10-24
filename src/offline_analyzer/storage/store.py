"""One DuckDB owner per CLI execution; all mutations are transactional."""

import json
from contextlib import contextmanager
from pathlib import Path

import duckdb

from offline_analyzer.contracts.r0 import Candidate, Decision, Normalized, Result
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import resolve_under
from offline_analyzer.storage.enterprise_schema import DDL as ENTERPRISE_DDL
from offline_analyzer.storage.management_schema import DDL as MANAGEMENT_DDL
from offline_analyzer.storage.report_schema import DDL as REPORT_DDL

DDL = (
    "CREATE TABLE IF NOT EXISTS schema_info(version INTEGER PRIMARY KEY)",
    "CREATE TABLE IF NOT EXISTS runs(run_id VARCHAR PRIMARY KEY, created_at "
    "VARCHAR, package VARCHAR)",
    "CREATE TABLE IF NOT EXISTS assessments(run_id VARCHAR PRIMARY KEY, engine_version VARCHAR, "
    "assessed_at VARCHAR)",
    "CREATE TABLE IF NOT EXISTS sources(run_id VARCHAR, source_id VARCHAR, data VARCHAR, "
    "PRIMARY KEY(run_id, source_id))",
    "CREATE TABLE IF NOT EXISTS artifacts(run_id VARCHAR, artifact_id VARCHAR, sha256 VARCHAR, "
    "size_bytes BIGINT, PRIMARY KEY(run_id, artifact_id))",
    "CREATE TABLE IF NOT EXISTS observations(run_id VARCHAR, observation_id VARCHAR, "
    "resource_id VARCHAR, account_id VARCHAR, region VARCHAR, tool VARCHAR, check_id VARCHAR, "
    "kind VARCHAR, data VARCHAR, PRIMARY KEY(run_id, observation_id))",
    "CREATE TABLE IF NOT EXISTS evidence_refs(run_id VARCHAR, observation_id VARCHAR, "
    "artifact_id VARCHAR, locator VARCHAR, PRIMARY KEY(run_id, artifact_id, locator))",
    "CREATE TABLE IF NOT EXISTS evaluations(run_id VARCHAR, evaluation_id VARCHAR, "
    "resource_id VARCHAR, outcome VARCHAR, data VARCHAR, PRIMARY KEY(run_id, evaluation_id))",
    "CREATE TABLE IF NOT EXISTS findings(run_id VARCHAR, finding_id VARCHAR, data VARCHAR, "
    "PRIMARY KEY(run_id, finding_id))",
    "CREATE TABLE IF NOT EXISTS finding_resources(run_id VARCHAR, finding_id VARCHAR, "
    "resource_id VARCHAR, account_id VARCHAR, region VARCHAR, PRIMARY "
    "KEY(run_id, finding_id, resource_id))",
    "CREATE TABLE IF NOT EXISTS decisions(decision_id VARCHAR PRIMARY KEY, finding_id VARCHAR, "
    "decided_at VARCHAR, data VARCHAR)",
    # ADR-008: append-only SRE verdicts, independent of analyst decisions.
    "CREATE TABLE IF NOT EXISTS sre_validations(validation_id VARCHAR PRIMARY KEY, "
    "finding_id VARCHAR, recorded_at VARCHAR, data VARCHAR)",
    "CREATE INDEX IF NOT EXISTS refs_observation ON evidence_refs(run_id, observation_id)",
    "CREATE INDEX IF NOT EXISTS observations_resource ON observations(run_id, resource_id)",
)

CONNECTION_CONFIG = {
    "enable_external_access": "false",
    "autoinstall_known_extensions": "false",
    "autoload_known_extensions": "false",
    "memory_limit": "512MB",
    "threads": "1",
}


class Store:
    def __init__(self, workspace: Path, *, _recover: bool = True, reader: bool = False):
        """`reader`: a read connection for the API's concurrent GET requests. It skips crash
        recovery and schema creation (the owner connection did both) and sees the last
        committed state while a job writes."""
        self.workspace = workspace.resolve()
        if __import__("os").environ.get("CLOGCP_PROFILE") == "1":
            from offline_analyzer.clogcp_profile import ensure_workspace

            ensure_workspace(self.workspace)
        self.workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
        if _recover and not reader:
            from offline_analyzer.storage.scope_journal import recover

            recover(self.workspace)
        # DuckDB provides the inter-process writer lock. CLI commands run sequentially
        # in one thread; all SQL is internal and parameters are never SQL fragments.
        try:
            self.db = duckdb.connect(
                str(resolve_under(self.workspace, "assessment.duckdb")),
                config=CONNECTION_CONFIG,
            )
        except duckdb.Error as exc:
            raise InputError("WORKSPACE_UNAVAILABLE_OR_BUSY") from exc
        if reader:
            return
        try:
            with self.transaction():
                for sql in (*DDL, *ENTERPRISE_DDL, *REPORT_DDL, *MANAGEMENT_DDL):
                    self.db.execute(sql)
                versions = self.db.execute("SELECT version FROM schema_info").fetchall()
                if not versions:
                    self.db.execute("INSERT INTO schema_info VALUES (1)")
                elif versions != [(1,)]:
                    raise InputError("UNSUPPORTED_DATABASE_VERSION")
        except Exception:
            self.db.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN TRANSACTION")
        try:
            yield
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def require_run(self, run_id):
        if not self.db.execute("SELECT 1 FROM runs WHERE run_id = ?", [run_id]).fetchone():
            raise InputError("RUN_NOT_FOUND")

    def rows(self, sql, params=()):
        from offline_analyzer.provenance.execution import checkpoint

        cursor = self.db.cursor()
        try:
            cursor.execute(sql, params)
            while batch := cursor.fetchmany(128):
                checkpoint()
                yield from batch
        finally:
            cursor.close()

    def observations(
        self, run_id, resource_id=None, observation_id=None, provider=None, project=None
    ):
        query = "SELECT data FROM observations WHERE run_id = ?"
        params = [run_id]
        if provider is not None:
            if provider not in {"AWS", "GCP"}:
                raise InputError("INVALID_PROVIDER")
            query += " AND tool='gcp'" if provider == "GCP" else " AND tool<>'gcp'"
        if project:
            # Filtered before parsing: one project of a large snapshot without the others.
            query += " AND json_extract_string(data,'$.project_id') = ?"
            params.append(project)
        if resource_id:
            query += " AND resource_id = ?"
            params.append(resource_id)
        if observation_id:
            query += " AND observation_id = ?"
            params.append(observation_id)
        query += " ORDER BY observation_id"
        for row in self.rows(query, params):
            yield Normalized.model_validate_json(row[0])

    def put_observation(self, run_id, obs):
        self.put_observations(run_id, [obs])

    def put_observations(self, run_id: str, observations: list[Normalized]) -> None:
        """Bounded columnar insertion avoids one transaction append buffer per row.

        Preserve the first canonical observation and every original evidence locator.
        Called inside the importer's transaction; a rejected tail rolls back all batches.
        """
        if not observations:
            return
        rows = [
            [
                run_id,
                obs.observation_id,
                obs.resource_id,
                obs.account_id,
                obs.region,
                obs.source_tool,
                obs.source_check_id,
                obs.resource_type,
                obs.model_dump_json(),
            ]
            for obs in observations
        ]
        self.db.execute(
            "INSERT INTO observations SELECT "
            + ",".join(["unnest(?)"] * 9)
            + " ON CONFLICT DO NOTHING",
            list(map(list, zip(*rows, strict=True))),
        )
        refs = [
            [run_id, obs.observation_id, obs.evidence.artifact_id, obs.evidence.locator]
            for obs in observations
        ]
        self.db.execute(
            "INSERT INTO evidence_refs SELECT "
            + ",".join(["unnest(?)"] * 4)
            + " ON CONFLICT DO NOTHING",
            list(map(list, zip(*refs, strict=True))),
        )

    def refs(self, run_id, observation_ids):
        from offline_analyzer.contracts.models import EvidenceRef

        refs = set()
        for oid in observation_ids:
            for artifact, locator in self.rows(
                "SELECT artifact_id, locator FROM evidence_refs WHERE run_id=? AND "
                "observation_id=?",
                [run_id, oid],
            ):
                refs.add((artifact, locator))
        return tuple(EvidenceRef(artifact_id=a, locator=locator) for a, locator in sorted(refs))

    def results(self, run_id):
        for row in self.rows(
            "SELECT data FROM evaluations WHERE run_id=? ORDER BY evaluation_id", [run_id]
        ):
            yield Result.model_validate_json(row[0])

    def candidates(self, run_id):
        for row in self.rows(
            "SELECT data FROM findings WHERE run_id=? ORDER BY finding_id", [run_id]
        ):
            yield Candidate.model_validate_json(row[0])

    def latest_decision(self, finding_id):
        row = self.db.execute(
            "SELECT data FROM decisions WHERE finding_id=? "
            "ORDER BY decided_at DESC, decision_id DESC LIMIT 1",
            [finding_id],
        ).fetchone()
        return Decision.model_validate_json(row[0]) if row else None

    def latest_decisions(self, run_id) -> dict:
        """Latest decision per finding in the run, same ordering as latest_decision()."""
        latest = {}
        for finding_id, data in self.rows(
            "SELECT d.finding_id, d.data FROM decisions d WHERE d.finding_id IN "
            "(SELECT finding_id FROM findings WHERE run_id=?) "
            "ORDER BY d.decided_at, d.decision_id",
            [run_id],
        ):
            latest[finding_id] = data
        return {k: Decision.model_validate_json(v) for k, v in latest.items()}

    def run_refs(self, run_id) -> dict:
        """Every observation's evidence refs and artifact digests in one read (refs() order)."""
        from offline_analyzer.contracts.models import EvidenceRef

        grouped: dict[str, list] = {}
        for observation, artifact, locator, digest in self.rows(
            "SELECT DISTINCT r.observation_id, r.artifact_id, r.locator, a.sha256 "
            "FROM evidence_refs r LEFT JOIN artifacts a "
            "ON a.run_id=r.run_id AND a.artifact_id=r.artifact_id WHERE r.run_id=? "
            "ORDER BY r.observation_id, r.artifact_id, r.locator",
            [run_id],
        ):
            if digest is None:
                raise InputError("EVIDENCE_ARTIFACT_MISSING")
            grouped.setdefault(observation, []).append(
                (EvidenceRef(artifact_id=artifact, locator=locator), digest)
            )
        return grouped

    def source_data(self, run_id):
        for row in self.rows(
            "SELECT data FROM sources WHERE run_id=? ORDER BY source_id", [run_id]
        ):
            yield json.loads(row[0])
