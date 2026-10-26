"""Faster scope deletion keeps exact results: compaction, verification scan, progress stages
(synthetic data only)."""

import hashlib
import shutil

from test_scope_management import mixed  # noqa: F401  (fixture)

from offline_analyzer.assessment import manage, purge_verify
from offline_analyzer.provenance.execution import Execution, executing
from offline_analyzer.storage.store import Store


def table_digests(store: Store) -> dict[str, tuple[int, str]]:
    result = {}
    for (name,) in store.db.execute("SHOW TABLES").fetchall():
        quoted = '"' + name.replace('"', '""') + '"'
        rows = sorted(map(repr, store.db.execute(f"SELECT * FROM {quoted}").fetchall()))
        result[name] = (len(rows), hashlib.sha256(repr(rows).encode()).hexdigest())
    return result


def test_compact_copies_every_row_exactly(mixed, tmp_path):  # noqa: F811
    work, _run = mixed
    copy = tmp_path / "copy"
    copy.mkdir()
    shutil.copyfile(work / "assessment.duckdb", copy / "assessment.duckdb")
    source = Store(copy, _recover=False)
    try:
        manage.compact(source, copy / "compact")
        target = Store(copy / "compact", _recover=False)
        try:
            assert table_digests(target) == table_digests(source)
        finally:
            target.db.close()
    finally:
        source.db.close()
    assert not (copy / "compact" / "assessment.duckdb.wal").exists()


def per_column_counts(store: Store, provider: str, identifiers: list[str]) -> dict[str, int]:
    """The original one-query-per-column-and-identifier definition of a matching row."""
    counts: dict[str, int] = {}
    columns = store.db.execute(
        "SELECT table_name,column_name FROM information_schema.columns "
        "WHERE table_schema='main' AND data_type='VARCHAR'"
    ).fetchall()
    for table, column in columns:
        for identifier in identifiers:
            (count,) = store.db.execute(
                f'SELECT count(*) FROM "{table}" WHERE regexp_matches("{column}", ?)',
                [purge_verify.token_pattern(identifier, provider)],
            ).fetchone()
            if count:
                counts[table] = counts.get(table, 0) + count
    return counts


def test_scan_counts_equal_the_per_column_definition(mixed):  # noqa: F811
    work, _run = mixed
    with Store(work) as store:
        for provider, identifiers in [
            ("GCP", ["demo-alpha", "123456789012"]),
            ("GCP", ["demo-alph"]),  # a prefix of a longer project ID never matches
            ("AWS", ["111111111111"]),
            ("AWS", ["11111111111"]),
        ]:
            found = purge_verify.scan(store, provider, identifiers)["database"]
            assert found == per_column_counts(store, provider, identifiers)


def test_file_search_spans_chunks_and_keeps_token_boundaries(tmp_path, monkeypatch):
    monkeypatch.setattr(purge_verify, "CHUNK", 8)
    searches = [
        (b"demo-alpha", purge_verify.re.compile(b"(^|[^a-z0-9-])demo\\-alpha($|[^a-z0-9-])"))
    ]
    split = tmp_path / "split.json"
    split.write_bytes(b'{"project": "demo-alpha"}')  # crosses several 8-byte chunks
    longer = tmp_path / "longer.json"
    longer.write_bytes(b'{"project": "demo-alpha2"}')
    absent = tmp_path / "absent.json"
    absent.write_bytes(b'{"project": "demo-beta"}')
    assert purge_verify._file_contains(split, searches, len("demo-alpha") + 2)
    assert not purge_verify._file_contains(longer, searches, len("demo-alpha") + 2)
    assert not purge_verify._file_contains(absent, searches, len("demo-alpha") + 2)


def test_scope_delete_reports_its_stages_in_order(mixed):  # noqa: F811
    work, _run = mixed
    stages: list[tuple[str, int | None, int | None]] = []
    execution = Execution(lambda stage, done, total: stages.append((stage, done, total)))
    with Store(work) as store, executing(execution):
        preview = manage.plan(store, "GCP", "demo-alpha")
        result = manage.delete_scope(
            store, "GCP", "demo-alpha", preview["preview_token"], "demo-alpha", True
        )
    assert result["verification"]["clean"] is True
    expected = [
        "SCOPE_BACKUP",
        "SCOPE_VERIFY_BEFORE",
        "SCOPE_STAGING",
        "SCOPE_PURGE",
        "SCOPE_REASSESS",
        "SCOPE_COMPACT",
        "SCOPE_PUBLISH",
        "SCOPE_VERIFY_AFTER",
    ]
    seen = [stage for stage, _, _ in stages if stage in expected]
    assert [s for i, s in enumerate(seen) if i == 0 or s != seen[i - 1]] == expected
    reassess = [(done, total) for stage, done, total in stages if stage == "SCOPE_REASSESS"]
    assert reassess and all(total and 0 <= done < total for done, total in reassess)


class CountingConnection:
    """Counts statements, so a preview cannot quietly become one query per row again."""

    def __init__(self, db):
        self.db, self.statements = db, 0

    def execute(self, *args, **kwargs):
        self.statements += 1
        return self.db.execute(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.db, name)


def inflate(store: Store, project: str, copies: int) -> None:
    """Synthetic copies of a project's observations and their evidence references."""
    predicate = manage.observation_predicate("GCP")
    columns = [
        name
        for (name,) in store.db.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name='observations' ORDER BY ordinal_position"
        ).fetchall()
    ]
    select = ",".join(
        "observation_id || '-copy' || g.i::VARCHAR" if c == "observation_id" else c for c in columns
    )
    store.db.execute(
        "CREATE TEMP TABLE originals AS SELECT run_id,observation_id FROM observations "
        f"WHERE {predicate}",
        [project],
    )
    store.db.execute(
        f"INSERT INTO observations SELECT {select} FROM observations, range(?) g(i) "
        f"WHERE {predicate}",
        [copies, project],
    )
    store.db.execute(
        "INSERT INTO evidence_refs SELECT e.* REPLACE ("
        "e.observation_id || '-copy' || g.i::VARCHAR AS observation_id, "
        "e.locator || '/copy' || g.i::VARCHAR AS locator) "
        "FROM evidence_refs e JOIN originals USING(run_id,observation_id), range(?) g(i)",
        [copies],
    )


def test_preview_query_count_does_not_grow_with_observations(mixed):  # noqa: F811
    work, _run = mixed
    with Store(work) as store:
        counting = CountingConnection(store.db)
        store.db = counting
        small = manage.plan(store, "GCP", "demo-alpha")
        before = counting.statements
        store.db = counting.db
        inflate(store, "demo-alpha", 50)
        counting = CountingConnection(store.db)
        store.db = counting
        large = manage.plan(store, "GCP", "demo-alpha")
        store.db = counting.db
    assert counting.statements == before
    assert large["shared_raw_blocked"] is small["shared_raw_blocked"] is False
    assert large["resources"] == small["resources"]


def test_relationship_count_without_evidence_keeps_every_edge(mixed):  # noqa: F811
    from offline_analyzer.inventory.cloud import relationships

    work, _run = mixed
    with Store(work) as store:
        for (run,) in store.db.execute("SELECT run_id FROM runs").fetchall():
            for project in ("", "demo-alpha", "demo-beta"):
                full = relationships(store, run, project=project)
                bare = relationships(store, run, project=project, evidence=False)
                assert [dict(e, evidence=[]) for e in full["items"]] == bare["items"]
                assert full["truncated"] == bare["truncated"]
                assert all(e["evidence"] for e in full["items"])
