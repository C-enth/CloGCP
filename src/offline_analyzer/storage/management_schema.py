"""Additive scope lifecycle/audit tables; no configuration contents in events."""

DDL = (
    (
        "CREATE TABLE IF NOT EXISTS scope_audit(event_id VARCHAR PRIMARY "
        "KEY, provider VARCHAR, scope_id VARCHAR, action VARCHAR, "
        "created_at VARCHAR, counts VARCHAR)"
    ),
    (
        "CREATE TABLE IF NOT EXISTS scope_state(provider VARCHAR, "
        "scope_id VARCHAR, active_run VARCHAR, PRIMARY "
        "KEY(provider,scope_id))"
    ),
    "CREATE TABLE IF NOT EXISTS scope_retired_runs(run_id VARCHAR PRIMARY KEY)",
    # Display names declared by collector manifests; identity never depends on them.
    (
        "CREATE TABLE IF NOT EXISTS scope_labels(provider VARCHAR, scope_id VARCHAR, "
        "name VARCHAR, source VARCHAR, PRIMARY KEY(provider,scope_id))"
    ),
    (
        "CREATE TABLE IF NOT EXISTS scope_invalidated_reports(report_id "
        "VARCHAR, revision INTEGER, PRIMARY KEY(report_id,revision))"
    ),
    (
        "CREATE TABLE IF NOT EXISTS scope_uploads(run_id VARCHAR, "
        "upload_id VARCHAR, PRIMARY KEY(run_id,upload_id))"
    ),
)
