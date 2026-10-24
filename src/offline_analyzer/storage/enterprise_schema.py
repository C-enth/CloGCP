"""Additive versioned enterprise projection tables; legacy schema remains readable."""

DDL = (
    "CREATE TABLE IF NOT EXISTS enterprise_projection(run_id VARCHAR PRIMARY KEY,data VARCHAR)",
    (
        "CREATE TABLE IF NOT EXISTS "
        "enterprise_snapshots(run_id VARCHAR PRIMARY KEY, members VARCHAR, version VARCHAR)"
    ),
    "CREATE TABLE IF NOT EXISTS enterprise_edges(run_id VARCHAR, relationship_id VARCHAR, "
    "source_account VARCHAR, destination_account VARCHAR, kind VARCHAR, "
    "domain VARCHAR, status VARCHAR, "
    "data VARCHAR, PRIMARY KEY(run_id,relationship_id))",
    (
        "CREATE INDEX IF NOT EXISTS enterprise_pair ON "
        "enterprise_edges(run_id,source_account,destination_account)"
    ),
    "CREATE TABLE IF NOT EXISTS enterprise_issues(run_id VARCHAR, "
    "investigation_id VARCHAR, data VARCHAR, "
    "PRIMARY KEY(run_id,investigation_id))",
)
