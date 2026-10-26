"""Additive tables for business-group shards and imported GCP frozen editions.

Created on first open. When an existing workspace database does not have one of these tables
yet, the store checkpoints the database and keeps a copy under `schema-backups/` before
creating it (storage/store.py), so the additive change can be rolled back by restoring that
copy. No existing table or column changes.
"""

TABLES = ("enterprise_shards", "gcp_frozen_editions")
DDL = (
    # One row per business-group snapshot of a shard set (enterprise/shards.py).
    "CREATE TABLE IF NOT EXISTS enterprise_shards(shard_set VARCHAR, run_id VARCHAR, "
    "group_name VARCHAR, data VARCHAR, PRIMARY KEY(shard_set, run_id))",
    # Read-only GCP frozen editions imported into this workspace (reporting/gcp_feed.py).
    "CREATE TABLE IF NOT EXISTS gcp_frozen_editions(edition_id VARCHAR PRIMARY KEY, "
    "imported_at VARCHAR, bundle_sha256 VARCHAR, data VARCHAR)",
)
