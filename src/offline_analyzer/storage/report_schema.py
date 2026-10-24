"""Additive append-only report revision storage; existing schema remains readable."""

DDL = (
    "CREATE TABLE IF NOT EXISTS path_reviews(review_id VARCHAR PRIMARY KEY, run_id VARCHAR, "
    "path_id VARCHAR, reviewed_at VARCHAR, data VARCHAR)",
    "CREATE TABLE IF NOT EXISTS finalized_assessments(run_id VARCHAR PRIMARY KEY, "
    "created_at VARCHAR, data VARCHAR)",
    "CREATE TABLE IF NOT EXISTS security_investigations(run_id VARCHAR, investigation_id VARCHAR, "
    "finding_id VARCHAR, data VARCHAR, PRIMARY KEY(run_id,investigation_id))",
    "CREATE TABLE IF NOT EXISTS report_revisions(report_id VARCHAR, revision INTEGER, "
    "primary_finding VARCHAR, run_id VARCHAR, created_at VARCHAR, data VARCHAR, "
    "PRIMARY KEY(report_id,revision))",
    "CREATE INDEX IF NOT EXISTS report_primary ON report_revisions(primary_finding,revision)",
    # Append-only client-report exclusions keyed by the stable finding identity.
    "CREATE TABLE IF NOT EXISTS finding_exclusions(exclusion_id VARCHAR PRIMARY KEY, "
    "finding_id VARCHAR, recorded_at VARCHAR, data VARCHAR)",
    # A purge override marks a frozen edition superseded; the edition record is kept.
    "CREATE TABLE IF NOT EXISTS finalized_supersessions(run_id VARCHAR, event_id VARCHAR, "
    "superseded_at VARCHAR, data VARCHAR, PRIMARY KEY(run_id,event_id))",
    # Append-only analyst scope-limitation text per run, rendered after the fixed limitations.
    "CREATE TABLE IF NOT EXISTS report_limitations(record_id VARCHAR PRIMARY KEY, "
    "run_id VARCHAR, recorded_at VARCHAR, data VARCHAR)",
)
