"""Reviewed semantic associations, not methodology IDs or automatic conclusions."""

MAPPINGS = {
    "rds_instance_storage_encrypted": "R0-RDS-ENCRYPTION",
    "cloudtrail_log_file_validation_enabled": "R0-CLOUDTRAIL-VALIDATION",
}


def correlate(rule_id, outcome, observations):
    supporting, contradictory, unresolved = [], [], []
    for obs in observations:
        if obs.source_tool != "prowler" or MAPPINGS.get(obs.source_check_id) != rule_id:
            continue
        if (
            obs.source_status_id not in (1, 2)
            or obs.configuration.get("muted")
            or obs.configuration.get("inactive")
            or obs.unresolved
            or obs.source_status not in {"PASS", "FAIL"}
        ):
            unresolved.append(obs.observation_id)
        elif obs.source_status == str(outcome):
            supporting.append(obs.observation_id)
        elif outcome in {"PASS", "FAIL"}:
            contradictory.append(obs.observation_id)
        else:
            unresolved.append(obs.observation_id)
    return tuple(supporting), tuple(contradictory), tuple(unresolved)
