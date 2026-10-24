"""Shared security domains and evidence-backed GCP relationship projection."""

from offline_analyzer.contracts.r0 import stable_id

DOMAINS = (
    "Identity and Access",
    "Credentials and API Security",
    "Network and Exposure",
    "Data Protection",
    "Workload Security",
    "Monitoring and Detection",
    "Governance",
    "Vulnerability and Risk",
    "Attack-Path Investigations",
)
AWS_DOMAINS = {
    "Identity and access": "Identity and Access",
    "Network exposure": "Network and Exposure",
    "Data protection": "Data Protection",
    "Compute security": "Workload Security",
    "Logging and monitoring": "Monitoring and Detection",
}


def domain(name: str) -> str:
    return AWS_DOMAINS.get(name, name)


def relationships(
    store, run: str, project: str = "", limit: int = 500, evidence: bool = True
) -> dict:
    """Bound output, retaining every edge's source locator. No implicit reachability.

    `evidence=False` leaves each edge's evidence list empty, for callers that only count
    edges (the deletion preview); the edges themselves are unchanged."""
    from offline_analyzer.rules.gcp import BASIC, IAM_UNCERTAINTY, IMPERSONATION

    edges, truncated = [], False
    refs: dict[str, list[dict]] = {}

    def evidence_of(obs) -> list[dict]:
        if not evidence:
            return []
        if obs.observation_id not in refs:  # One lookup per observation, not per edge.
            refs[obs.observation_id] = [
                r.model_dump() for r in store.refs(run, [obs.observation_id])
            ]
        return [dict(r) for r in refs[obs.observation_id]]

    def add(obs, source, destination, relation, status="STRUCTURAL_ONLY", missing=()):
        nonlocal truncated
        if len(edges) >= limit:
            truncated = True
            return
        edges.append(
            {
                "relationship_id": stable_id(
                    "gcp-edge", [source, destination, relation, obs.observation_id]
                ),
                "provider": "GCP",
                "project_id": obs.project_id,
                "source": source,
                "destination": destination,
                "relationship": relation,
                "status": status,
                "evidence": evidence_of(obs),
                "missing_evidence": list(missing),
                "attack_prerequisites": list(missing),
                "blocking_controls": [],
                "confidence": "MEDIUM" if missing else "HIGH",
                "authorization": "NOT_ESTABLISHED",
                "collected_at": obs.collected_at.isoformat() if obs.collected_at else None,
            }
        )

    for obs in store.observations(run, provider="GCP", project=project or None):
        if obs.provider != "GCP" or (project and obs.project_id != project) or not obs.resource_id:
            continue
        if obs.resource_type == "GCP::Unsupported" or obs.unresolved:
            continue
        if len(edges) >= limit:
            truncated = True
            break
        scope = "gcp:projects/" + obs.project_id
        add(obs, scope, obs.resource_id, "CONTAINS_OBSERVED_RESOURCE")
        if obs.organization_id:
            add(
                obs,
                "gcp:organizations/" + obs.organization_id,
                "gcp:folders/" + obs.folder_id if obs.folder_id else scope,
                "DECLARED_PARENT_SCOPE",
            )
        if obs.folder_id:
            add(obs, "gcp:folders/" + obs.folder_id, scope, "DECLARED_PARENT_SCOPE")
        c = obs.configuration
        if obs.resource_type == "GCP::IAMBinding":
            role = c.get("role")
            if role:
                add(obs, obs.resource_id, "gcp:" + role, "OBSERVED_ROLE_BINDING")
            for principal in c.get("members", []):
                add(
                    obs,
                    "gcp:principal:" + principal,
                    obs.resource_id,
                    "OBSERVED_ALLOW_BINDING",
                    "POTENTIAL" if role in BASIC | IMPERSONATION else "STRUCTURAL_ONLY",
                    IAM_UNCERTAINTY if role in BASIC | IMPERSONATION else (),
                )
        elif obs.resource_type == "GCP::ServiceAccountKey" and "/keys/" in obs.native_id:
            add(
                obs,
                obs.resource_id,
                "gcp:" + obs.native_id.split("/keys/", 1)[0],
                "KEY_BELONGS_TO_SERVICE_ACCOUNT",
            )
        elif obs.resource_type == "GCP::SCCFinding" and c.get("resourceName"):
            add(obs, obs.resource_id, "gcp:" + c["resourceName"], "SCC_OBSERVES_RESOURCE")
    return {"items": edges, "truncated": truncated, "limit": limit}
