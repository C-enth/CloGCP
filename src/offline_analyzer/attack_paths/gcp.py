"Bounded GCP candidate investigations with explicit unverified exploit prerequisites."

from offline_analyzer.contracts.gcp import CloudTransition
from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.findings.generate import validation_status
from offline_analyzer.rules.gcp import IAM_UNCERTAINTY

INVESTIGATION_RULES = frozenset(
    {
        "GCP-KEY-PERSISTENT",
        "GCP-KEY-PRIVILEGED",
        "GCP-IAM-IMPERSONATION",
        "GCP-IAM-CROSSPROJECT",
        "GCP-IAM-PUBLIC",
        "GCP-API-BOTH",
        "GCP-STORAGE-PUBLIC",
    }
)


def investigations(store, run: str, project: str = "", limit: int = 100) -> dict:
    store.require_run(run)
    paths = []
    decisions = store.latest_decisions(run)
    observations = {
        o.resource_id: o
        for o in store.observations(run, provider="GCP")
        if o.provider == "GCP" and o.resource_id
    }
    for finding in store.candidates(run):
        if finding.provider != "GCP" or (project and finding.project_id != project):
            continue
        if finding.rule_id not in INVESTIGATION_RULES:
            continue
        if len(paths) >= limit:
            return {"items": paths, "truncated": True}
        credential = finding.rule_id.startswith(("GCP-KEY-", "GCP-API-"))
        prerequisite = (
            "Attacker possession of the credential"
            if credential
            else "Attacker control of an authorized principal"
        )
        refs = [r.model_dump() for r in finding.evidence]
        observed = observations.get(finding.resource_id)
        transitions = [
            {
                "provider": "GCP",
                "source": "Hypothetical attacker",
                "destination": finding.resource_id,
                "relationship": prerequisite,
                "status": "UNKNOWN",
                "evidence": [],
                "attack_prerequisites": [prerequisite],
                "missing_evidence": [prerequisite],
                "blocking_controls": [],
            }
        ]
        if finding.rule_id.startswith("GCP-KEY-"):
            subject = finding.native_id.split("/keys/", 1)[0]
            transitions.append(
                {
                    "provider": "GCP",
                    "source": finding.resource_id,
                    "destination": "gcp:" + subject,
                    "relationship": "Observed user-managed key belongs to the service account",
                    "status": "STRUCTURAL_ONLY",
                    "evidence": refs,
                    "attack_prerequisites": [],
                    "missing_evidence": [],
                    "blocking_controls": [],
                }
            )
            endpoint = "gcp:" + subject
            email = subject.split("/serviceAccounts/", 1)[-1]
            privileged = [
                o
                for o in observations.values()
                if o.project_id == finding.project_id
                and o.resource_type == "GCP::IAMBinding"
                and o.configuration.get("role") in {"roles/owner", "roles/editor"}
                and "serviceAccount:" + email in o.configuration.get("members", [])
            ]
            if privileged:
                binding = privileged[0]
                transitions.append(
                    {
                        "provider": "GCP",
                        "source": endpoint,
                        "destination": binding.resource_id,
                        "relationship": "Observed service-account privilege binding",
                        "status": "STRUCTURAL_ONLY",
                        "evidence": [
                            r.model_dump() for r in store.refs(run, [binding.observation_id])
                        ],
                        "attack_prerequisites": [],
                        "missing_evidence": [],
                        "blocking_controls": [],
                    }
                )
                endpoint = binding.resource_id
        else:
            endpoint = finding.resource_id
        api_key = finding.rule_id.startswith("GCP-API-")
        destination = (
            "gcp:api-usage-scope/" + finding.project_id
            if api_key
            else "gcp:projects/" + finding.project_id
        )
        unresolved_key = finding.rule_id.startswith("GCP-KEY-") and not privileged
        if unresolved_key:
            destination = "gcp:authorization-context/" + subject
        dependency = (
            [
                "API accepts API-key authentication",
                "Authorized service usage, billing/quota and intended client context",
            ]
            if api_key
            else list(IAM_UNCERTAINTY)
        )
        if observed and observed.resource_type == "GCP::IAMBinding":
            destination = "gcp:" + observed.configuration.get(
                "subject", "projects/" + finding.project_id
            )
        transitions.append(
            {
                "provider": "GCP",
                "source": endpoint,
                "destination": destination,
                "relationship": "Potential API usage subject to service/possession prerequisites"
                if api_key
                else (
                    "Observed binding or credential risk; effective authorization requires "
                    "separate evidence"
                ),
                "status": "UNKNOWN" if unresolved_key else "POTENTIAL",
                "evidence": refs,
                "attack_prerequisites": dependency,
                "missing_evidence": list(finding.missing_evidence) or dependency,
                "blocking_controls": [],
            }
        )
        paths.append(
            {
                "path_id": stable_id("gcp-path", [finding.finding_id, "1.0.0"]),
                "provider": "GCP",
                "project_id": finding.project_id,
                "finding_id": finding.finding_id,
                "title": finding.title,
                "severity": finding.suggested_severity,
                "domain": finding.security_domain,
                "status": "UNKNOWN",
                "confidence": finding.evidence_confidence,
                "analyst_status": validation_status(store, finding, decisions)[0],
                "transitions": [
                    CloudTransition.model_validate(t).model_dump(mode="json") for t in transitions
                ],
                "evidence": refs,
                "missing_evidence": [prerequisite, *finding.missing_evidence],
                "qualification": (
                    "Candidate investigation; no confirmed effective access or exploitation. "
                    "No cross-cloud transition."
                ),
            }
        )
    return {"items": paths, "truncated": False}
