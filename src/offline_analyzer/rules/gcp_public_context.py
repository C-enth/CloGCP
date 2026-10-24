"""Apply collected bucket/ingress controls to CAI public-policy observations.

Policy projections contain only original binding fields and keep the original observation
ID/evidence reference. They are never inserted as new normalized evidence or relationships.
"""

from dataclasses import replace

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.rules.configuration import Verdict
from offline_analyzer.rules.gcp_context import GCPContext, canonical, usable


def _public_context(
    rule_id: str, observation: Normalized, context: GCPContext, native_findings: dict
) -> Verdict | None:
    c = observation.configuration
    resource = c.get("resource", "")
    kind = c.get("assetType")
    if rule_id == "GCP-ORG-PUBLIC-DATA" and kind == "storage.googleapis.com/Bucket":
        from offline_analyzer.rules.gcp import evaluate

        subject = resource.removeprefix("//storage.googleapis.com/")
        if not subject.startswith("buckets/"):
            subject = "buckets/" + subject
        verdicts = []
        for binding in (c.get("policy") or {}).get("bindings", []):
            if (
                not isinstance(binding, dict)
                or binding.get("condition")
                or not {"allUsers", "allAuthenticatedUsers"}.intersection(
                    binding.get("members", [])
                )
            ):
                continue
            projection = observation.model_copy(
                update={
                    "configuration": {**binding, "subject": subject},
                    "resource_type": "GCP::IAMBinding",
                }
            )
            verdicts.append(evaluate("GCP-STORAGE-PUBLIC", projection, context))
        if not verdicts:
            return None
        selected = next(
            (v for v in verdicts if v.outcome == Outcome.FAIL),
            next((v for v in verdicts if v.outcome == Outcome.UNKNOWN), verdicts[0]),
        )
        if selected.outcome == Outcome.PASS and (
            not context.complete(observation)
            or any(
                oid not in context.by_id or not context.complete(context.by_id[oid])
                for oid in selected.related
            )
        ):
            return Verdict(
                Outcome.UNKNOWN,
                "Complete bucket and effective-policy evidence required.",
                ("Complete supporting public-access prevention evidence",),
            )
        return (
            replace(selected, outcome=Outcome.NOT_APPLICABLE)
            if selected.outcome == Outcome.PASS
            else selected
        )
    if rule_id != "GCP-ORG-PUBLIC-SERVERLESS":
        return None
    from offline_analyzer.rules.gcp_domains import serverless_public

    services = [
        o
        for resource_type in ("GCP::RunService", "GCP::Function")
        for o in context.of(resource_type)
        if usable(o) and canonical(o.native_id) == canonical(resource)
    ]
    if not services:
        return Verdict(
            Outcome.UNKNOWN,
            (
                "A public invoker binding is observed; service ingress, generation "
                "and IAM-check configuration were not collected."
            ),
            ("Exact service configuration and effective ingress",),
        )
    if not observation.collected_at or any(
        not o.collected_at
        or abs((o.collected_at - observation.collected_at).total_seconds()) > 86400
        for o in services
    ):
        return Verdict(
            Outcome.UNKNOWN,
            "Native service and CAI policy timestamps cannot establish a consistent snapshot.",
            ("Time-aligned service and IAM configuration",),
        )
    policy = observation.model_copy(
        update={
            "configuration": dict(c["policy"]),
            "resource_type": "GCP::IAMPolicy",
            "native_id": canonical(resource),
        }
    )
    projected_context = context.with_policy(policy)
    values = [serverless_public(o, projected_context) for o in services]
    if len({v.outcome for v in values}) != 1:
        return Verdict(
            Outcome.UNKNOWN,
            "Contradictory native service snapshots.",
            ("Consistent service ingress and authorization snapshots",),
        )
    value = values[0]
    related = tuple(dict.fromkeys((*value.related, *(o.observation_id for o in services))))
    native_rule = (
        "GCP-RUN-PUBLIC"
        if services[0].resource_type == "GCP::RunService"
        else "GCP-FUNCTION-PUBLIC"
    )
    existing = native_findings.get((native_rule, services[0].resource_id))
    fresh = observation.collected_at and all(
        o.collected_at and abs((o.collected_at - observation.collected_at).total_seconds()) <= 300
        for o in services
    )
    if value.outcome == Outcome.FAIL and existing and fresh:
        return Verdict(
            Outcome.MANUAL_VALIDATION_REQUIRED,
            (
                f"Equivalent public-invocation condition is reported once by native "
                f"finding {existing}; this CAI policy is related supporting evidence."
            ),
            related=related,
        )
    return replace(value, related=related)


def public_context(
    rule_id: str, observation: Normalized, context: GCPContext, native_findings: dict
) -> Verdict | None:
    try:
        return _public_context(rule_id, observation, context, native_findings)
    except (TypeError, ValueError, AttributeError, KeyError):
        return Verdict(
            Outcome.UNKNOWN,
            "Public policy or related service configuration is malformed.",
            ("Valid public policy and resource configuration types",),
        )
