"""Correlate stored rule results into typed attack-path prerequisite records.

Derived deterministically from persisted evaluations at report time. States follow the
PathEvaluation vocabulary, but SUPPORTED is unreachable here: every implemented path
retains an EXPLOITATION or IAM_ENGINE prerequisite that configuration cannot verify.
"""

from collections import defaultdict
from dataclasses import dataclass, field

from offline_analyzer.attack_paths.specs import BY_PATH, SPEC_VERSION
from offline_analyzer.contracts.r0 import Normalized, stable_id

VERIFIED, ABSENT, UNKNOWN, NOT_EVALUATED = "VERIFIED", "NOT_PRESENT", "UNKNOWN", "NOT_EVALUATED"
STATUS_BY_OUTCOME = {"FAIL": VERIFIED, "PASS": ABSENT, "NOT_APPLICABLE": ABSENT}


@dataclass(frozen=True)
class PathRecord:
    record_id: str
    path_id: str
    account_id: str
    region: str
    anchor: str
    state: str
    prerequisites: dict[str, str]
    evaluations: tuple[str, ...]
    threats: tuple[str, ...]
    blockers: tuple[str, ...]
    reasoning: str
    missing: tuple[str, ...] = field(default=())
    definition_version: str = SPEC_VERSION


def unresolved(spec, statuses: dict[str, str]) -> tuple[str, ...]:
    return tuple(
        f"{p.key} ({p.kind})" for p in spec.prerequisites if statuses.get(p.key) != VERIFIED
    )


def internet_exposed_instances(store, run_id, results) -> list[PathRecord]:
    """AP-04: public sensitive-port exposure (P1) correlated with IMDSv1 (P2) per instance."""
    spec = BY_PATH["AP-04"]
    imds = {
        r.resource_id: r
        for r in results
        if r.rule_id == "R0-EC2-IMDSV2" and r.evaluation_scope == "RESOURCE"
    }
    exposures = defaultdict(list)
    for result in results:
        if result.rule_id != "R1-EC2-SG-SENSITIVE-INGRESS" or result.outcome != "FAIL":
            continue
        for oid in result.supporting_observations:
            row = store.db.execute(
                "SELECT data FROM observations WHERE run_id=? AND observation_id=? AND kind=?",
                [run_id, oid, "AWS::EC2::NetworkInterface"],
            ).fetchone()
            if not row:
                continue
            interface = Normalized.model_validate_json(row[0])
            instance = interface.configuration.get("AttachmentInstanceId")
            if not isinstance(instance, str) or not interface.partition:
                continue
            resource = stable_id(
                "resource",
                [
                    interface.partition,
                    interface.account_id,
                    interface.region,
                    "AWS::EC2::Instance",
                    instance,
                ],
            )
            exposures[(resource, interface.account_id, interface.region, instance)].append(
                result.evaluation_id
            )
    records = []
    for (resource, account, region, instance), evaluations in sorted(exposures.items()):
        statuses = {p.key: NOT_EVALUATED for p in spec.prerequisites}
        statuses["AP-04.P1"] = VERIFIED
        blockers = []
        metadata = imds.get(resource)
        if metadata:
            statuses["AP-04.P2"] = STATUS_BY_OUTCOME.get(str(metadata.outcome), UNKNOWN)
            evaluations = evaluations + [metadata.evaluation_id]
            if statuses["AP-04.P2"] == ABSENT:
                blockers.append("IMDSv2 required or endpoint disabled: SSRF-to-IMDSv1 variant")
        else:
            statuses["AP-04.P2"] = UNKNOWN
        records.append(
            PathRecord(
                record_id=stable_id("path-record", ["AP-04", resource]),
                path_id="AP-04",
                account_id=account,
                region=region,
                anchor=instance,
                state="UNKNOWN",
                prerequisites=statuses,
                evaluations=tuple(sorted(set(evaluations))),
                threats=spec.threats,
                blockers=tuple(blockers),
                reasoning="Entry prerequisite verified from configuration; exploitation and "
                "instance-role impact are not evaluated, so the chain is not established.",
                missing=unresolved(spec, statuses),
            )
        )
    return records


def public_storage_accounts(results) -> list[PathRecord]:
    """AP-05: account-level Block Public Access as a verified blocker or open prerequisite."""
    spec = BY_PATH["AP-05"]
    records = []
    for result in results:
        if result.rule_id != "R1-S3-ACCOUNT-BPA" or result.evaluation_scope != "RESOURCE":
            continue
        status = STATUS_BY_OUTCOME.get(str(result.outcome), UNKNOWN)
        statuses = {p.key: NOT_EVALUATED for p in spec.prerequisites}
        statuses["AP-05.P1"] = status
        blocked = str(result.outcome) == "PASS"
        records.append(
            PathRecord(
                record_id=stable_id("path-record", ["AP-05", result.resource_id]),
                path_id="AP-05",
                account_id=result.account_id,
                region=result.region,
                anchor=result.native_id,
                state="BLOCKED" if blocked else "UNKNOWN",
                prerequisites=statuses,
                evaluations=(result.evaluation_id,),
                threats=spec.threats,
                blockers=("All four account-level Block Public Access settings enabled",)
                if blocked
                else (),
                reasoning="Account-level settings block anonymous public access to every "
                "bucket in the account at collection time; cross-account grants are separate."
                if blocked
                else "Account-level guardrail absent or unresolved; bucket policies, ACLs and "
                "data sensitivity are not evaluated, so exposure is not established.",
                missing=() if blocked else unresolved(spec, statuses),
            )
        )
    # Bucket-level evidence: a FAIL of R1-S3-BUCKET-PUBLIC-ACCESS means a policy/ACL grants
    # anonymous access that bucket-level Block Public Access does not block (P2 and P3).
    accounts = {
        r.account_id: r
        for r in results
        if r.rule_id == "R1-S3-ACCOUNT-BPA" and r.evaluation_scope == "RESOURCE"
    }
    for result in results:
        if result.rule_id != "R1-S3-BUCKET-PUBLIC-ACCESS" or str(result.outcome) != "FAIL":
            continue
        account = accounts.get(result.account_id)
        statuses = {p.key: NOT_EVALUATED for p in spec.prerequisites}
        statuses["AP-05.P1"] = (
            STATUS_BY_OUTCOME.get(str(account.outcome), UNKNOWN) if account else UNKNOWN
        )
        statuses["AP-05.P2"] = statuses["AP-05.P3"] = VERIFIED
        blocked = bool(account) and str(account.outcome) == "PASS"
        records.append(
            PathRecord(
                record_id=stable_id("path-record", ["AP-05", result.resource_id]),
                path_id="AP-05",
                account_id=result.account_id,
                region=result.region,
                anchor=result.native_id,
                state="BLOCKED" if blocked else "UNKNOWN",
                prerequisites=statuses,
                evaluations=tuple(e.evaluation_id for e in (account, result) if e is not None),
                threats=spec.threats,
                blockers=("All four account-level Block Public Access settings enabled",)
                if blocked
                else (),
                reasoning="Bucket policy/ACL grants anonymous access not blocked at bucket "
                "level; account-level guardrail status is taken from R1-S3-ACCOUNT-BPA. "
                "Data sensitivity is not evaluated.",
                missing=() if blocked else unresolved(spec, statuses),
            )
        )
    return records


PRIVILEGE_STATUS = {
    "ADMIN_EQUIVALENT": VERIFIED,
    "ESCALATION_CAPABLE": VERIFIED,
    "NOT_SHOWN_PRIVILEGED": ABSENT,
}


def instance_role_privilege(records, analysis) -> list[PathRecord]:
    """AP-04.P4 from the IAM analysis of the instance's role (supported levels only)."""
    roles_by_instance = {}
    for instance in analysis.instances:
        profile = instance.configuration["InstanceProfileArn"]
        roles_by_instance[instance.native_id] = analysis.inventory.profiles.get(profile, ())
    updated = []
    for record in records:
        if record.path_id != "AP-04":
            updated.append(record)
            continue
        statuses = dict(record.prerequisites)
        levels = [
            analysis.privilege(analysis.inventory.by_arn[arn])[0]
            for arn in roles_by_instance.get(record.anchor, ())
            if arn in analysis.inventory.by_arn
        ]
        statuses["AP-04.P4"] = (
            next((PRIVILEGE_STATUS[lv] for lv in levels if lv in PRIVILEGE_STATUS), UNKNOWN)
            if levels
            else NOT_EVALUATED
        )
        spec = BY_PATH["AP-04"]
        updated.append(
            PathRecord(
                **{
                    **record.__dict__,
                    "prerequisites": statuses,
                    "missing": unresolved(spec, statuses),
                }
            )
        )
    return updated


def iam_escalation(analysis) -> list[PathRecord]:
    """AP-06 records from PassRole investigations; exploitation is never evaluated."""
    spec = BY_PATH["AP-06"]
    records = []
    grouped = {}
    for record in analysis.passrole():
        if record.classification in {"SUPPORTED_ESCALATION_PREREQUISITES", "POTENTIAL_ESCALATION"}:
            grouped.setdefault(record.principal, []).append(record)
    for principal, items in sorted(grouped.items()):
        role = analysis.inventory.by_arn[principal]
        supported = any(r.classification == "SUPPORTED_ESCALATION_PREREQUISITES" for r in items)
        statuses = {p.key: NOT_EVALUATED for p in spec.prerequisites}
        statuses["AP-06.P1"] = VERIFIED if supported else UNKNOWN
        scp = analysis.org.applicability(
            role.account, "SERVICE_CONTROL_POLICY", role.service_linked
        )
        statuses["AP-06.P4"] = (
            VERIFIED if supported else (UNKNOWN if scp != "NOT_APPLICABLE" else VERIFIED)
        )
        records.append(
            PathRecord(
                record_id=stable_id("path-record", ["AP-06", principal]),
                path_id="AP-06",
                account_id=role.account,
                region="global",
                anchor=principal,
                state="UNKNOWN",
                prerequisites=statuses,
                evaluations=tuple(sorted(f"{r.target} via {r.service}" for r in items)),
                threats=spec.threats,
                blockers=(),
                reasoning="PassRole escalation prerequisites "
                + ("supported by evidence" if supported else "partly evidenced")
                + "; attacker control of the principal is not evaluated.",
                missing=unresolved(spec, statuses),
            )
        )
    return records


def path_records(store, run_id, registry=None) -> list[PathRecord]:
    from offline_analyzer.iam.analysis import IamAnalysis

    results = list(store.results(run_id))
    analysis = IamAnalysis(store, run_id, list(store.source_data(run_id)), registry)
    exposed = instance_role_privilege(internet_exposed_instances(store, run_id, results), analysis)
    return exposed + public_storage_accounts(results) + iam_escalation(analysis)
