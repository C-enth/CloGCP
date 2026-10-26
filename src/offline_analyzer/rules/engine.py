"""Reproducible per-resource checks plus explicit scope gaps; no account-wide PASS."""

import json
from datetime import datetime

from offline_analyzer.contracts.models import EvidenceRef, Outcome
from offline_analyzer.contracts.r0 import Normalized, Result, stable_id
from offline_analyzer.correlation.prowler import MAPPINGS, correlate
from offline_analyzer.findings.generate import candidate
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import resolve_under, sha256_file
from offline_analyzer.inventory.accounts import workspace_registry
from offline_analyzer.provenance.execution import checkpoint, committing
from offline_analyzer.rules.aws_identity import enrich
from offline_analyzer.rules.configuration import as_verdict
from offline_analyzer.rules.context import EvaluationContext
from offline_analyzer.rules.methodology_links import mapping_fields
from offline_analyzer.rules.registry import (
    ALL_RULES,
    AWS_IDENTITY_ENRICHED,
    AWS_PRINCIPAL_CONTEXT_RULES,
    DEPENDENT_PARENTS,
    primary_operations,
    rule_operations,
)

GLOBAL = "global"
ENGINE_VERSION = "1.7.0"


def verify_raw(store, run_id: str) -> None:
    for digest, size in store.rows(
        "SELECT DISTINCT sha256, size_bytes FROM artifacts WHERE run_id=?", [run_id]
    ):
        path = resolve_under(store.workspace, f"raw/{digest}.json")
        if path.stat().st_size != size or sha256_file(path) != digest:
            raise InputError("STORED_RAW_INTEGRITY_FAILURE")


def evaluate_resource(
    store,
    run_id,
    rule,
    observations,
    assessed_at,
    source_list,
    context=None,
    refs=None,
    by_artifact=None,
):
    identity = observations[0]
    operations = primary_operations(rule)
    native = [
        o
        for o in observations
        if o.source_tool == "aws"
        and o.operation in operations
        and o.resource_type == rule.resource_type
    ]
    scanner = [
        o
        for o in observations
        if o.source_tool == "prowler" and MAPPINGS.get(o.source_check_id) == rule.rule_id
    ]
    if not native and not scanner:
        return None
    selected = native + scanner
    limitations = [
        "Proposed methodology mapping pending approval; evaluates only the named criteria"
        if rule.methodology
        else (
            "Additional security observation outside the approved methodology; "
            "analyst review required"
        ),
        "Configuration snapshot only; not proof of exposure or exploitation",
    ]
    missing = ()
    native_conflicts = ()
    related = ()
    context_fields = {}
    verdicts = {}
    # by_artifact: the same mapping, built once per assessment by the caller.
    sources = (
        by_artifact
        if by_artifact is not None
        else {s["artifact_id"]: s for s in source_list if s["artifact_id"]}
    )
    if not identity.resource_id:
        outcome, reasoning, missing = (
            Outcome.UNKNOWN,
            "Resource identity or scope is unresolved.",
            ("verified resource identity and account/region",),
        )
    elif not native:
        source_errors = [
            s
            for s in source_list
            if s["operation"] in operations
            and s["account_id"] == identity.account_id
            and (s["region"] == identity.region or rule.scope == "GLOBAL")
            and (s["effective_coverage"] == "ERROR" or s["errors"])
        ]
        outcome = Outcome.COLLECTION_ERROR if source_errors else Outcome.MANUAL_VALIDATION_REQUIRED
        reasoning = (
            "Scanner status is retained; native configuration is required "
            "for this analyzer conclusion."
        )
        missing = (rule.operation,)
    else:
        usable = []
        for obs in native:
            source = sources[obs.evidence.artifact_id]
            if source["effective_coverage"] in {"ERROR", "NOT_COLLECTED"}:
                continue
            usable.append(obs)
            verdict = as_verdict(
                rule.evaluate(obs, context) if rule.contextual else rule.evaluate(obs)
            )
            verdict = rule.annotate(obs, verdict) if rule.annotate else verdict
            if rule.rule_id in AWS_IDENTITY_ENRICHED | AWS_PRINCIPAL_CONTEXT_RULES:
                verdict = enrich(rule.rule_id, obs, verdict, context)
            verdicts[obs.observation_id] = verdict
            if source["effective_coverage"] != "COMPLETE":
                limitations.append(
                    "Collection is partial; result applies only to the observed resource"
                )
            limitations.extend(obs.unresolved)
        answers = list(verdicts.values())
        if not usable:
            outcome, reasoning, missing = (
                Outcome.COLLECTION_ERROR
                if any(
                    sources[o.evidence.artifact_id]["effective_coverage"] == "ERROR" for o in native
                )
                else Outcome.UNKNOWN,
                "Native collection did not establish a successful configuration snapshot.",
                (rule.operation,),
            )
        elif len({(a.outcome, a.reasoning, a.missing) for a in answers}) > 1:
            native_conflicts = tuple(o.observation_id for o in usable)
            outcome, reasoning, missing = (
                Outcome.UNKNOWN,
                "Native snapshots disagree or prerequisites differ; reconcile collection times.",
                ("consistent configuration snapshot",),
            )
        else:
            outcome, reasoning, missing = (
                answers[0].outcome,
                answers[0].reasoning,
                answers[0].missing,
            )
            # Agreeing snapshots keep every caveat and related-evidence reference.
            related = tuple(sorted({oid for a in answers for oid in a.related}))
            limitations.extend(item for a in answers for item in a.limitations)
            context_fields = risk_context(rule, outcome, answers)
    support, contradiction, unresolved = correlate(rule.rule_id, outcome, scanner)
    contradiction = native_conflicts + contradiction
    if contradiction:
        limitations.append(
            "Configuration observations disagree; resolve timestamp/scope before approval"
        )
    if unresolved:
        limitations.append(
            "Prowler observation needs validation; it cannot establish a configuration conclusion"
        )
    wanted = [o.observation_id for o in selected] + list(related)
    refs = refs(wanted) if refs else store.refs(run_id, wanted)
    # Native configuration drives FAIL/PASS; retain all supporting/conflicting evidence.
    confidence = "MEDIUM" if contradiction or any(o.unresolved for o in native) else "HIGH"
    if outcome not in {Outcome.PASS, Outcome.FAIL, Outcome.NOT_APPLICABLE}:
        confidence = "UNASSESSED"
    return Result(
        evaluation_id=stable_id(
            "evaluation",
            [rule.rule_id, rule.version, identity.resource_id or identity.observation_id],
        ),
        rule_id=rule.rule_id,
        rule_version=rule.version,
        **mapping_fields(rule),
        account_id=identity.account_id,
        region=identity.region,
        resource_id=identity.resource_id,
        native_id=identity.native_id,
        outcome=outcome,
        reasoning=reasoning,
        evidence=refs,
        supporting_observations=tuple(
            oid
            for oid, verdict in verdicts.items()
            if not native_conflicts and identity.resource_id and verdict.outcome == outcome
        )
        + tuple(related)
        + support,
        contradictory_observations=contradiction,
        missing_dependencies=missing,
        confidence=confidence,
        limitations=tuple(sorted(set(limitations))),
        assessed_at=assessed_at,
        **context_fields,
    )


def risk_context(rule, outcome, answers) -> dict:
    """Class/severity/exposure for FAIL results; agreeing snapshots keep every detail."""
    if outcome != Outcome.FAIL:
        return {}
    first = answers[0]
    return {
        "finding_class": first.finding_class or rule.finding_class,
        "suggested_severity": first.severity or rule.severity,
        "exposure_status": first.exposure,
        "evidence_needed": tuple(sorted({e for a in answers for e in a.evidence_needed})),
        "compensating_controls": tuple(sorted({c for a in answers for c in a.compensating})),
    }


PER_RESOURCE_LIMITATION = "filtered or resource-selected request"


def parent_listings(store, run_id) -> dict:
    """(account, region, parent operation) -> latest journal rows of the parent listings in the
    run's own collection summary, or in its members' summaries for an enterprise snapshot."""
    from offline_analyzer.ingestion.collector import stored_summary

    row = store.db.execute(
        "SELECT members FROM enterprise_snapshots WHERE run_id=?", [run_id]
    ).fetchone()
    members = json.loads(row[0]) if row else [run_id]
    parents = set(DEPENDENT_PARENTS.values())
    found = {}
    for member in members:
        summary = stored_summary(store.workspace, member) or {}
        for op in summary.get("operations", ()):
            # Only collector 0.3.x journals record the original outcome and record count.
            if op.get("operation") not in parents or "original_outcome" not in op:
                continue
            key = (summary.get("account_id"), op.get("region"), op["operation"])
            stamp = op.get("completed_at") or ""
            latest = found.get(key)
            if latest is None or stamp > latest[0]:
                found[key] = (stamp, [op])
            elif stamp == latest[0]:
                latest[1].append(op)
    return {key: rows for key, (_stamp, rows) in found.items()}


def parent_state(rows) -> tuple[str, int] | None:
    """("EMPTY", 0), ("LISTED", n) or ("FAILED", 0) when the latest parent rows agree."""
    states = set()
    for op in rows or ():
        records = op.get("records_returned")
        if (
            op.get("status") == "SUCCEEDED"
            and op.get("original_outcome") == "COMPLETE"
            and op.get("pagination") != "TRUNCATED"
            and type(records) is int
        ):
            states.add(("EMPTY", 0) if records == 0 else ("LISTED", records))
        elif op.get("status") == "FAILED":
            states.add(("FAILED", 0))
        else:
            return None
    return states.pop() if len(states) == 1 else None


def dependent_scope(rule, native_sources, parent) -> tuple[str, str] | None:
    """Scope decided by the parent listing of a per-resource dataset, or None (unchanged).

    COMPLETE when every listed resource has its dependent evidence (per-resource requests are
    complete for their resource); NOT_APPLICABLE when the complete listing is empty;
    COLLECTION_ERROR when the listing failed, so no dependent call was made."""
    operation = next(iter(primary_operations(rule) & DEPENDENT_PARENTS.keys()), None)
    if operation is None or parent is None:
        return None
    state, listed = parent
    if not native_sources:
        if state == "EMPTY":
            return "NOT_APPLICABLE", (
                f"The complete {DEPENDENT_PARENTS[operation]} listing returned no resources; "
                "no account-wide PASS is asserted."
            )
        if state == "FAILED":
            return "COLLECTION_ERROR", (
                f"{DEPENDENT_PARENTS[operation]} failed, so {operation} was not collected for "
                "any resource in this scope."
            )
        return "UNKNOWN", (
            f"{DEPENDENT_PARENTS[operation]} listed {listed} resource(s) but {operation} "
            "was not collected for them; their state is unresolved."
        )
    if state != "LISTED" or any(s["errors"] for s in native_sources):
        return None
    if not all(
        s["effective_coverage"] == "COMPLETE"
        or (
            s["effective_coverage"] == "PARTIAL"
            and set(s.get("limitations") or ()) == {PER_RESOURCE_LIMITATION}
        )
        for s in native_sources
    ):
        return None
    subjects = {
        json.dumps(s.get("request_parameters") or {}, sort_keys=True) for s in native_sources
    }
    return ("COMPLETE", "") if len(subjects) >= listed else None


def scope_result(rule, account, region, native_sources, store, run_id, assessed_at, parent=None):
    """Collection-scope row; None when complete evidence makes per-resource rows sufficient."""
    dependent = dependent_scope(rule, native_sources, parent)
    if dependent and dependent[0] == "COMPLETE":
        return None
    complete = bool(native_sources) and all(
        s["effective_coverage"] == "COMPLETE" for s in native_sources
    )
    shadow_only = False
    if complete and any(s["record_count"] for s in native_sources):
        if rule.operation == "cloudtrail:DescribeTrails":
            owned = store.db.execute(
                "SELECT 1 FROM observations WHERE run_id=? AND "
                "tool='aws' AND kind=? AND account_id=? AND region=? LIMIT 1",
                [run_id, rule.resource_type, account, region],
            ).fetchone()
            shadow_only = not bool(owned)
        if not shadow_only:
            return None
    if dependent:
        outcome, reason = Outcome(dependent[0]), dependent[1]
    elif any(s["effective_coverage"] == "ERROR" or s["errors"] for s in native_sources):
        outcome = Outcome.COLLECTION_ERROR
        reason = "Collection error prevents complete scope assessment."
    elif shadow_only:
        outcome = Outcome.UNKNOWN
        reason = (
            "Only shadow trails were returned in this collection scope; "
            "owner resources "
            "are assessed separately. Local/member logging coverage is unresolved."
        )
    elif complete:
        outcome = Outcome.NOT_APPLICABLE
        reason = (
            "Declared complete collection contains no resources; no account-wide PASS is asserted."
        )
    else:
        outcome = Outcome.UNKNOWN
        reason = (
            "Scope inventory is missing or incomplete; observed resource results "
            "do not establish scope coverage."
        )
    refs = tuple(
        EvidenceRef(artifact_id=s["artifact_id"], locator="/")
        for s in native_sources
        if s["artifact_id"]
    )
    return Result(
        evaluation_id=stable_id("scope-evaluation", [rule.rule_id, account, region]),
        rule_id=rule.rule_id,
        rule_version=rule.version,
        **mapping_fields(rule),
        account_id=account,
        region=region,
        resource_id=None,
        native_id=None,
        evaluation_scope="COLLECTION_SCOPE",
        outcome=outcome,
        reasoning=reason,
        evidence=refs,
        missing_dependencies=("approved shadow-trail scope applicability",)
        if shadow_only
        else ()
        if complete
        else (f"complete {rule.operation} collection",),
        confidence="UNASSESSED",
        limitations=("Collector completeness is a declaration, not independently verified",),
        assessed_at=assessed_at,
    )


def parent_of(rule) -> str | None:
    return next(
        (DEPENDENT_PARENTS[o] for o in sorted(primary_operations(rule)) if o in DEPENDENT_PARENTS),
        None,
    )


def supplied_rules(sources, listed=frozenset()) -> list:
    """Ungated rules always report scope gaps; gated rules only when evidence was supplied.
    A per-resource rule is supplied when its parent listing was journaled (it may be empty)."""
    supplied = {s["operation"] for s in sources}
    return [
        r
        for r in ALL_RULES
        if not r.family_gated or primary_operations(r) & supplied or parent_of(r) in listed
    ]


def assess(store, run_id: str) -> str:
    checkpoint("SOURCE_INTEGRITY")
    store.require_run(run_id)
    from offline_analyzer.findings.finalisation import require_editable

    require_editable(store, run_id)
    verify_raw(store, run_id)
    package_json, time = store.db.execute(
        "SELECT package, created_at FROM runs WHERE run_id=?", [run_id]
    ).fetchone()
    assessed_at = datetime.fromisoformat(time)  # fixed run time: reproducible reruns
    sources = list(store.source_data(run_id))
    # Historical R0 imports remain readable; legacy COMPLETE declarations lacked
    # request context and must not establish full scope under the hardened rules.
    sources = [
        {**s, "effective_coverage": "PARTIAL"}
        if s["format"] == "aws-json-v1"
        and s.get("request_parameters") is None
        and s["effective_coverage"] == "COMPLETE"
        else s
        for s in sources
    ]
    scopes = {(s["account_id"], s["region"]) for s in sources if s["account_id"] and s["region"]}
    scopes.update((t["account_id"], t["region"]) for t in json.loads(package_json)["targets"])
    scopes.update(
        (a, r)
        for a, r in store.rows(
            "SELECT DISTINCT account_id, region FROM observations WHERE run_id=? AND "
            "account_id IS NOT NULL "
            "AND region IS NOT NULL",
            [run_id],
        )
    )
    # "global" labels non-Regional resources; it is never a Regional collection scope.
    regional_scopes = sorted((a, r) for a, r in scopes if r != GLOBAL)
    accounts = sorted({a for a, _ in scopes})
    context = EvaluationContext(store, run_id, sources, workspace_registry(store.workspace))
    parents = parent_listings(store, run_id)
    reported = supplied_rules(sources, {operation for _a, _r, operation in parents})
    with store.transaction():
        for table in ("evaluations", "findings", "finding_resources", "security_investigations"):
            store.db.execute(f"DELETE FROM {table} WHERE run_id=?", [run_id])
        resource_count = store.db.execute(
            "SELECT count(*) FROM (SELECT resource_id, CASE WHEN resource_id IS NULL "
            "THEN observation_id ELSE NULL END FROM observations WHERE run_id=? GROUP BY ALL)",
            [run_id],
        ).fetchone()[0]
        # One ordered pass over the run's observations and one evidence-reference index
        # replace per-resource queries; results are written in columnar batches. Groups,
        # their order and the per-resource limits are unchanged.
        refs = evidence_index(store, run_id)
        by_artifact = {s["artifact_id"]: s for s in sources if s["artifact_id"]}
        writer = ResultWriter(store, run_id)
        for completed, observations in enumerate(resource_groups(store, run_id)):
            checkpoint("SECURITY_ANALYSIS", completed, resource_count)
            for rule in ALL_RULES:
                if any(rule.applies(o) for o in observations):
                    result = evaluate_resource(
                        store,
                        run_id,
                        rule,
                        observations,
                        assessed_at,
                        sources,
                        context,
                        refs,
                        by_artifact,
                    )
                    if result:
                        writer.add(result)
        writer.flush()
        # Separate coverage rows preserve uncollected rules/scopes, even where some assets pass.
        for rule in reported:
            checkpoint()
            operations = primary_operations(rule)
            if rule.scope == "GLOBAL":
                for account in accounts:
                    native_sources = [
                        s
                        for s in sources
                        if s["account_id"] == account and s["operation"] in operations
                    ]
                    result = scope_result(
                        rule,
                        account,
                        GLOBAL,
                        native_sources,
                        store,
                        run_id,
                        assessed_at,
                        parent_state(parents.get((account, GLOBAL, parent_of(rule)))),
                    )
                    if result:
                        persist_result(store, run_id, result)
                continue
            for account, region in regional_scopes:
                native_sources = [
                    s
                    for s in sources
                    if s["account_id"] == account
                    and s["region"] == region
                    and s["operation"] in operations
                ]
                result = scope_result(
                    rule,
                    account,
                    region,
                    native_sources,
                    store,
                    run_id,
                    assessed_at,
                    parent_state(parents.get((account, region, parent_of(rule)))),
                )
                if result:
                    persist_result(store, run_id, result)
        for source in sources:
            if source["operation"] == "prowler:Scan":
                continue
            for rule in reported:
                if source["operation"] not in rule_operations(rule):
                    continue
                if source["account_id"] and (source["region"] or rule.scope == "GLOBAL"):
                    continue
                has_error = source["effective_coverage"] == "ERROR" or bool(source["errors"])
                result = Result(
                    evaluation_id=stable_id("unassigned-source", [rule.rule_id, source]),
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    **mapping_fields(rule),
                    account_id=source["account_id"],
                    region=source["region"],
                    resource_id=None,
                    native_id=None,
                    evaluation_scope="COLLECTION_SCOPE",
                    outcome=Outcome.COLLECTION_ERROR if has_error else Outcome.UNKNOWN,
                    reasoning=(
                        "Collection scope is unresolved; no complete account/Region "
                        "conclusion is possible."
                    ),
                    evidence=(EvidenceRef(artifact_id=source["artifact_id"], locator="/"),)
                    if source["artifact_id"]
                    else (),
                    missing_dependencies=("verified collection account/Region scope",),
                    confidence="UNASSESSED",
                    limitations=("No account or Region identity is invented",),
                    assessed_at=assessed_at,
                )
                persist_result(store, run_id, result)
        from offline_analyzer.rules.gcp import assess_gcp

        assess_gcp(store, run_id, assessed_at)
        store.db.execute(
            "INSERT INTO assessments VALUES (?, ?, ?) ON CONFLICT(run_id) "
            "DO UPDATE SET engine_version=excluded.engine_version, "
            "assessed_at=excluded.assessed_at",
            [run_id, ENGINE_VERSION, assessed_at.isoformat()],
        )
        committing()
    # Path feasibility reads committed evaluations through separate cursors, so severity
    # calibration runs in its own transaction once the assessment is published.
    from offline_analyzer.attack_paths.feasibility import calibrate

    checkpoint("CORRELATION")
    with store.transaction():
        calibrate(store, run_id)
    return run_id


RESOURCE_OBSERVATIONS = 4096
RESOURCE_BYTES = 8 * 1024 * 1024


def resource_groups(store, run_id: str):
    """Observations grouped as the assessment evaluates them: one group per resource ID
    (ascending), then one group per observation without a resource ID; each group ordered
    by observation ID. A group over the per-resource limits refuses the assessment."""
    group, key, size = [], object(), 0
    for resource_id, data in store.rows(
        "SELECT resource_id, data FROM observations WHERE run_id=? "
        "ORDER BY resource_id ASC NULLS LAST, observation_id",
        [run_id],
    ):
        current = resource_id if resource_id is not None else object()
        if group and current != key:
            yield group
            group, size = [], 0
        key = current
        group.append(Normalized.model_validate_json(data))
        size += len(data.encode())
        if len(group) > RESOURCE_OBSERVATIONS or size > RESOURCE_BYTES:
            raise InputError("RESOURCE_OBSERVATION_LIMIT")
    if group:
        yield group


def evidence_index(store, run_id: str):
    """Lookup equivalent to Store.refs, built from one query of the run's references."""
    from offline_analyzer.contracts.models import EvidenceRef

    index: dict[str, list[tuple[str, str]]] = {}
    for observation, artifact, locator in store.rows(
        "SELECT observation_id, artifact_id, locator FROM evidence_refs WHERE run_id=?", [run_id]
    ):
        index.setdefault(observation, []).append((artifact, locator))

    def lookup(observation_ids):
        found = {ref for oid in observation_ids for ref in index.get(oid, ())}
        return tuple(EvidenceRef(artifact_id=a, locator=loc) for a, loc in sorted(found))

    return lookup


class ResultWriter:
    """Buffered persist_result: the same rows, inserted in columnar batches."""

    BATCH = 2000

    def __init__(self, store, run_id: str):
        self.store, self.run_id = store, run_id
        self.tables = {
            "evaluations": [],
            "findings": [],
            "finding_resources": [],
            "security_investigations": [],
        }

    def add(self, result: Result) -> None:
        checkpoint()
        run = self.run_id
        self.tables["evaluations"].append(
            [run, result.evaluation_id, result.resource_id, str(result.outcome),
             result.model_dump_json()]
        )  # fmt: skip
        finding = candidate(result)
        if finding:
            if finding.rule_id.startswith("SEC-"):
                from offline_analyzer.findings.investigations import investigation_row

                self.tables["security_investigations"].append(
                    investigation_row(run, finding, result)
                )
            self.tables["findings"].append([run, finding.finding_id, finding.model_dump_json()])
            self.tables["finding_resources"].append(
                [run, finding.finding_id, finding.resource_id, finding.account_id, finding.region]
            )
        if len(self.tables["evaluations"]) >= self.BATCH:
            self.flush()

    def flush(self) -> None:
        for table, rows in self.tables.items():
            if rows:
                columns = len(rows[0])
                self.store.db.execute(
                    f"INSERT INTO {table} SELECT " + ",".join(["unnest(?)"] * columns),
                    list(map(list, zip(*rows, strict=True))),
                )
                rows.clear()


def persist_result(store, run_id: str, result: Result) -> None:
    checkpoint()
    store.db.execute(
        "INSERT INTO evaluations VALUES (?, ?, ?, ?, ?)",
        [
            run_id,
            result.evaluation_id,
            result.resource_id,
            str(result.outcome),
            result.model_dump_json(),
        ],
    )
    finding = candidate(result)
    if finding:
        if finding.rule_id.startswith("SEC-"):
            from offline_analyzer.findings.investigations import persist

            persist(store, run_id, finding, result)
        store.db.execute(
            "INSERT INTO findings VALUES (?, ?, ?)",
            [run_id, finding.finding_id, finding.model_dump_json()],
        )
        store.db.execute(
            "INSERT INTO finding_resources VALUES (?, ?, ?, ?, ?)",
            [run_id, finding.finding_id, finding.resource_id, finding.account_id, finding.region],
        )
