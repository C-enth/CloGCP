"Persisted multi-cloud projections with distinct scope and evaluation denominators."

import json
from collections import Counter

from offline_analyzer.findings.generate import validation_status
from offline_analyzer.findings.report_ready import approved_revisions
from offline_analyzer.inventory.accounts import workspace_registry
from offline_analyzer.inventory.cloud import DOMAINS, domain
from offline_analyzer.methodology.coverage_spec import COVERAGE, REVIEWED_METHODOLOGY_SHA256
from offline_analyzer.normalization.gcp import PROFILES
from offline_analyzer.reporting.coverage_reasons import reason_text, source_category
from offline_analyzer.rules.registry import PROVIDER_RULES

COVERAGE_DEFINITIONS = {
    "effective_coverage": "Collection usability and completeness after parser validation; "
    "not a percentage of controls passed or a security assurance rating.",
    "COMPLETE": "The supported collection declares complete scope and pagination. "
    "Security rules may still cover only part of a control.",
    "PARTIAL": "Usable observations exist, but scope, pagination, provenance or dependencies "
    "are incomplete. Only the evidenced resource criterion can be evaluated.",
    "ERROR": "Collection or validation failed. It cannot support a PASS or prove resource absence.",
    "NOT_COLLECTED": "Required evidence was not supplied or is unsupported; "
    "no security conclusion.",
}
STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)


def workspace_scope_summary(store) -> dict:
    """Stable estate summary, independent of the active run/account selector."""
    from offline_analyzer.enterprise.snapshot import members

    scopes = {p: set() for p in ("AWS", "GCP")}
    domains = {d: {p: set() for p in scopes} for d in DOMAINS}
    for run in members(store):
        for source in store.source_data(run):
            p = "GCP" if source["format"] == "gcp-json-v1" else "AWS"
            identity = source.get("project_id") or source.get("account_id")
            if not identity:
                continue
            scopes[p].add(identity)
            if source["effective_coverage"] in {"ERROR", "NOT_COLLECTED"}:
                continue
            d = COLLECTOR_DOMAINS.get((source.get("gcp_metadata") or {}).get("domain"))
            if d:
                domains[d][p].add(identity)
            for rule in PROVIDER_RULES:
                if source["operation"] in (rule.operation, *rule.context_operations):
                    domains[domain(rule.domain)][p].add(identity)
    return {
        "providers": {p: sorted(ids) for p, ids in scopes.items()},
        "domains": [
            {"domain": d, **{p: sorted(ids) for p, ids in clouds.items()}}
            for d, clouds in domains.items()
        ],
        "qualification": "Active original imports across the workspace. Listed accounts "
        "have collected evidence for the domain; this does not mean full control coverage.",
    }


COLLECTOR_DOMAINS = {
    "identity": "Identity and Access",
    "api": "Credentials and API Security",
    "network": "Network and Exposure",
    "storage": "Data Protection",
    "data": "Data Protection",
    "security": "Data Protection",
    "compute": "Workload Security",
    "serverless": "Workload Security",
    "devops": "Workload Security",
    "messaging": "Workload Security",
    "ai": "Workload Security",
    "logging": "Monitoring and Detection",
    "monitoring": "Monitoring and Detection",
    "governance": "Governance",
    "inventory": "Governance",
}


def source_support(source: dict) -> bool:
    return (
        source["format"] != "gcp-json-v1"
        or bool(source.get("gcp_metadata", {}).get("dataset_contract"))
        or source["operation"] in PROFILES
    )


def dataset_coverage(store, run: str, sources: list[dict]) -> list[dict]:
    """Operation denominator is the actual manifest journal, not possible cloud resources."""
    result_support = Counter()
    for result in store.results(run):
        for artifact in {ref.artifact_id for ref in result.evidence}:
            result_support[artifact] += 1
    rows = []
    for source in sources:
        metadata = source.get("gcp_metadata") or {}
        resource_type = metadata.get("dataset_contract", {}).get("resource_type")
        supported = source_support(source)
        collected = source["effective_coverage"] not in {"ERROR", "NOT_COLLECTED"}
        rows.append(
            {
                "provider": "GCP" if source["format"] == "gcp-json-v1" else "AWS",
                "scope": source.get("project_id") or source.get("account_id"),
                "domain": metadata.get("domain"),
                "security_domain": "Vulnerability and Risk"
                if resource_type == "GCP::SCCFinding"
                else COLLECTOR_DOMAINS.get(metadata.get("domain")),
                "dataset": metadata.get("dataset"),
                "operation": source["operation"],
                "collection_status": metadata.get("status", source["effective_coverage"]),
                "coverage": source["effective_coverage"],
                "parser_supported": supported,
                "normalized_observations": source["record_count"] if supported else 0,
                "retained_unsupported_observations": source["record_count"] if not supported else 0,
                "evaluations_using_source": result_support[source["artifact_id"]],
                "assessment_state": "COLLECTION_FAILED"
                if not collected
                else "UNSUPPORTED_PARSER"
                if not supported
                else "EVALUATED_WITH_LIMITATIONS"
                if result_support[source["artifact_id"]]
                else "NOT_EVALUATED",
                "limitations": metadata.get("completeness_limitations", [])
                + source.get("limitations", []),
                "coverage_reason": reason_text(
                    source_category(source), metadata.get("completeness_limitations")
                ),
                "denominator": "ONE_DECLARED_COLLECTION_OPERATION",
            }
        )
    return rows


def methodology_matrix() -> dict:
    return {
        "source_sha256": REVIEWED_METHODOLOGY_SHA256,
        "controls": [
            {
                "control_id": c.control_id,
                "AWS": c.status,
                "GCP": "UNRESOLVED_PROVIDER_MAPPING",
                "aws_rules": list(c.rules),
                "gcp_rules": [],
            }
            for c in COVERAGE
        ],
        "implementations": [
            {
                "provider": "GCP" if r.rule_id.startswith("GCP-") else "AWS",
                "rule_id": r.rule_id,
                "version": r.version,
                "domain": domain(r.domain),
                "methodology_id": r.methodology_id,
                "mapping_status": "PROPOSED" if r.methodology else "UNRESOLVED",
                "required_evidence": [r.operation, *r.context_operations],
                "full_control_coverage": False,
            }
            for r in PROVIDER_RULES
        ],
        "qualification": (
            "Domain alignment is not source-control coverage. GCP mappings require "
            "source-clause review; no unrelated AWS row is reused."
        ),
    }


def dashboard(store, run: str, provider: str = "Consolidated", paths=None) -> dict:
    """`paths`: optional callable returning attack_paths(store, run) for this run state."""
    store.require_run(run)
    providers = ("AWS", "GCP") if provider == "Consolidated" else (provider,)
    all_sources = list(store.source_data(run))
    datasets = dataset_coverage(store, run, all_sources)
    by_provider = {}
    matrix = {d: {"domain": d, "AWS": Counter(), "GCP": Counter()} for d in DOMAINS}
    for dataset in datasets:
        name = dataset["security_domain"]
        if name:
            counts = matrix[name][dataset["provider"]]
            counts["declared_operations"] += 1
            counts[dataset["assessment_state"]] += 1
            counts["incomplete_operations"] += dataset["coverage"] != "COMPLETE"
    latest = store.latest_decisions(run)
    approved = {s.finding_id for r in approved_revisions(store, run) for s in r.snapshots}
    from offline_analyzer.findings.exclusions import excluded

    hidden = excluded(store, run)
    registry = workspace_registry(store.workspace)
    package = json.loads(
        store.db.execute("SELECT package FROM runs WHERE run_id=?", [run]).fetchone()[0]
    )
    # Decode every evaluation and candidate once for both providers; first rule wins on ID.
    all_results = list(store.results(run))
    all_candidates = list(store.candidates(run))
    rules_by_id: dict = {}
    for r in PROVIDER_RULES:
        rules_by_id.setdefault(r.rule_id, r)
    for p in ("AWS", "GCP"):
        sources = [
            s for s in all_sources if ("GCP" if s["format"] == "gcp-json-v1" else "AWS") == p
        ]
        expected = set()
        imported = {
            s.get("project_id") if p == "GCP" else s["account_id"] for s in sources if s["path"]
        }
        imported.discard(None)
        for s in sources:
            expected.update(
                s.get("gcp_metadata", {}).get("expected_projects", [])
            ) if p == "GCP" else expected.update([s["account_id"]] if s["account_id"] else [])
        if p == "AWS" and registry:
            expected.update(registry.in_scope)
        if p == "AWS":
            expected.update(t["account_id"] for t in package.get("targets", []))
        resources = store.db.execute(
            "SELECT count(DISTINCT resource_id) FROM observations WHERE run_id=? AND tool "
            + ("='gcp' AND kind <> 'GCP::Unsupported'" if p == "GCP" else "<>'gcp'"),
            [run],
        ).fetchone()[0]
        outcomes, severity, reviews, themes, evaluated_scopes = (
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            set(),
        )
        for r in PROVIDER_RULES:
            if ("GCP" if r.rule_id.startswith("GCP-") else "AWS") == p:
                matrix.setdefault(
                    domain(r.domain),
                    {"domain": domain(r.domain), "AWS": Counter(), "GCP": Counter()},
                )[p]["implemented_checks"] += 1
        for result in all_results:
            if result.provider != p:
                continue
            outcomes[str(result.outcome)] += 1
            if result.evaluation_scope == "RESOURCE":
                evaluated_scopes.add(result.project_id if p == "GCP" else result.account_id)
            rule = rules_by_id.get(result.rule_id)
            if rule:
                row = matrix[domain(rule.domain)][p]
                row["evaluations"] += 1
                row[str(result.outcome)] += 1
                row["resource_evaluations"] += result.evaluation_scope == "RESOURCE"
                row["resource_known_outcomes"] += result.evaluation_scope == "RESOURCE" and str(
                    result.outcome
                ) in {"PASS", "FAIL"}
                row["resource_unknown_outcomes"] += (
                    result.evaluation_scope == "RESOURCE" and str(result.outcome) == "UNKNOWN"
                )
        findings = excluded_findings = 0
        for finding in all_candidates:
            if finding.provider != p:
                continue
            if finding.finding_id in hidden:
                # Excluded from client reporting: reported separately so totals reconcile.
                excluded_findings += 1
                continue
            findings += 1
            severity[finding.suggested_severity] += 1
            status = validation_status(store, finding, latest)[0]
            reviews[status] += 1
            row = matrix.setdefault(
                domain(finding.security_domain),
                {"domain": domain(finding.security_domain), "AWS": Counter(), "GCP": Counter()},
            )[p]
            row["candidates"] += 1
            row["confirmed"] += status == "CONFIRMED"
            row["approved"] += finding.finding_id in approved
            themes[finding.title] += 1
        by_provider[p] = {
            "expected_scopes": sorted(expected),
            "imported_scopes": sorted(imported),
            "assessed_scopes": sorted(evaluated_scopes - {None}),
            "expected_scope_count": len(expected),
            "imported_scope_count": len(imported),
            "assessed_scope_count": len(evaluated_scopes - {None}),
            "resources": resources,
            "unsupported_observations": store.db.execute(
                "SELECT count(*) FROM observations WHERE run_id=? AND kind='GCP::Unsupported'",
                [run],
            ).fetchone()[0]
            if p == "GCP"
            else 0,
            "collection_status": dict(Counter(s["effective_coverage"] for s in sources)),
            "source_collections": len(sources),
            "complete_collections": sum(s["effective_coverage"] == "COMPLETE" for s in sources),
            "evaluations": sum(outcomes.values()),
            "outcomes": dict(outcomes),
            "candidate_findings": findings,
            "excluded_findings": excluded_findings,
            "confirmed_findings": reviews["CONFIRMED"],
            "approved_findings": sum(row[p]["approved"] for row in matrix.values()),
            "severity": dict(severity),
            "reviews": dict(reviews),
            "remediation_themes": dict(themes.most_common(10)),
        }
    gaps = [
        {
            "provider": "GCP" if s["format"] == "gcp-json-v1" else "AWS",
            "scope": s.get("project_id") or s["account_id"],
            "operation": s["operation"],
            "dataset": s.get("gcp_metadata", {}).get("dataset"),
            "domain": s.get("gcp_metadata", {}).get("domain"),
            "exit_code": s.get("gcp_metadata", {}).get("exit_code"),
            "status": s.get("gcp_metadata", {}).get("status", s["effective_coverage"]),
            "effective_coverage": s["effective_coverage"],
            "parser_supported": source_support(s),
            "collection_time_known": bool(s.get("gcp_metadata", {}).get("completed_at"))
            if s["format"] == "gcp-json-v1"
            else bool(s.get("collected_at")),
            "provenance": s.get("gcp_metadata", {}).get("provenance", "collector-declared"),
            "integrity_assurance": s.get("gcp_metadata", {}).get(
                "integrity_assurance", "DECLARED_CHECKSUMS"
            ),
            "original_status": s.get("gcp_metadata", {}).get("status"),
            "error_category": s.get("gcp_metadata", {}).get("error_category"),
            "collection_correction_required": s.get("gcp_metadata", {}).get(
                "collection_correction_required", False
            ),
            "coverage_reason": reason_text(
                s.get("gcp_metadata", {}).get("error_category"),
                s.get("gcp_metadata", {}).get("completeness_limitations"),
            ),
        }
        for s in all_sources
        if s["effective_coverage"] != "COMPLETE"
    ]
    domains = []
    for name, row in matrix.items():
        projected = {"domain": name}
        for p in ("AWS", "GCP"):
            counts = dict(row[p])
            counts["assessment_status"] = (
                "AVAILABLE_EVIDENCE_EVALUATED"
                if counts.get("resource_known_outcomes")
                else "UNKNOWN"
                if counts.get("resource_unknown_outcomes")
                else "NOT_APPLICABLE_OBSERVED_CRITERIA"
                if counts.get("resource_evaluations")
                else "NOT_ASSESSED"
            )
            projected[p] = counts
        projected["comparable_totals"] = {
            k: row["AWS"][k] + row["GCP"][k] for k in ("candidates", "confirmed", "approved")
        }
        domains.append(projected)
    from offline_analyzer.attack_paths.feasibility import attack_paths
    from offline_analyzer.enterprise.validation import validate_snapshot
    from offline_analyzer.findings.quality import run_quality

    # Paths that depend on an excluded finding are not counted (they stay listed, flagged).
    paths = [
        p
        for p in (paths() if paths else attack_paths(store, run))["items"]
        if p["provider"] in providers and not p.get("excluded_dependency")
    ]
    stride = []
    results = all_results
    for category in STRIDE_CATEGORIES:
        linked_rules = {
            r.rule_id
            for r in PROVIDER_RULES
            if r.methodology and category in r.methodology.stride_category
        }
        evaluated = [r for r in results if r.provider in providers and r.rule_id in linked_rules]
        stride.append(
            {
                "category": category,
                "evaluations": len(evaluated),
                "known": sum(str(r.outcome) in {"PASS", "FAIL"} for r in evaluated),
                "paths": sum(category in p.get("stride", []) for p in paths),
                "state": "PARTIAL" if evaluated else "NOT_ASSESSED",
            }
        )
    total_severity = Counter()
    for p in providers:
        total_severity.update(by_provider[p]["severity"])
    posture = (
        "Critical findings observed"
        if total_severity["CRITICAL"]
        else "High findings observed"
        if total_severity["HIGH"]
        else "Findings require review"
        if sum(total_severity.values())
        else "Insufficient evidence"
        if not any(by_provider[p]["evaluations"] for p in providers)
        or any(g["provider"] in providers for g in gaps)
        else "No gaps in evaluated criteria"
    )
    view = {
        "run_id": run,
        "provider": provider,
        "providers": {p: by_provider[p] for p in providers},
        "domains": domains,
        "gaps": [g for g in gaps if g["provider"] in providers],
        "datasets": [d for d in datasets if d["provider"] in providers],
        "coverage_definitions": COVERAGE_DEFINITIONS,
        "stride": stride,
        "posture": {
            "rating": posture,
            "basis": "Observed technical findings in the selected "
            "run. Partial criteria and missing evidence cannot establish an estate-wide "
            "secure rating; business risk and analyst approval are separate.",
        },
        "snapshot_validation": validate_snapshot(store, run),
        "finding_quality": {
            key: value for key, value in run_quality(store, run).items() if key != "items"
        },
        "qualification": (
            "Assessed scopes have at least one resource evaluation; they are not "
            "fully assessed. Resource counts are inventory, not control coverage. No "
            "security completeness percentage is calculated."
        ),
    }
    from offline_analyzer.reporting.gcp_feed import linked, merge_dashboard

    record = linked(store, run)
    return merge_dashboard(view, record, provider) if record else view


def collection_requests(store, run: str) -> list[dict]:
    requests = {}
    for source in store.source_data(run):
        meta = source.get("gcp_metadata") or {}
        if source["format"] == "gcp-json-v1" and (
            source["effective_coverage"] != "COMPLETE" or not source_support(source)
        ):
            status = meta.get("status", source["effective_coverage"])
            request = {
                "ACCESS_DENIED": (
                    "Obtain approved read-only collection permissions and recollect; "
                    "denied evidence cannot establish a pass."
                ),
                "API_DISABLED": (
                    "Service not enabled (per enabled-services evidence). Confirm the intended "
                    "API state with the owner; a disabled API does not prove resource absence."
                ),
                "QUOTA_PROJECT_DENIED": (
                    "The quota/billing project was refused. Recollect with an owner-approved "
                    "-QuotaProject; coverage is insufficient until then."
                ),
                "AUTH_ERROR": (
                    "Restore approved local collector authentication and recollect; "
                    "never include credentials in evidence."
                ),
                "TRUNCATED": (
                    "Recollect with reviewed pagination/detail limits; retained partial "
                    "evidence cannot establish complete coverage."
                ),
                "RATE_LIMITED": (
                    "Retry the separate read-only collector with bounded backoff "
                    "after rate limits recover."
                ),
            }.get(
                status,
                "Review collector completeness and source provenance; recollect missing evidence "
                "or perform analyst validation.",
            )
            if not source_support(source):
                request = (
                    "CloSec parser support is unavailable; retain the observation "
                    "and perform manual validation."
                )
                status = "UNSUPPORTED_PARSER"
            requests[(source.get("project_id"), source["operation"])] = {
                "provider": "GCP",
                "project_id": source.get("project_id"),
                "operation_or_requirement": source["operation"],
                "status": status,
                "request": request,
            }
        if meta.get("collection_correction_required"):
            requests[(source.get("project_id"), source["operation"])] = {
                "provider": "GCP",
                "project_id": source.get("project_id"),
                "operation_or_requirement": source["operation"],
                "status": "COLLECTOR_COMMAND_CORRECTION",
                "request": (
                    "Correct the collector command against native help; recollect "
                    "approved read-only evidence. Preserve the failed attempt."
                ),
            }
    for result in store.results(run):
        if result.provider != "GCP" or not result.missing_dependencies:
            continue
        for requirement in result.missing_dependencies:
            key = (result.project_id, requirement)
            requests[key] = {
                "provider": "GCP",
                "project_id": result.project_id,
                "operation_or_requirement": requirement,
                "status": "MISSING_OR_UNRESOLVED",
                "request": (
                    "Collect approved read-only native evidence, including scope, UTC times, "
                    "permissions and every page; do not include secrets."
                ),
            }
    return list(requests.values())
