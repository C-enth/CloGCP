"Provider-labelled supporting worksheets using the existing streaming Excel writer."

import json

from offline_analyzer.attack_paths.gcp import investigations
from offline_analyzer.findings.generate import validation_status
from offline_analyzer.findings.report_ready import approved_revisions
from offline_analyzer.inventory.cloud import relationships
from offline_analyzer.reporting.cloud import (
    collection_requests,
    dashboard,
    methodology_matrix,
    source_support,
)


def sheets(wb, store, run: str) -> None:
    from offline_analyzer.reporting.excel import append, sheet

    summary = dashboard(store, run)
    overview = sheet(
        wb,
        "Cloud Overview",
        [
            "Provider",
            "Expected scopes",
            "Imported scopes",
            "Assessed scopes",
            "Resources",
            "Evaluations",
            "Candidates",
            "Confirmed",
            "Approved",
            "Complete collections",
            "Total collections",
            "Qualification",
        ],
    )
    for p, metrics in summary["providers"].items():
        append(
            overview,
            [
                p,
                *[
                    metrics[k]
                    for k in (
                        "expected_scope_count",
                        "imported_scope_count",
                        "assessed_scope_count",
                        "resources",
                        "evaluations",
                        "candidate_findings",
                        "confirmed_findings",
                        "approved_findings",
                        "complete_collections",
                        "source_collections",
                    )
                ],
                summary["qualification"],
            ],
        )
    domains = sheet(
        wb,
        "Cloud Domain Comparison",
        [
            "Domain",
            "Provider",
            "Status",
            "Implemented checks",
            "Resource evaluations",
            "All evaluations",
            "Outcomes",
            "Candidate findings",
            "Confirmed",
            "Approved",
        ],
    )
    for row in summary["domains"]:
        for p in ("AWS", "GCP"):
            m = row[p]
            append(
                domains,
                [
                    row["domain"],
                    p,
                    m["assessment_status"],
                    m.get("implemented_checks", 0),
                    m.get("resource_evaluations", 0),
                    m.get("evaluations", 0),
                    {k: m.get(k, 0) for k in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")},
                    m.get("candidates", 0),
                    m.get("confirmed", 0),
                    m.get("approved", 0),
                ],
            )
    register = sheet(
        wb,
        "Unified Findings Register",
        [
            "Finding ID",
            "Provider",
            "Security Domain",
            "Account/Project",
            "Affected Resource",
            "Finding Title",
            "Severity",
            "Validation Status",
            "Recommendation",
            "Client Action Status",
            "Client Remarks",
            "Target Date",
            "Last Updated",
            "Report Approved",
        ],
    )
    revisions = approved_revisions(store, run)
    approved = {s.finding_id for r in revisions for s in r.snapshots}
    latest = store.latest_decisions(run)
    from offline_analyzer.findings.exclusions import excluded

    hidden = excluded(store, run)
    for finding in store.candidates(run):
        if finding.finding_id in hidden:
            continue  # Excluded from client reporting by the assessor.
        append(
            register,
            [
                finding.finding_id,
                finding.provider,
                finding.security_domain,
                finding.project_id or finding.account_id,
                finding.native_id,
                finding.title,
                finding.suggested_severity,
                validation_status(store, finding, latest)[0],
                finding.remediation,
                "",
                "",
                "",
                "",
                finding.finding_id in approved,
            ],
        )
    remediation = sheet(
        wb,
        "Approved Remediation Tracker",
        [
            "Finding ID",
            "Provider",
            "Security Domain",
            "Account/Project",
            "Affected Resource",
            "Approved Title",
            "Approved Severity",
            "Validation Status",
            "Approved Recommendation",
            "Client Action Status",
            "Client Remarks",
            "Target Date",
            "Last Updated",
            "Report Revision",
        ],
    )
    finding_map = {f.finding_id: f for f in store.candidates(run)}
    for revision in revisions:
        finding = finding_map[revision.primary_finding]
        for snapshot in revision.snapshots:
            append(
                remediation,
                [
                    snapshot.finding_id,
                    snapshot.provider,
                    finding.security_domain,
                    snapshot.project_id or snapshot.account_id,
                    snapshot.native_id,
                    revision.sections.title,
                    revision.sections.severity,
                    "CONFIRMED",
                    revision.sections.remediation,
                    "",
                    "",
                    "",
                    revision.created_at.isoformat(),
                    revision.revision,
                ],
            )
    resources = sheet(
        wb,
        "Cloud Resource Inventory",
        [
            "Provider",
            "Project/Account",
            "Project number",
            "Organization",
            "Folder",
            "Resource ID",
            "Native ID",
            "Type",
            "Location",
            "Collection time",
            "Evidence",
            "Normalization gaps",
        ],
    )
    for _rid, raw in store.rows(
        (
            "SELECT resource_id,arg_min(data,(CASE WHEN kind IN ('GCP::Asset',"
            "'GCP::AssetIAMSearchResult','GCP::AssetResourceSnapshot','GCP::AssetIAMSnapshot') "
            "THEN 1 ELSE 0 END,observation_id)) FROM observations WHERE "
            "run_id=? AND resource_id IS NOT NULL AND kind <> 'GCP::Unsupported' "
            "GROUP BY resource_id ORDER BY "
            "resource_id"
        ),
        [run],
    ):
        o = json.loads(raw)
        append(
            resources,
            [
                o.get("provider", "AWS"),
                o.get("project_id") or o.get("account_id"),
                o.get("project_number"),
                o.get("organization_id"),
                o.get("folder_id"),
                o["resource_id"],
                o["native_id"],
                o["resource_type"],
                o["region"],
                o["collected_at"],
                o["evidence"],
                o["unresolved"],
            ],
        )
    evaluations = sheet(
        wb,
        "Cloud Evaluations",
        [
            "Provider",
            "Project/Account",
            "Rule",
            "Version",
            "Resource",
            "Scope",
            "Outcome",
            "Reason",
            "Confidence",
            "Missing evidence",
            "Evidence",
            "Excluded (reason)",
        ],
    )
    from offline_analyzer.contracts.r0 import stable_id
    from offline_analyzer.findings.exclusions import evaluation_exclusions

    excluded_by_finding = evaluation_exclusions(store, run)
    for r in store.results(run):
        append(
            evaluations,
            [
                r.provider,
                r.project_id or r.account_id,
                r.rule_id,
                r.rule_version,
                r.native_id,
                r.evaluation_scope,
                str(r.outcome),
                r.reasoning,
                r.confidence,
                r.missing_dependencies + r.evidence_needed,
                [e.model_dump() for e in r.evidence],
                excluded_by_finding.get(stable_id("finding", [r.rule_id, r.resource_id or ""]), ""),
            ],
        )
    evidence = sheet(
        wb,
        "Cloud Collection Coverage",
        [
            "Provider",
            "Project/Account",
            "Operation",
            "Original status",
            "Effective coverage",
            "Parser support",
            "Provenance",
            "Timestamp",
            "Errors",
            "Artifact",
            "Expected projects",
            "Domain",
            "Dataset",
            "Normalized observations",
            "Assessment state",
        ],
    )
    dataset_states = {(d["scope"], d["operation"], d["dataset"]): d for d in summary["datasets"]}

    for source in store.source_data(run):
        metadata = source.get("gcp_metadata", {})
        append(
            evidence,
            [
                "GCP" if source["format"] == "gcp-json-v1" else "AWS",
                source.get("project_id") or source["account_id"],
                source["operation"],
                metadata.get("status", source["coverage"]),
                source["effective_coverage"],
                source_support(source),
                metadata.get("provenance", "collector-declared"),
                metadata.get("completed_at", source["collected_at"]),
                source["errors"],
                source["artifact_id"],
                metadata.get("expected_projects", []),
                metadata.get("domain"),
                metadata.get("dataset"),
                source["record_count"],
                dataset_states[
                    (
                        source.get("project_id") or source["account_id"],
                        source["operation"],
                        metadata.get("dataset"),
                    )
                ]["assessment_state"],
            ],
        )
    edges = sheet(
        wb,
        "GCP Relationships",
        [
            "Source",
            "Destination",
            "Relationship",
            "Status",
            "Project",
            "Evidence",
            "Missing evidence",
            "Confidence",
        ],
    )
    projection = relationships(store, run, limit=500)
    for e in projection["items"]:
        append(
            edges,
            [
                e[k]
                for k in (
                    "source",
                    "destination",
                    "relationship",
                    "status",
                    "project_id",
                    "evidence",
                    "missing_evidence",
                    "confidence",
                )
            ],
        )
    if projection["truncated"]:
        append(
            edges,
            [
                "TRUNCATED",
                "",
                "Output limited to 500 edges; investigate project-specific views",
                "UNKNOWN",
            ],
        )
    paths = sheet(
        wb,
        "GCP Path Investigations",
        [
            "Path ID",
            "Project",
            "Title",
            "Status",
            "Severity",
            "Transitions",
            "Evidence",
            "Missing evidence",
            "Qualification",
        ],
    )
    for p in investigations(store, run)["items"]:
        if p.get("finding_id") in hidden:
            continue  # Excluded (for example false positive): not in report sections.
        append(
            paths,
            [
                p[k]
                for k in (
                    "path_id",
                    "project_id",
                    "title",
                    "status",
                    "severity",
                    "transitions",
                    "evidence",
                    "missing_evidence",
                    "qualification",
                )
            ],
        )
    mapping = sheet(
        wb,
        "Provider Methodology Matrix",
        ["Control ID", "AWS implementation", "GCP implementation", "AWS rules", "GCP rules"],
    )
    for row in methodology_matrix()["controls"]:
        append(mapping, [row[k] for k in ("control_id", "AWS", "GCP", "aws_rules", "gcp_rules")])
    requests = sheet(
        wb, "GCP Collection Requests", ["Project", "Operation or requirement", "Status", "Request"]
    )
    for r in collection_requests(store, run):
        append(
            requests,
            [r[k] for k in ("project_id", "operation_or_requirement", "status", "request")],
        )
    from offline_analyzer.correlation.gcp import scc_correlations

    scc = sheet(
        wb,
        "SCC Native Correlation",
        [
            "Project",
            "Original finding",
            "Category",
            "Original severity",
            "State",
            "Event time",
            "Resource",
            "Native evaluation",
            "Correlation",
            "Evidence",
            "Qualification",
        ],
    )
    for row in scc_correlations(store, run):
        append(
            scc,
            [
                row[k]
                for k in (
                    "project_id",
                    "source_finding_id",
                    "category",
                    "original_severity",
                    "state",
                    "event_time",
                    "resource",
                    "native_evaluation_id",
                    "status",
                    "evidence",
                    "qualification",
                )
            ],
        )
