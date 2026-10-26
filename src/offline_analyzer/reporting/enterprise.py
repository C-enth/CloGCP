"""Eight additive worksheets from persisted enterprise records; preserve original sheets."""

import json

from offline_analyzer.enterprise.queries import EnterpriseViews


def enterprise_sheets(workbook, store, run: str) -> None:
    from offline_analyzer.reporting.excel import append, sheet

    views = EnterpriseViews()
    accounts = sheet(
        workbook,
        "Enterprise Account Summary",
        [
            "Account",
            "Approved alias",
            "Identity basis",
            "Represented",
            "Assessed",
            "Resources",
            "Findings",
            "Groups / OU",
            "Coverage",
            "Regions",
            "Collection timestamps",
        ],
    )
    for a in views.accounts(store, run):
        append(
            accounts,
            [
                a[k]
                for k in (
                    "account",
                    "alias",
                    "identity_basis",
                    "represented",
                    "assessed",
                    "resources",
                    "findings",
                    "groups",
                    "coverage",
                    "regions",
                    "collected_at",
                )
            ],
        )
    headers = [
        "Relationship ID",
        "Source partition",
        "Source account",
        "Source",
        "Destination partition",
        "Destination account",
        "Destination",
        "Type",
        "Domain",
        "Service",
        "Region",
        "Status",
        "Authorization conclusion",
        "Confidence",
        "Evidence",
        "Observation IDs",
        "Collection times",
        "Assessment time",
        "Missing prerequisites",
        "Blocking predicates",
        "Limitations",
        "Related findings",
        "Methodology IDs",
        "Target privilege",
        "Outside approved registry",
        "Explanation",
        "Run ID",
    ]
    sheets = {
        name: sheet(workbook, name, headers)
        for name in (
            "Cross-Account Relationships",
            "Cross-Account IAM Investigation",
            "Shared Resource Access",
            "Shared Network Relationships",
            "Cross-Account Evidence Gaps",
        )
    }
    from offline_analyzer.findings.exclusions import excluded_ids, without_excluded

    hidden = set(excluded_ids(store, run))
    for (data,) in store.rows(
        "SELECT data FROM enterprise_edges WHERE run_id=? ORDER BY relationship_id", [run]
    ):
        # Excluded findings are not cited by relationship rows (the edge itself is evidence).
        e = without_excluded(json.loads(data), hidden, "related_findings")
        row = [
            e.get(k)
            for k in (
                "relationship_id",
                "source_partition",
                "source_account",
                "source",
                "destination_partition",
                "destination_account",
                "destination",
                "relationship_type",
                "domain",
                "service",
                "region",
                "status",
                "authorization",
                "confidence",
                "evidence",
                "observation_ids",
                "collected_at",
                "assessed_at",
                "missing",
                "blocking",
                "limitations",
                "related_findings",
                "methodology_ids",
                "target_privilege",
                "outside_registry",
                "detail",
                "run_id",
            )
        ]
        append(sheets["Cross-Account Relationships"], row)
        if e["domain"] == "IAM" and e["relationship_type"] in ("ASSUME_ROLE", "PASS_ROLE"):
            append(sheets["Cross-Account IAM Investigation"], row)
        if e["domain"] == "RESOURCE_ACCESS":
            append(sheets["Shared Resource Access"], row)
        if e["domain"] == "NETWORK":
            append(sheets["Shared Network Relationships"], row)
        if e["missing"]:
            append(sheets["Cross-Account Evidence Gaps"], row)
    issues = sheet(
        workbook,
        "Enterprise Security Gaps",
        [
            "Investigation",
            "Root-cause classification",
            "Shared resource",
            "Affected accounts",
            "Affected count",
            "Related candidate findings",
            "Primary finding",
            "Suggested severity",
            "Confidence",
            "Analyst status",
            "Missing evidence",
            "Evidence",
            "Methodology IDs",
            "Limitations",
        ],
    )
    affected = sheet(
        workbook,
        "Affected Accounts and Resources",
        ["Investigation", "Account", "Resource", "Ownership qualification"],
    )
    from offline_analyzer.enterprise.queries import VISIBLE_ISSUE

    for (data,) in store.rows(
        "SELECT data FROM enterprise_issues WHERE run_id=? AND "
        + VISIBLE_ISSUE
        + " ORDER BY investigation_id",
        [run, excluded_ids(store, run)],
    ):
        i = without_excluded(
            views.review_state(store, json.loads(data)), hidden, "finding_ids", "primary_finding"
        )
        append(
            issues,
            [
                i.get(k)
                for k in (
                    "investigation_id",
                    "root_cause_classification",
                    "anchor",
                    "affected_accounts",
                    "affected_account_count",
                    "finding_ids",
                    "primary_finding",
                    "suggested_severity",
                    "confidence",
                    "analyst_status",
                    "missing",
                    "evidence",
                    "methodology_ids",
                    "limitations",
                )
            ],
        )
        for account in i["affected_accounts"]:
            append(
                affected,
                [
                    i["investigation_id"],
                    account,
                    None,
                    "Affected/reference account; no ownership inferred",
                ],
            )
        for resource in i["affected_resources"]:
            append(
                affected,
                [
                    i["investigation_id"],
                    None,
                    resource,
                    "Explicit relationship endpoint; see relationship ownership/evidence",
                ],
            )
