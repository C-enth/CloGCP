"""One-click assessment report: native Excel workbook and Word report for one run.

Deliverables: technical findings register, control coverage matrix, attack-path
feasibility, posture by account/project and organization-wide, and a prioritized
remediation roadmap. Everything is projected from persisted analyzer data for the
selected run; candidates are never labelled validated without an analyst decision.
Account/project display names come from collector manifests (labels, never identity).
"""

import json
import re
import zipfile
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from offline_analyzer.findings.location import display_region
from offline_analyzer.ingestion.safety import excel_literal

OUTCOME_LABEL = {
    "PASS": "PASS",
    "FAIL": "FAIL",
    "NOT_APPLICABLE": "NOT APPLICABLE",
    "UNKNOWN": "INSUFFICIENT EVIDENCE",
    "COLLECTION_ERROR": "INSUFFICIENT EVIDENCE",
    "MANUAL_VALIDATION_REQUIRED": "MANUAL VALIDATION",
}
LABELS = ("PASS", "FAIL", "NOT APPLICABLE", "INSUFFICIENT EVIDENCE", "MANUAL VALIDATION")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
ROADMAP = {
    "CRITICAL": ("P1", "Immediate (0-7 days)"),
    "HIGH": ("P2", "Short term (0-30 days)"),
    "MEDIUM": ("P3", "Medium term (30-90 days)"),
    "LOW": ("P4", "Planned (90+ days)"),
    "INFO": ("P5", "Best practice / backlog"),
}
VALIDATION = {
    "CANDIDATE": "Candidate - analyst review pending",
    "CONFIRMED": "Validated by analyst",
    "REJECTED": "Rejected by analyst",
    "NEEDS_VALIDATION": "Analyst requested further validation",
    "NEEDS_REVALIDATION": "Evidence changed since analyst decision - revalidate",
}
# Which findings a report contains, chosen at download time from the analyst's marking.
SCOPE_NOTICE = (
    "This report is not limited to analyst-confirmed findings: it also contains findings that "
    "are still under review. Treat unconfirmed findings as candidates, not verified results."
)
INCLUDE = {
    "valid": "All findings except those marked not valid (rejected) or No gap (BAU) by SRE",
    "confirmed": "Only findings the analyst marked valid (confirmed)",
    "all": "All findings, including those marked not valid",
}
EXCLUDED_STAGES = {"valid": {"REJECTED", "NO_GAP_BAU"}}
BUSINESS = (
    "Business context not provided: business impact is not assessed. Technical impact is "
    "stated; asset criticality must be confirmed with the client."
)


def _scope(item) -> tuple[str, str]:
    provider = getattr(item, "provider", None) or (
        "GCP" if getattr(item, "project_id", None) else "AWS"
    )
    return provider, (getattr(item, "project_id", None) or getattr(item, "account_id", None) or "")


def included(include: str, status: str, stage: str) -> bool:
    if include == "confirmed":
        return status == "CONFIRMED"
    return stage not in EXCLUDED_STAGES.get(include, set())


def model(
    store,
    run_id: str,
    include: str = "confirmed",
    provider_filter: str = "",
    scope_filter: str = "",
    grouped: bool = True,
) -> dict:
    """Report data; `include` applies the analyst/SRE marking, filters select one account."""
    from offline_analyzer.attack_paths.diagram import diagram_text
    from offline_analyzer.attack_paths.feasibility import attack_paths
    from offline_analyzer.findings.explanations import explain
    from offline_analyzer.findings.recommendations import recommendation
    from offline_analyzer.findings.sre import STAGES, latest_sre, review_state
    from offline_analyzer.ingestion.labels import scope_names
    from offline_analyzer.methodology.cloud_checklist import describe, matrix

    store.require_run(run_id)
    names = scope_names(store)
    sources = list(store.source_data(run_id))
    collected = {s["artifact_id"]: s for s in sources if s.get("artifact_id")}
    if include not in INCLUDE:
        raise ValueError("Unknown report scope")
    decisions = store.latest_decisions(run_id)
    sre = latest_sre(store, run_id)
    scopes: dict[tuple[str, str], dict] = {}

    def wanted(provider: str, scope: str) -> bool:
        return (not provider_filter or provider == provider_filter) and (
            not scope_filter or scope == scope_filter
        )

    def scope_entry(provider: str, scope: str) -> dict:
        return scopes.setdefault(
            (provider, scope),
            {
                "provider": provider,
                "scope": scope,
                "name": names.get((provider, scope), ""),
                "severity": Counter(),
                "outcomes": Counter(),
                "gaps": 0,
                "sources": 0,
            },
        )

    for source in sources:
        provider = "GCP" if source.get("format") == "gcp-json-v1" else "AWS"
        scope = source.get("project_id") or source.get("account_id") or ""
        if not wanted(provider, scope):
            continue
        entry = scope_entry(provider, scope)
        entry["sources"] += 1
        if source.get("effective_coverage") in {"ERROR", "NOT_COLLECTED"}:
            entry["gaps"] += 1
    from offline_analyzer.reporting.coverage_reasons import (
        ERROR_REASONS,
        NOTE_REASONS,
        notable,
        source_category,
    )

    notes: Counter = Counter()
    for source in sources:
        provider = "GCP" if source.get("format") == "gcp-json-v1" else "AWS"
        scope = source.get("project_id") or source.get("account_id") or ""
        metadata = source.get("gcp_metadata") or {}
        if wanted(provider, scope):
            for code in notable(source_category(source), metadata.get("completeness_limitations")):
                notes[(provider, scope, code)] += 1
    coverage_notes = [
        {
            "provider": provider,
            "scope": scope,
            "name": names.get((provider, scope), ""),
            "code": code,
            "reason": ERROR_REASONS.get(code) or NOTE_REASONS.get(code) or code,
            "datasets": count,
        }
        for (provider, scope, code), count in sorted(notes.items())
    ]
    coverage: dict[tuple, Counter] = defaultdict(Counter)
    for result in store.results(run_id):
        provider, scope = _scope(result)
        if not wanted(provider, scope):
            continue
        label = OUTCOME_LABEL.get(str(result.outcome), "INSUFFICIENT EVIDENCE")
        scope_entry(provider, scope)["outcomes"][label] += 1
        coverage[(provider, scope, result.rule_id)][label] += 1
    from offline_analyzer.findings.exclusions import appendix, excluded
    from offline_analyzer.reporting.limitations import latest as custom_limitations

    hidden = excluded(store, run_id)
    excluded_count = 0
    from offline_analyzer.contracts.report_finding import ReportRevision

    covering: dict = {}
    for (raw,) in store.rows(
        "SELECT data FROM report_revisions QUALIFY row_number() OVER "
        "(PARTITION BY report_id ORDER BY revision DESC)=1 ORDER BY report_id"
    ):
        group_revision = ReportRevision.model_validate_json(raw)
        for snapshot in group_revision.snapshots:
            covering.setdefault(snapshot.finding_id, group_revision)
    # Latest revision per primary finding in one query (same rows as latest_revision()).
    own_revision = {
        primary: ReportRevision.model_validate_json(raw)
        for primary, raw in store.rows(
            "SELECT primary_finding, data FROM report_revisions QUALIFY row_number() OVER "
            "(PARTITION BY primary_finding ORDER BY revision DESC)=1"
        )
    }
    findings = []
    for finding in store.candidates(run_id):
        provider, scope = _scope(finding)
        if not wanted(provider, scope):
            continue
        if finding.finding_id in hidden:
            # Excluded from client reporting by the analyst; counted so totals reconcile.
            excluded_count += 1
            continue
        status, stage = review_state(store, finding, decisions, sre)
        if not included(include, status, stage):
            continue
        advice = recommendation(finding.rule_id)
        decision = decisions.get(finding.finding_id)
        evidence = []
        for ref in finding.evidence:
            source = collected.get(ref.artifact_id, {})
            evidence.append(
                f"{source.get('operation', 'source')} {ref.locator} "
                f"(collected {source.get('collected_at', 'unknown')})"
            )
        scope_entry(provider, scope)["severity"][finding.suggested_severity] += 1
        checklist = describe(finding.methodology_id)
        explanation = explain(finding)
        from offline_analyzer.contracts.r0 import stable_id
        from offline_analyzer.findings.groups import group_key

        rule_key, key_kind, key_value = group_key(finding)
        findings.append(
            {
                "group_id": stable_id("finding-group", [rule_key, key_kind, key_value]),
                "group_key": key_value or rule_key,
                "checklist_domain": checklist["checklist_domain"],
                "checklist_title": checklist["checklist_title"],
                "stride": finding.stride_category or "",
                "methodology_paths": ", ".join(finding.attack_paths),
                "id": finding.finding_id,
                "title": finding.title,
                "domain": finding.security_domain,
                "control": finding.methodology_id or "Unclassified",
                "rule": finding.rule_id,
                "severity": finding.suggested_severity,
                "rationale": finding.severity_rationale,
                "provider": provider,
                "scope": scope,
                "scope_name": names.get((provider, scope), ""),
                "region": display_region(finding.region),
                "resource": finding.native_id,
                "observed": finding.technical_observation,
                "expected": advice.get("expected_posture") or "Analyst to define expected state",
                "impact": explanation["impact"],
                "why": explanation["why_flagged"],
                "misuse": explanation["misuse"],
                "recommendation": explanation["recommendation"],
                "business": BUSINESS,
                "evidence": "; ".join(evidence) or "No evidence reference",
                "remediation": " ".join(
                    filter(
                        None,
                        [
                            advice.get("recommended_action"),
                            advice.get("permanent_remediation"),
                            advice.get("implementation_guidance"),
                        ],
                    )
                )
                or finding.remediation,
                "validation_procedure": advice.get("validation_procedure", ""),
                "status": VALIDATION.get(status, status),
                "stage": STAGES[stage],
                "confidence": finding.evidence_confidence,
                "framework": finding.methodology_id
                or "Not mapped (verifiable mapping unavailable)",
                "missing": ", ".join(finding.missing_evidence),
                "analyst": decision.analyst if decision else "",
            }
        )
        # Report edits belong to Client Reporting; only evidence-current revisions are
        # used. Approval state stays explicit and is never inferred from the text edit.
        from offline_analyzer.findings.report_ready import current_findings, validity

        # The finding's own revision, else a group revision that names it as a member.
        revision = own_revision.get(finding.finding_id) or covering.get(finding.finding_id)
        if revision:
            state = validity(
                revision,
                current_findings(store, run_id, [s.finding_id for s in revision.snapshots]),
                decisions,
                store,
            )
            if state["member_states"].get(finding.finding_id) == "CURRENT":
                section = revision.sections
                findings[-1].update(
                    title=section.title,
                    severity=section.severity,
                    rationale=section.severity_rationale,
                    observed=section.technical_observation,
                    why=section.technical_observation,
                    expected=section.expected_posture,
                    impact=section.risk,
                    misuse=section.attack_scenario,
                    recommendation=section.remediation,
                    remediation=section.remediation,
                    immediate=section.immediate_mitigation,
                    validation_procedure=section.validation,
                    report_revision=revision.revision,
                    report_approval="APPROVED"
                    if state["eligible"]
                    else "DRAFT — report approval pending",
                )
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(
        key=lambda f: (order.get(f["severity"], 9), f["provider"], f["scope"], f["title"])
    )
    evaluated = attack_paths(store, run_id)
    reported = {f["id"] for f in findings}
    coverage_notes += truncation_notes(store, run_id, evaluated, provider_filter)
    coverage_notes += organization_notes(store, run_id, sources, wanted, names)
    coverage_notes += collection_fact_notes(store, run_id, wanted, names, coverage_notes)
    from offline_analyzer.enterprise.shards import coverage_note as shard_note

    if sharded := shard_note(store, run_id):
        coverage_notes.append(sharded)

    def visible(ids) -> list[str]:
        # Excluded findings stay excluded: paths and hops never cite them.
        return [i for i in ids or [] if i not in hidden]

    paths = [
        {
            **p,
            "diagram": diagram_text(p),
            "finding_ids": visible(p.get("finding_ids")),
            **(
                {"hops": [{**h, "finding_ids": visible(h["finding_ids"])} for h in p["hops"]]}
                if "hops" in p
                else {}
            ),
        }
        for p in evaluated["items"]
        if not p.get("excluded_dependency")
        and (not provider_filter or p["provider"] == provider_filter)
        and (not scope_filter or scope_filter in {p.get("project_id"), p.get("account_id")})
        and (include != "confirmed" or set(p.get("finding_ids", [])) & reported)
    ]
    assessed = {"GCP" if s.get("format") == "gcp-json-v1" else "AWS" for s in sources}
    for finding in findings:
        finding["evaluated_paths"] = "; ".join(
            f"{p.get('attack_path') or p['path_id']}: {p.get('title', '')}; "
            f"{p['feasibility']}; STRIDE: {', '.join(p.get('stride', [])) or 'Unmapped'}"
            for p in paths
            if p.get("analyst_review") == "CONFIRMED" and finding["id"] in p.get("finding_ids", [])
        )
    data = {
        "run_id": run_id,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "include": INCLUDE[include],
        # Safe default is analyst-confirmed findings only; any wider scope is stated on the cover.
        "include_key": include,
        "excluded": excluded_count,
        # Transparency appendix: excluded findings grouped by rule and reason (with IDs).
        "excluded_findings": appendix(store, run_id, provider_filter, scope_filter),
        # Analyst scope-limitation text for this run (reporting/limitations.py).
        "custom_limitations": custom_limitations(store, run_id),
        "scopes": sorted(scopes.values(), key=lambda s: (s["provider"], s["name"], s["scope"])),
        "findings": findings,
        # Root-cause groups of the reported findings (owner brief 2c); totals stay per finding.
        "grouped": grouped,
        "groups": report_groups(findings),
        "coverage": coverage,
        "checklist": matrix(
            [r for r in store.results(run_id) if wanted(*_scope(r))],
            assessed=assessed,
        ),
        "paths": paths,
        "provider_scope": provider_filter
        or " + ".join(p for p in ("GCP", "AWS") if p in assessed)
        or "No evidence",
        # Why path kinds were or were not formed (counts only), per provider.
        "path_coverage": [
            {**reason, "provider": provider}
            for provider, reasons in evaluated.get("coverage", {}).items()
            if (not provider_filter or provider == provider_filter) and provider in assessed
            for reason in reasons
        ],
        # Collection gaps and limitations per account/project, with plain-language reasons.
        "coverage_notes": coverage_notes,
        # Areas where evidence could not support an outcome (UNKNOWN / collection error) or
        # a manual check is required; never reported as passing.
        "unknown_areas": [
            {
                "provider": provider,
                "scope": scope,
                "name": names.get((provider, scope), ""),
                "rule": rule,
                "insufficient": counts["INSUFFICIENT EVIDENCE"],
                "manual": counts["MANUAL VALIDATION"],
            }
            for (provider, scope, rule), counts in sorted(coverage.items())
            if counts["INSUFFICIENT EVIDENCE"] or counts["MANUAL VALIDATION"]
        ],
    }
    from offline_analyzer.reporting.gcp_feed import linked, merge_report

    record = linked(store, run_id)
    if record:
        # AWS live + linked GCP frozen edition, labelled by source and edition.
        data = merge_report(data, record, provider_filter, scope_filter)
        # Register groups must cover the merged findings, including frozen members.
        # This is a new report projection; the edition and original decisions stay intact.
        data["groups"] = report_groups(data["findings"])
    from offline_analyzer.reporting.contextual import check, register

    # Contextual findings register (Excel sheet, Word findings, UI) from the same model.
    data["contextual_register"] = register(store, run_id, data)
    data["register_reconciliation"] = check(data)
    return data


def organization_notes(store, run_id: str, sources, wanted, names) -> list[dict]:
    """One coverage note per AWS account with IAM evidence whose organization controls (SCP
    and RCP) cannot be evaluated: absent Organizations evidence is stated, never read as
    "no SCP"."""
    from types import SimpleNamespace

    from offline_analyzer.iam.analysis import ORG_KINDS, load
    from offline_analyzer.iam.organizations import OrganizationModel
    from offline_analyzer.rules.aws_identity import organization_note

    accounts = sorted(
        {
            s["account_id"]
            for s in sources
            if s.get("format") != "gcp-json-v1"
            and s.get("account_id")
            and str(s.get("operation", "")).startswith("iam:")
        }
    )
    if not accounts:
        return []
    holder = SimpleNamespace(org=OrganizationModel(load(store, run_id, ORG_KINDS), sources))
    notes = []
    for account in accounts:
        text = organization_note(holder, account) if wanted("AWS", account) else None
        if text:
            notes.append(
                {
                    "provider": "AWS",
                    "scope": account,
                    "name": names.get(("AWS", account), ""),
                    "code": "ORGANIZATION_CONTROLS_NOT_ASSESSED",
                    "reason": text,
                    "datasets": 0,
                }
            )
    return notes


def collection_fact_notes(store, run_id: str, wanted, names, existing) -> list[dict]:
    """Coverage notes from AWS collector 0.3.3 manifest facts (retries, limits, fallbacks,
    Regions, organization access, resume). Organization access already stated from the
    evidence (ORGANIZATION_CONTROLS_NOT_ASSESSED) is not repeated."""
    from offline_analyzer.reporting.aws_collection import account_notes, reason

    stated = {(n["scope"], n["code"]) for n in existing if n["provider"] == "AWS"}
    notes = []
    for account, counts in sorted(account_notes(store, run_id).items()):
        if not wanted("AWS", account):
            continue
        for code, count in sorted(counts.items()):
            if code == "AWS_ORGANIZATION_ACCESS_MISSING" and (
                (account, "ORGANIZATION_CONTROLS_NOT_ASSESSED") in stated
            ):
                continue
            notes.append(
                {
                    "provider": "AWS",
                    "scope": account,
                    "name": names.get(("AWS", account), ""),
                    "code": code,
                    "reason": reason(code),
                    "datasets": count,
                }
            )
    return notes


def truncation_notes(store, run_id: str, evaluated: dict, provider_filter: str) -> list[dict]:
    """Coverage notes for every limit that dropped records: attack-path and IAM budgets, the
    enterprise relationship budget and the Word report's path limit. Empty when nothing was
    dropped, so untruncated reports are unchanged."""
    from offline_analyzer.provenance.truncation import note, record
    from offline_analyzer.reporting.report_document import PATH_LIMIT

    entries = list(evaluated.get("truncation") or [])
    cached = store.db.execute(
        "SELECT data FROM enterprise_projection WHERE run_id=?", [run_id]
    ).fetchone()
    if cached:
        entries += json.loads(cached[0]).get("truncation_detail") or []
    listed = [p for p in evaluated["items"] if not p.get("excluded_dependency")]
    if len(listed) > PATH_LIMIT:
        entries.append(
            record(
                "Word report attack-path limit",
                "report",
                PATH_LIMIT,
                len(listed),
                "the Word report details the first paths; the Excel workbook lists all of them",
                provider="Report",
            )
        )
    return [
        note(e)
        for e in entries
        if not provider_filter or e.get("provider") in {provider_filter, "Enterprise", "Report"}
    ]


def report_groups(findings: list[dict]) -> list[dict]:
    """One entry per root-cause group: highest member severity, members, affected resources."""
    from offline_analyzer.findings.groups import SEVERITY_ORDER, highest

    found: dict[str, dict] = {}
    for f in findings:
        entry = found.setdefault(f["group_id"], {"group_id": f["group_id"], "members": []})
        entry["members"].append(f)
    result = []
    for entry in found.values():
        members = sorted(
            entry["members"], key=lambda f: (-SEVERITY_ORDER.get(f["severity"], -1), f["id"])
        )
        result.append(
            {
                "group_id": entry["group_id"],
                "title": members[0]["title"],
                "rule": members[0]["rule"],
                "key": members[0]["group_key"],
                "severity": highest(f["severity"] for f in members),
                "representative": members[0],
                "members": members,
                "affected_resources": len(
                    {(f["provider"], f["scope"], f["resource"]) for f in members}
                ),
            }
        )
    result.sort(key=lambda g: (-SEVERITY_ORDER.get(g["severity"], -1), g["title"], g["group_id"]))
    return result


def scope_title(data: dict) -> str:
    # Collected accounts/projects name the report; org-wide findings add other scopes.
    collected = [s for s in data["scopes"] if s["scope"] and s["sources"]]
    names = [s["name"] or s["scope"] for s in collected or data["scopes"] if s["scope"]]
    return ", ".join(names[:3]) + (f" +{len(names) - 3}" if len(names) > 3 else "") or "assessment"


def file_label(data: dict) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", scope_title(data))[:80].strip("_") or "assessment"


def _cell(value) -> object:
    if isinstance(value, str):
        return excel_literal(value)
    return value


def write_excel(data: dict, path: Path, *, gcp_register: dict | None = None) -> None:
    """Executive Summary, Technical Findings and Attack Paths (reporting.report_document)."""
    from offline_analyzer.reporting.report_document import write_excel as document

    document(data, path, gcp_register=gcp_register)


def rtf(text: str) -> str:
    from offline_analyzer.reporting.approved import rtf_escape

    return rtf_escape(text)


def heading(text: str) -> str:
    """Section heading with spacing; kept with the following paragraph."""
    return "{\\pard\\sb360\\sa120\\keepn\\b\\fs28 " + rtf(text) + "\\par}\n"


def field(label: str, value: str) -> str:
    """One labelled line: bold label, plain value."""
    return "{\\pard\\sa60 {\\b " + rtf(label + ": ") + "}" + rtf(str(value)) + "\\par}\n"


def write_rtf(data: dict, path: Path) -> None:
    """Word document: title page, executive summary, technical findings, attack paths."""
    from offline_analyzer.reporting.report_document import write_rtf as document

    document(data, path)


def _path_export(
    store, run: str, version: dict, data: dict, edition, include: str, provider: str, scope: str
) -> dict:
    """Apply the same provider, scope and review policy to supplemental path material."""
    if not version["latest"] or provider == "AWS":
        return {"latest": None, "paths": [], "versions": []}
    if edition:
        allowed = {f["id"] for f in edition.get("document", {}).get("findings", [])}
    else:
        from offline_analyzer.findings.exclusions import excluded
        from offline_analyzer.findings.sre import latest_sre, review_state

        hidden = excluded(store, run)
        decisions, sre = store.latest_decisions(run), latest_sre(store, run)
        allowed = {
            f.finding_id
            for f in store.candidates(run)
            if f.finding_id not in hidden
            and included(include, *review_state(store, f, decisions, sre))
        }
    reported = {f.get("id", f.get("finding_id")) for f in data.get("findings", [])}
    paths = [
        p
        for p in version["paths"]
        if (not scope or p["project_id"] == scope)
        and set(p.get("original_finding_ids", [])) <= allowed
        and (include != "confirmed" or bool(set(p.get("original_finding_ids", [])) & reported))
    ]
    ids = {p["path_id"] for p in paths}
    comparison = [
        r
        for r in version["latest"]["comparison"]
        if r["new_path_id"] in ids
        or (not r["new_path_id"] and not scope and include != "confirmed")
    ]
    metadata = {
        **version["latest"],
        "comparison": comparison,
        "new_path_count": len(paths),
        "old_path_count": len({r["old_path_id"] for r in comparison if r["old_path_id"]}),
        "classification_counts": dict(Counter(p["classification"] for p in paths)),
        "export_scope": {"provider": provider or "ALL", "scope": scope, "include": include},
        "export_qualification": (
            "Scope/review-filtered projection. The result hash and evaluation ID "
            "identify the retained full evaluation; omitted history remains there."
        ),
    }
    return {**version, "latest": metadata, "paths": paths}


def export_assessment(
    store,
    run_id: str,
    path: Path,
    progress=None,
    include: str = "confirmed",
    provider: str = "",
    scope: str = "",
    grouped: bool = True,
) -> str:
    """Write a ZIP with the Excel workbook and Word report; returns the download name."""
    import tempfile

    from offline_analyzer.findings.finalisation import filtered, frozen

    edition = frozen(store, run_id)
    data = (
        filtered(edition, "document", provider, scope)
        if edition
        else model(store, run_id, include, provider, scope, grouped)
    )
    from offline_analyzer.reporting.gcp_feed import require_reconciled

    require_reconciled(data)  # consolidated counts must reconcile before any export
    label = file_label(data) + ("" if include == "valid" else f"-{include}")
    from offline_analyzer.attack_paths.versioned import latest as latest_paths

    path_version = _path_export(
        store,
        run_id,
        latest_paths(store.workspace, run_id),
        data,
        edition,
        include,
        provider,
        scope,
    )
    if path_version["latest"]:
        data["versioned_path_evaluation"] = path_version
        data["paths"] = [
            {
                **p,
                "title": "Historical projection — see current v2 evaluation: " + p.get("title", ""),
            }
            if p.get("provider") == "GCP"
            else p
            for p in data.get("paths", [])
        ]
        for finding in data.get("findings", []):
            matched = [
                p
                for p in path_version["paths"]
                if finding.get("id", finding.get("finding_id")) in p.get("original_finding_ids", [])
            ]
            if matched:
                finding["evaluated_paths"] = "; ".join(
                    p["path_id"]
                    + ": "
                    + p["classification"]
                    + "; execution UNVERIFIED; review UNREVIEWED"
                    for p in matched
                )
            else:
                finding["evaluated_paths"] = (
                    "No linked current path is included by these report filters; "
                    "inspect the saved v2 comparison for review."
                )
        data["groups"] = report_groups(data.get("findings", []))
    with tempfile.TemporaryDirectory() as temporary:
        workbook = Path(temporary) / "report.xlsx"
        document = Path(temporary) / "report.docx"
        from offline_analyzer.reporting.gcp_register import build as gcp_register

        register = gcp_register(store, run_id, data, provider=provider, scope=scope)
        write_excel(data, workbook, gcp_register=register)
        if progress:
            progress("Writing assessment report", 1, 2)
        from offline_analyzer.reporting.docx import write_docx

        write_docx(data, document)
        with zipfile.ZipFile(path, "x", zipfile.ZIP_DEFLATED) as archive:
            archive.write(workbook, f"CloSec-{label}-assessment.xlsx")
            archive.write(document, f"CloSec-{label}-assessment-report.docx")
            if path_version["latest"]:
                archive.writestr(
                    "attack-path-evaluation-v2.json",
                    json.dumps(
                        {"evaluation": path_version["latest"], "paths": path_version["paths"]},
                        indent=2,
                    ),
                )
            from offline_analyzer.evidence.composition import description

            composition = description(store, run_id)
            if composition and provider != "AWS":
                if provider or scope:
                    composition = {
                        "schema_version": composition["schema_version"],
                        "source_runs": composition["source_runs"],
                        "export_scope": {"provider": provider, "scope": scope},
                        "qualification": (
                            "Full reconciliation retained in the workspace and unfiltered "
                            "consolidated export; scoped exports omit unrelated project/review "
                            "details."
                        ),
                    }
                archive.writestr(
                    "evidence-composition-reconciliation.json", json.dumps(composition, indent=2)
                )
            archive.writestr(
                "README.txt",
                "Excel workbook and Word report: cover, executive summary, coverage and "
                "limitations, attack surface, attack paths with one row per hop, STRIDE and "
                "direction justification, findings and appendix.\n"
                "Word: open the .docx in Microsoft Word. Excel: every table has a frozen "
                "header row and filters.\n",
            )
    return f"CloSec-{label}-assessment-report.zip"
