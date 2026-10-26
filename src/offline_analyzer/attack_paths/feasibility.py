"""Deterministic attack-path feasibility and severity calibration.

A path is FEASIBLE only when every prerequisite that evidence can establish (CONFIG,
IAM_ENGINE, REACHABILITY, ORG_EVIDENCE) is VERIFIED; attacker-side prerequisites
(EXPLOITATION, MANUAL, CLASSIFICATION, DETECTION) are never auto-verified, so FEASIBLE
means "the configuration supports the attack", not "the attack happened". A prerequisite
verified absent, or a verified blocker, makes the path BLOCKED. Anything else is
INSUFFICIENT_EVIDENCE. Nothing here invents identifiers, permissions or edges.

Severity calibration raises (never lowers) a candidate's severity only for documented
reasons, with the reason appended to its rationale. Business criticality is unknown and
stated as an assumption.
"""

import json
from collections import Counter

from offline_analyzer.attack_paths.specs import ALTERNATIVES, BY_PATH
from offline_analyzer.contracts.r0 import Candidate, stable_id

EVIDENCE_KINDS = {"CONFIG", "IAM_ENGINE", "REACHABILITY", "ORG_EVIDENCE"}
FEASIBLE, BLOCKED, INSUFFICIENT = "FEASIBLE", "BLOCKED", "INSUFFICIENT_EVIDENCE"
ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# Feasible paths reaching administrative-equivalent access are CRITICAL; public data
# exposure is at least HIGH (data classification unknown).
CROSS_LIMIT = 300  # cross-project/cross-cloud paths listed per run
INVESTIGATION_LIMIT = 100  # GCP candidate investigations listed per run or project
PATH_SEVERITY = {"AP-04": "CRITICAL", "AP-06": "CRITICAL", "AP-05": "HIGH"}
PATH_TITLES = {
    "AP-04": "Internet-exposed instance -> metadata credentials -> privileged role",
    "AP-05": "Public storage access to bucket contents",
    "AP-06": "IAM privilege escalation to administrative access",
}
PRIVILEGED_ROLES = {"roles/owner", "roles/editor"}
ASSUMPTION = " Assumption: asset business criticality is unknown; exploitation was not performed."


def aws_feasibility(record) -> tuple[str, str]:
    spec = BY_PATH.get(record.path_id)
    statuses = dict(record.prerequisites)
    # Alternatives (specs.ALTERNATIVES): one VERIFIED member meets the group; the group is
    # absent only when every member is verified absent.
    for group in ALTERNATIVES.get(record.path_id, ()):
        states = [statuses.get(k, "NOT_EVALUATED") for k in group]
        merged = (
            "VERIFIED"
            if "VERIFIED" in states
            else "NOT_PRESENT"
            if all(s == "NOT_PRESENT" for s in states)
            else "UNKNOWN"
        )
        statuses.update({k: merged for k in group})
    if record.state == "BLOCKED" or record.blockers or "NOT_PRESENT" in statuses.values():
        return BLOCKED, "A prerequisite is verified absent or a blocking control is verified."
    checkable = [p for p in (spec.prerequisites if spec else ()) if p.kind in EVIDENCE_KINDS]
    missing = [p.key for p in checkable if statuses.get(p.key) != "VERIFIED"]
    if checkable and not missing:
        attacker = [p.key for p in spec.prerequisites if p.kind not in EVIDENCE_KINDS]
        return FEASIBLE, (
            f"All {len(checkable)} evidence-checkable prerequisites are verified"
            + (f"; attacker-side prerequisites remain: {', '.join(attacker)}." if attacker else ".")
        )
    return INSUFFICIENT, "Unverified prerequisites: " + ", ".join(missing or ["path definition"])


def gcp_feasibility(path: dict, rule_id: str, binding_role: str | None) -> tuple[str, str]:
    privileged_key = any(
        t["relationship"] == "Observed service-account privilege binding"
        for t in path["transitions"]
    )
    if rule_id in {"GCP-IAM-PUBLIC", "GCP-STORAGE-PUBLIC"}:
        return INSUFFICIENT, (
            "A public allow binding is observed, but effective deny, boundary, conditional "
            "and service enforcement context is not fully verified. A binding alone does "
            "not establish a feasible end-to-end attack path."
        )
    if rule_id.startswith("GCP-KEY-") and privileged_key:
        return INSUFFICIENT, (
            "User-managed key belongs to a service account with an observed owner/editor "
            "allow binding. Effective deny/boundary context is unresolved; attacker-side "
            "prerequisite: possession of the key. Effective privilege is not established."
        )
    return INSUFFICIENT, (
        "Effective authorization or credential exposure is not established by the evidence."
    )


GCP_IMPACT = {
    "GCP-KEY-PERSISTENT": "Whoever holds the key acts as the service account.",
    "GCP-KEY-PRIVILEGED": "Whoever holds the key acts as a privileged service account.",
    "GCP-IAM-IMPERSONATION": "The grant holder acts as the impersonable service account.",
    "GCP-IAM-CROSSPROJECT": "A principal from another project acts in this project.",
    "GCP-IAM-PUBLIC": "Any internet client acts with the publicly granted role.",
    "GCP-API-BOTH": "Whoever holds the API key consumes the project's enabled APIs.",
    "GCP-STORAGE-PUBLIC": "Any internet client accesses the bucket.",
}


def aws_evidence(store, run_id: str, stored: set[str]):
    """evidence_of(record, key) -> (rule_ids, finding_ids, observation_ids, refs)."""
    from offline_analyzer.attack_paths.model import AWS_EVIDENCE_RULES

    results = {r.evaluation_id: r for r in store.results(run_id)}
    # AP-06 P1 is established by the IAM engine from the principal's own role document.
    roles = {
        native: observation
        for observation, native in store.rows(
            "SELECT observation_id, json_extract_string(data,'$.native_id') FROM observations "
            "WHERE run_id=? AND kind='AWS::IAM::Role'",
            [run_id],
        )
    }

    def evidence_of(record, key: str):
        spec = BY_PATH.get(record.path_id)
        prerequisite = next((p for p in spec.prerequisites if p.key == key), None) if spec else None
        rules = set(prerequisite.rules if prerequisite else ()) | set(
            AWS_EVIDENCE_RULES.get(key, ())
        )
        used = [
            results[e] for e in record.evaluations if e in results and results[e].rule_id in rules
        ]
        observations = {o for r in used for o in r.supporting_observations}
        if key == "AP-06.P1" and record.anchor in roles:
            observations.add(roles[record.anchor])
        return (
            sorted(rules),  # the rules behind the prerequisite, evaluated or not
            sorted(
                {stable_id("finding", [r.rule_id, r.resource_id]) for r in used if r.resource_id}
                & stored
            ),
            sorted(observations),
            [r.model_dump(mode="json") for u in used for r in u.evidence],
        )

    return evidence_of


def aws_paths(store, run_id: str, truncation: list | None = None) -> list[dict]:
    """AWS path items; `truncation` receives budget records that limited them."""
    from offline_analyzer.attack_paths.model import AWS_OBJECTIVES, aws_assumptions, aws_hops
    from offline_analyzer.attack_paths.model import summarize as summarize_hops
    from offline_analyzer.attack_paths.prerequisites import path_records

    if not any(
        True
        for _ in store.rows(
            "SELECT 1 FROM sources WHERE run_id=? AND "
            "json_extract_string(data,'$.format') <> 'gcp-json-v1' LIMIT 1",
            [run_id],
        )
    ):
        return []
    rule_by_evaluation = {
        evaluation: (rule, resource)
        for evaluation, rule, resource in store.rows(
            "SELECT evaluation_id, json_extract_string(data,'$.rule_id'), resource_id "
            "FROM evaluations WHERE run_id=?",
            [run_id],
        )
    }
    stored = {f for (f,) in store.rows("SELECT finding_id FROM findings WHERE run_id=?", [run_id])}
    evidence_of = aws_evidence(store, run_id, stored)
    items = []
    for record in path_records(store, run_id, truncation=truncation):
        verdict, reason = aws_feasibility(record)
        spec = BY_PATH.get(record.path_id)
        hops = aws_hops(record, spec, lambda key, record=record: evidence_of(record, key))
        objective, impact = AWS_OBJECTIVES.get(record.path_id, (record.path_id, ""))
        findings = sorted(
            {
                stable_id("finding", [rule, resource])
                for evaluation in record.evaluations
                for rule, resource in [rule_by_evaluation.get(evaluation, (None, None))]
                if rule and resource
            }
            & stored
        )
        items.append(
            summarize_hops(
                {
                    "path_id": record.record_id,
                    "attack_path": record.path_id,
                    "provider": "AWS",
                    "account_id": record.account_id,
                    "region": record.region,
                    "title": PATH_TITLES.get(record.path_id, record.path_id),
                    "anchor": record.anchor,
                    "feasibility": verdict,
                    "feasibility_reason": reason,
                    "status": record.state,
                    "prerequisites": record.prerequisites,
                    "unresolved": list(record.missing),
                    "finding_ids": findings,
                    "confidence": "MEDIUM" if verdict == FEASIBLE else "LOW",
                    "qualification": "Configuration prerequisites only; exploitation not "
                    "performed.",
                },
                hops,
                hops[0]["source"] if hops else record.anchor,
                objective,
                impact,
                aws_assumptions(spec),
            )
        )
    return items


def gcp_paths(
    store, run_id: str, project: str = "", *, projection: dict | None = None
) -> list[dict]:
    from offline_analyzer.attack_paths.gcp import investigations
    from offline_analyzer.attack_paths.model import from_transitions, observation_index
    from offline_analyzer.attack_paths.model import summarize as summarize_hops

    candidates = {c.finding_id: c for c in store.candidates(run_id) if c.provider == "GCP"}
    roles = {
        o.resource_id: o.configuration.get("role")
        for o in store.observations(run_id, provider="GCP")
        if o.resource_type == "GCP::IAMBinding" and o.resource_id
    }
    paths = (projection if projection is not None else investigations(store, run_id, project, 100))[
        "items"
    ]
    index = observation_index(
        store, run_id, [r for p in paths for t in p["transitions"] for r in t["evidence"]]
    )
    items = []
    for path in paths:
        finding = candidates.get(path["finding_id"])
        rule = finding.rule_id if finding else ""
        verdict, reason = gcp_feasibility(
            path, rule, roles.get(finding.resource_id) if finding else None
        )
        record = {
            **path,
            "feasibility": verdict,
            "feasibility_reason": reason,
            "finding_ids": [path["finding_id"]],
            "binding_role": roles.get(finding.resource_id) if finding else None,
        }
        hops = from_transitions(record, index)
        attacker = [
            p
            for t in path["transitions"]
            if t["source"] == "Hypothetical attacker"
            for p in t["attack_prerequisites"]
        ]
        items.append(
            summarize_hops(
                record,
                hops,
                hops[0]["source"] if hops else path["transitions"][0]["destination"],
                hops[-1]["target"] if hops else path["transitions"][-1]["destination"],
                GCP_IMPACT.get(rule, "Use of the access the observed configuration grants."),
                attacker,
            )
        )
    return items


def calibrate(store, run_id: str) -> int:
    """Raise candidate severity for findings anchoring feasible paths. Returns updates."""
    targets: dict[str, tuple[str, str]] = {}

    def propose(finding_id: str, severity: str, reason: str) -> None:
        current = targets.get(finding_id)
        if current is None or ORDER[severity] > ORDER[current[0]]:
            targets[finding_id] = (severity, reason)

    for path in aws_paths(store, run_id):
        if path["feasibility"] != FEASIBLE or path["attack_path"] not in PATH_SEVERITY:
            continue
        for finding in path["finding_ids"]:
            propose(
                finding,
                PATH_SEVERITY[path["attack_path"]],
                f"Anchors feasible attack path {path['attack_path']} ({path['title']}).",
            )
    for path in gcp_paths(store, run_id):
        if path["feasibility"] != FEASIBLE:
            continue
        role = path.get("binding_role")
        rule_critical = path["finding_ids"] and (
            any(
                t["relationship"] == "Observed service-account privilege binding"
                for t in path["transitions"]
            )
            or role in PRIVILEGED_ROLES
        )
        propose(
            path["finding_id"],
            "CRITICAL" if rule_critical else "HIGH",
            "Anchors a feasible attack path: " + path["feasibility_reason"],
        )
    updated = 0
    for finding_id, (severity, reason) in targets.items():
        row = next(
            iter(
                store.rows(
                    "SELECT data FROM findings WHERE run_id=? AND finding_id=?",
                    [run_id, finding_id],
                )
            ),
            None,
        )
        if not row:
            continue
        data = json.loads(row[0])
        if data.get("finding_class") == "BASELINE_DEVIATION":
            continue  # a baseline deviation keeps its severity; the path raises the exposure
        if severity == "CRITICAL" and data.get("finding_class") != "SUPPORTED_SECURITY_GAP":
            # CRITICAL needs a supported gap; potential exposure (effective access
            # unresolved) is capped at HIGH until an analyst confirms it.
            severity = "HIGH"
            reason += " CRITICAL withheld: effective access is not established by evidence."
        if ORDER[severity] <= ORDER[data["suggested_severity"]]:
            continue
        data["severity_rationale"] = (
            f"{data['severity_rationale']} Raised from {data['suggested_severity']} to "
            f"{severity}: {reason}{ASSUMPTION}"
        )
        data["suggested_severity"] = severity
        # Canonical model JSON, as written at assessment: review and SRE fingerprints are the
        # SHA-256 of these bytes (findings/sre.py:STAGE_SQL, generate.py:fingerprint).
        store.db.execute(
            "UPDATE findings SET data=? WHERE run_id=? AND finding_id=?",
            [Candidate.model_validate(data).model_dump_json(), run_id, finding_id],
        )
        updated += 1
    return updated


def path_coverage(store, run_id: str, items: list[dict]) -> dict[str, list[dict]]:
    """Why each path kind was or was not formed, per provider, from counts only.

    Reasons restate the inputs the builders read; they never add an edge or a verdict.
    """
    from offline_analyzer.attack_paths.cross import classify
    from offline_analyzer.attack_paths.gcp import INVESTIGATION_RULES
    from offline_analyzer.rules.gcp_org import org_records, project_index

    def reason(kind: str, formed: int, text: str) -> dict:
        return {"kind": kind, "formed": formed, "reason": text}

    formed = Counter(p.get("attack_path") or "GCP investigation" for p in items)
    providers = {
        "GCP" if fmt == "gcp-json-v1" else "AWS"
        for (fmt,) in store.rows(
            "SELECT DISTINCT json_extract_string(data,'$.format') FROM sources WHERE run_id=?",
            [run_id],
        )
    }
    result: dict[str, list[dict]] = {"GCP": [], "AWS": []}
    if "GCP" not in providers:
        result["GCP"].append(reason("GCP", 0, "No GCP evidence is part of this run."))
    else:
        candidates = [c for c in store.candidates(run_id) if c.provider == "GCP"]
        eligible = sum(c.rule_id in INVESTIGATION_RULES for c in candidates)
        result["GCP"].append(
            reason(
                "GCP investigation",
                formed["GCP investigation"],
                f"{eligible} of {len(candidates)} GCP findings use an investigation rule "
                "(service-account keys, impersonation, cross-project, public IAM or storage, "
                "API keys); each one forms a candidate investigation.",
            )
        )
        records = org_records(store.observations(run_id, provider="GCP"))
        if not records:
            result["GCP"].append(
                reason(
                    "XP-01/XP-02/XP-03",
                    0,
                    "No Cloud Asset Inventory IAM search results were collected, so "
                    "cross-project paths cannot be built.",
                )
            )
        else:
            found = classify(records, project_index(records), records[0].project_id)
            counts = found.counts
            result["GCP"].append(
                reason(
                    "XP-01/XP-02",
                    formed["XP-01"] + formed["XP-02"],
                    f"{len(found.privileged)} customer-managed service account(s) hold an "
                    "administrative role on a project, folder or organization"
                    + (
                        f" ({counts['agent_admin']} such grant(s) to Google-managed service "
                        "agents are excluded: customers cannot impersonate them)"
                        if counts["agent_admin"]
                        else ""
                    )
                    + "; impersonation and cross-project escalation paths need one.",
                )
            )
            result["GCP"].append(
                reason(
                    "XP-03",
                    formed["XP-03"],
                    f"{len(found.public)} allUsers/allAuthenticatedUsers grant(s) on serverless "
                    "or data resources.",
                )
            )
            aws_roles = next(
                iter(
                    store.rows("SELECT count(*) FROM observations WHERE kind='AWS::IAM::Role'", [])
                )
            )[0]
            other = sum(
                v for k, v in counts.items() if k.startswith("federated_") and k != "federated_AWS"
            )
            result["GCP"].append(
                reason(
                    "XC-01/XC-02",
                    formed["XC-01"] + formed["XC-02"],
                    f"{counts['federated_AWS']} workload identity binding(s) map an AWS identity; "
                    f"{aws_roles} AWS IAM role record(s) are imported in the workspace."
                    + (
                        f" {other} federated principal(s) from non-AWS pools (for example "
                        "GitHub) are not modelled as path entries; GCP-ORG-FEDERATION reports "
                        "them for manual validation."
                        if other
                        else ""
                    ),
                )
            )
    if "AWS" not in providers:
        result["AWS"].append(reason("AWS", 0, "No AWS evidence is part of this run."))
    else:
        for kind, text in (
            (
                "AP-04",
                "internet-exposed instance with a sensitive port (R1-EC2-SG-SENSITIVE-"
                "INGRESS FAIL) correlated with its IMDS setting",
            ),
            (
                "AP-05",
                "S3 account or bucket public-access evaluation (R1-S3-ACCOUNT-BPA, "
                "R1-S3-BUCKET-PUBLIC-ACCESS)",
            ),
            ("AP-06", "IAM PassRole escalation candidate from the IAM engine"),
        ):
            result["AWS"].append(reason(kind, formed[kind], f"One record per {text}."))
    return result


def display_limits(store, run_id: str, project: str, cross_total: int, projection: dict) -> list:
    """Truncation records for the cross-path and GCP investigation display limits."""
    from offline_analyzer.attack_paths.gcp import INVESTIGATION_RULES
    from offline_analyzer.provenance.truncation import record as truncated_view

    truncation: list[dict] = []
    if cross_total > CROSS_LIMIT:
        truncation.append(
            truncated_view(
                "Cross-project attack-path display limit",
                "run",
                CROSS_LIMIT,
                cross_total,
                "further cross-project and cross-cloud paths are not listed; narrow the scope",
                provider="GCP",
            )
        )
    if projection["truncated"]:
        eligible = sum(
            c.provider == "GCP"
            and c.rule_id in INVESTIGATION_RULES
            and (not project or c.project_id == project)
            for c in store.candidates(run_id)
        )
        truncation.append(
            truncated_view(
                "GCP investigation display limit",
                project or "run",
                len(projection["items"]),
                eligible,
                "further GCP candidate investigations are not listed; narrow the project scope",
                provider="GCP",
            )
        )
    return truncation


def view_limits(store, run_id: str) -> list[dict]:
    """Display-limit records for a whole run (Excel gaps sheet); IAM budgets come from the
    workbook's own IAM analysis."""
    from offline_analyzer.attack_paths.cross import cross_paths
    from offline_analyzer.attack_paths.gcp import investigations

    return display_limits(
        store,
        run_id,
        "",
        len(cross_paths(store, run_id, limit=None)),
        investigations(store, run_id, "", INVESTIGATION_LIMIT),
    )


def attack_paths(store, run_id: str, project: str = "") -> dict:
    from offline_analyzer.attack_paths.cross import cross_paths
    from offline_analyzer.attack_paths.gcp import investigations

    # Build every cross path, display the budget, and count what is not displayed.
    cross_all = cross_paths(store, run_id, limit=None)
    cross = [p for p in cross_all[:CROSS_LIMIT] if not project or p["project_id"] == project]
    projection = investigations(store, run_id, project, INVESTIGATION_LIMIT)
    truncation = display_limits(store, run_id, project, len(cross_all), projection)
    items = (
        gcp_paths(store, run_id, project, projection=projection)
        + ([] if project else aws_paths(store, run_id, truncation))
        + cross
    )
    candidates = {c.finding_id: c for c in store.candidates(run_id)}
    for path in items:
        linked = [candidates[f] for f in path.get("finding_ids", []) if f in candidates]
        path["stride"] = sorted(
            {
                category.strip()
                for f in linked
                for category in (f.stride_category or "").split("/")
                if category.strip()
            }
        )
        spec = BY_PATH.get(path.get("attack_path"))
        path["stride_scenarios"] = list(spec.threats) if spec else []
        path["stride_mapping_basis"] = (
            "Existing linked finding/control metadata; proposed mapping only, "
            "not verified exploitation."
            if linked
            else "UNMAPPED: no linked finding category"
        )
        if not linked and path.get("provider") == "AWS" and path.get("hop_stride"):
            # No rule finding links this AWS path (for example a broad iam:PassRole principal
            # that no rule flags): the hop edge types carry the proposed mapping.
            path["stride"] = list(path["hop_stride"])
            path["stride_mapping_basis"] = (
                "Hop edge types (model.EDGE_STRIDE); no linked finding, so exclusion works "
                "through path review only. Proposed mapping, not verified exploitation."
            )
    order = {FEASIBLE: 0, INSUFFICIENT: 1, BLOCKED: 2}
    items.sort(key=lambda p: order.get(p["feasibility"], 3))
    from offline_analyzer.attack_paths.review import attach
    from offline_analyzer.findings.exclusions import REASONS, excluded

    # A path that relies on an excluded finding (any reason) is flagged in the GUI, left out of
    # report sections and of path counts; a false-positive dependency is also named as such.
    hidden = excluded(store, run_id)
    fp = {f for f, entry in hidden.items() if entry.reason == "FALSE_POSITIVE"}
    for path in items:
        dependent = sorted(set(path.get("finding_ids") or []) & set(hidden))
        if dependent:
            path["excluded_dependency"] = {
                "flag": "depends on an excluded finding",
                "finding_ids": dependent,
                "reasons": sorted(
                    {REASONS.get(hidden[f].reason or "", "Excluded") for f in dependent}
                ),
            }
        linked = sorted(set(path.get("finding_ids") or []) & fp)
        if linked:
            path["false_positive_dependency"] = {
                "flag": "depends on a false-positive finding",
                "finding_ids": linked,
            }
    attach(store, run_id, items)
    return {
        "items": items,
        "feasible": sum(p["feasibility"] == FEASIBLE for p in items),
        # Every dropped record is named with shown/total counts; never "not truncated"
        # while a budget limited the list (IAM investigation budgets included).
        "truncated": bool(truncation),
        **({"truncation": truncation} if truncation else {}),
        "coverage": path_coverage(store, run_id, items),
    }
