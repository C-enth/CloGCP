"""Client-grade contextual findings register: one row per finding (or per root-cause group).

Every cell derives from existing data: the report-model finding (after analyst marking,
exclusions and report revisions), the stored candidate and evaluation, the rule templates
(findings/explanations.py, findings/recommendations.py), the collection sources and their
coverage reasons, attack-path hops (proof status from the hop model) and the curated MITRE
mapping (rules/mitre_mapping.py). Nothing is invented: where a fact cannot be established the
cell states exactly what is missing. Unproven attack steps are labelled hypothesis.

The same rows feed the report Excel sheet "Findings Register (Contextual)", the Word findings
section, the API register view and the finding detail view.
"""

from collections import defaultdict

from offline_analyzer.rules.mitre_mapping import mitre

SHEET = "Findings Register (Contextual)"
COLUMNS = (
    "Assessment ID (internal)",
    "Domain",
    "Sub-domain",
    "Asset / context",
    "Gap / observation",
    "Criticality",
    "Source result",
    "Conclusion type",
    "Business impact and example",
    "Recommendation",
    "Observed evidence / excerpt",
    "Expected requirement / baseline",
    "Affected objects / services",
    "Artifact reference",
    "Evidence type",
    "Evidence sufficiency",
    "Evidence not established",
    "Criticality justification",
    "Possible attack example",
    "Attack prerequisites",
    "Related records (thematic)",
    "Attack-path confidence",
    "MITRE technique",
    "MITRE tactic",
    "MITRE mapping rationale",
    "MITRE reference",
    "Evidence limitations / data quality",
)
CONCLUSIONS = {
    "SUPPORTED_SECURITY_GAP": "Supported security gap",
    "POTENTIAL_EXPOSURE": "Potential exposure",
    "BASELINE_DEVIATION": "Baseline deviation",
}
FROZEN = (
    "Not available in this workspace: the frozen GCP edition carries classification fields "
    "only ({source}); see that edition's report."
)
FORMATS = {
    "aws-json-v1": "Native configuration export (AWS collector)",
    "gcp-json-v1": "Native configuration dataset (GCP collector)",
    "prowler-ocsf-5.10": "Scanner output (Prowler OCSF)",
    "prowler-ocsf-5.26.1": "Scanner output (Prowler OCSF)",
}


def _join(items, separator="; ") -> str:
    seen = []
    for item in items:
        if item and item not in seen:
            seen.append(item)
    return separator.join(seen)


class Context:
    """Run-wide lookups, loaded once per register."""

    def __init__(self, store, run: str, data: dict):
        self.candidates = {c.finding_id: c for c in store.candidates(run)}
        wanted = {(c.rule_id, c.resource_id) for c in self.candidates.values()}
        self.results = {
            (r.rule_id, r.resource_id): r
            for r in store.results(run)
            if (r.rule_id, r.resource_id) in wanted
        }
        self.sources = {s["artifact_id"]: s for s in store.source_data(run) if s.get("artifact_id")}
        self.paths = defaultdict(list)
        for path in data.get("paths") or []:
            for fid in {*(path.get("finding_ids") or []), path.get("finding_id")} - {None}:
                self.paths[fid].append(path)
        self.notes = defaultdict(list)
        for note in data.get("coverage_notes") or []:
            self.notes[(note.get("provider"), note.get("scope"))].append(note)
        self.by_resource = defaultdict(list)
        for finding in data.get("findings") or []:
            self.by_resource[(finding["provider"], finding["scope"], finding["resource"])].append(
                finding
            )


def asset(f: dict) -> str:
    kind = "project" if f["provider"] == "GCP" else "account"
    name = f.get("scope_name") or ""
    owner = f"{f['provider']} {kind} {f['scope']}" + (f" ({name})" if name else "")
    return f"{f['resource']} — {owner}, Region {f.get('region') or 'not recorded'}"


def criticality(f: dict, candidate) -> str:
    severity = f["severity"]
    if candidate and candidate.suggested_severity != severity:
        reason = f.get("rationale") or "reason not recorded"
        return f"{severity} (analyst-adjusted from {candidate.suggested_severity}: {reason})"
    return severity


def evidence_cells(f: dict, candidate, ctx: Context) -> dict:
    if f.get("frozen") or candidate is None:
        text = FROZEN.format(source=f.get("source") or "frozen edition")
        return {
            "Artifact reference": f.get("evidence") or text,
            "Evidence type": "Frozen GCP edition (classification fields only)",
            "Evidence sufficiency": text,
        }
    refs, types, coverage = [], [], []
    for ref in candidate.evidence:
        source = ctx.sources.get(ref.artifact_id)
        if source is None:
            refs.append(f"{ref.artifact_id} {ref.locator} (source record not found in this run)")
            coverage.append(("UNKNOWN", "source record not found"))
            continue
        refs.append(
            f"{source.get('operation')} {ref.locator} — artifact "
            f"{(source.get('sha256') or '')[:12]} (collected {source.get('collected_at')})"
        )
        types.append(FORMATS.get(source.get("format"), source.get("format") or "unrecorded"))
        from offline_analyzer.reporting.coverage_reasons import reason_text, source_category

        reason = reason_text(
            source_category(source),
            (source.get("gcp_metadata") or {}).get("completeness_limitations")
            or source.get("limitations"),
        )
        coverage.append((source.get("effective_coverage") or "UNKNOWN", reason))
    states = {c for c, _ in coverage}
    confidence = candidate.evidence_confidence
    if not refs:
        sufficiency = "No evidence reference recorded for this finding."
    elif states == {"COMPLETE"} and confidence == "HIGH":
        sufficiency = (
            f"Sufficient for the evaluated criteria: {len(refs)} source(s) completely "
            "collected; rule confidence HIGH."
        )
    else:
        partial = [
            f"{state}: {reason}" if reason else state
            for state, reason in coverage
            if state != "COMPLETE"
        ]
        sufficiency = _join(
            [
                "Limited" if partial or confidence != "HIGH" else "Sufficient",
                *partial,
                f"rule confidence {confidence}",
                "the conclusion applies to the observed resource only" if partial else "",
            ],
            "; ",
        )
    return {
        "Artifact reference": _join(refs) or "No evidence reference recorded for this finding.",
        "Evidence type": _join(sorted(set(types))) or "Not recorded",
        "Evidence sufficiency": sufficiency,
    }


def attack_cells(f: dict, candidate, ctx: Context) -> dict:
    paths = ctx.paths.get(f["id"], [])
    misuse = f.get("misuse") or ""
    observed = (f.get("observed") or "").strip()
    if not misuse:
        example = (
            FROZEN.format(source=f.get("source") or "frozen edition")
            if f.get("frozen")
            else "No attack example is defined for this rule template."
        )
    else:
        example = f"Hypothesis (not demonstrated): {misuse}" + (
            f" Observed on {f['resource']}: {observed}" if observed else ""
        )
    proven = [p for p in paths if p.get("proof_status") == "PROVEN"]
    if proven:
        example += " " + _join(
            [
                f"Attack path {p.get('path_id', '')[:24]} ({p.get('title', '')}) has every hop "
                "proven from collected evidence; exploitation itself is not demonstrated."
                for p in proven
            ]
        )
    steps = []
    for path in paths:
        for hop in path.get("hops") or []:
            status = hop.get("status") or "UNKNOWN"
            label = "hypothesis" if status != "PROVEN" else "proven from evidence"
            missing = hop.get("missing_evidence") or []
            steps.append(
                f"Hop {hop.get('index')}: {hop.get('source')} → {hop.get('target')} "
                f"({hop.get('edge_type')}; {status}, {label})"
                + (f"; missing: {', '.join(missing)}" if missing else "")
            )
    if not steps:
        follow = list(candidate.validation_requirements) if candidate else []
        steps = [
            "No attack-path record cites this finding"
            + (f"; prerequisites to validate (hypothesis): {_join(follow)}" if follow else "")
        ]
    if paths:
        statuses = sorted({p.get("proof_status") or "UNKNOWN" for p in paths})
        confidence = _join(
            [f"{s} ({sum(p.get('proof_status') == s for p in paths)} path(s))" for s in statuses],
            ", ",
        )
    else:
        confidence = "No attack path cites this finding"
    return {
        "Possible attack example": example,
        "Attack prerequisites": _join(steps),
        "Attack-path confidence": confidence,
        "_paths": [p.get("path_id") for p in paths],
    }


def services(candidate, ctx: Context) -> str:
    """Services named by the evidence operations (ec2, s3api, compute, storage, ...)."""
    if candidate is None:
        return "service as frozen in the GCP edition"
    names = []
    for ref in candidate.evidence:
        operation = (ctx.sources.get(ref.artifact_id) or {}).get("operation") or ""
        if operation.startswith("gcp:"):
            names.append(operation[4:].split(".", 1)[0])
        elif ":" in operation:
            names.append(operation.split(":", 1)[0])
    found = _join(sorted(set(names)), ", ")
    return f"service {found}" if found else "service not recorded in the evidence references"


def finding_row(f: dict, ctx: Context) -> dict:
    """Register cells for one report-model finding."""
    candidate = ctx.candidates.get(f["id"])
    result = ctx.results.get((candidate.rule_id, candidate.resource_id)) if candidate else None
    frozen = f.get("frozen") or candidate is None
    missing_text = FROZEN.format(source=f.get("source") or "frozen edition")
    mapped = mitre(f["rule"], f["resource"])
    attack = attack_cells(f, candidate, ctx)
    related = [
        m["id"]
        for m in ctx.by_resource.get((f["provider"], f["scope"], f["resource"]), [])
        if m["id"] != f["id"]
    ]
    limitations = list(result.limitations) if result else []
    limitations += [
        f"{n['code']}: {n['reason']}" for n in ctx.notes.get((f["provider"], f["scope"]), [])
    ]
    if frozen:
        limitations.append(missing_text)
    impact = f.get("impact") or ""
    business = f.get("business") or ""
    row = {
        "Assessment ID (internal)": f["id"],
        "Domain": f.get("domain") or "Not classified by the rule",
        "Sub-domain": (
            f"{f['control']} {f['checklist_title']}".strip()
            if f.get("checklist_title")
            else f"Not mapped to a checklist control (rule {f['rule']})"
        ),
        "Asset / context": asset(f),
        "Gap / observation": f["title"],
        "Criticality": criticality(f, candidate),
        "Source result": (
            f"FAIL — rule {f['rule']} v{candidate.rule_version}; analyst status {f.get('status')}"
            if candidate
            else f"FAIL — rule {f['rule']} (as frozen); analyst status {f.get('status')}"
        ),
        "Conclusion type": CONCLUSIONS.get(
            candidate.finding_class if candidate else None,
            "Not classified by the rule" if candidate else missing_text,
        ),
        "Business impact and example": _join([impact, business], " ") or missing_text,
        "Recommendation": f.get("recommendation") or missing_text,
        "Observed evidence / excerpt": _join(
            [
                (f.get("observed") or "").strip(),
                (candidate.exposure_status or "") if candidate else "",
            ],
            " ",
        )
        or missing_text,
        "Expected requirement / baseline": f.get("expected") or missing_text,
        "Affected objects / services": f"{f['resource']} ({services(candidate, ctx)}; "
        f"{f['provider']} {f['scope']}, {f.get('region') or 'Region not recorded'})",
        **evidence_cells(f, candidate, ctx),
        "Evidence not established": (
            _join(candidate.missing_evidence)
            or "None: the rule named no missing evidence for this conclusion."
        )
        if candidate
        else missing_text,
        "Criticality justification": _join(
            [f.get("rationale") or "", (candidate.exposure_status or "") if candidate else ""],
            " ",
        )
        or missing_text,
        "Possible attack example": attack["Possible attack example"],
        "Attack prerequisites": attack["Attack prerequisites"],
        "Related records (thematic)": _join(
            [
                f"same resource: {', '.join(related)}" if related else "",
                f"attack paths: {', '.join(attack['_paths'])}" if attack["_paths"] else "",
            ]
        )
        or "No other finding or attack path refers to this resource",
        "Attack-path confidence": attack["Attack-path confidence"],
        "MITRE technique": mapped["technique"],
        "MITRE tactic": mapped["tactic"],
        "MITRE mapping rationale": mapped["rationale"],
        "MITRE reference": mapped["reference"],
        "Evidence limitations / data quality": _join(limitations)
        or "No collection limitation recorded for this evaluation.",
    }
    return row


def group_row(group: dict, ctx: Context) -> dict:
    """One row per root-cause group: the representative's cells, all affected objects."""
    members = group["members"]
    row = finding_row(group["representative"], ctx)
    member_rows = [finding_row(m, ctx) for m in members]
    row["Assessment ID (internal)"] = group["group_id"]
    if len(members) > 1:
        row["Asset / context"] += f" (+{len(members) - 1} more; see Affected objects / services)"
    row["Affected objects / services"] = _join(
        [
            r["Affected objects / services"] + f" [finding {m['id']}]"
            for r, m in zip(member_rows, members, strict=True)
        ]
    )
    for column in (
        "Artifact reference",
        "Evidence not established",
        "Attack prerequisites",
        "Evidence limitations / data quality",
    ):
        row[column] = _join(r[column] for r in member_rows)
    row["Related records (thematic)"] = _join(
        [f"group members: {', '.join(m['id'] for m in members)}", row["Related records (thematic)"]]
    )
    return row


def register(store, run: str, data: dict) -> list[dict]:
    """Rows of the register for a report model (grouped as the report is)."""
    ctx = Context(store, run, data)
    if data.get("grouped") and data.get("groups") is not None:
        rows = [group_row(g, ctx) for g in data["groups"]]
    else:
        rows = [finding_row(f, ctx) for f in data["findings"]]
    members = {g["group_id"]: [m["id"] for m in g["members"]] for g in data.get("groups") or []}
    grouped = data.get("grouped") and data.get("groups") is not None
    for row in rows:
        row["_members"] = members[row[COLUMNS[0]]] if grouped else [row[COLUMNS[0]]]
        row["_severity"] = row["Criticality"].split(" ", 1)[0]
    return rows


def check(data: dict) -> dict:
    """Register rows cover exactly the reported findings; excluded findings are absent."""
    rows = data.get("contextual_register") or []
    covered = [fid for row in rows for fid in row.get("_members", [])]
    reported = [f["id"] for f in data["findings"]]
    excluded = {i for e in data.get("excluded_findings") or [] for i in e.get("finding_ids") or []}
    checks = [
        ("every reported finding has a register row", sorted(covered) == sorted(reported)),
        ("no finding appears twice", len(covered) == len(set(covered))),
        ("excluded findings absent", not excluded & set(covered)),
        ("columns complete", all(list(r)[: len(COLUMNS)] == list(COLUMNS) for r in rows)),
        ("no empty cell", all(str(r[c]).strip() for r in rows for c in COLUMNS)),
    ]
    return {
        "status": "PASS" if all(ok for _, ok in checks) else "FAIL",
        "rows": len(rows),
        "findings": len(reported),
        "checks": [{"check": n, "result": "PASS" if ok else "FAIL"} for n, ok in checks],
    }
