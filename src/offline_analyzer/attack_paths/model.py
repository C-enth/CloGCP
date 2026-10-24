"""Direction-justified, STRIDE-mapped hops for every attack-path record.

A hop is one directed edge `source -> target` with an edge type, the reason the
direction is what it is, a STRIDE mapping and the evidence that supports it (rule IDs,
finding IDs, observation IDs and source locators). Its status is:

- PROVEN: the configuration that creates the edge is in collected evidence;
- HYPOTHESIS: plausible, but evidence is missing or UNKNOWN (named in missing_evidence);
- BLOCKED: collected evidence shows the edge does not exist.

Nothing is promoted: a path is PROVEN only when every hop is PROVEN, BLOCKED when any hop
is BLOCKED, otherwise HYPOTHESIS. Attacker-side prerequisites (credential possession,
workload compromise, exploitation) are never configuration and never verified; they are
listed as assumptions, not as edges. No edge is created without a source record.
"""

from offline_analyzer.contracts.attack_path import PathHop

PROVEN, HYPOTHESIS, BLOCKED = "PROVEN", "HYPOTHESIS", "BLOCKED"
# Proposed STRIDE mapping per edge type (documented in docs/RULE_SPECIFICATIONS.md).
EDGE_STRIDE = {
    "network-reachable": ("Tampering", "Information Disclosure", "Denial of Service"),
    "can-invoke-anonymously": ("Spoofing", "Elevation of Privilege"),
    "can-read-anonymously": ("Information Disclosure",),
    "can-impersonate": ("Spoofing", "Elevation of Privilege"),
    "authenticates-as": ("Spoofing",),
    "holds-role": ("Elevation of Privilege",),
    "can-access": ("Elevation of Privilege", "Information Disclosure"),
    "can-call-api": ("Information Disclosure", "Spoofing"),
    "reads-credentials": ("Information Disclosure", "Spoofing"),
    "can-assume": ("Spoofing", "Elevation of Privilege"),
    "federates-as": ("Spoofing", "Elevation of Privilege"),
    "can-escalate": ("Elevation of Privilege",),
    "not-blocked-by": ("Elevation of Privilege",),
    "stores": ("Information Disclosure",),
}
EVIDENCED = {"STRUCTURAL_ONLY", "OBSERVED", "VERIFIED", "DIRECTLY_OBSERVED"}
# Keys this module adds to a path record. They restate the record, so an analyst path
# review fingerprinted before the hop model existed stays valid (see review.fingerprint).
HOP_KEYS = frozenset(
    {
        "entry_point",
        "objective",
        "impact",
        "hops",
        "assumptions",
        "proof_status",
        "missing_evidence_named",
        "hop_stride",
    }
)


def hop(
    index: int,
    source: str,
    target: str,
    edge_type: str,
    justification: str,
    status: str,
    *,
    rule_ids=(),
    finding_ids=(),
    observation_ids=(),
    refs=(),
    missing=(),
) -> dict:
    observation_ids = [o for o in observation_ids if o]
    if status == PROVEN and not (refs or observation_ids):
        status = HYPOTHESIS  # never PROVEN without a source record; a rule ID is not one
        missing = (*missing, "a cited source record (observation or source locator) for this edge")
    if status != PROVEN and not missing and status != BLOCKED:
        missing = ("evidence establishing this edge",)
    return PathHop(
        index=index,
        source=source,
        target=target,
        edge_type=edge_type,
        direction=f"{source} → {target}",
        justification=justification,
        stride=list(EDGE_STRIDE[edge_type]),
        status=status,
        rule_ids=sorted(set(rule_ids)),
        finding_ids=sorted(set(finding_ids)),
        observation_ids=sorted(set(observation_ids)),
        evidence_refs=[dict(r) for r in refs][:20],
        missing_evidence=list(dict.fromkeys(missing)),
    ).model_dump(mode="json")


def summarize(
    path: dict, hops: list[dict], entry: str, objective: str, impact: str, assumptions=()
) -> dict:
    """Attach the hop model to a path record; the existing feasibility is unchanged."""
    if not hops:
        status = HYPOTHESIS
    elif any(h["status"] == BLOCKED for h in hops):
        status = BLOCKED
    elif all(h["status"] == PROVEN for h in hops):
        status = PROVEN
    else:
        status = HYPOTHESIS
    path.update(
        entry_point=entry,
        objective=objective,
        impact=impact,
        hops=hops,
        assumptions=list(dict.fromkeys(assumptions)),
        proof_status=status,
        missing_evidence_named=list(dict.fromkeys(m for h in hops for m in h["missing_evidence"]))
        or ([] if hops else ["no evidence-backed edge could be built for this record"]),
        hop_stride=sorted({s for h in hops for s in h["stride"]}),
    )
    return path


def observation_index(store, run: str, refs: list[dict]) -> dict[tuple, list[str]]:
    """(artifact_id, locator) -> observation IDs, for click-through from an edge."""
    wanted = {(r.get("artifact_id"), r.get("locator")) for r in refs if r.get("artifact_id")}
    if not wanted:
        return {}
    index: dict[tuple, list[str]] = {}
    for artifact, locator, observation in store.rows(
        "SELECT artifact_id,locator,observation_id FROM evidence_refs WHERE run_id=? "
        "AND artifact_id IN (SELECT unnest(?))",
        [run, sorted({a for a, _ in wanted})],
    ):
        if (artifact, locator) in wanted:
            index.setdefault((artifact, locator), []).append(observation)
    return index


def from_transitions(path: dict, index: dict) -> list[dict]:
    """GCP investigation records: source -> destination with relationship and status."""
    hops = []
    for t in path.get("transitions") or []:
        relationship = t.get("relationship", "")
        if t["source"] == "Hypothetical attacker":
            continue  # attacker-side prerequisite: an assumption, not an edge
        refs = t.get("evidence") or []
        observations = [o for r in refs for o in index.get((r["artifact_id"], r["locator"]), [])]
        if relationship.startswith("Observed user-managed key"):
            edge, why = (
                "authenticates-as",
                f"{t['source']} is a user-managed key of {t['destination']}; whoever holds the "
                "key authenticates as that service account, so access flows key → service "
                "account.",
            )
        elif relationship.startswith("Observed service-account privilege binding"):
            edge, why = (
                "holds-role",
                f"{t['source']} is a member of the privileged binding {t['destination']}; the "
                "binding grants its role to the account, so access flows account → binding "
                "scope.",
            )
        elif relationship.startswith("Potential API usage"):
            edge, why = (
                "can-call-api",
                f"The API key {t['source']} can call services within {t['destination']} when "
                "presented, so access flows key holder → API usage scope.",
            )
        else:
            edge, why = (
                "can-access",
                f"The observed binding or credential {t['source']} grants a role on "
                f"{t['destination']}, so access flows grant holder → {t['destination']}; "
                "effective authorization depends on context not fully collected.",
            )
        status = PROVEN if t.get("status") in EVIDENCED and refs else HYPOTHESIS
        hops.append(
            hop(
                len(hops) + 1,
                t["source"],
                t["destination"],
                edge,
                why,
                status,
                finding_ids=path.get("finding_ids", []),
                observation_ids=observations,
                refs=refs,
                missing=[] if status == PROVEN else t.get("missing_evidence") or [],
            )
        )
    return hops


# AWS prerequisite records: ordered hops, each depending on specification prerequisites.
# A hop needs ALL its prerequisites unless marked ANY (alternatives, e.g. AP-06 P1 or P2).
ALL, ANY = "ALL", "ANY"
# Prerequisites without a specification rule, evidenced by a rule that establishes them
# (prerequisites.public_storage_accounts: a bucket-public FAIL verifies P2 and P3).
AWS_EVIDENCE_RULES = {
    "AP-05.P2": ("R1-S3-BUCKET-PUBLIC-ACCESS",),
    "AP-05.P3": ("R1-S3-BUCKET-PUBLIC-ACCESS",),
}
EVIDENCE_KINDS = {"CONFIG", "IAM_ENGINE", "REACHABILITY", "ORG_EVIDENCE"}
AWS_CHAINS = {
    "AP-04": (
        (
            "Internet",
            "{anchor}",
            "network-reachable",
            ("AP-04.P1",),
            "The instance has a public IPv4 address and its security group admits 0.0.0.0/0 "
            "on a sensitive port, so traffic flows internet → instance.",
        ),
        (
            "{anchor}",
            "instance metadata credentials",
            "reads-credentials",
            ("AP-04.P2",),
            "The instance accepts IMDSv1 requests, so code running on (or proxied through) it "
            "reads the instance-role credentials: access flows instance → credentials.",
        ),
        (
            "instance metadata credentials",
            "instance role permissions",
            "can-escalate",
            ("AP-04.P4",),
            "The credentials are those of the instance role; its permissions apply to whoever "
            "presents them, so access flows credentials → role permissions.",
        ),
    ),
    "AP-05": (
        (
            "Internet",
            "{anchor}",
            "can-read-anonymously",
            ("AP-05.P1", "AP-05.P2", "AP-05.P3"),
            "Block Public Access does not prevent it and the bucket policy or ACL grants a "
            "public principal access, so data flows bucket → anonymous reader.",
        ),
        (
            "{anchor}",
            "sensitive data",
            "stores",
            ("AP-05.P4",),
            "Impact depends on what the bucket stores; classification is not evidenced.",
        ),
    ),
    "AP-06": (
        (
            "{anchor}",
            "elevated principal",
            "can-escalate",
            ("AP-06.P1", "AP-06.P2"),
            "The principal holds escalation-capable permissions or is trusted cross-account "
            "without binding conditions, so access flows principal → elevated principal.",
            ANY,
        ),
        (
            "elevated principal",
            "administrative access",
            "not-blocked-by",
            ("AP-06.P4",),
            "No SCP or permission boundary is evidenced to stop the escalation, so the "
            "elevated principal reaches administrative access.",
        ),
    ),
}
AWS_OBJECTIVES = {
    "AP-04": ("instance role permissions", "Use of the instance role's permissions"),
    "AP-05": ("bucket contents", "Disclosure of bucket contents"),
    "AP-06": ("administrative access", "Administrative control of the account"),
}


def aws_hops(record, spec, evidence_of) -> list[dict]:
    """Hops for one AWS prerequisite record.

    `evidence_of(key)` returns (rule_ids, finding_ids, observation_ids, refs): the rules
    behind that prerequisite and the evidence of `record`'s evaluations of it. A hop cites
    the rules of all its prerequisites but only the evidence of those that establish it.
    """
    statuses = record.prerequisites
    kinds = {p.key: p for p in spec.prerequisites} if spec else {}
    hops = []
    for source, target, edge, keys, why, *mode in AWS_CHAINS.get(record.path_id, ()):
        source, target = source.format(anchor=record.anchor), target.format(anchor=record.anchor)
        states = {k: statuses.get(k, "NOT_EVALUATED") for k in keys}
        checkable = [k for k in keys if k in kinds and kinds[k].kind in EVIDENCE_KINDS]
        if (mode or [ALL])[0] == ANY:
            verified = [k for k in checkable if states[k] == "VERIFIED"]
            used = verified[:1] or keys
            if all(s == "NOT_PRESENT" for s in states.values()):
                status = BLOCKED
            else:
                status = PROVEN if verified else HYPOTHESIS
        else:
            used = keys
            attacker = [k for k in keys if k in kinds and k not in checkable]
            if "NOT_PRESENT" in states.values():
                status = BLOCKED
            elif all(s == "VERIFIED" for s in states.values()) and not attacker:
                status = PROVEN
            else:
                status = HYPOTHESIS
        missing = [
            f"{k}: {kinds[k].summary} ({states[k]})"
            for k in keys
            if k in kinds and states[k] not in {"VERIFIED", "NOT_PRESENT"}
        ]
        evidence = [evidence_of(k) for k in used]
        rules = sorted({r for k in keys for r in evidence_of(k)[0]})
        hops.append(
            hop(
                len(hops) + 1,
                source,
                target,
                edge,
                why
                + (
                    " Blocked: "
                    + "; ".join(f"{k} verified absent" for k in keys if states[k] == "NOT_PRESENT")
                    + "."
                    if status == BLOCKED
                    else ""
                ),
                status,
                rule_ids=rules,
                finding_ids=[f for e in evidence for f in e[1]],
                observation_ids=[o for e in evidence for o in e[2]],
                refs=[r for e in evidence for r in e[3]],
                missing=[] if status in {PROVEN, BLOCKED} else missing,
            )
        )
    return hops


def aws_assumptions(spec) -> list[str]:
    """Attacker-side prerequisites of an AWS path: listed, never edges, never verified."""
    return [
        f"{p.key}: {p.summary}"
        for p in (spec.prerequisites if spec else ())
        if p.kind not in EVIDENCE_KINDS and p.kind != "CLASSIFICATION"
    ]
