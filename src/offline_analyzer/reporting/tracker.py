"""Staging rows aligned to the approved tracker's per-account control results sheet.

This is a staging sheet, never the customer tracker. Analyst columns stay empty. Evidence
Ref and Resource ARN / ID carry analyzer evidence for FAIL results (authorized for staging
on 2026-10-10). Every in-scope registry account gets a row per mapped control, so accounts
without evidence appear as Not Assessed rather than disappearing. No row ever states Pass
unless every evaluated rule fully covers the control's criteria (none currently do).
"""

import hashlib
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from offline_analyzer.inventory.accounts import legacy_key_map
from offline_analyzer.rules.engine import ENGINE_VERSION
from offline_analyzer.rules.registry import BY_ID, primary_operations

TRACKER_COLUMNS = (
    "Result ID",
    "Account ID",
    "Control ID",
    "Scanner_Status",
    "Scanner_Severity",
    "Scanner_Source",
    "Scan_Date",
    "Analyst_Status",
    "Analyst_Validated",
    "Finding_ID",
    "Evidence Ref",
    "Resource ARN / ID",
    "Assessed_By",
    "Assessed_Date",
    "Analyst_Notes",
)
REFERENCE_COLUMNS = (
    "Analyzer: AWS account (12-digit)",
    "Analyzer: account key status",
    "Analyzer: finding classes",
    "Analyzer: technical observations",
    "Analyzer: evidence needed",
    "Analyzer: control coverage",
    "Analyzer: rule outcomes",
    "Analyzer: affected resources",
    "Analyzer: candidate finding IDs",
    "Analyzer: evidence artifact IDs",
    "Analyzer: run ID",
)
SEVERITY = {
    "CRITICAL": (4, "Critical"),
    "HIGH": (3, "High"),
    "MEDIUM": (2, "Medium"),
    "LOW": (1, "Low"),
    "INFO": (0, "Info"),
}
TRACKER_KEY = re.compile(r"^(?:ACCT-[0-9]{3,}|[0-9]{12})$")


def load_account_keys(path: Path | None) -> dict[str, str]:
    """R1 compatibility: explicit 12-digit -> tracker key map supplied at export."""
    return legacy_key_map(path) if path else {}


def scanner_status(outcomes: list[str], full_coverage: bool) -> str:
    if "FAIL" in outcomes:
        return "Fail"
    if outcomes and all(o == "NOT_APPLICABLE" for o in outcomes):
        return "Not Applicable"
    if full_coverage and outcomes and all(o in {"PASS", "NOT_APPLICABLE"} for o in outcomes):
        return "Pass"
    return "Not Assessed"


def key_status(account, account_keys, registry) -> str:
    if account in account_keys:
        return "MAPPED"
    if registry and account in registry.accounts:
        return "IN_REGISTRY_NO_TRACKER_KEY"
    return "NOT_IN_REGISTRY_MAPPING_REQUIRED" if registry else "ACCOUNT_KEY_MAPPING_REQUIRED"


def tracker_rows(store, run_id: str, account_keys: dict[str, str], registry=None) -> list[list]:
    grouped = defaultdict(list)
    for result in store.results(run_id):
        if result.methodology_id and result.account_id:
            grouped[(result.account_id, result.methodology_id)].append(result)
    controls = sorted({r.methodology.control_id for r in BY_ID.values() if r.methodology})
    for account in registry.in_scope if registry else ():
        for control in controls:
            grouped.setdefault((account, control), [])
    findings = defaultdict(list)
    from offline_analyzer.findings.exclusions import excluded

    hidden = excluded(store, run_id)
    for finding in store.candidates(run_id):
        if finding.finding_id in hidden:
            continue  # excluded findings are not counted as gaps
        if finding.methodology_id:
            findings[(finding.account_id, finding.methodology_id)].append(finding)
    digests = dict(store.rows("SELECT artifact_id, sha256 FROM artifacts WHERE run_id=?", [run_id]))
    sources = list(store.source_data(run_id))
    rows = []
    for (account, control), results in sorted(grouped.items()):
        rules = sorted({(r.rule_id, r.rule_version) for r in results})
        links = [BY_ID[rule_id].methodology for rule_id, _ in rules] or [
            r.methodology
            for r in BY_ID.values()
            if r.methodology and r.methodology.control_id == control
        ]
        full = bool(rules) and all(link.full_coverage for link in links)
        outcomes = [str(r.outcome) for r in results]
        counts = defaultdict(int)
        for rule_id, outcome in ((r.rule_id, str(r.outcome)) for r in results):
            counts[f"{rule_id} {outcome}"] += 1
        candidates = findings.get((account, control), [])
        failed = [r for r in results if str(r.outcome) == "FAIL"]
        severity = max((SEVERITY[f.suggested_severity] for f in candidates), default=(0, ""))[1]
        operations = set().union(set(), *(primary_operations(BY_ID[r]) for r, _ in rules))
        dates = [
            datetime.fromisoformat(s["collected_at"].replace("Z", "+00:00")).astimezone(UTC)
            for s in sources
            if s["account_id"] == account and s["operation"] in operations
        ]
        evaluated = sorted({c for link in links for c in link.criteria} if rules else ())
        remaining = sorted({c for link in links for c in link.not_evaluated} - set(evaluated))
        key = account_keys.get(account)
        status = scanner_status(outcomes, full)
        evidence = sorted(
            {f"raw/{digests.get(ref.artifact_id, 'unresolved')}.json{ref.locator}"
             for r in failed for ref in r.evidence}
        )  # fmt: skip
        rows.append(
            [
                "OA-" + hashlib.sha256(f"{account}|{control}".encode()).hexdigest()[:16].upper(),
                key or "",
                control,
                status,
                severity if status == "Fail" else "",
                "offline-analyzer engine "
                + ENGINE_VERSION
                + ": "
                + (
                    ", ".join(f"{rule_id}@{version}" for rule_id, version in rules)
                    if rules
                    else "no evidence for this control in the run"
                ),
                max(dates).date().isoformat() if dates else "",
                "",
                "",
                "",
                "; ".join(evidence),
                "; ".join(sorted({r.native_id for r in failed if r.native_id})),
                "",
                "",
                "",
                account,
                key_status(account, account_keys, registry),
                sorted({f.finding_class for f in candidates if f.finding_class}),
                sorted({r.reasoning for r in failed}),
                sorted({e for f in candidates for e in f.missing_evidence}),
                ("FULL" if full else "PARTIAL" if rules else "NOT_ASSESSED")
                + f": evaluated {', '.join(evaluated) or 'none'}; "
                + f"not evaluated {', '.join(remaining)}",
                "; ".join(f"{k}={v}" for k, v in sorted(counts.items())),
                sorted({c.native_id for c in candidates}),
                sorted(c.finding_id for c in candidates),
                sorted({ref.artifact_id for r in results for ref in r.evidence}),
                run_id,
            ]
        )
    return rows
