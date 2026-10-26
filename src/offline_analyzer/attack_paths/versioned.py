"""Independent path-only recalculation from stored evidence. No rule-engine invocation."""

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from offline_analyzer.attack_paths.gcp_engine import evaluate
from offline_analyzer.contracts.gcp_attack_path import DiscoveryLimits
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import resolve_under
from offline_analyzer.reporting.gcp_attack_path_register import write_register
from offline_analyzer.storage.store import Store


def directory(workspace: Path, run: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", run):
        raise InputError("INVALID_RUN_ID")
    return resolve_under(workspace, "attack-path-evaluations/" + run)


def history(workspace: Path, run: str) -> list[dict]:
    root = directory(workspace, run)
    records = []
    if root.is_dir():
        for path in root.glob("*/comparison.json"):
            if path.is_symlink() or path.stat().st_size > 16 * 1024 * 1024:
                raise InputError("INVALID_PATH_EVALUATION_ARTIFACT")
            value = json.loads(path.read_text())
            if value.get("evaluation_id") != path.parent.name or not re.fullmatch(
                r"[0-9a-f]{32}", path.parent.name
            ):
                raise InputError("INVALID_PATH_EVALUATION_ARTIFACT")
            records.append(value)
    return sorted(records, key=lambda r: r["created_at"], reverse=True)


def latest(workspace: Path, run: str) -> dict:
    records = history(workspace, run)
    paths = []
    if records:
        result = (
            directory(workspace, run)
            / records[0]["evaluation_id"]
            / "attack-path-evaluation-v2.json"
        )
        if result.stat().st_size > 64 * 1024 * 1024:
            raise InputError("PATH_EVALUATION_BYTE_LIMIT")
        data = result.read_bytes()
        if hashlib.sha256(data).hexdigest() != records[0]["result_sha256"]:
            raise InputError("PATH_EVALUATION_INTEGRITY_FAILURE")
        paths = json.loads(data)["paths"]
    return {
        "run_id": run,
        "latest": records[0] if records else None,
        "paths": paths,
        "versions": [
            {k: r[k] for k in ("evaluation_id", "created_at", "engine_version", "new_path_count")}
            for r in records
        ],
    }


def recalculate(workspace: Path, run: str, *, limits: DiscoveryLimits | None = None) -> dict:
    from offline_analyzer.attack_paths.feasibility import attack_paths
    from offline_analyzer.evidence.composition import description
    from offline_analyzer.findings.finalisation import frozen
    from offline_analyzer.rules.engine import verify_raw

    # Importing verify_raw does not execute rules. No assess/import/snapshot call is made.
    with Store(workspace, read_only=True) as store:
        store.require_run(run)
        if not any(s.get("format") == "gcp-json-v1" for s in store.source_data(run)):
            raise InputError("NORMALIZED_GCP_EVIDENCE_REQUIRED")
        verify_raw(store, run)
        versions = history(workspace, run)
        prior_kind = "VERSIONED_PATH_EVALUATION"
        prior_v2 = bool(versions)
        comparison_run = run
        if versions:
            prior = latest(workspace, run)["paths"]
        else:
            # A supplementary version compares against the actual previous analysis,
            # rather than a legacy projection already computed with the new evidence.
            comparison_run = description(store, run).get("base_run", run)
            store.require_run(comparison_run)
            if comparison_run != run and history(workspace, comparison_run):
                prior = latest(workspace, comparison_run)["paths"]
                prior_kind, prior_v2 = "BASE_ANALYSIS_PATH_EVALUATION", True
            else:
                edition = frozen(store, comparison_run)
                if edition:
                    prior = edition.get("document", {}).get("paths", [])
                    prior_kind = "FROZEN_ASSESSMENT_PATHS"
                else:
                    prior = attack_paths(store, comparison_run)["items"]
                    prior_kind = "LEGACY_PROJECTION_CAPTURED_BEFORE_RECALCULATION"
                if comparison_run != run:
                    prior_kind = "BASE_ANALYSIS_" + prior_kind
            prior = [p for p in prior if "GCP" in p.get("provider", "GCP")]
        register = evaluate(store, run, limits=limits, legacy_paths=prior if not prior_v2 else None)
        verify_raw(store, run)
    evaluation_id = uuid.uuid4().hex
    output = directory(workspace, run) / evaluation_id
    write_register(register, output, legacy_paths=prior if not prior_v2 else None)
    (output / "prior-paths.json").write_text(json.dumps(prior, indent=2, default=str))
    comparison = []
    old_by_key = {p.get("canonical_key"): p for p in prior if p.get("canonical_key")}
    matched = set()
    for path in register.paths:
        old = old_by_key.get(path.canonical_key)
        candidates = [old] if old else path.legacy_paths
        if candidates:
            for record in candidates:
                previous_id = record.get("path_id")
                state = record.get(
                    "classification",
                    record.get("prior_status", record.get("proof_status", "UNKNOWN")),
                )
                matched.add(previous_id)
                comparison.append(
                    {
                        "old_path_id": previous_id,
                        "old_state": state,
                        "new_path_id": path.path_id,
                        "new_state": path.classification,
                        "change": "UNCHANGED"
                        if old and state == path.classification
                        else "RECOMPUTED_REQUIRES_REVIEW",
                        "reason": (
                            "Recomputed mandatory permission, scope and evidence prerequisites; no "
                            "approval inherited."
                        ),
                    }
                )
        else:
            comparison.append(
                {
                    "old_path_id": "",
                    "old_state": "NOT_MODELLED",
                    "new_path_id": path.path_id,
                    "new_state": path.classification,
                    "change": "NEWLY_DISCOVERED",
                    "reason": "Found from stored normalized resources independently of findings.",
                }
            )
    comparison += [
        {
            "old_path_id": p["path_id"],
            "old_state": p.get("classification", p.get("proof_status", p.get("status", "UNKNOWN"))),
            "new_path_id": "",
            "new_state": "NOT_REPRODUCED",
            "change": "UNMATCHED_REQUIRES_REVIEW",
            "reason": (
                "Old chain has no unambiguous current canonical mechanism match; "
                "retained in prior-paths.json."
            ),
        }
        for p in prior
        if p["path_id"] not in matched
    ]
    metadata = {
        "schema_version": "gcp-path-comparison-1",
        "evaluation_id": evaluation_id,
        "run_id": run,
        "created_at": datetime.now(UTC).isoformat(),
        "engine_version": register.engine_version,
        "prior_kind": prior_kind,
        "comparison_base_run": comparison_run,
        "old_path_count": len(prior),
        "new_path_count": len(register.paths),
        "comparison": comparison,
        "truncated": register.truncated,
        "truncation_reasons": register.truncation_reasons,
        "classification_counts": {
            state: sum(p.classification == state for p in register.paths)
            for state in (
                "SUPPORTED",
                "CONDITIONAL",
                "BLOCKED",
                "INSUFFICIENT_EVIDENCE",
                "UNSUPPORTED",
            )
        },
        "findings_modified": False,
        "analyst_sre_validations_modified": False,
        "security_analysis_rerun": False,
        "evidence_reimported": False,
        "enterprise_rebuilt": False,
        "result_sha256": hashlib.sha256(
            (output / "attack-path-evaluation-v2.json").read_bytes()
        ).hexdigest(),
        "qualification": (
            "Configuration support is not verified exploitation. Prior history and "
            "all unmatched chains remain available; new path review is "
            "independent."
        ),
    }
    temporary = output / "comparison.tmp"
    temporary.write_text(json.dumps(metadata, indent=2))
    temporary.replace(output / "comparison.json")
    return metadata
