"""GCP frozen-edition feed: export a finalized GCP edition, import it read-only elsewhere.

Export (GCP workspace, read-only): a ZIP `CloSec-GCP-frozen-edition-<id>.zip` whose files under
`GCP-FROZEN-EDITION/` are built only from the finalized edition document (never live or raw
evidence) with whitelisted fields: findings (ID, rule, title, severity, status, group,
resource, project), STRIDE mapping, attack paths with hops and status, coverage and limitation
summary, excluded findings, project list and edition metadata (edition ID, freeze date,
collector versions). `manifest.json` lists every file with its SHA-256; `signature.json` is
an HMAC-SHA256 of the manifest bytes with a per-export key shown once to the operator (stdlib
only; an asymmetric signature would need a new runtime dependency and an ADR).

Import (AWS workspace): bounded read of the ZIP (exact file names only, size caps), manifest
hashes and the HMAC verified with the operator-supplied key, fields validated against the
same whitelist, stored in `gcp_frozen_editions` with the bundle bytes kept under
`frozen-editions/`. An edition is immutable: re-importing different content under the same
edition ID is refused; no decision, exclusion or review API reaches its findings.

Consolidation: an edition is linked to one AWS run without live GCP data (`link`). Reports
and the dashboard of that run then include the frozen GCP data labelled by source and
edition, and `reconcile` blocks export unless AWS live + GCP frozen = consolidated.
"""

import hashlib
import hmac
import json
import re
import secrets
import zipfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.ingestion.json_input import InputError
from offline_analyzer.ingestion.safety import resolve_under

SCHEMA = "closec-gcp-frozen-edition-1"
ROOT = "GCP-FROZEN-EDITION/"
FILES = (
    "edition.json",
    "findings.json",
    "stride.json",
    "attack_paths.json",
    "coverage.json",
    "projects.json",
)
MAX_FILE = 64 * 1024 * 1024
MAX_BUNDLE = 256 * 1024 * 1024
SOURCE = "GCP frozen edition"
FINDING_FIELDS = (
    "id",
    "rule",
    "title",
    "severity",
    "status",
    "stage",
    "group_id",
    "group_key",
    "resource",
    "scope",
    "scope_name",
    "region",
    "domain",
    "stride",
    "control",
    "provider",
    "methodology_paths",
)
PATH_FIELDS = (
    "path_id",
    "provider",
    "project_id",
    "finding_id",
    "finding_ids",
    "title",
    "severity",
    "domain",
    "status",
    "proof_status",
    "feasibility",
    "feasibility_reason",
    "entry_point",
    "objective",
    "impact",
    "stride",
    "hop_stride",
    "assumptions",
    "missing_evidence_named",
    "qualification",
    "analyst_review",
    "hops",
)
HOP_FIELDS = (
    "schema_version",
    "index",
    "source",
    "target",
    "edge_type",
    "direction",
    "status",
    "stride",
    "rule_ids",
    "finding_ids",
    "missing_evidence",
    "justification",
)
NOTE_FIELDS = ("provider", "scope", "name", "code", "reason", "datasets")
UNKNOWN_FIELDS = ("provider", "scope", "name", "rule", "insufficient", "manual")
PATH_COVERAGE_FIELDS = ("kind", "formed", "reason", "provider")
EXCLUDED_FIELDS = ("rule", "reason", "detail", "count", "finding_ids")
SCOPE_FIELDS = ("provider", "scope", "name", "severity", "outcomes", "gaps", "sources")
EDITION_ID = re.compile(r"^gcp-edition-[0-9a-f]{64}$")
SCALAR = (str, int, float, bool, type(None))


def _pick(item: dict, fields) -> dict:
    return {k: item.get(k) for k in fields if k in item}


def _plain(value):
    """JSON-safe value: Counters become sorted dicts."""
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _encode(value) -> bytes:
    return (json.dumps(_plain(value), indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode()


def collector_versions(store, run: str) -> list[str]:
    from offline_analyzer.reporting.aws_collection import members

    versions = set()
    for member in members(store, run):
        for (version,) in store.rows(
            "SELECT DISTINCT json_extract_string(data,'$.collector_version') FROM sources "
            "WHERE run_id=? AND json_extract_string(data,'$.format')='gcp-json-v1'",
            [member],
        ):
            if version:
                versions.add(version)
    return sorted(versions)


def contents(store, run: str) -> tuple[str, dict[str, bytes]]:
    """Bundle files of the finalized GCP edition of `run` (whitelisted fields only)."""
    from offline_analyzer.findings.finalisation import frozen

    edition = frozen(store, run)
    if not edition:
        raise InputError("GCP_EDITION_NOT_FINALIZED")
    document = edition["document"]
    findings = document.get("findings") or []
    if not findings or any(f.get("provider") != "GCP" for f in findings):
        raise InputError("GCP_EDITION_MUST_BE_GCP_ONLY")
    identifier = "gcp-edition-" + stable_id("e", [run, edition["created_at"]]).split("-", 1)[1]
    paths = [
        {**_pick(p, PATH_FIELDS), "hops": [_pick(h, HOP_FIELDS) for h in p.get("hops") or []]}
        for p in document.get("paths") or []
        if p.get("provider") == "GCP"
    ]
    stride = {
        "findings": dict(Counter(f.get("stride") or "Unmapped" for f in findings)),
        "paths": dict(Counter(c for p in paths for c in p.get("stride") or [])),
        "hops": dict(Counter(c for p in paths for h in p["hops"] for c in h.get("stride") or [])),
    }
    projects = sorted(
        {(f.get("scope") or "", f.get("scope_name") or "") for f in findings}
        | {(s.get("scope") or "", s.get("name") or "") for s in document.get("scopes") or []}
    )
    files = {
        "edition.json": {
            "schema": SCHEMA,
            "edition_id": identifier,
            "source_run_id": run,
            "frozen_at": edition["created_at"],
            "frozen_by": edition.get("analyst") or "",
            "provider": "GCP",
            "include": document.get("include") or "",
            "collector_versions": collector_versions(store, run),
            "counts": {
                "findings": len(findings),
                "paths": len(paths),
                "excluded_findings": sum(
                    len(e.get("finding_ids") or []) for e in document.get("excluded_findings") or []
                ),
                "severity": dict(Counter(f.get("severity") for f in findings)),
            },
        },
        "findings.json": [_pick(f, FINDING_FIELDS) for f in findings],
        "stride.json": stride,
        "attack_paths.json": paths,
        "coverage.json": {
            "coverage_notes": [_pick(n, NOTE_FIELDS) for n in document.get("coverage_notes") or []],
            "unknown_areas": [
                _pick(u, UNKNOWN_FIELDS) for u in document.get("unknown_areas") or []
            ],
            "path_coverage": [
                _pick(c, PATH_COVERAGE_FIELDS) for c in document.get("path_coverage") or []
            ],
            "excluded_findings": [
                _pick(e, EXCLUDED_FIELDS) for e in document.get("excluded_findings") or []
            ],
            "scopes": [_pick(s, SCOPE_FIELDS) for s in document.get("scopes") or []],
            "custom_limitations": document.get("custom_limitations") or "",
        },
        "projects.json": [{"project_id": p, "name": n} for p, n in projects if p],
    }
    return identifier, {name: _encode(value) for name, value in files.items()}


def manifest(identifier: str, files: dict[str, bytes]) -> bytes:
    return _encode(
        {
            "schema": SCHEMA,
            "edition_id": identifier,
            "files": [
                {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                for name, data in sorted(files.items())
            ],
        }
    )


def sign(key: str, data: bytes) -> str:
    return hmac.new(bytes.fromhex(key), data, hashlib.sha256).hexdigest()


def export_edition(store, run: str, output: Path) -> dict:
    """Write the bundle into folder `output`; returns the file, its SHA-256 and the key."""
    identifier, files = contents(store, run)
    body = manifest(identifier, files)
    key = secrets.token_hex(32)
    signature = _encode(
        {"algorithm": "HMAC-SHA256", "signed": "manifest.json", "value": sign(key, body)}
    )
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"CloSec-GCP-frozen-edition-{identifier[-16:]}.zip"
    if target.exists():
        raise InputError("GCP_EDITION_EXPORT_EXISTS")
    fixed = (2026, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(target, "x", zipfile.ZIP_DEFLATED) as archive:
        for name, data in [
            *sorted(files.items()),
            ("manifest.json", body),
            ("signature.json", signature),
        ]:
            info = zipfile.ZipInfo(ROOT + name, fixed)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    return {
        "edition_id": identifier,
        "file": str(target),
        "sha256": digest,
        "key": key,
        "findings": len(json.loads(files["findings.json"])),
    }


def _read(bundle: Path) -> dict[str, bytes]:
    if bundle.is_symlink() or not bundle.is_file() or bundle.stat().st_size > MAX_BUNDLE:
        raise InputError("GCP_EDITION_BUNDLE_UNREADABLE")
    wanted = {ROOT + n for n in (*FILES, "manifest.json", "signature.json")}
    try:
        with zipfile.ZipFile(bundle) as archive:
            names = {i.filename for i in archive.infolist()}
            if names != wanted:
                raise InputError("GCP_EDITION_BUNDLE_LAYOUT")
            data = {}
            for info in archive.infolist():
                if info.file_size > MAX_FILE or info.flag_bits & 1:
                    raise InputError("GCP_EDITION_BUNDLE_LAYOUT")
                data[info.filename[len(ROOT) :]] = archive.read(info)
    except zipfile.BadZipFile as exc:
        raise InputError("GCP_EDITION_BUNDLE_UNREADABLE") from exc
    return data


def _only(items, fields, code="GCP_EDITION_FIELDS_INVALID"):
    if not isinstance(items, list):
        raise InputError(code)
    for item in items:
        if not isinstance(item, dict) or not item.keys() <= set(fields):
            raise InputError(code)


def verify(bundle: Path, key: str) -> dict:
    """Verified, validated bundle content; raises InputError on any deviation."""
    if not re.fullmatch(r"[0-9a-f]{64}", key or ""):
        raise InputError("GCP_EDITION_KEY_INVALID")
    data = _read(bundle)
    body = data["manifest.json"]
    signature = json.loads(data["signature.json"])
    if not hmac.compare_digest(str(signature.get("value", "")), sign(key, body)):
        raise InputError("GCP_EDITION_SIGNATURE_INVALID")
    listed = json.loads(body)
    if listed.get("schema") != SCHEMA or not EDITION_ID.fullmatch(str(listed.get("edition_id"))):
        raise InputError("GCP_EDITION_MANIFEST_INVALID")
    entries = {e["path"]: e for e in listed.get("files", [])}
    if set(entries) != set(FILES):
        raise InputError("GCP_EDITION_MANIFEST_INVALID")
    for name in FILES:
        if hashlib.sha256(data[name]).hexdigest() != entries[name]["sha256"]:
            raise InputError("GCP_EDITION_HASH_MISMATCH")
    parsed = {name[:-5]: json.loads(data[name]) for name in FILES}
    edition = parsed["edition"]
    if edition.get("schema") != SCHEMA or edition.get("edition_id") != listed["edition_id"]:
        raise InputError("GCP_EDITION_MANIFEST_INVALID")
    _only(parsed["findings"], FINDING_FIELDS)
    if any(f.get("provider") != "GCP" for f in parsed["findings"]):
        raise InputError("GCP_EDITION_FIELDS_INVALID")
    _only(parsed["attack_paths"], PATH_FIELDS)
    for path in parsed["attack_paths"]:
        _only(path.get("hops") or [], HOP_FIELDS)
    coverage = parsed["coverage"]
    for key_name, fields in (
        ("coverage_notes", NOTE_FIELDS),
        ("unknown_areas", UNKNOWN_FIELDS),
        ("path_coverage", PATH_COVERAGE_FIELDS),
        ("excluded_findings", EXCLUDED_FIELDS),
        ("scopes", SCOPE_FIELDS),
    ):
        _only(coverage.get(key_name) or [], fields)
    _only(parsed["projects"], ("project_id", "name"))
    excluded = {
        i for e in coverage.get("excluded_findings") or [] for i in e.get("finding_ids") or []
    }
    if excluded & {f["id"] for f in parsed["findings"]}:
        raise InputError("GCP_EDITION_EXCLUDED_FINDING_PRESENT")
    if edition.get("counts", {}).get("findings") != len(parsed["findings"]):
        raise InputError("GCP_EDITION_COUNTS_INVALID")
    parsed["bundle_sha256"] = hashlib.sha256(bundle.read_bytes()).hexdigest()
    return parsed


def import_edition(store, bundle: Path, key: str) -> dict:
    """Store a verified edition read-only; idempotent for identical bytes."""
    parsed = verify(Path(bundle), key)
    edition = parsed["edition"]
    identifier = edition["edition_id"]
    row = store.db.execute(
        "SELECT bundle_sha256 FROM gcp_frozen_editions WHERE edition_id=?", [identifier]
    ).fetchone()
    if row:
        if row[0] != parsed["bundle_sha256"]:
            raise InputError("GCP_EDITION_IMMUTABLE_CONFLICT")
        return summary(store, identifier)
    folder = resolve_under(store.workspace, "frozen-editions")
    folder.mkdir(mode=0o700, exist_ok=True)
    resolve_under(folder, f"{identifier}.zip").write_bytes(Path(bundle).read_bytes())
    record = {k: v for k, v in parsed.items() if k != "bundle_sha256"}
    record["links"] = []
    with store.transaction():
        store.db.execute(
            "INSERT INTO gcp_frozen_editions VALUES (?,?,?,?)",
            [
                identifier,
                datetime.now(UTC).isoformat(),
                parsed["bundle_sha256"],
                json.dumps(record),
            ],
        )
    return summary(store, identifier)


def load(store, identifier: str) -> dict:
    row = store.db.execute(
        "SELECT imported_at, bundle_sha256, data FROM gcp_frozen_editions WHERE edition_id=?",
        [identifier],
    ).fetchone()
    if not row:
        raise InputError("GCP_EDITION_NOT_FOUND")
    record = json.loads(row[2])
    stored = resolve_under(store.workspace, f"frozen-editions/{identifier}.zip")
    if not stored.is_file() or hashlib.sha256(stored.read_bytes()).hexdigest() != row[1]:
        raise InputError("GCP_EDITION_STORED_BUNDLE_CHANGED")
    record["imported_at"], record["bundle_sha256"] = row[0], row[1]
    return record


def summary(store, identifier: str) -> dict:
    record = load(store, identifier)
    edition = record["edition"]
    return {
        "edition_id": identifier,
        "source": SOURCE,
        "frozen_at": edition["frozen_at"],
        "frozen_by": edition["frozen_by"],
        "imported_at": record["imported_at"],
        "bundle_sha256": record["bundle_sha256"],
        "collector_versions": edition["collector_versions"],
        "counts": edition["counts"],
        "projects": len(record["projects"]),
        "linked_runs": record.get("links", []),
        "read_only": True,
    }


def editions(store) -> list[dict]:
    return [
        summary(store, identifier)
        for (identifier,) in store.rows(
            "SELECT edition_id FROM gcp_frozen_editions ORDER BY imported_at"
        )
    ]


def link(store, run: str, identifier: str) -> dict:
    """Use the edition as the GCP part of the consolidated view of AWS run `run`."""
    store.require_run(run)
    live_gcp = store.db.execute(
        "SELECT 1 FROM sources WHERE run_id=? AND json_extract_string(data,'$.format')="
        "'gcp-json-v1' LIMIT 1",
        [run],
    ).fetchone()
    if live_gcp:
        raise InputError("RUN_HAS_LIVE_GCP_DATA")
    if linked(store, run):
        raise InputError("RUN_ALREADY_HAS_GCP_EDITION")
    record = load(store, identifier)
    links = sorted({*record.get("links", []), run})
    stored = {k: v for k, v in record.items() if k not in {"imported_at", "bundle_sha256"}}
    stored["links"] = links
    store.db.execute(
        "UPDATE gcp_frozen_editions SET data=? WHERE edition_id=?", [json.dumps(stored), identifier]
    )
    return summary(store, identifier)


def linked(store, run: str) -> dict | None:
    """The edition linked to `run`, verified against its stored bundle; None when unlinked."""
    if not store.db.execute(
        "SELECT 1 FROM information_schema.tables WHERE table_name='gcp_frozen_editions'"
    ).fetchone():
        return None
    for identifier, data in store.rows("SELECT edition_id, data FROM gcp_frozen_editions"):
        if run in json.loads(data).get("links", []):
            return load(store, identifier)
    return None


def label(record: dict) -> str:
    edition = record["edition"]
    return f"{SOURCE} {edition['edition_id'][-16:]} (frozen {edition['frozen_at'][:10]})"


NARRATIVE = (
    "Frozen GCP edition: detail, evidence and remediation text are in the GCP edition report "
    "({label}); this consolidated view carries classification fields only."
)


def report_findings(record: dict) -> list[dict]:
    """Edition findings in the report-model finding shape, labelled by source and edition."""
    text = NARRATIVE.format(label=label(record))
    rows = []
    for finding in record["findings"]:
        rows.append(
            {
                **{k: "" for k in ("observed", "expected", "impact", "why", "misuse")},
                "recommendation": text,
                "remediation": text,
                "business": text,
                "evidence": f"{label(record)}; bundle SHA-256 {record['bundle_sha256']}",
                "validation_procedure": "",
                "rationale": "As frozen in the GCP edition.",
                "confidence": "",
                "framework": finding.get("control") or "",
                "missing": "",
                "analyst": record["edition"].get("frozen_by") or "",
                "checklist_domain": "",
                "checklist_title": "",
                "evaluated_paths": "",
                **finding,
                "source": label(record),
                "frozen": True,
            }
        )
    return rows


def scoped(record: dict, scope: str) -> dict:
    """The edition restricted to one GCP project (report scope filter)."""
    if not scope:
        return record
    result = dict(record)
    result["findings"] = [f for f in record["findings"] if f.get("scope") == scope]
    result["attack_paths"] = [p for p in record["attack_paths"] if p.get("project_id") == scope]
    coverage = dict(record["coverage"])
    for key in ("coverage_notes", "unknown_areas", "scopes"):
        coverage[key] = [n for n in coverage[key] if n.get("scope") == scope]
    coverage["excluded_findings"] = []
    result["coverage"] = coverage
    result["projects"] = [p for p in record["projects"] if p["project_id"] == scope]
    edition = dict(record["edition"])
    edition["counts"] = {**edition["counts"], "excluded_findings": 0}
    result["edition"] = edition
    return result


def merge_report(data: dict, record: dict, provider_filter: str, scope: str = "") -> dict:
    """Add the frozen GCP edition to an AWS report model (AWS live + GCP frozen)."""
    if scope and scope not in {p["project_id"] for p in record["projects"]}:
        provider_filter = "AWS"  # an AWS account scope: no GCP data belongs to it
    record = scoped(record, scope)
    if provider_filter == "AWS":
        data["reconciliation"] = reconcile(data, None)
        return data
    live = {
        "findings": len(data["findings"]),
        "severity": dict(Counter(f["severity"] for f in data["findings"])),
    }
    source = label(record)
    findings = report_findings(record)
    for finding in data["findings"]:
        finding.setdefault("source", "AWS live assessment")
    data["findings"] = data["findings"] + findings
    paths = []
    for path in record["attack_paths"]:
        paths.append(
            {
                "evidence": [],
                "missing_evidence": path.get("missing_evidence_named") or [],
                "transitions": [],
                "confidence": "",
                "analyst_status": "FROZEN",
                "binding_role": None,
                "stride_scenarios": [],
                "stride_mapping_basis": "As frozen in the GCP edition.",
                "diagram": "",
                **path,
                "source": source,
                "frozen": True,
            }
        )
    data["paths"] = list(data.get("paths") or []) + paths
    coverage = record["coverage"]
    data["coverage_notes"] = (
        list(data.get("coverage_notes") or [])
        + [{**n, "reason": f"{n.get('reason', '')} [{source}]"} for n in coverage["coverage_notes"]]
        + [
            {
                "provider": "GCP",
                "scope": "Cross-cloud",
                "name": "",
                "code": "GCP_FROZEN_EDITION_NOT_CORRELATED",
                "reason": f"GCP results come from {source}. A frozen edition carries findings and "
                "paths, not evidence, so cross-cloud relationships with the live AWS data are not "
                "correlated.",
                "datasets": 0,
            }
        ]
    )
    data["unknown_areas"] = list(data.get("unknown_areas") or []) + coverage["unknown_areas"]
    data["path_coverage"] = list(data.get("path_coverage") or []) + coverage["path_coverage"]
    data["excluded_findings"] = list(data.get("excluded_findings") or []) + [
        {**e, "detail": f"{e.get('detail', '')} [{source}]"} for e in coverage["excluded_findings"]
    ]
    data["excluded"] = (
        int(data.get("excluded") or 0) + record["edition"]["counts"]["excluded_findings"]
    )
    data["scopes"] = list(data.get("scopes") or []) + coverage["scopes"]
    if provider_filter == "GCP":
        data["provider_scope"] = "GCP"
    elif data.get("provider_scope") in ("AWS", None, ""):
        data["provider_scope"] = "GCP + AWS"
    data["sources"] = [
        {"source": "AWS live assessment", "run_id": data.get("run_id")},
        {
            "source": SOURCE,
            "edition_id": record["edition"]["edition_id"],
            "frozen_at": record["edition"]["frozen_at"],
            "collector_versions": record["edition"]["collector_versions"],
            "bundle_sha256": record["bundle_sha256"],
        },
    ]
    data["reconciliation"] = reconcile(data, record, live)
    return data


def reconcile(data: dict, record: dict | None, live: dict | None = None) -> dict:
    """AWS live + GCP frozen = consolidated (findings and severity); excluded GCP findings
    absent; frozen findings identical to the edition. Status FAIL blocks report export."""
    findings = data["findings"]
    frozen = [f for f in findings if f.get("frozen")]
    aws = [f for f in findings if not f.get("frozen")]
    checks = []
    if record is None:
        checks.append(("no frozen edition merged", not frozen))
        return {"status": "PASS" if all(ok for _, ok in checks) else "FAIL", "checks": checks}
    expected = record["findings"]
    excluded = {
        i for e in record["coverage"]["excluded_findings"] for i in e.get("finding_ids") or []
    }
    consolidated = Counter(f["severity"] for f in findings)
    combined = Counter(live["severity"]) + Counter(f.get("severity") for f in expected)
    checks += [
        ("AWS live findings unchanged", len(aws) == live["findings"]),
        ("GCP frozen findings = edition", len(frozen) == len(expected)),
        ("consolidated = AWS live + GCP frozen", len(findings) == live["findings"] + len(expected)),
        ("severity totals reconcile", consolidated == combined),
        ("excluded GCP findings stay excluded", not excluded & {f["id"] for f in findings}),
        (
            "frozen findings identical to the edition",
            [_pick(f, FINDING_FIELDS) for f in frozen] == expected,
        ),
    ]
    return {
        "status": "PASS" if all(ok for _, ok in checks) else "FAIL",
        "aws_live": live["findings"],
        "gcp_frozen": len(expected),
        "consolidated": len(findings),
        "checks": [{"check": name, "result": "PASS" if ok else "FAIL"} for name, ok in checks],
    }


def require_reconciled(data: dict) -> None:
    result = data.get("reconciliation")
    if result and result["status"] != "PASS":
        raise InputError("CONSOLIDATED_RECONCILIATION_FAILED")
    register = data.get("register_reconciliation")
    if register and register["status"] != "PASS":
        raise InputError("FINDINGS_REGISTER_RECONCILIATION_FAILED")


def merge_dashboard(view: dict, record: dict, provider: str) -> dict:
    """Frozen GCP summary in the dashboard: provider summary, STRIDE, paths and posture."""
    if provider not in ("Consolidated", "GCP"):
        return view
    edition = record["edition"]
    severity = Counter(f.get("severity") for f in record["findings"])
    view.setdefault("providers", {})["GCP"] = {
        "source": label(record),
        "frozen": True,
        "read_only": True,
        "candidate_findings": len(record["findings"]),
        "confirmed_findings": len(record["findings"]),
        "excluded_findings": edition["counts"]["excluded_findings"],
        "severity": dict(severity),
        "imported_scopes": [p["project_id"] for p in record["projects"]],
        "imported_scope_count": len(record["projects"]),
        "assessed_scope_count": len(record["projects"]),
        "evaluations": 0,
        "collector_versions": edition["collector_versions"],
    }
    paths = Counter(c for p in record["attack_paths"] for c in p.get("stride") or [])
    finding_stride = Counter(f.get("stride") for f in record["findings"])
    for row in view.get("stride") or []:
        row["frozen_gcp_paths"] = paths.get(row["category"], 0)
        row["frozen_gcp_findings"] = finding_stride.get(row["category"], 0)
        row["paths"] += row["frozen_gcp_paths"]
    total = Counter()
    for name, summary_row in view["providers"].items():
        if provider == "Consolidated" or name == "GCP":
            total.update(summary_row.get("severity") or {})
    rating = view["posture"]["rating"]
    if total["CRITICAL"]:
        rating = "Critical findings observed"
    elif total["HIGH"] and rating != "Critical findings observed":
        rating = "High findings observed"
    elif sum(total.values()) and rating in (
        "Insufficient evidence",
        "No gaps in evaluated criteria",
    ):
        rating = "Findings require review"
    view["posture"]["rating"] = rating
    view["posture"]["basis"] += f" GCP results from {label(record)}."
    view["frozen_editions"] = [
        {
            "edition_id": edition["edition_id"],
            "source": label(record),
            "frozen_at": edition["frozen_at"],
            "collector_versions": edition["collector_versions"],
            "findings": len(record["findings"]),
            "paths": len(record["attack_paths"]),
            "bundle_sha256": record["bundle_sha256"],
        }
    ]
    aws = view["providers"].get("AWS", {}).get("candidate_findings", 0)
    view["reconciliation"] = {
        "aws_live": aws if provider == "Consolidated" else 0,
        "gcp_frozen": len(record["findings"]),
        "consolidated": (aws if provider == "Consolidated" else 0) + len(record["findings"]),
    }
    view["cross_cloud"] = {
        "status": "NOT_CORRELATED",
        "reason": "A frozen GCP edition carries findings and paths, not evidence; cross-cloud "
        "relationships with live AWS data are not correlated.",
    }
    return view


def frozen_paths(record: dict) -> list[dict]:
    """Attack-path view items of the edition (read-only, labelled)."""
    return [
        {
            **path,
            "evidence": [],
            "missing_evidence": path.get("missing_evidence_named") or [],
            "source": label(record),
            "frozen": True,
            "read_only": True,
        }
        for path in record["attack_paths"]
    ]
