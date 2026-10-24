"""Transport-independent GUI projections over existing analyzer services."""

import json
import re
import secrets
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.findings.generate import validation_status
from offline_analyzer.iam.analysis import IamAnalysis
from offline_analyzer.ingestion.json_input import SECRET_KEYS, SECRET_VALUE, InputError
from offline_analyzer.ingestion.safety import resolve_under, sha256_file
from offline_analyzer.inventory.accounts import workspace_registry
from offline_analyzer.reporting.excel import export_excel
from offline_analyzer.reporting.metrics import assessment_metrics
from offline_analyzer.storage.store import Store

Json = dict[str, Any]


def redact(value: Any, depth: int = 0) -> Any:
    """Bounded normalized inspection; never serve raw source documents or policy contents."""
    if depth > 10:
        return "[depth limited]"
    if isinstance(value, dict):
        result = {}
        for k, v in list(value.items())[:100]:
            key = re.sub(r"[^a-z]", "", k.lower())
            if key in SECRET_KEYS or any(
                x in key
                for x in (
                    "document",
                    "content",
                    "externalid",
                    "email",
                    "tag",
                    "condition",
                    "description",
                )
            ):
                result[k] = "[redacted]"
            else:
                result[k] = redact(v, depth + 1)
        return result
    if isinstance(value, list | tuple):
        return [redact(v, depth + 1) for v in value[:100]]
    if isinstance(value, str):
        return SECRET_VALUE.sub("[redacted]", value[:4000])
    return value


def page(
    items: list,
    offset: int,
    limit: int,
    q: str = "",
    account: str = "",
    field: str = "",
    value: str = "",
) -> Json:
    filtered = []
    for item in items:
        text = json.dumps(item, default=str)
        if q and q.casefold() not in text.casefold():
            continue
        if account and account not in text:
            continue
        if field and value and str(item.get(field, "")) != value:
            continue
        filtered.append(item)
    return {
        "items": filtered[offset : offset + limit],
        "total": len(filtered),
        "offset": offset,
        "limit": limit,
    }


class Views:
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.iam_cache: dict[str, Json] = {}
        self.gcp_iam_cache: dict[str, Json] = {}

    def runs(self, store: Store) -> list[Json]:
        # Human-readable run identity: provider, exact account/project scopes and counts.
        scopes: dict[str, dict[str, set[str]]] = {}
        for run, fmt, account, project in store.rows(
            "SELECT run_id, json_extract_string(data,'$.format'), "
            "json_extract_string(data,'$.account_id'), json_extract_string(data,'$.project_id') "
            "FROM sources"
        ):
            entry = scopes.setdefault(run, {"providers": set(), "aws": set(), "gcp": set()})
            entry["providers"].add("GCP" if fmt == "gcp-json-v1" else "AWS")
            if project:
                entry["gcp"].add(project)
            elif account:
                entry["aws"].add(account)
        from offline_analyzer.findings.exclusions import excluded_ids

        # Excluded findings (any reason) are not counted as findings of a run.
        counts = {
            run: (evaluations, findings - len(excluded_ids(store, run)))
            for run, evaluations, findings in store.rows(
                "SELECT r.run_id, (SELECT count(*) FROM evaluations e WHERE e.run_id=r.run_id), "
                "(SELECT count(*) FROM findings f WHERE f.run_id=r.run_id) FROM runs r"
            )
        }
        from offline_analyzer.enterprise.snapshot import superseded_imports

        superseded = superseded_imports(store)
        result = []
        for r, t, a in store.rows(
            "SELECT r.run_id,r.created_at,a.assessed_at FROM runs r LEFT JOIN assessments a "
            "ON r.run_id=a.run_id ORDER BY r.created_at DESC LIMIT 200"
        ):
            entry = scopes.get(r, {"providers": set(), "aws": set(), "gcp": set()})
            providers = sorted(entry["providers"])
            evaluations, findings = counts.get(r, (0, 0))
            result.append(
                {
                    "run_id": r,
                    "created_at": t,
                    "assessed": bool(a),
                    "assessed_at": str(a) if a else None,
                    "provider": providers[0]
                    if len(providers) == 1
                    else "Consolidated"
                    if providers
                    else "UNRESOLVED",
                    "aws_accounts": sorted(entry["aws"]),
                    "gcp_projects": sorted(entry["gcp"]),
                    "evaluation_count": evaluations,
                    "finding_count": findings,
                    "enterprise": bool(
                        store.db.execute(
                            "SELECT 1 FROM enterprise_snapshots WHERE run_id=?", [r]
                        ).fetchone()
                    ),
                    "historical": bool(
                        store.db.execute(
                            "SELECT 1 FROM scope_retired_runs WHERE run_id=?", [r]
                        ).fetchone()
                    ),
                    # A newer import exists for every scope: not a snapshot member by default.
                    "superseded_by": superseded.get(r, []),
                }
            )
        return result

    EMPTY_FILTERS = {
        key: ""
        for key in (
            "provider",
            "project_id",
            "project_number",
            "organization_id",
            "folder_id",
            "region",
            "service",
            "finding_class",
            "security_domain",
            "evidence_confidence",
            "validation",
            "resource",
            "dataset",
            "collection_domain",
            "collection_status",
            "support",
        )
    } | {"priority": False}

    def reconciliation(self, store: Store, run: str) -> Json:
        from offline_analyzer.reporting.reconciliation import reconciliation

        api_total = self.records(
            store,
            run,
            "findings",
            "",
            "",
            "",
            0,
            1,
            {**self.EMPTY_FILTERS, "false_positive": "show"},
        )
        return reconciliation(store, self.workspace, run, api_total["total"])

    def imported_uploads(self, store: Store) -> set[str]:
        return {u for (u,) in store.rows("SELECT upload_id FROM scope_uploads")}

    def collection(self, store: Store, run: str) -> Json:
        from offline_analyzer.reporting.collection import collection_readiness

        return collection_readiness(store, run)

    def evidence_requests_csv(self, store: Store, run: str) -> str:
        import csv
        import io

        from offline_analyzer.ingestion.safety import excel_literal

        output = io.StringIO()
        writer = csv.writer(output)
        columns = ["account_id", "region", "operation", "state", "reason", "request"]
        writer.writerow(columns)
        for item in self.collection(store, run)["evidence_requests"]:
            writer.writerow([excel_literal(str(item[c] or "")) for c in columns])
        return output.getvalue()

    def iam(self, store: Store, run: str) -> Json:
        store.require_run(run)
        if run not in self.iam_cache:
            analysis = IamAnalysis(
                store, run, list(store.source_data(run)), workspace_registry(store.workspace)
            )
            investigations = [asdict(i) for i in analysis.transitions() + analysis.passrole()]
            roles = []
            for role in analysis.inventory.roles.values():
                privilege, notes = analysis.privilege(role)
                roles.append(
                    {
                        "role": role.arn,
                        "account": role.account,
                        "privilege": privilege,
                        "attached_policies": role.attached,
                        "inline_names": role.inline_names,
                        "boundary": role.boundary_arn,
                        "profiles": role.instance_profiles,
                        "missing": analysis.privilege_missing(role),
                        "probes": notes,
                    }
                )
            self.iam_cache[run] = {
                "investigations": investigations,
                "relationships": [asdict(i) for i in analysis.relationships()],
                "roles": roles,
                "gaps": [
                    {"category": g[0], "scope": g[1], "missing": g[2]}
                    for g in analysis.evidence_gaps()
                ],
                "policies": [
                    {
                        "arn": p.arn,
                        "default_version": p.default_version,
                        "document_resolved": p.document is not None,
                        "gap": p.reason,
                    }
                    for p in analysis.inventory.policies.values()
                ],
                "organization": {
                    "organization_observed": analysis.org.evidence,
                    "root_count": len(analysis.org.roots),
                    "policy_count": len(analysis.org.policies),
                    "truncation": analysis.truncated,
                },
            }
            # Bound cache to the active run; run data can be large.
            for other in list(self.iam_cache):
                if other != run:
                    del self.iam_cache[other]
        return self.iam_cache[run]

    def dashboard(self, store: Store, run: str) -> Json:
        metric = assessment_metrics(store, run)
        severity, domains, reviews = Counter(), Counter(), Counter()
        latest = store.latest_decisions(run)
        for finding in store.candidates(run):
            severity[finding.suggested_severity] += 1
            domains[finding.security_domain] += 1
            reviews[validation_status(store, finding, latest)[0]] += 1
        iam = self.iam(store, run)
        metric.update(
            severity=dict(severity),
            domains=dict(domains),
            reviews=dict(reviews),
            iam_investigations=len(iam["investigations"]),
            iam_states=dict(Counter(i["state"] for i in iam["investigations"])),
            coverage=dict(Counter(s["effective_coverage"] for s in store.source_data(run))),
        )
        return metric

    def finding_facets(self, store: Store, run: str, provider: str = "") -> Json:
        """Filter values present in the run, with counts, and severity/status per account."""
        from offline_analyzer.findings.sre import latest_sre, review_state
        from offline_analyzer.ingestion.labels import scope_names
        from offline_analyzer.inventory.cloud import domain

        store.require_run(run)
        names = scope_names(store)
        latest = store.latest_decisions(run)
        sre = latest_sre(store, run)
        facets: dict[str, Counter] = {
            key: Counter()
            for key in (
                "severity",
                "finding_class",
                "domain",
                "control",
                "validation",
                "region",
                "stage",
            )
        }
        accounts: dict[tuple[str, str], Json] = {}
        for source in store.source_data(run):
            p = "GCP" if source["format"] == "gcp-json-v1" else "AWS"
            identity = source.get("project_id") or source.get("account_id")
            if identity and (not provider or p == provider):
                accounts[(p, identity)] = {
                    "provider": p,
                    "scope": identity,
                    "name": names.get((p, identity), ""),
                    "total": 0,
                    "severity": Counter(),
                    "validation": Counter(),
                    "stage": Counter(),
                }
        from offline_analyzer.findings.exclusions import excluded

        # Excluded findings (every reason) stay out of severity totals; false positives are
        # also counted separately for the "N excluded as false positive" line.
        hidden = excluded(store, run)
        fp_count = 0
        for finding in store.candidates(run):
            finding_provider = finding.provider or "AWS"
            if provider and finding_provider != provider:
                continue
            if finding.finding_id in hidden:
                fp_count += hidden[finding.finding_id].reason == "FALSE_POSITIVE"
                continue
            status, finding_stage = review_state(store, finding, latest, sre)
            facets["stage"][finding_stage] += 1
            facets["severity"][finding.suggested_severity] += 1
            facets["finding_class"][finding.finding_class] += 1
            facets["domain"][domain(finding.security_domain)] += 1
            facets["control"][finding.methodology_id or ""] += 1
            facets["validation"][status] += 1
            facets["region"][finding.region] += 1
            scope = finding.project_id or finding.account_id or ""
            entry = accounts.setdefault(
                (finding_provider, scope),
                {
                    "provider": finding_provider,
                    "scope": scope,
                    "name": names.get((finding_provider, scope), ""),
                    "total": 0,
                    "severity": Counter(),
                    "validation": Counter(),
                    "stage": Counter(),
                },
            )
            entry["total"] += 1
            entry["severity"][finding.suggested_severity] += 1
            entry["validation"][status] += 1
            entry["stage"][finding_stage] += 1
        return {
            **{
                key: [{"value": v, "count": n} for v, n in sorted(counts.items()) if v]
                for key, counts in facets.items()
            },
            "false_positive_excluded": fp_count,
            "accounts": sorted(
                (
                    {
                        **a,
                        "severity": dict(a["severity"]),
                        "validation": dict(a["validation"]),
                        "stage": dict(a["stage"]),
                    }
                    for a in accounts.values()
                ),
                key=lambda a: (a["provider"], a["name"] or a["scope"]),
            ),
        }

    def records(
        self,
        store: Store,
        run: str,
        kind: str,
        q: str,
        account: str,
        value: str,
        offset: int,
        limit: int,
        finding_filters: dict | None = None,
    ) -> Json:
        store.require_run(run)
        from offline_analyzer.api.gcp_views import iam_projection, scoped
        from offline_analyzer.normalization.gcp import PROFILES

        filters = finding_filters or {}
        if kind == "security_investigations" and filters.get("provider") == "GCP":
            from offline_analyzer.attack_paths.gcp import investigations

            paths = investigations(store, run, filters.get("project_id", ""))
            items = [
                {
                    **item,
                    "investigation_id": item["path_id"],
                    "security_domain": item["domain"],
                    "technical_hypothesis": item["title"],
                    "run_id": run,
                    "basis": "PERSISTED_CANDIDATE_PROJECTION",
                }
                for item in paths["items"]
            ]
            result = page(scoped(items, filters), offset, limit, q)
            result["truncated"] = paths["truncated"]
            return result
        if kind in {"investigations", "relationships", "roles", "policies", "gaps"}:
            items = [] if filters.get("provider") == "GCP" else self.iam(store, run)[kind]
            if filters.get("provider") != "AWS":
                if run not in self.gcp_iam_cache:
                    self.gcp_iam_cache = {run: iam_projection(store, run)}
                items = [*items, *self.gcp_iam_cache[run][kind]]
            return page(
                scoped(items, filters),
                offset,
                limit,
                q,
                account,
                "state" if kind == "investigations" else "",
                value,
            )
        if kind == "accounts":
            sources_by_account: dict[str, list] = {}
            for source in store.source_data(run):
                if source["account_id"]:
                    sources_by_account.setdefault(source["account_id"], []).append(source)
            resource_counts = dict(
                store.rows(
                    "SELECT account_id,count(DISTINCT resource_id) FROM observations "
                    "WHERE run_id=? AND account_id IS NOT NULL GROUP BY account_id",
                    [run],
                )
            )
            finding_counts = dict(
                store.rows(
                    "SELECT account_id,count(*) FROM finding_resources WHERE run_id=? "
                    "AND account_id IS NOT NULL GROUP BY account_id",
                    [run],
                )
            )
            registry = workspace_registry(store.workspace)
            ids = set(sources_by_account) | set(resource_counts)
            ids |= set(registry.in_scope if registry else ())
            items = []
            for a in sorted(ids):
                sources = sources_by_account.get(a, [])
                items.append(
                    {
                        "provider": "AWS",
                        "account": a,
                        "resources": resource_counts.get(a, 0),
                        "findings": finding_counts.get(a, 0),
                        "sources": len(sources),
                        "coverage": sorted({s["effective_coverage"] for s in sources})
                        or ["NOT_COLLECTED"],
                        "registry": registry.accounts[a].tracker_key
                        if registry and a in registry.accounts
                        else "Not mapped",
                    }
                )
            projects = sorted(
                {s.get("project_id") for s in store.source_data(run) if s.get("project_id")}
            )
            from offline_analyzer.findings.exclusions import excluded_ids

            hidden_ids = excluded_ids(store, run)
            for project in projects:
                sources = [s for s in store.source_data(run) if s.get("project_id") == project]
                resource_count = store.db.execute(
                    "SELECT count(DISTINCT resource_id) FROM observations WHERE run_id=? "
                    "AND kind <> 'GCP::Unsupported' "
                    "AND json_extract_string(data,'$.project_id')=?",
                    [run, project],
                ).fetchone()[0]
                finding_count = store.db.execute(
                    "SELECT count(*) FROM findings WHERE run_id=? "
                    "AND json_extract_string(data,'$.project_id')=? "
                    "AND finding_id NOT IN (SELECT unnest(?))",
                    [run, project, hidden_ids],
                ).fetchone()[0]
                items.append(
                    {
                        "provider": "GCP",
                        "project_id": project,
                        "account": project,
                        "resources": resource_count,
                        "findings": finding_count,
                        "sources": len(sources),
                        "coverage": sorted({s["effective_coverage"] for s in sources}),
                        "registry": "Project evidence scope",
                    }
                )
            return page(scoped(items, filters), offset, limit, q, account)
        if kind == "coverage":
            items = [
                {
                    k: s.get(k)
                    for k in (
                        "account_id",
                        "region",
                        "operation",
                        "coverage",
                        "effective_coverage",
                        "errors",
                        "record_count",
                        "limitations",
                        "artifact_id",
                        "collected_at",
                        "collector_version",
                    )
                }
                for s in store.source_data(run)
            ]
            for item, source in zip(items, store.source_data(run), strict=True):
                metadata = source.get("gcp_metadata") or {}
                item.update(
                    provider="GCP" if source["format"] == "gcp-json-v1" else "AWS",
                    project_id=source.get("project_id"),
                    domain=metadata.get("domain"),
                    dataset=metadata.get("dataset"),
                    collection_status=metadata.get("status"),
                    parser_supported=bool(metadata.get("dataset_contract"))
                    or source["operation"] in PROFILES
                    if source["format"] == "gcp-json-v1"
                    else True,
                    analysis_support=metadata.get("dataset_contract", {}).get(
                        "analysis_support", "NOT_EVALUATED"
                    ),
                )
                item.update(
                    collection_domain=item["domain"],
                    support="SUPPORTED" if item["parser_supported"] else "UNSUPPORTED",
                )
            return page(
                scoped(items, filters), offset, limit, q, account, "effective_coverage", value
            )
        original_kind = kind
        if kind in {"iam_findings", "network_findings"}:
            kind = "findings"
        table, id_field = {
            "findings": ("findings", "finding_id"),
            "evaluations": ("evaluations", "evaluation_id"),
            "evidence": ("observations", "observation_id"),
            "resources": ("observations", "observation_id"),
            "network": ("observations", "observation_id"),
            "security_investigations": ("security_investigations", "investigation_id"),
        }[kind]
        where, params = ["run_id=?"], [run]
        filters = finding_filters or {}
        for key in (
            "provider",
            "project_id",
            "project_number",
            "organization_id",
            "folder_id",
            "region",
        ):
            if filters.get(key):
                where.append(
                    f"coalesce(json_extract_string(data,'$.{key}'),'AWS')=?"
                    if key == "provider"
                    else f"json_extract_string(data,'$.{key}')=?"
                )
                params.append(filters[key])
        from offline_analyzer.inventory.cloud import domain
        from offline_analyzer.rules.registry import PROVIDER_RULES

        if filters.get("security_domain"):
            rules = [
                r for r in PROVIDER_RULES if domain(r.domain) == domain(filters["security_domain"])
            ]
            if kind in {"findings", "evaluations"}:
                where.append("json_extract_string(data,'$.rule_id') IN (SELECT unnest(?))")
                params.append([r.rule_id for r in rules])
            elif kind in {"resources", "evidence"}:
                from offline_analyzer.reporting.cloud import COLLECTOR_DOMAINS

                collection_domains = [
                    key
                    for key, name in COLLECTOR_DOMAINS.items()
                    if name == domain(filters["security_domain"])
                ]
                where.append(
                    "(kind IN (SELECT unnest(?)) OR EXISTS (SELECT 1 FROM evidence_refs er "
                    "JOIN sources ds ON ds.run_id=er.run_id "
                    "AND json_extract_string(ds.data,'$.artifact_id')=er.artifact_id "
                    "WHERE er.run_id=observations.run_id "
                    "AND er.observation_id=observations.observation_id "
                    "AND observations.kind <> 'GCP::SCCFinding' "
                    "AND json_extract_string(ds.data,'$.gcp_metadata.domain') "
                    "IN (SELECT unnest(?))))"
                )
                params.extend([sorted({r.resource_type for r in rules}), collection_domains])
        if filters.get("service"):
            service = filters["service"]
            if kind in {"findings", "evaluations"}:
                ids = [
                    r.rule_id
                    for r in PROVIDER_RULES
                    if r.operation.split(":")[-1].split(".")[0] == service
                    or r.operation.split(":")[0] == service
                ]
                where.append("json_extract_string(data,'$.rule_id') IN (SELECT unnest(?))")
                params.append(ids)
            else:
                where.append(
                    "(json_extract_string(data,'$.operation') LIKE ? OR "
                    "json_extract_string(data,'$.operation') LIKE ?)"
                )
                params.extend([service + ":%", "gcp:" + service + ".%"])
        if kind in {"evidence", "resources", "network"}:
            metadata_filters = {
                "dataset": "dataset",
                "collection_domain": "domain",
                "collection_status": "status",
            }
            for key, metadata_key in metadata_filters.items():
                if filters.get(key):
                    where.append(
                        "EXISTS (SELECT 1 FROM evidence_refs er JOIN sources ds "
                        "ON ds.run_id=er.run_id "
                        "AND json_extract_string(ds.data,'$.artifact_id')=er.artifact_id "
                        "WHERE er.run_id=observations.run_id "
                        "AND er.observation_id=observations.observation_id "
                        f"AND json_extract_string(ds.data,'$.gcp_metadata.{metadata_key}')=?)"
                    )
                    params.append(filters[key])
            if filters.get("support") in {"SUPPORTED", "UNSUPPORTED"}:
                where.append(
                    "kind <> 'GCP::Unsupported'"
                    if filters["support"] == "SUPPORTED"
                    else "kind = 'GCP::Unsupported'"
                )
        if kind == "findings":
            if any(len(str(v)) > 200 for v in filters.values()):
                raise InputError("INVALID_FINDING_FILTER")
            for key in ("finding_class", "evidence_confidence", "methodology_id"):
                if filters.get(key):
                    where.append(f"json_extract_string(data,'$.{key}')=?")
                    params.append(filters[key])
            if filters.get("resource"):
                where.append(
                    "(json_extract_string(data,'$.resource_id')=? OR "
                    "json_extract_string(data,'$.native_id')=?)"
                )
                params.extend([filters["resource"], filters["resource"]])
            if filters.get("validation") or filters.get("stage"):
                # Stored candidate JSON is the canonical fingerprint input. One bounded
                # set query uses the same latest ordering and stale-review gates as review.
                from offline_analyzer.findings.sre import REVIEWED_FINDINGS_SQL

                table = REVIEWED_FINDINGS_SQL
                for key, column in (("validation", "review_state"), ("stage", "stage")):
                    if filters.get(key):
                        where.append(f"{column}=?")
                        params.append(filters[key])
        fp_ids: dict = {}
        fp_clause: tuple[int, int] | None = None
        if kind == "findings":
            from offline_analyzer.findings.exclusions import false_positives

            # False-positive dispositions: hidden by default, shown with an FP tag on request.
            fp_ids = false_positives(store, run)
            mode = filters.get("false_positive") or "hide"
            if mode not in {"hide", "show", "only"}:
                raise InputError("INVALID_FINDING_FILTER")
            if fp_ids and mode != "show":
                where.append(
                    ("finding_id IN" if mode == "only" else "finding_id NOT IN")
                    + " (SELECT unnest(?))"
                )
                params.append(sorted(fp_ids))
                fp_clause = (len(where) - 1, len(params) - 1)
        if q:
            where.append("lower(data) LIKE ?")
            params.append("%" + q.lower() + "%")
        if account:
            where.append("json_extract_string(data,'$.account_id')=?")
            params.append(account)
        field = "suggested_severity" if kind == "findings" else "outcome"
        if value and kind in {"findings", "evaluations"}:
            where.append(f"json_extract_string(data,'$.{field}')=?")
            params.append(value)
        if kind == "network":
            where.append(
                "kind IN ('AWS::EC2::Instance','AWS::EC2::SecurityGroup',"
                "'AWS::EC2::NetworkInterface','AWS::EC2::RouteTable','AWS::RDS::DBInstance',"
                "'GCP::Network','GCP::Subnet','GCP::Firewall','GCP::FirewallPolicy','GCP::Route',"
                "'GCP::Address','GCP::Router','GCP::ForwardingRule','GCP::VPNTunnel','GCP::DNSZone',"
                "'GCP::DNSPolicy','GCP::SecurityPolicy','GCP::SSLPolicy','GCP::BackendService',"
                "'GCP::URLMap','GCP::InterconnectAttachment')"
            )
        if original_kind == "iam_findings":
            where.append(
                "(json_extract_string(data,'$.rule_id') LIKE 'R1-IAM-%' "
                "OR json_extract_string(data,'$.rule_id') LIKE 'GCP-IAM-%' "
                "OR json_extract_string(data,'$.rule_id') LIKE 'GCP-KEY-%' "
                "OR (json_extract_string(data,'$.rule_id') LIKE 'GCP-ORG-%' "
                "AND json_extract_string(data,'$.rule_id') NOT LIKE 'GCP-ORG-PUBLIC-%'))"
            )
        if original_kind == "network_findings":
            where.append(
                "(json_extract_string(data,'$.rule_id') LIKE '%RDS%' OR "
                "json_extract_string(data,'$.rule_id') LIKE '%SG-SENSITIVE%' OR "
                "json_extract_string(data,'$.security_domain')='Network and Exposure')"
            )
        if kind == "resources":
            where.append("resource_id IS NOT NULL")
            where.append("kind <> 'GCP::Unsupported'")
        predicate = " AND ".join(where)
        fp_count = 0
        if fp_ids:
            base_where = [w for i, w in enumerate(where) if not fp_clause or i != fp_clause[0]]
            base_params = [p for i, p in enumerate(params) if not fp_clause or i != fp_clause[1]]
            fp_count = store.db.execute(
                f"SELECT count(*) FROM {table} WHERE {' AND '.join(base_where)} "
                "AND finding_id IN (SELECT unnest(?))",
                [*base_params, sorted(fp_ids)],
            ).fetchone()[0]
        if kind == "resources":
            total = store.db.execute(
                f"SELECT count(DISTINCT resource_id) FROM {table} WHERE {predicate}", params
            ).fetchone()[0]
            rows = store.rows(
                "SELECT arg_min(data,(CASE WHEN kind IN ('GCP::Asset','GCP::AssetIAMSearchResult',"
                "'GCP::AssetResourceSnapshot','GCP::AssetIAMSnapshot') THEN 1 ELSE 0 END,"
                f"observation_id)) FROM {table} WHERE {predicate} "
                "GROUP BY resource_id ORDER BY resource_id LIMIT ? OFFSET ?",
                [*params, limit, offset],
            )
        else:
            total = store.db.execute(
                f"SELECT count(*) FROM {table} WHERE {predicate}", params
            ).fetchone()[0]
            ordering = id_field
            if kind == "findings" and filters.get("priority"):
                ordering = (
                    "CASE json_extract_string(data,'$.suggested_severity') "
                    "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,"
                    + id_field
                )
            rows = store.rows(
                f"SELECT data FROM {table} WHERE {predicate} ORDER BY {ordering} LIMIT ? OFFSET ?",
                [*params, limit, offset],
            )
        raw_items = [json.loads(data) for (data,) in rows]
        if kind == "findings":
            from offline_analyzer.api.finding_context import page_context
            from offline_analyzer.findings.explanations import explain
            from offline_analyzer.findings.generate import fingerprint
            from offline_analyzer.findings.sre import STAGES, latest_sre, stage

            evaluation_map, timestamp_map, linked_map = page_context(store, run, raw_items)
            decisions = store.latest_decisions(run)
            sre_map = latest_sre(store, run)
        items = []
        evaluation_excluded = None
        source_by_artifact = (
            {s["artifact_id"]: s for s in store.source_data(run)}
            if kind in {"evidence", "resources", "network"}
            else {}
        )
        for item in raw_items:
            if kind == "security_investigations":
                finding = store.db.execute(
                    "SELECT data FROM findings WHERE run_id=? AND finding_id=?",
                    [run, item["finding_id"]],
                ).fetchone()
                if finding:
                    from offline_analyzer.contracts.r0 import Candidate

                    item["analyst_status"] = validation_status(
                        store, Candidate.model_validate_json(finding[0])
                    )[0]
            if kind == "findings":
                from offline_analyzer.contracts.r0 import Candidate

                candidate = Candidate.model_validate(item)
                status, decision = validation_status(store, candidate, decisions)
                sre = sre_map.get(item["finding_id"])
                finding_stage = stage(status, sre, fingerprint(candidate))
                supporting = evaluation_map.get((item["resource_id"], item["rule_id"]), {}).get(
                    "supporting_observations", []
                )
                timestamps = [
                    timestamp_map[oid] for oid in supporting[:100] if oid in timestamp_map
                ]
                linked = linked_map.get(item["finding_id"], [])
                item.update(
                    relationships=[e["relationship_id"] for e in linked],
                    affected_accounts=sorted(
                        {
                            item.get("project_id") or item["account_id"],
                            *[
                                a
                                for e in linked
                                for a in (e["source_account"], e["destination_account"])
                                if a
                            ],
                        }
                    ),
                    source_accounts=sorted(
                        {e["source_account"] for e in linked if e["source_account"]}
                    ),
                    destination_accounts=sorted(
                        {e["destination_account"] for e in linked if e["destination_account"]}
                    ),
                    cross_account_classification="CROSS_ACCOUNT_DEPENDENCY"
                    if any(
                        e["source_account"]
                        and e["destination_account"]
                        and e["source_account"] != e["destination_account"]
                        for e in linked
                    )
                    else "ACCOUNT_LOCAL",
                    supporting_observations=supporting,
                    source_timestamps=timestamps,
                    explanation=explain(item),
                    stage=finding_stage,
                    stage_label=STAGES[finding_stage],
                    sre=sre.model_dump(mode="json") if sre else None,
                    analyst_status=status,
                    decision=decision.model_dump(mode="json") if decision else None,
                    false_positive={
                        "reason": fp_ids[item["finding_id"]].note,
                        "analyst": fp_ids[item["finding_id"]].analyst,
                        "recorded_at": fp_ids[item["finding_id"]].recorded_at.isoformat(),
                        "previous_state": fp_ids[item["finding_id"]].previous_state,
                        "carried_from": fp_ids[item["finding_id"]].carried_from,
                    }
                    if item["finding_id"] in fp_ids
                    else None,
                )
            elif kind in {"evidence", "resources", "network"}:
                metadata = (
                    source_by_artifact.get(item.get("evidence", {}).get("artifact_id"), {}).get(
                        "gcp_metadata"
                    )
                    or {}
                )
                item = {
                    k: item.get(k)
                    for k in (
                        "observation_id",
                        "provider",
                        "project_id",
                        "project_number",
                        "organization_id",
                        "folder_id",
                        "account_id",
                        "region",
                        "resource_id",
                        "native_id",
                        "resource_type",
                        "operation",
                        "source_tool",
                        "source_version",
                        "collected_at",
                        "unresolved",
                        "source_status",
                        "source_details",
                        "evidence",
                    )
                }
                item.update(
                    domain=metadata.get("domain"),
                    dataset=metadata.get("dataset"),
                    collection_status=metadata.get("status"),
                    support_status="UNSUPPORTED"
                    if item["resource_type"] == "GCP::Unsupported"
                    else "SUPPORTED",
                    analysis_support=metadata.get("dataset_contract", {}).get(
                        "analysis_support", "NOT_EVALUATED"
                    ),
                )
            item["provider"] = item.get("provider") or "AWS"
            if kind in {"findings", "evaluations"}:
                from offline_analyzer.methodology.cloud_checklist import describe

                # Checklist classification: domain, area and control title for the ID.
                item.update(describe(item.get("methodology_id")))
            if kind == "evaluations":
                if evaluation_excluded is None:
                    from offline_analyzer.findings.exclusions import evaluation_exclusions

                    evaluation_excluded = evaluation_exclusions(store, run)
                item["excluded"] = evaluation_excluded.get(
                    stable_id("finding", [item.get("rule_id"), item.get("resource_id") or ""]), ""
                )
            items.append(item)
        result = {"items": items, "total": total, "offset": offset, "limit": limit}
        if kind == "findings":
            result["false_positive_excluded"] = fp_count
        return result

    def evidence_detail(self, store: Store, run: str, oid: str) -> Json:
        obs = next(store.observations(run, observation_id=oid), None)
        if not obs:
            raise InputError("OBSERVATION_NOT_FOUND")
        refs = store.refs(run, [oid])
        integrity = []
        for ref in refs:
            row = store.db.execute(
                "SELECT sha256 FROM artifacts WHERE run_id=? AND artifact_id=?",
                [run, ref.artifact_id],
            ).fetchone()
            intact = bool(
                row and sha256_file(resolve_under(store.workspace, f"raw/{row[0]}.json")) == row[0]
            )
            integrity.append(
                {
                    "artifact_id": ref.artifact_id,
                    "locator": ref.locator,
                    "sha256": row[0] if row else None,
                    "integrity": intact,
                }
            )
        # Match provenance inside DuckDB and bound results before decoding. The previous
        # projection deserialized every evaluation/finding for each evidence click.
        provenance_match = (
            "EXISTS (SELECT 1 FROM json_each(data,'$.evidence') e "
            "JOIN evidence_refs ref ON ref.artifact_id="
            "json_extract_string(e.value,'$.artifact_id') AND ref.locator="
            "json_extract_string(e.value,'$.locator') "
            "WHERE ref.run_id=? AND ref.observation_id=?)"
        )
        linked_results = [
            json.loads(data)
            for (data,) in store.rows(
                "SELECT data FROM evaluations WHERE run_id=? AND (EXISTS "
                "(SELECT 1 FROM json_each(data,'$.supporting_observations') o "
                "WHERE json_extract_string(o.value,'$')=?) OR "
                + provenance_match
                + ") ORDER BY evaluation_id LIMIT 100",
                [run, oid, run, oid],
            )
        ]
        linked_findings = [
            fid
            for (fid,) in store.rows(
                "SELECT finding_id FROM findings WHERE run_id=? AND "
                + provenance_match
                + " ORDER BY finding_id LIMIT 100",
                [run, run, oid],
            )
        ]
        return {
            "observation": redact(obs.model_dump(mode="json")),
            "provenance": integrity,
            "evaluations": linked_results[:100],
            "findings": linked_findings[:100],
            "relationships": [
                json.loads(d)
                for (d,) in store.rows(
                    "SELECT data FROM enterprise_edges WHERE run_id=? "
                    "AND EXISTS (SELECT 1 FROM "
                    "json_each(data,'$.observation_ids') o "
                    "WHERE json_extract_string(o.value,'$')=?) "
                    "ORDER BY relationship_id LIMIT 100",
                    [run, oid],
                )
            ],
            "inspection": "Redacted normalized evidence; raw source and policy documents omitted",
        }

    def export(
        self, store: Store, run: str, kind: str, progress=None, selected=None, options=None
    ) -> Json:
        """Write to a private partial file and publish atomically; failures leave no report."""
        from offline_analyzer.provenance.execution import checkpoint, committing

        checkpoint("REPORT_EXPORT")
        store.require_run(run)
        if kind not in {
            "assessment",
            "excel",
            "findings",
            "accounts",
            "coverage",
            "evidence",
            "approved-rtf",
            "approved-docx",
            "approved-text",
        }:
            raise InputError("UNSUPPORTED_REPORT")
        report_id = secrets.token_hex(16)
        directory = resolve_under(self.workspace, "reports")
        directory.mkdir(mode=0o700, exist_ok=True)
        suffix = {
            "assessment": ".zip",
            "excel": ".xlsx",
            "approved-rtf": ".rtf",
            "approved-docx": ".docx",
            "approved-text": ".txt",
        }.get(kind, ".json")
        final = directory / (report_id + suffix)
        path = directory / (report_id + suffix + ".partial")
        staged = directory / (report_id + ".meta.partial")
        try:
            name = f"CloSec-assessment-{kind}{suffix}"
            if kind == "assessment":
                from offline_analyzer.reporting.assessment_report import export_assessment

                name = export_assessment(store, run, path, progress, **(options or {}))
            elif kind.startswith("approved-"):
                from offline_analyzer.reporting.approved import export_approved

                export_approved(store, run, path, kind, selected, progress)
            else:
                self.write_report(store, run, kind, path, progress)
            metadata = {
                "id": report_id,
                "run_id": run,
                "kind": kind,
                "name": name,
                "bytes": path.stat().st_size,
            }
            staged.write_text(json.dumps(metadata))
            path.rename(final)
            committing("REPORT_PUBLICATION")
            staged.rename(directory / (report_id + ".meta"))
            return metadata
        except BaseException:
            path.unlink(missing_ok=True)
            final.unlink(missing_ok=True)
            staged.unlink(missing_ok=True)
            raise

    def write_report(self, store: Store, run: str, kind: str, path: Path, progress) -> None:
        if kind == "excel":
            export_excel(store, run, path, progress=progress)
        else:
            # Stream register output to disk; do not load the dataset into browser memory.
            with path.open("x", encoding="utf-8") as output:
                output.write("[")
                first, offset = True, 0
                while True:
                    result = self.records(
                        store,
                        run,
                        "evaluations" if kind == "accounts" else kind,
                        "",
                        "",
                        "",
                        offset,
                        100,
                    )
                    for item in result["items"]:
                        if not first:
                            output.write(",\n")
                        json.dump(item, output)
                        first = False
                    offset += 100
                    if progress:
                        progress(
                            f"Writing {kind} records", min(offset, result["total"]), result["total"]
                        )
                    if offset >= result["total"]:
                        break
                output.write("]")
