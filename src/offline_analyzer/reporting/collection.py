"""Persisted readiness and registry-bound collection requests; no AWS execution."""

import json
from collections import Counter, defaultdict

from offline_analyzer.contracts.r0 import AWS_OPERATIONS, GLOBAL_OPERATIONS, stable_id
from offline_analyzer.contracts.requests import EvidenceRequest
from offline_analyzer.ingestion.collector import stored_summary
from offline_analyzer.inventory.accounts import workspace_registry
from offline_analyzer.rules.registry import ALL_RULES, BY_ID, primary_operations, rule_operations


def collection_readiness(store, run: str) -> dict:
    store.require_run(run)
    sources = list(store.source_data(run))
    package = json.loads(
        store.db.execute("SELECT package FROM runs WHERE run_id=?", [run]).fetchone()[0]
    )
    members_row = store.db.execute(
        "SELECT members FROM enterprise_snapshots WHERE run_id=?", [run]
    ).fetchone()
    members = json.loads(members_row[0]) if members_row else [run]
    collectors = [s for m in members if (s := stored_summary(store.workspace, m))]
    registry = workspace_registry(store.workspace)
    aliases = registry.accounts if registry else {}
    accounts = {}
    operations = {}
    requests = {}
    manual = []
    present = defaultdict(list)
    rows = []
    investigation_ids = dict(
        store.rows(
            "SELECT json_extract_string(data,'$.evaluation_id'),investigation_id "
            "FROM security_investigations WHERE run_id=?",
            [run],
        )
    )

    def account_row(account):
        return accounts.setdefault(
            account,
            {
                "account_id": account,
                "alias": aliases[account].alias if account in aliases else None,
                "last_collection": None,
                "regions": set(),
                "declared_regions": set(),
                "completed_operations": 0,
                "partial_collections": 0,
                "access_denied": 0,
                "api_failures": 0,
                "unsupported_evidence": 0,
                "missing_required_operations": set(),
                "parsed_records": 0,
                "evaluations": Counter(),
                "sufficient_evaluations": 0,
            },
        )

    def request(account, region, operation, state, reason, evaluation=None, parameters=None):
        if operation not in AWS_OPERATIONS or not account or not region:
            return
        scope = "global" if operation in GLOBAL_OPERATIONS else region
        key = (account, scope, operation, json.dumps(parameters or {}, sort_keys=True))
        item = requests.setdefault(
            key,
            {
                "request_id": stable_id("request", [run, key]),
                "account_id": account,
                "region": scope,
                "operation": operation,
                "state": state,
                "reason": reason,
                "request": (
                    "Collect the registered operation and retain scope, errors and every page"
                ),
                "request_parameters": parameters or {},
                "related_investigations": set(),
                "related_controls": set(),
                "priority": "HIGH" if state == "ERROR" else "NORMAL",
                "recommended_freshness_hours": 24,
                "freshness_basis": "Operational request recommendation; no inferred control SLA",
            },
        )
        if evaluation:
            item["related_investigations"].add(evaluation.evaluation_id)
            if evaluation.evaluation_id in investigation_ids:
                item["related_investigations"].add(investigation_ids[evaluation.evaluation_id])
            if evaluation.methodology_id:
                item["related_controls"].add(evaluation.methodology_id)

    for target in package.get("targets", []):
        account_row(target["account_id"])["declared_regions"].add(target["region"])
    for source in sources:
        account, region, op = source["account_id"], source["region"], source["operation"]
        state = source["effective_coverage"]
        entry = operations.setdefault(
            op, {"operation": op, "sources": 0, "records": 0, "errors": set()}
        )
        entry["sources"] += 1
        entry[state] = entry.get(state, 0) + 1
        entry["records"] += source["record_count"]
        entry["errors"].update(source["errors"])
        scope = "global" if op in GLOBAL_OPERATIONS else region
        present[(account, scope, op)].append(source)
        rows.append(
            {
                "account_id": account,
                "region": scope,
                "operation": op,
                "domain": op.split(":")[0],
                "status": state,
                "source_type": source["format"],
                "collected": bool(source["path"]),
                "parsed_records": source["record_count"],
                "collected_at": source["collected_at"],
                "errors": source["errors"],
                "limitations": source["limitations"],
                "artifact_id": source["artifact_id"],
            }
        )
        if account:
            row = account_row(account)
            if region:
                row["declared_regions"].add(region)
                if source["path"]:
                    row["regions"].add(region)
            stamp = source["collected_at"]
            if stamp and source["path"]:
                row["last_collection"] = max(stamp, row["last_collection"] or stamp)
            row["parsed_records"] += source["record_count"]
            row["completed_operations"] += state == "COMPLETE"
            row["partial_collections"] += state == "PARTIAL"
            denied = any(
                "accessdenied" in e.lower() or "unauthorized" in e.lower() for e in source["errors"]
            )
            row["access_denied"] += denied
            row["api_failures"] += state == "ERROR" and not denied
        if state != "COMPLETE":
            request(
                account,
                region,
                op,
                state,
                "; ".join(source["errors"] + source["limitations"]) or "Collection incomplete",
                parameters=source.get("request_parameters"),
            )

    # Required operations come from executable rule declarations.
    for account, row in list(accounts.items()):
        for rule in ALL_RULES:
            for region in (
                ["global"]
                if rule.scope == "GLOBAL"
                else sorted(row["declared_regions"] - {"global"})
            ):
                if not any(present[(account, region, op)] for op in primary_operations(rule)):
                    row["missing_required_operations"].add(f"{region}:{rule.operation}")
                    request(
                        account,
                        region,
                        rule.operation,
                        "MISSING",
                        f"Primary collection for {rule.rule_id}",
                    )

    for result in store.results(run):
        if not result.account_id:
            continue
        row = account_row(result.account_id)
        outcome = str(result.outcome)
        row["evaluations"][outcome] += 1
        sufficient = (
            bool(result.evidence)
            and not result.missing_dependencies
            and not result.contradictory_observations
            and outcome in {"PASS", "FAIL"}
        )
        row["sufficient_evaluations"] += sufficient
        if (
            outcome not in {"UNKNOWN", "COLLECTION_ERROR", "MANUAL_VALIDATION_REQUIRED"}
            and not result.missing_dependencies
        ):
            continue
        rule = BY_ID[result.rule_id]
        # Explicit operation dependencies and absent declared context operations are actionable.
        needed = set(result.missing_dependencies) & set(AWS_OPERATIONS)
        for op in rule_operations(rule):
            scope = "global" if op in GLOBAL_OPERATIONS else result.region
            if not present[(result.account_id, scope, op)]:
                if op in primary_operations(rule) and any(
                    present[(result.account_id, scope, alias)] for alias in primary_operations(rule)
                ):
                    continue
                needed.add(op)
        for op in needed:
            request(
                result.account_id, result.region, op, "MISSING_DEPENDENCY", result.reasoning, result
            )
        for dependency in result.missing_dependencies:
            if dependency not in AWS_OPERATIONS:
                manual.append(
                    {
                        "account_id": result.account_id,
                        "region": result.region,
                        "investigation": result.evaluation_id,
                        "control": result.methodology_id,
                        "requirement": dependency,
                    }
                )
        # Attach control context to recollection requests for this rule's incomplete operations.
        for op in rule_operations(rule):
            scope = "global" if op in GLOBAL_OPERATIONS else result.region
            for source in present[(result.account_id, scope, op)]:
                if source["effective_coverage"] != "COMPLETE":
                    request(
                        result.account_id,
                        scope,
                        op,
                        source["effective_coverage"],
                        result.reasoning,
                        result,
                        source.get("request_parameters"),
                    )

    # Resolve concrete IAM document requests from the existing bounded inventory model.
    from offline_analyzer.iam.analysis import load
    from offline_analyzer.iam.model import KINDS, IamInventory

    inventory = IamInventory(load(store, run, KINDS))
    for role in inventory.roles.values():
        for arn in set(role.attached or ()) | ({role.boundary_arn} if role.boundary_arn else set()):
            policy = inventory.policies.get(arn)
            if policy and policy.document is not None:
                continue
            version = policy.default_version if policy else None
            operation = "iam:GetPolicyVersion" if version else "iam:GetPolicy"
            parameters = {"PolicyArn": arn}
            if version:
                parameters["VersionId"] = version
            request(
                role.account,
                "global",
                operation,
                "MISSING_POLICY_DOCUMENT",
                "Resolve the attached or boundary document used by IAM authorization",
                parameters=parameters,
            )
            key = (role.account, "global", operation, json.dumps(parameters, sort_keys=True))
            requests[key]["related_investigations"].add(role.arn)
            requests[key]["related_controls"].update(
                r.methodology.control_id
                for r in ALL_RULES
                if r.resource_type == "AWS::IAM::Role" and r.methodology
            )
            requests[key]["priority"] = "HIGH"

    for summary in collectors:
        for op in summary["operations"]:
            if op["import_handling"] != "IMPORTED":
                account = account_row(summary["account_id"])
                account["unsupported_evidence"] += 1
                if op["artifact_path"]:
                    account["regions"].add(op["region"])
                    stamp = op.get("completed_at")
                    if stamp:
                        account["last_collection"] = max(stamp, account["last_collection"] or stamp)
                code = op["error_code"] or ""
                denied = "accessdenied" in code.lower() or "unauthorized" in code.lower()
                account["access_denied"] += denied
                account["api_failures"] += op["status"] == "FAILED" and not denied
                rows.append(
                    {
                        "account_id": summary["account_id"],
                        "region": op["region"],
                        "operation": op["operation"],
                        "domain": op["operation"].split(":")[0],
                        "status": "UNSUPPORTED",
                        "source_type": "unsupported",
                        "collected": bool(op["artifact_path"]),
                        "parsed_records": 0,
                        "collected_at": summary["completed_at"],
                        "errors": [code] if code else [],
                        "limitations": [],
                        "artifact_id": None,
                    }
                )
    for row in accounts.values():
        row["regions"] = sorted(row["regions"])
        row["declared_regions"] = sorted(row["declared_regions"])
        row["missing_required_operations"] = sorted(row["missing_required_operations"])
        row["evaluations"] = dict(row["evaluations"])
        row["readiness"] = (
            "NOT_ASSESSED"
            if not row["evaluations"]
            else "REQUIRES_VALIDATION"
            if (
                row["missing_required_operations"]
                or row["partial_collections"]
                or row["access_denied"]
                or row["api_failures"]
                or any(
                    row["evaluations"].get(s)
                    for s in ("UNKNOWN", "COLLECTION_ERROR", "MANUAL_VALIDATION_REQUIRED")
                )
            )
            else "AVAILABLE_EVIDENCE_EVALUATED"
        )
    for item in requests.values():
        item["related_investigations"] = sorted(item["related_investigations"])
        item["related_controls"] = sorted(item["related_controls"])
    return {
        "schema": "closec-readiness-1",
        "run_id": run,
        "accounts": sorted(accounts.values(), key=lambda a: a["account_id"]),
        "sources": rows,
        "operations": [{**e, "errors": sorted(e["errors"])} for _, e in sorted(operations.items())],
        "collector_packages": collectors,
        "evidence_requests": [
            EvidenceRequest.model_validate(r).model_dump(by_alias=True) for r in requests.values()
        ],
        "manual_validation": manual,
        "qualification": "Sufficiency applies only to evaluated rule criteria; "
        "no control-level completeness or PASS is claimed",
    }
