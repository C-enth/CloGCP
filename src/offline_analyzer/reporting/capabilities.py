"""Executable-registry coverage: collection compatibility is not security coverage."""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from offline_analyzer.findings.generate import validation_status
from offline_analyzer.findings.recommendations import TEMPLATES
from offline_analyzer.findings.report_ready import current_findings
from offline_analyzer.ingestion.collector import contract
from offline_analyzer.normalization.adapters import AWS_SHAPES, EXTRA_SHAPES, SINGLETONS
from offline_analyzer.normalization.enterprise_adapters import PROFILES
from offline_analyzer.normalization.iam_adapters import LIST_KINDS, ORG_LISTS, SINGLE
from offline_analyzer.rules.registry import ALL_RULES, BY_ID, primary_operations, rule_operations
from offline_analyzer.storage.store import Store

# Evidence domains consumed by correlate.py and IAM analysis; these are dependencies,
# not a promise that every row produces an edge or an authorization conclusion.
RELATIONSHIP_PROJECTION = {
    "iam:GetAccountAuthorizationDetails",
    "iam:ListRoles",
    "iam:GetRole",
    "ec2:DescribeInstances",
    "ec2:DescribeSubnets",
    "ec2:DescribeNetworkAcls",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeRouteTables",
    "rds:DescribeDBInstances",
    "s3api:GetBucketPolicy",
    "kms:GetKeyPolicy",
    "kms:ListGrants",
    "lambda:ListFunctions",
    "ecs:DescribeTaskDefinition",
    "ec2:DescribeVpcPeeringConnections",
    "ec2:DescribeTransitGatewayAttachments",
    "ec2:GetTransitGatewayRouteTableAssociations",
    "ec2:GetTransitGatewayRouteTablePropagations",
    "ec2:SearchTransitGatewayRoutes",
    "ram:ListResources",
    "ram:ListPrincipals",
    "cloudtrail:DescribeTrails",
    "organizations:ListTargetsForPolicy",
    "organizations:ListPoliciesForTarget",
    "organizations:ListParents",
    "organizations:ListAccountsForParent",
    "organizations:ListOrganizationalUnitsForParent",
}
RELATIONSHIP_CONTEXT = {
    op for op in (*LIST_KINDS, *ORG_LISTS, *SINGLE) if op.startswith(("iam:", "organizations:"))
} | {"ec2:DescribeVpcs", "ec2:DescribeTransitGateways", "ec2:DescribeTransitGatewayRouteTables"}
PATH_OPERATIONS = {
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeNetworkInterfaces",
    "iam:GetAccountAuthorizationDetails",
    "iam:ListRoles",
    "iam:GetRole",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:GetRolePolicy",
    "iam:GetInstanceProfile",
    "s3control:GetPublicAccessBlock",
}


def kinds(operation: str) -> list[str]:
    if operation in AWS_SHAPES:
        return [AWS_SHAPES[operation][4], *[s[4] for s in EXTRA_SHAPES.get(operation, ())]]
    if operation in PROFILES:
        return [PROFILES[operation][3]]
    if operation in SINGLETONS:
        return [SINGLETONS[operation][2]]
    profile = LIST_KINDS.get(operation) or ORG_LISTS.get(operation) or SINGLE.get(operation)
    return [profile[1]] if profile else []


def matrix() -> dict:
    rows = []
    for operation in contract()["supported_operations"]:
        op = operation["operation"]
        direct = [r for r in ALL_RULES if op in primary_operations(r)]
        contextual = [r for r in ALL_RULES if op in rule_operations(r) and r not in direct]
        scanner = op == "prowler:Scan"
        rows.append(
            {
                "service": op.split(":")[0],
                "operation": op,
                "format": operation["format"],
                "resource_types": kinds(op)
                if not scanner
                else ["AWS::EC2::Instance", "AWS::RDS::DBInstance", "AWS::CloudTrail::Trail"],
                "parser_status": "IMPLEMENTED_SYNTHETIC_VALIDATED",
                "normalization_status": "IDENTITY_METADATA_ONLY"
                if op == "sts:GetCallerIdentity"
                else "IMPLEMENTED_CONDITIONAL_ON_VALID_IDENTITY",
                "canonical_resources": bool(kinds(op)) or scanner,
                "relationship_support": "CONDITIONAL_RELATIONSHIP_PROJECTION"
                if op in RELATIONSHIP_PROJECTION
                else "CONTEXT_DEPENDENCY"
                if op in RELATIONSHIP_CONTEXT
                else "NONE",
                "rule_availability": "DIRECT_EVALUATION"
                if direct
                else "CONTEXT_ONLY"
                if contextual
                else "SUPPLEMENTARY_SCANNER_MAPPING"
                if scanner
                else "NOT_IMPLEMENTED",
                "rules": [
                    {
                        "rule_id": r.rule_id,
                        "security_domain": r.domain,
                        "security_scenario": r.title,
                        "required_evidence": sorted(rule_operations(r)),
                        "methodology_id": r.methodology_id,
                        "recommendation_available": r.rule_id in TEMPLATES,
                        "finding_generation": "ON_EVIDENCE_BACKED_FAIL",
                    }
                    for r in direct
                ],
                "context_rules": [r.rule_id for r in contextual],
                "required_response_fields": operation["required_response_fields"],
                "native_structure": operation.get("native_structure"),
                "missing_evidence_requests": bool(direct or contextual) or op.startswith("iam:"),
                "attack_prerequisite_support": "BOUNDED_AP_04_05_06_CONTEXT"
                if op in PATH_OPERATIONS
                else "NONE",
                "confidence_limitations": [
                    (
                        "Complete collection and valid account/resource identity required; absent "
                        "evidence cannot establish PASS."
                    ),
                    (
                        "Configuration and policy references do not demonstrate exploitation or "
                        "effective access."
                    ),
                ]
                + (
                    [
                        (
                            "Only explicitly mapped checks supplement evaluations; scanner output "
                            "is not "
                            "complete inventory."
                        )
                    ]
                    if scanner
                    else []
                ),
                "actual_export_compatibility": "NOT_ESTABLISHED",
            }
        )
    aws = [r for r in rows if r["operation"] != "prowler:Scan"]
    return {
        "schema_version": "security-capability-1",
        "operations": rows,
        "summary": {
            "aws_operations_accepted": len(aws),
            "aws_operations_normalized": sum(
                r["normalization_status"] != "IDENTITY_METADATA_ONLY" for r in aws
            ),
            "aws_operations_with_canonical_resource_support": sum(
                r["canonical_resources"] for r in aws
            ),
            "aws_operations_used_as_relationship_context": sum(
                r["relationship_support"] != "NONE" for r in aws
            ),
            "aws_operations_with_relationship_projection": sum(
                r["relationship_support"] == "CONDITIONAL_RELATIONSHIP_PROJECTION" for r in aws
            ),
            "aws_operations_with_direct_checks": sum(bool(r["rules"]) for r in aws),
            "aws_operations_with_candidate_generation": sum(bool(r["rules"]) for r in aws),
            "aws_operations_with_evidence_requests": sum(
                r["missing_evidence_requests"] for r in aws
            ),
            "aws_operations_with_implemented_path_context": sum(
                r["attack_prerequisite_support"] != "NONE" for r in aws
            ),
            "deterministic_rules": len(ALL_RULES),
        },
        "definitions": (
            "Operation support describes code paths, not observed counts or complete "
            "service coverage. Context dependency does not guarantee an edge. AP support "
            "covers constituent prerequisites only; full exploitation remains unresolved."
        ),
    }


def coverage(store: Store, run: str) -> dict:
    store.require_run(run)
    counts = defaultdict(Counter)
    domains = defaultdict(Counter)
    artifact_services = {}
    for source in store.source_data(run):
        service = source["operation"].split(":")[0]
        counts[service]["evidence_collected"] += bool(source.get("path"))
        counts[service]["sources_incomplete"] += source["effective_coverage"] != "COMPLETE"
        artifact_services[source.get("artifact_id")] = service
    # SQL aggregates provenance once, avoids per-resource lookups and graph rebuilding.
    resources = defaultdict(set)
    for _oid, resource, artifact in store.rows(
        "SELECT o.observation_id,o.resource_id,e.artifact_id "
        "FROM observations o JOIN evidence_refs e USING(run_id,observation_id) WHERE o.run_id=?",
        [run],
    ):
        service = artifact_services.get(artifact, "unknown")
        counts[service]["evidence_understood"] += 1
        if resource:
            resources[service].add(resource)
    for service, ids in resources.items():
        counts[service]["canonical_resources"] = len(ids)
    for r in ALL_RULES:
        counts[r.operation.split(":")[0]]["security_checks_implemented"] += 1
        domains[r.domain]["security_checks_implemented"] += 1
    for result in store.results(run):
        rule = next((r for r in ALL_RULES if r.rule_id == result.rule_id), None)
        if not rule:
            continue
        count = counts[rule.operation.split(":")[0]]
        count["checks_evaluated"] += 1
        count["unresolved_evaluations"] += str(result.outcome) not in {
            "PASS",
            "FAIL",
            "NOT_APPLICABLE",
        } or bool(result.missing_dependencies)
        domains[rule.domain]["checks_evaluated"] += 1
        domains[rule.domain]["unresolved_evaluations"] += str(result.outcome) not in {
            "PASS",
            "FAIL",
            "NOT_APPLICABLE",
        } or bool(result.missing_dependencies)
    decisions = store.latest_decisions(run)
    for finding in current_findings(store, run).values():
        rule = BY_ID[finding.rule_id]
        count = counts[rule.operation.split(":")[0]]
        count["findings_generated"] += 1
        count["analyst_validated"] += validation_status(store, finding, decisions)[0] == "CONFIRMED"
        domains[rule.domain]["findings_generated"] += 1
        domains[rule.domain]["analyst_validated"] += (
            validation_status(store, finding, decisions)[0] == "CONFIRMED"
        )
    return {
        "run_id": run,
        "services": [
            {"service": service, **dict(count)} for service, count in sorted(counts.items())
        ],
        "capabilities": matrix(),
        "domains": [{"domain": domain, **dict(count)} for domain, count in sorted(domains.items())],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(matrix(), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
