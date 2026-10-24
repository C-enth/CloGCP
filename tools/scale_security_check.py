"""Source-to-conclusion assertions for the scale-v1 SYNTHETIC generator only."""

import argparse
import json
from collections import Counter
from pathlib import Path

from offline_analyzer.api.services import Views
from offline_analyzer.iam.analysis import IamAnalysis
from offline_analyzer.storage.store import Store


def check(workspace: Path) -> dict:
    counts = Counter()
    with Store(workspace) as store:
        for item in Views(workspace).runs(store):
            run = item["run_id"]
            sources = list(store.source_data(run))
            assert all(s["collector_version"] == "synthetic-scale-v1" for s in sources)
            for data, raw in store.rows(
                "SELECT e.data,o.data FROM evaluations e JOIN observations o "
                "ON e.run_id=o.run_id AND e.resource_id=o.resource_id "
                "WHERE e.run_id=? AND o.tool='aws'",
                [run],
            ):
                result, obs = json.loads(data), json.loads(raw)
                if (
                    result["rule_id"] == "R0-EC2-IMDSV2"
                    and obs["configuration"].get("MetadataOptions") is None
                ):
                    assert result["outcome"] == "UNKNOWN"
                    counts["missing_metadata_unknown"] += 1
                if result["rule_id"] == "R0-RDS-ENCRYPTION":
                    assert result["outcome"] == "FAIL" and result["confidence"] == "MEDIUM"
                    assert result["contradictory_observations"]
                    counts["native_rds_fail_scanner_contradiction"] += 1
            analysis = IamAnalysis(store, run, sources)
            for investigation in analysis.transitions() + analysis.passrole():
                assert investigation.state != "ALLOWED_WITH_SUPPORTED_CONTEXT"
                counts["iam_" + investigation.state] += 1
            for role in analysis.inventory.roles.values():
                if role.arn.endswith("/blocked"):
                    decision = analysis.identity(
                        role,
                        "iam:PassRole",
                        f"arn:aws:iam::{role.account}:role/admin",
                        {"iam:PassedToService": ("ec2.amazonaws.com",)},
                    )
                    assert decision.state == "DENIED_BY_EVIDENCE"
                    documents, _ = analysis.inventory.identity_documents(role)
                    explicit_denies = {
                        statement.origin
                        for document in documents
                        for statement in document.statements
                        if statement.effect == "Deny"
                    }
                    assert set(decision.blocking) & explicit_denies
                    counts["applicable_explicit_deny_checked"] += 1
            counts["partial_collections"] += sum(
                s["effective_coverage"] == "PARTIAL" for s in sources
            )
            counts["candidate_status"] += sum(
                store.latest_decision(f.finding_id) is None for f in store.candidates(run)
            )
        assert (
            store.db.execute(
                "SELECT count(*) FROM decisions WHERE "
                "json_extract_string(data,'$.status')='CONFIRMED'"
            ).fetchone()[0]
            == 0
        )
    assert counts["missing_metadata_unknown"] > 0
    assert counts["native_rds_fail_scanner_contradiction"] > 0
    return {"origin": "SYNTHETIC", "checks": dict(counts)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = check(args.workspace)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
