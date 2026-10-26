"""Synthetic upgrade-compatibility check: build a workspace with every kind of analyst state, or
read every status back, so an older and a newer analyzer can be compared (synthetic data only).

    python -m tools.upgrade_state build <dir>    # creates <dir>/work and <dir>/before.json
    python -m tools.upgrade_state read <dir> <out.json>
"""

import json
import sys
from pathlib import Path


def build(root: Path) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
    from test_theme_browser import workspace

    from offline_analyzer.attack_paths.feasibility import attack_paths
    from offline_analyzer.attack_paths.review import record as review_path
    from offline_analyzer.contracts.exclusion import ExclusionRequest
    from offline_analyzer.contracts.report_finding import ReportEdit
    from offline_analyzer.findings.exclusions import record as exclude
    from offline_analyzer.findings.generate import record_decision
    from offline_analyzer.findings.report_ready import save_revision, sections_for
    from offline_analyzer.findings.sre import record_sre
    from offline_analyzer.storage.store import Store

    work = workspace(root)
    with Store(work) as store:
        runs = [r for (r,) in store.rows("SELECT run_id FROM runs ORDER BY run_id")]
        for run in runs:
            findings = sorted(store.candidates(run), key=lambda f: f.finding_id)
            for index, finding in enumerate(findings[:6]):
                if store.latest_decision(finding.finding_id):
                    continue
                if index == 0:
                    record_decision(store, run, finding.finding_id, "CONFIRMED", "analyst", "ok")
                elif index == 1:
                    record_decision(store, run, finding.finding_id, "REJECTED", "analyst", "no")
                elif index == 2:
                    record_sre(store, run, [finding.finding_id], "SENT_TO_SRE", "analyst")
                elif index == 3:
                    exclude(
                        store,
                        run,
                        finding.finding_id,
                        ExclusionRequest(
                            action="EXCLUDE",
                            reason="FALSE_POSITIVE",
                            note="Google-managed service agent (platform-managed)",
                            analyst="analyst",
                        ),
                    )
                elif index == 4:
                    exclude(
                        store,
                        run,
                        finding.finding_id,
                        ExclusionRequest(
                            action="EXCLUDE", reason="ACCEPTED_RISK", analyst="analyst"
                        ),
                    )
                elif index == 5:
                    edit = ReportEdit(
                        expected_revision=0,
                        analyst="analyst",
                        sections=sections_for(finding),
                        member_ids=[finding.finding_id],
                        include_in_report=True,
                    )
                    save_revision(store, run, finding.finding_id, edit)
            for path in attack_paths(store, run)["items"][:2]:
                review_path(store, run, path["path_id"], "CONFIRMED", "analyst")
    (root / "before.json").write_text(json.dumps(read(work), indent=1, sort_keys=True))


def read(work: Path) -> dict:
    from offline_analyzer.attack_paths.feasibility import attack_paths
    from offline_analyzer.findings.exclusions import excluded
    from offline_analyzer.findings.report_ready import current_findings, validity
    from offline_analyzer.findings.sre import latest_sre, review_state
    from offline_analyzer.storage.store import Store

    state: dict = {}
    with Store(work) as store:
        for (run,) in store.rows("SELECT run_id FROM runs ORDER BY run_id"):
            decisions, sre = store.latest_decisions(run), latest_sre(store, run)
            hidden = excluded(store, run)
            rows = {}
            for finding in store.candidates(run):
                status, stage = review_state(store, finding, decisions, sre)
                entry = hidden.get(finding.finding_id)
                rows[finding.finding_id] = {
                    "status": status,
                    "stage": stage,
                    "excluded": entry.reason if entry else None,
                }
            reviews = {
                p["path_id"]: p.get("analyst_review")
                for p in attack_paths(store, run)["items"]
                if p.get("analyst_review") not in (None, "UNREVIEWED")
            }
            state[run] = {"findings": rows, "path_reviews": reviews}
        from offline_analyzer.contracts.report_finding import ReportRevision

        revisions = {}
        for (raw,) in store.rows("SELECT data FROM report_revisions"):
            revision = ReportRevision.model_validate_json(raw)
            findings = current_findings(store, revision.run_id)
            revisions[revision.report_id] = validity(
                revision, findings, store.latest_decisions(revision.run_id), store
            )["evidence_state"]
        state["report_revisions"] = revisions
    return state


if __name__ == "__main__":
    if sys.argv[1] == "build":
        build(Path(sys.argv[2]))
    else:
        Path(sys.argv[3]).write_text(
            json.dumps(read(Path(sys.argv[2]) / "work"), indent=1, sort_keys=True)
        )
