"""Time GUI API endpoints on a synthetic GCP estate (never a client workspace).

Builds the workspace once (import, assess, confirm a share of findings), then requests each
screen's endpoint through the real application twice: cold (first request) and warm.

    PYTHONPATH=src:. python -m tools.screen_timings --packages <estate> --workspace <new dir>
"""

import argparse
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

ORIGIN = "http://127.0.0.1:8765"
TOKEN = "synthetic-timing-secret"
SCREENS = (
    ("Dashboard", "/api/runs/{run}/dashboard"),
    ("Cloud dashboard (GCP)", "/api/runs/{run}/cloud/dashboard?provider=GCP"),
    ("Attack paths (GCP)", "/api/runs/{run}/cloud/paths?provider=GCP"),
    ("Path evaluations", "/api/runs/{run}/attack-path-evaluations"),
    ("Findings Finalized (GCP)", "/api/runs/{run}/finalized?provider=GCP"),
    ("Findings Finalized (all)", "/api/runs/{run}/finalized"),
    ("Report findings", "/api/runs/{run}/report-findings"),
    ("Finding groups", "/api/runs/{run}/finding-groups"),
    ("Finding facets", "/api/runs/{run}/finding-facets"),
    ("Finding quality", "/api/runs/{run}/finding-quality"),
    ("Findings list", "/api/runs/{run}/records/findings"),
    ("Exclusions", "/api/runs/{run}/exclusions"),
    ("Security coverage", "/api/runs/{run}/security-coverage"),
    ("Checklist", "/api/runs/{run}/checklist"),
    ("GCP principals", "/api/runs/{run}/gcp/principals"),
    ("Collection", "/api/runs/{run}/collection"),
    ("Finding detail", "/api/runs/{run}/findings/{finding}/detail"),
)


def prepare(packages: Path, workspace: Path, confirm: int) -> tuple[str, str]:
    from offline_analyzer.enterprise.snapshot import assess_enterprise
    from offline_analyzer.findings.generate import record_decision
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.inventory.environment import set_environment
    from offline_analyzer.storage.store import Store

    marker = workspace / "timing-run.json"
    if marker.is_file():
        data = json.loads(marker.read_text())
        return data["run"], data["finding"]
    set_environment(workspace, "SYNTHETIC")
    with Store(workspace) as store:
        imports = [import_package(store, p) for p in sorted(packages.iterdir()) if p.is_dir()]
        run = assess_enterprise(store, imports)
        findings = sorted(store.candidates(run), key=lambda f: f.finding_id)
        for finding in findings[:confirm]:
            record_decision(store, run, finding.finding_id, "CONFIRMED", "Synthetic", "timing")
    marker.write_text(json.dumps({"run": run, "finding": findings[0].finding_id}))
    return run, findings[0].finding_id


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--confirm", type=int, default=150)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    from offline_analyzer.api.app import create_app

    run, finding = prepare(args.packages, args.workspace, args.confirm)
    results = []
    with TestClient(
        create_app(args.workspace, origin=ORIGIN, bootstrap=TOKEN), base_url=ORIGIN
    ) as client:
        csrf = client.post(
            "/api/session", json={}, headers={"Origin": ORIGIN, "X-Bootstrap-Token": TOKEN}
        ).json()["csrf"]
        headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf}
        for name, url in SCREENS:
            timings, status = [], None
            for _ in range(2):
                start = time.perf_counter()
                response = client.get(url.format(run=run, finding=finding), headers=headers)
                timings.append(round(time.perf_counter() - start, 3))
                status = response.status_code
            results.append(
                {"screen": name, "status": status, "cold_s": timings[0], "warm_s": timings[1]}
            )
            print(f"{name:28} {status}  cold {timings[0]:7.3f} s  warm {timings[1]:7.3f} s")
    if args.output:
        args.output.write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
