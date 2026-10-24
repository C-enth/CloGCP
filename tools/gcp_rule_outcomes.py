"""Per-rule outcome counts of every GCP rule over the synthetic GCP fixtures (counts only).

Used as a regression table: `python -m tools.gcp_rule_outcomes <workdir>` prints JSON
{fixture: {rule_id: {outcome: count}}}. Synthetic packages only; no real evidence.
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def fixtures(root: Path) -> dict[str, Path]:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
    from test_gcp_collector_227 import package_227

    from tools.fixtures.gcp_expanded import expanded, expanded22
    from tools.fixtures.gcp_pilot import pilot
    from tools.gcp_fixture import build

    return {
        "gcp_fixture": build(root / "simple"),
        "expanded": expanded(root / "expanded"),
        "expanded_mixed": expanded(root / "expanded-mixed", mixed=True),
        "expanded22": expanded22(root / "expanded22"),
        "pilot": pilot(root / "pilot"),
        "package_227": package_227(root / "p227"),
    }


def outcomes(root: Path) -> dict:
    from offline_analyzer.ingestion.importer import import_package
    from offline_analyzer.inventory.environment import set_environment
    from offline_analyzer.rules.engine import assess
    from offline_analyzer.storage.store import Store

    table = {}
    for name, package in fixtures(root).items():
        work = root / f"work-{name}"
        set_environment(work, "SYNTHETIC")
        with Store(work) as store:
            run = import_package(store, package)
            assess(store, run)
            counts: dict[str, Counter] = defaultdict(Counter)
            for result in store.results(run):
                if result.rule_id.startswith("GCP-"):
                    counts[result.rule_id][str(result.outcome)] += 1
            table[name] = {rule: dict(sorted(c.items())) for rule, c in sorted(counts.items())}
    return table


if __name__ == "__main__":
    print(json.dumps(outcomes(Path(sys.argv[1])), indent=1, sort_keys=True))
