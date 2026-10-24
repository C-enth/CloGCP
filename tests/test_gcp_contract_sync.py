"""Collector <-> analyzer contract sync: every dataset name and manifest field the GCP
collector can emit must be known to the catalog, the contract JSON and the manifest models.
Static reading of the PowerShell source; nothing is executed."""

import json
import re
from pathlib import Path

from offline_analyzer.contracts.gcp_expanded import (
    DependencyFallback,
    DetailLimitsReached,
    ExpandedDataset22,
    ExpandedManifest22,
)
from offline_analyzer.contracts.gcp_expanded_catalog import (
    DATASETS,
    EXTENSIONS_22,
    dataset_contract,
)

SCRIPT = Path("collectors/gcp/GCP_Security_Evidence_Collector.ps1").read_text(encoding="utf-8-sig")
CONTRACT = json.loads(Path("collectors/collector-analyzer-contract.json").read_text())
CALL = re.compile(
    r"^\s*(?:Run|RestList|Invoke-RestEvidence|Add-ManifestEntry)\s+'([a-z_]+)'\s+"
    r"('[^']*'|\"[^\"]*\"|\([^)]*\))",
    re.MULTILINE,
)
EXAMPLES = {
    "$nodeDataset": "folder_123",
    "$node.id": "123",
    "[string]$node.id": "123",
    "${safe}": "sample",
}


def example(expression: str) -> str:
    """A representative dataset name for a PowerShell name expression."""
    if expression.startswith("'"):
        return expression.strip("'")
    if expression.startswith('"'):
        text = expression.strip('"')
        for variable, value in EXAMPLES.items():
            text = text.replace(variable, value)
        return re.sub(r"\$\w+", "1", text)
    parts = [p.strip() for p in expression.strip("()").split("+")]
    return "".join(p.strip("'") if p.startswith("'") else EXAMPLES.get(p, "1") for p in parts)


def emitted(script: str) -> set[tuple[str, str]]:
    return {(domain, example(name)) for domain, name in CALL.findall(script)}


def unknown(script: str) -> list[tuple[str, str]]:
    return sorted(
        (domain, name)
        for domain, name in emitted(script)
        if dataset_contract(domain, name, "assessment-expanded-2.2") is None
    )


def keys(body: str) -> set[str]:
    """Leading `name=` of each statement in a PowerShell hashtable literal."""
    return set(re.findall(r"(?:^|;)\s*([a-z_]+)=", body.replace("\n", ";").replace("{", ";")))


def block_keys(start: str, end: str) -> set[str]:
    return keys(SCRIPT[SCRIPT.index(start) : SCRIPT.index(end, SCRIPT.index(start))])


def test_every_emitted_dataset_is_in_the_catalog():
    found = emitted(SCRIPT)
    assert len(found) > 100
    assert unknown(SCRIPT) == []


def test_a_new_collector_dataset_without_a_catalog_row_fails():
    mutated = SCRIPT + "\nRun 'storage' 'brand_new_listing' @('storage','x','list')\n"
    assert unknown(mutated) == [("storage", "brand_new_listing")]


def test_catalog_rows_are_in_the_contract_json():
    gcp = next(c for c in CONTRACT["providers"] if c["provider"] == "GCP")
    published = {(row["domain"], row["dataset_pattern"]) for row in gcp["datasets"]}
    for row in (*DATASETS, *EXTENSIONS_22):
        assert (row["domain"], row["pattern"]) in published, row["family"]
    version = re.search(r"\$CollectorVersion = '([0-9.]+)'", SCRIPT)[1]
    assert gcp["collector_version"] == version
    assert version in ExpandedManifest22.model_fields["collector_version"].annotation.__args__


def test_every_emitted_manifest_field_is_modelled():
    summary = block_keys("$summary = [pscustomobject]@{", "datasets=@($manifest.ToArray())")
    assert {"detail_limits_reached", "dependency_fallbacks", "collector_version"} <= summary
    assert summary <= set(ExpandedManifest22.model_fields)
    entries = set()
    for match in re.finditer(r"\[pscustomobject\]@\{\s*\n?\s*domain=", SCRIPT):
        entries |= keys(SCRIPT[match.start() : SCRIPT.index("})", match.start())])
    assert entries <= set(ExpandedDataset22.model_fields), entries - set(
        ExpandedDataset22.model_fields
    )
    fallback = block_keys("[void]$script:Fallbacks.Add([pscustomobject]@{", "})")
    assert fallback == set(DependencyFallback.model_fields)
    limits = re.search(r"\$DetailLimits = \[ordered\]@\{([^}]*)\}", SCRIPT)[1]
    assert {k.split("=")[0].strip() for k in limits.split(";")} == set(
        DetailLimitsReached.model_fields
    )
