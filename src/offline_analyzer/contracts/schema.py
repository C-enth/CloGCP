"""Export public JSON schemas, never evidence."""

import argparse
import json
from pathlib import Path

from offline_analyzer.contracts import models, r0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    output = parser.parse_args().output
    output.mkdir(parents=True, exist_ok=False)
    from offline_analyzer.contracts.diagnostic import SanitizedDiagnostic
    from offline_analyzer.contracts.enterprise import Edge, EnterpriseSnapshot
    from offline_analyzer.contracts.exclusion import ExclusionRequest, FindingExclusion
    from offline_analyzer.contracts.finalisation import FrozenAssessment
    from offline_analyzer.contracts.gcp import CloudTransition, GCPManifest
    from offline_analyzer.contracts.gcp_expanded import ExpandedManifest
    from offline_analyzer.contracts.gcp_legacy import Pilot15Manifest, PilotManifest
    from offline_analyzer.contracts.investigation import SecurityInvestigation
    from offline_analyzer.contracts.jobs import LocalJob
    from offline_analyzer.contracts.management import (
        FileDelete,
        FileRequest,
        ScopeDelete,
        ScopeReplace,
        ScopeRequest,
    )
    from offline_analyzer.contracts.path_review import PathReview
    from offline_analyzer.contracts.report_finding import (
        ReportApproval,
        ReportEdit,
        ReportRevision,
        ReportSections,
    )
    from offline_analyzer.contracts.requests import EvidenceRequest
    from offline_analyzer.contracts.sre import SreValidation
    from offline_analyzer.ingestion.collector import CollectorManifest

    for contract in (
        FrozenAssessment,
        PathReview,
        LocalJob,
        SanitizedDiagnostic,
        GCPManifest,
        PilotManifest,
        Pilot15Manifest,
        ExpandedManifest,
        ScopeRequest,
        ScopeDelete,
        ScopeReplace,
        FileRequest,
        FileDelete,
        CloudTransition,
        ReportSections,
        ReportEdit,
        ReportApproval,
        ReportRevision,
        SecurityInvestigation,
        CollectorManifest,
        SreValidation,
        ExclusionRequest,
        FindingExclusion,
    ):
        (output / f"{contract.__name__}.json").write_text(
            json.dumps(contract.model_json_schema(), indent=2), encoding="utf-8"
        )

    for name, contract in (("EnterpriseEdge", Edge), ("EnterpriseSnapshot", EnterpriseSnapshot)):
        (output / f"{name}.json").write_text(
            json.dumps(contract.model_json_schema(), indent=2), encoding="utf-8"
        )
    (output / "EvidenceRequest.json").write_text(
        json.dumps(EvidenceRequest.model_json_schema(), indent=2), encoding="utf-8"
    )
    for name in (
        "Manifest",
        "Observation",
        "Relationship",
        "RuleSpec",
        "Evaluation",
        "PathEvaluation",
        "Resource",
    ):
        schema = getattr(models, name).model_json_schema()
        (output / f"{name}.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")
    for name in ("Package", "Scope", "Source", "Normalized", "Result", "Candidate", "Decision"):
        schema = getattr(r0, name).model_json_schema()
        (output / f"R0_{name}.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
