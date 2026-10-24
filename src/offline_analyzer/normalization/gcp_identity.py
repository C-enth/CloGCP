"""Project identity diagnostics, separate from display labels and persisted logs."""

from offline_analyzer.contracts.errors import InputError


def mismatch(
    file: str,
    project: str,
    field: str,
    observed: object,
    code: str = "GCP_PROJECT_IDENTITY_MISMATCH",
) -> InputError:
    """Literal bounded values for the authenticated UI only; exception text is fixed."""
    return InputError(
        code,
        identity_context={
            "file": file[:500],
            "declared_project": project[:200],
            "field": field[:100],
            "observed_identity": str(observed)[:200],
        },
    )
