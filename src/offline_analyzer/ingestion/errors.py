"""Fixed, sanitized operator explanations; never include exception/source text."""

EXPLANATIONS = {
    "ASSESSMENT_FINALIZED": (
        "This assessment edition is frozen.",
        "Build a new enterprise snapshot with updated imports for further review; "
        "the frozen edition is preserved.",
    ),
    "FINALISATION_REQUIRES_COMPLETE_ENTERPRISE_SNAPSHOT": (
        "Finalisation requires a reconciled enterprise snapshot containing every active import.",
        "Build Enterprise Assessment with all imports, review the findings, "
        "then freeze the edition.",
    ),
    "ENTERPRISE_RECONCILIATION_FAILED": (
        "The enterprise union did not reconcile with its selected imports.",
        "Preserve original imports. No incomplete snapshot was published; "
        "review the import selection and retry.",
    ),
    "JOB_CANCELLED": (
        "The operation was cancelled at a safe checkpoint.",
        "Previous runs remain available. Select the unchanged package and retry when ready.",
    ),
    "JOB_INTERRUPTED": (
        "CloSec stopped before this job recorded completion.",
        "Reopen the workspace and retry the original package or assessment. "
        "No incomplete transaction is activated.",
    ),
    "JOB_TIME_LIMIT": (
        "The local execution budget expired.",
        "Preserve the workspace and export sanitized job diagnostics. "
        "Use scope-specific collections for retry.",
    ),
    "JOB_JOURNAL_UNAVAILABLE": (
        "Local job details could not be saved reliably.",
        "Check free disk space and workspace write permissions, then restart and retry. "
        "Keep existing evidence and databases intact.",
    ),
    "WORKSPACE_OPERATION_IN_PROGRESS": (
        "A local job currently owns database access.",
        "Use the independent job details, wait or cancel safely, then refresh this view.",
    ),
    "APPLICATION_REVISION_CHANGED": (
        "Application files changed while this backend was running.",
        "Stop CloSec and launch it from the current checkout. Your existing workspace is retained.",
    ),
    "TRANSFER_IDLE_TIMEOUT": (
        "The local transfer stopped receiving data.",
        "Retry the unchanged package and keep the browser open during transfer.",
    ),
    "MULTIPART_REJECTED": (
        "The local multipart transfer was refused before validation.",
        "Check the displayed limits and retry a complete supported ZIP or folder.",
    ),
    "UPLOAD_BYTE_LIMIT": (
        "The local transfer exceeded a file or package byte limit.",
        "Compare the displayed allowed and observed byte counts. "
        "Collect smaller scope-specific packages; do not edit evidence.",
    ),
    "ASSESSMENT_WORKSPACE_REJECTS_SYNTHETIC": (
        "Synthetic evidence is prohibited in an assessment workspace.",
        "Use a separate SYNTHETIC workspace for engineering demonstrations.",
    ),
    "SYNTHETIC_WORKSPACE_REJECTS_TOOL_GENERATED": (
        "Real evidence is prohibited in a synthetic workspace.",
        "Import authorized customer evidence into a separate ASSESSMENT workspace.",
    ),
    "SCOPE_RECOVERY_REQUIRED": (
        "An interrupted scope operation requires local recovery before workspace access.",
        "Stop and restart CloSec to retry the checked journal. Preserve the workspace; "
        "do not remove databases, checkpoints or locks manually.",
    ),
    "SCOPE_OPERATION_IN_PROGRESS": (
        "Another scope lifecycle operation owns the workspace lock.",
        "Wait for the existing operation to finish before retrying.",
    ),
    "MALFORMED_JSON": (
        "A declared JSON dataset is unreadable or malformed.",
        "Recopy the original evidence or request a corrected collection; "
        "do not edit evidence in place.",
    ),
    "ARCHIVE_BYTE_LIMIT": (
        "The archive exceeds the expanded file or package size limit.",
        "Use smaller scope-specific collection packages.",
    ),
    "ARCHIVE_RATIO_LIMIT": (
        "An entry exceeds the allowed decompression ratio.",
        "Request a collector archive using lower compression; safety limits remain enabled.",
    ),
    "ARCHIVE_MEMBER_LIMIT": (
        "The archive exceeds the allowed number of entries.",
        "Split collections by approved scope.",
    ),
    "ENCRYPTED_ARCHIVE": (
        "Encrypted ZIP entries cannot be imported.",
        "Use an approved unencrypted evidence transport within the authorized local workspace.",
    ),
    "UNSUPPORTED_ARCHIVE_COMPRESSION": (
        "The ZIP uses an unsupported compression method.",
        "Use a standard ZIP with stored or deflated entries.",
    ),
    "UNSUPPORTED_SOURCE_FORMAT": (
        "The package contains an unsupported source format.",
        "Review the supported collector profiles and collection-request export.",
    ),
    "LEGACY_INTEGRITY_ACKNOWLEDGMENT_REQUIRED": (
        "Legacy evidence has no declared source checksums.",
        "Review the integrity limitation and explicitly acknowledge it before importing.",
    ),
    "LEGACY_GCP_MANIFEST_INVALID": (
        "The GCP collection manifest does not satisfy the contract of its declared schema "
        "version (timestamps, statuses, dataset references or project identity). A collector "
        "version outside the accepted range is reported as GCP_COLLECTOR_VERSION_UNSUPPORTED.",
        "Preserve the original package and verify it with the collector owner; do not edit "
        "the manifest.",
    ),
    "LOCATION_PATH_INVALID": (
        "Enter a full folder path (for example /Users/name/CloSec-workspace or "
        "D:\\CloSec\\workspace).",
        "Paste the absolute path of the folder.",
    ),
    "LOCATION_CONFIRMATION_REQUIRED": (
        "Workspace changes need an explicit confirmation.",
        "Tick the confirmation box and try again.",
    ),
    "LOCATION_BLOCKED": (
        "This location is not allowed: it is inside the CloSec source tree or a CloSec "
        "release/application folder.",
        "Choose a folder outside the code repository and the CloSec release folders.",
    ),
    "TARGET_NOT_EMPTY": (
        "The destination must be a new or empty folder; CloSec never overwrites files.",
        "Choose a new folder name or an empty folder.",
    ),
    "TARGET_INSIDE_WORKSPACE": (
        "The destination is inside the current workspace.",
        "Choose a folder outside the current workspace.",
    ),
    "NOT_A_DIRECTORY": ("The path is not a folder.", "Choose a folder."),
    "COPY_VERIFICATION_FAILED": (
        "The copy did not match the original (sizes, hashes or counts). Nothing was switched "
        "and the original workspace is unchanged.",
        "Check free space and the destination drive, then try again.",
    ),
    "SYMLINK_IN_WORKSPACE": (
        "The workspace contains a symbolic link; it is not copied.",
        "Remove the link from the workspace and try again.",
    ),
    "WORKSPACE_NOT_A_DIRECTORY": ("The path is not an existing folder.", "Choose a folder."),
    "WORKSPACE_NOT_A_WORKSPACE": (
        "The folder has no CloSec database (assessment.duckdb).",
        "Choose the workspace folder itself, or use Create new workspace for an empty folder.",
    ),
    "WORKSPACE_WAL_WITHOUT_DATABASE": (
        "A database journal (.wal) exists without its database file.",
        "Restore the database file next to its journal before opening; keep both together.",
    ),
    "WORKSPACE_ENVIRONMENT_UNREADABLE": (
        "workspace-environment.json cannot be read.",
        "Restore the file from a backup; do not edit it by hand.",
    ),
    "WORKSPACE_IN_USE": (
        "Another CloSec process has this workspace open.",
        "Stop that CloSec window (its process id is shown), then try again.",
    ),
    "WORKSPACE_NEWER_SCHEMA": (
        "The workspace was written by a newer CloSec; this version never downgrades it.",
        "Open it with the CloSec version that created it.",
    ),
    "WORKSPACE_DATABASE_UNREADABLE": (
        "The workspace database could not be opened.",
        "Keep the folder unchanged and restore from a backup.",
    ),
    "WORKSPACE_INTEGRITY_FAILED": (
        "The workspace failed its integrity check after opening.",
        "Keep the folder unchanged and restore from a backup or the pre-migration backup.",
    ),
    # Size limits fail closed: nothing is assessed or truncated silently (owner brief 4a).
    "GCP_ASSESSMENT_RECORD_LIMIT": (
        "The GCP assessment stopped: one run holds more than 100,000 GCP observations or more "
        "than 128 MiB of observation data. Nothing was assessed partially or truncated.",
        "Assess fewer projects per run (for example one import per project, then a "
        "consolidated snapshot of the latest imports), or collect with a narrower scope.",
    ),
    "ENTERPRISE_OBSERVATION_LIMIT": (
        "The consolidated snapshot was refused: the selected imports hold more than 250,000 "
        "observations. No snapshot was created or truncated.",
        "Select fewer imports (the default selects only the latest import per project or "
        "account) or build separate snapshots per group of projects.",
    ),
    "INVALID_ENTERPRISE_MEMBERS": (
        "The consolidated snapshot was refused: no imports were selected or more than 2,048 "
        "were selected. No snapshot was created.",
        "Select between 1 and 2,048 original imports.",
    ),
    "GCP_COLLECTOR_VERSION_UNSUPPORTED": (
        "The package was produced by a GCP collector version this analyzer does not accept. "
        "Accepted for assessment-expanded-2.2: 2.2.0 to 2.2.8.",
        "Collect again with the GCP collector bundled with this CloSec release (Evidence "
        "import, 1. Collect evidence), or use a CloSec release that accepts this collector "
        "version. Do not edit the manifest.",
    ),
    "REPLACEMENT_PROJECT_NUMBER_MISMATCH": (
        "The replacement project number contradicts the existing project identity.",
        "Verify the canonical project ID and number before refreshing the assessment.",
    ),
    "CORRUPT_ARCHIVE": (
        "The ZIP structure or member CRC failed validation.",
        "Recreate or recopy the original archive; do not edit evidence.",
    ),
    "UNSAFE_ARCHIVE_PATH": (
        "An archive member has an unsafe path.",
        "Ask the collector owner to correct paths; safety checks remain enabled.",
    ),
    "UNSAFE_ARCHIVE_MEMBER": (
        "A link or unsupported filesystem member was found.",
        "Collect regular files only.",
    ),
    "DUPLICATE_ARCHIVE_PATH": (
        "Two entries collide after separator/case normalization.",
        "Create unique Windows-compatible paths.",
    ),
    "ARCHIVE_MANIFEST_REQUIRED": (
        "One supported package manifest is required.",
        "Supply the complete original collector package.",
    ),
    "UNSUPPORTED_MANIFEST_VERSION": (
        "This collector manifest version is unsupported.",
        "Use closec-gcp-1 or the documented pilot-1.2.2 profile.",
    ),
    "MANIFEST_FILE_REFERENCE_MISMATCH": (
        "Manifest references do not match the package files.",
        "Supply the original complete package with matching paths.",
    ),
    "MISSING_DECLARED_EVIDENCE": (
        "A successful dataset's declared file is missing.",
        "Recopy the complete package or correct the collector.",
    ),
    "ARTIFACT_CHECKSUM_MISMATCH": (
        "Declared evidence checksums do not match bytes.",
        "Obtain the original intact package.",
    ),
    "GCP_PROJECT_IDENTITY_MISMATCH": (
        "Evidence contradicts the declared GCP project.",
        "Review the failing file and identity field in this session's job details. "
        "Match the canonical project ID and project number to the manifest; display names "
        "are not identities. Collect separate project packages; preserve original evidence.",
    ),
    "GCP_PROJECT_NUMBER_REQUIRED": (
        "Evidence names the project by number, but no project number was declared.",
        "For a guided JSON import, enter the GCP project number as well as the project ID "
        "and import again. For a collector package, recollect so project metadata is "
        "captured. Preserve original evidence.",
    ),
    "LEGACY_EMPTY_RECORD_MISMATCH": (
        "An EMPTY result contains records.",
        "Correct the collector status without rewriting original evidence.",
    ),
    "SHARED_RAW_SCOPE_DELETION_UNSUPPORTED": (
        "A raw file contains configurations owned by multiple scopes.",
        (
            "Separate collection packages are needed for safe permanent "
            "scoped deletion; no data was deleted."
        ),
    ),
    "SCOPE_CONFIRMATION_REQUIRED": (
        "Exact identifier and a second explicit confirmation are required.",
        "Review the preview and type the selected canonical identifier.",
    ),
    "FROZEN_EDITION_DECISION_REQUIRED": (
        "A finalised (frozen) edition includes this data.",
        "Nothing was deleted. Frozen editions are never altered or deleted automatically. "
        'To proceed, choose "Purge and mark edition superseded", type the account or '
        "project ID, give a reason and keep the pre-purge backup.",
    ),
    "SUPERSEDE_CONFIRMATION_REQUIRED": (
        "The account or project ID typed for the override does not match.",
        "Nothing was deleted. Type the exact ID of the affected account or project.",
    ),
    "SUPERSEDE_REASON_REQUIRED": (
        "A reason (10 to 2000 characters) is required to mark an edition superseded.",
        "Nothing was deleted. Enter why the frozen edition is superseded.",
    ),
    "SUPERSEDE_REQUIRES_BACKUP": (
        "Marking an edition superseded requires the pre-purge backup.",
        "Nothing was deleted. Keep the backup option selected.",
    ),
    "SUPERSEDE_BACKUP_UNVERIFIED": (
        "The pre-purge backup could not be confirmed to contain the frozen edition.",
        "Nothing was deleted. Check free space and permissions beside the workspace and retry.",
    ),
    "FINDING_ALREADY_EXCLUDED": (
        "This finding is already excluded from client reporting.",
        "Refresh the finding; use Undo in Excluded findings to include it again.",
    ),
    "FINDING_NOT_EXCLUDED": (
        "This finding is not excluded from client reporting.",
        "Refresh the finding; nothing needs to be undone.",
    ),
    "SCOPE_PREVIEW_STALE": (
        "Data changed after the deletion preview.",
        "Refresh the preview and confirm again.",
    ),
    "SCOPE_COMPACT_SCHEMA_MISMATCH": (
        "The working copy has a column the current database layout does not; nothing changed.",
        "Restart CloSec from the current release so the workspace is upgraded, then retry.",
    ),
    "REPLACEMENT_SCOPE_MISMATCH": (
        "The replacement package does not contain exactly the selected provider and scope.",
        "Choose a scope-specific collection package.",
    ),
}


def explanation(code: str) -> dict:
    message, action = EXPLANATIONS.get(
        code,
        (
            "Local validation refused this operation.",
            "Review the fixed error code and collection coverage; preserve original evidence.",
        ),
    )
    return {"error": code, "message": message, "action": action}
