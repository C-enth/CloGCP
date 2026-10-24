import { api, type Row } from "./api";

const names: Record<string, string> = {
  PENDING: "Waiting for local worker",
  UPLOAD_LOCAL_TRANSFER: "Local file transfer",
  PACKAGE_VALIDATION: "Package validation",
  ARCHIVE_VALIDATION: "Archive safety and extraction",
  MANIFEST_IDENTIFICATION: "Identifying manifest",
  EVIDENCE_PARSING: "Parsing evidence",
  RESOURCE_NORMALIZATION: "Normalizing resources",
  DATABASE_COMMIT: "Committing database transaction",
  PACKAGE_READY: "Validated package ready to import",
  SECURITY_ANALYSIS: "Security analysis",
  SOURCE_INTEGRITY: "Checking stored source integrity",
  SNAPSHOT_NORMALIZATION: "Building normalized snapshot",
  SNAPSHOT_COMMIT: "Publishing normalized snapshot",
  CORRELATION: "Correlating supported relationships",
  REPORT_EXPORT: "Generating report",
  REPORT_PUBLICATION: "Publishing completed report",
  SCOPE_BACKUP: "Backing up the workspace before deletion",
  SCOPE_VERIFY_BEFORE: "Recording references before deletion",
  SCOPE_STAGING: "Preparing a private working copy",
  SCOPE_PURGE: "Removing the selected data",
  SCOPE_REASSESS: "Re-assessing affected runs",
  SCOPE_COMPACT: "Writing a compact database without the removed data",
  SCOPE_PUBLISH: "Installing the updated database",
  SCOPE_VERIFY_AFTER: "Verifying nothing of the removed data remains",
};
export function JobDetails({
  job,
  now,
  onJob,
  onError,
}: {
  job: Row;
  now: number;
  onJob: (job: Row) => void;
  onError: (error: string) => void;
}) {
  const active = ["QUEUED", "RUNNING"].includes(job.status);
  const diagnostics = job.result?.diagnostics;
  const sources: Row[] = diagnostics?.sources || [];
  const supported = sources.filter(
    (source) => source.parser_supported !== false,
  ).length;
  const errors = sources.filter(
    (source) => source.effective_coverage === "ERROR",
  ).length;
  return (
    <section className="panel job-details" aria-label="Local operation details">
      <div className="toolbar" role="status">
        <b>{job.kind}</b>
        <span className="badge">{job.status}</span>
        <span>
          {job.state || job.status} · {names[job.stage] || job.stage}
        </span>
        <span>
          {Math.max(
            0,
            Math.round(
              ((job.finished_at ? job.finished_at * 1000 : now) -
                job.submitted_at * 1000) /
                1000,
            ),
          )}{" "}
          s elapsed
        </span>
        {active && job.cancel_supported && (
          <button
            onClick={() =>
              api(`/jobs/${job.id}/cancel`, {})
                .then(onJob)
                .catch((error) => onError(error.message))
            }
          >
            Cancel job
          </button>
        )}
      </div>
      {job.progress?.completed != null && (
        <p>
          Processing count: {job.progress.completed.toLocaleString()}
          {job.progress.total != null
            ? " / " + job.progress.total.toLocaleString()
            : " (total not yet known)"}
        </p>
      )}
      {job.error && (
        <p role="alert">
          {job.error} —{" "}
          {job.explanation?.message || "This operation did not complete."}{" "}
          {job.explanation?.action ||
            "Retry the unchanged package; previous runs remain available."}
        </p>
      )}
      {job.manifest_detection && (
        <dl aria-label="Manifest detection details">
          <dt>Detected manifest filename</dt>
          <dd>{job.manifest_detection.filename}</dd>
          <dt>Detected schema version</dt>
          <dd>{job.manifest_detection.detected_version}</dd>
          <dt>Selected adapter</dt>
          <dd>{job.manifest_detection.selected_adapter}</dd>
          <dt>Expected versions</dt>
          <dd>{job.manifest_detection.expected_versions.join(", ")}</dd>
          {job.manifest_detection.rejection_condition && (
            <>
              <dt>Exact reason for rejection</dt>
              <dd>{job.manifest_detection.rejection_condition}</dd>
              <dt>Suggested corrective action</dt>
              <dd>{job.manifest_detection.corrective_action}</dd>
            </>
          )}
        </dl>
      )}
      {job.identity_context && (
        <section aria-label="Project identity mismatch details">
          <h3>Project identity mismatch</h3>
          <p>
            Session-only details; excluded from diagnostic downloads and saved
            job history.
          </p>
          <dl>
            {Object.entries(job.identity_context).map(([k, v]) => (
              <div key={k}>
                <dt>{k.replaceAll("_", " ")}</dt>
                <dd>{String(v)}</dd>
              </div>
            ))}
          </dl>
          <p>
            {job.error === "GCP_PROJECT_NUMBER_REQUIRED"
              ? "The observed identity is a project number. Enter the GCP project number with the project ID and import again."
              : "Recollect this project and file with matching canonical identity metadata. Preserve the original package."}
          </p>
        </section>
      )}
      {job.limit && (
        <p>
          Exceeded {job.limit.name}: {job.limit.observed.toLocaleString()}{" "}
          bytes; allowed {job.limit.allowed.toLocaleString()} bytes.
        </p>
      )}
      {active && (
        <p className="muted">
          Other job actions are disabled until this operation completes. Health
          and job details remain available.
        </p>
      )}
      {active && !job.cancel_supported && (
        <p className="muted">
          Publication has started; cancellation is closed. Wait for the terminal
          job result.
        </p>
      )}
      <details>
        <summary>View Import Details</summary>
        <dl>
          <dt>Job ID</dt>
          <dd>{job.id}</dd>
          <dt>Provider</dt>
          <dd>{job.provider}</dd>
          {job.scopes?.length > 0 && (
            <>
              <dt>Account/project</dt>
              <dd>{job.scopes.join(", ")}</dd>
            </>
          )}
          <dt>Mode</dt>
          <dd>{job.import_mode}</dd>
          <dt>Manifest version</dt>
          <dd>{job.manifest_version || "Not identified yet"}</dd>
          {job.collection_id && (
            <>
              <dt>Collection identity</dt>
              <dd>{job.collection_id}</dd>
            </>
          )}
          <dt>Selected/package files</dt>
          <dd>{job.files_total ?? "Not counted yet"}</dd>
          <dt>Last actual progress</dt>
          <dd>{job.last_progress_at}</dd>
          <dt>Worker heartbeat</dt>
          <dd>{job.heartbeat_at}</dd>
          {sources.length > 0 && (
            <>
              <dt>Supported datasets</dt>
              <dd>{supported}</dd>
              <dt>Unsupported datasets</dt>
              <dd>{sources.length - supported}</dd>
              <dt>Collection errors</dt>
              <dd>{errors}</dd>
            </>
          )}
          {job.result?.run_id && (
            <>
              <dt>Completed run</dt>
              <dd>{job.result.run_id}</dd>
            </>
          )}
        </dl>
        {diagnostics?.original_status_totals && (
          <p>
            Dataset status totals:{" "}
            {JSON.stringify(diagnostics.original_status_totals)}
          </p>
        )}
      </details>
      <a className="button" href={`/api/jobs/${job.id}/diagnostic`} download>
        Export Sanitized Diagnostic Report
      </a>
    </section>
  );
}
