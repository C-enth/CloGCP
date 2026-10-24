import { useState } from "react";
import { type Row } from "./api";

// One guided path: SELECT EVIDENCE → VALIDATE → IMPORT → ANALYZE → OPEN RESULTS.
// The panel only describes persisted backend state; it never infers results.
export const STEPS = [
  "Select evidence",
  "Validate package",
  "Import evidence",
  "Run security analysis",
  "Open assessment results",
];

export function runLabel(r: Row): string {
  const scopes = [...(r.aws_accounts || []), ...(r.gcp_projects || [])];
  const scope =
    scopes.length === 0
      ? "scope unresolved"
      : scopes.length <= 2
        ? scopes.join(", ")
        : `${scopes.slice(0, 2).join(", ")} +${scopes.length - 2}`;
  const state = r.assessed
    ? `Assessed · ${r.finding_count} candidate finding${r.finding_count === 1 ? "" : "s"}`
    : "Imported · analysis not run";
  return `${r.enterprise ? "Enterprise consolidated snapshot" : r.provider} · ${scope} · ${String(
    r.created_at,
  ).slice(0, 16)} · ${state}${r.historical ? " · superseded" : ""}`;
}

export function pendingLabel(p: Row): string {
  const scopes: string[] = p.scopes || [];
  return `${p.provider} · ${scopes.length ? scopes.join(", ") : "scope from manifest"} · ${
    p.manifest_version || "native package"
  }`;
}

export function WorkflowPanel({
  stage,
  job,
  pending,
  active,
  busy,
  showOpen,
  onImport,
  onAnalyze,
  onOpen,
  onNavigate,
}: {
  stage: number;
  job?: Row;
  pending: Row[];
  active?: Row;
  busy: boolean;
  showOpen: boolean;
  onImport: (upload: Row, analyze: boolean, acknowledged: boolean) => void;
  onAnalyze: () => void;
  onOpen: () => void;
  onNavigate: (screen: string) => void;
}) {
  const running = job && ["QUEUED", "RUNNING"].includes(job.status);
  const failed =
    job && ["FAILED", "CANCELLED", "INTERRUPTED"].includes(job.status);
  return (
    <section className="panel workflow" aria-label="Assessment workflow">
      <ol className="stepper">
        {STEPS.map((label, i) => (
          <li
            key={label}
            className={i < stage ? "done" : i === stage ? "current" : "todo"}
            aria-current={i === stage ? "step" : undefined}
          >
            <span>{i < stage ? "✓" : i + 1}</span>
            {label}
          </li>
        ))}
      </ol>
      {running && (
        <p role="status" className="workflow-status">
          <b>{job.kind}</b> in progress — {job.stage}. Other actions wait until
          it completes.{" "}
          <button
            className="small"
            onClick={() => onNavigate("Evidence import")}
          >
            View job details
          </button>
        </p>
      )}
      {!running && failed && (
        <p role="alert" className="workflow-status">
          <b>{job.kind}</b> {job.status.toLowerCase()}: {job.error}.{" "}
          {job.explanation?.action ||
            "Retry the unchanged package; previous runs remain available."}{" "}
          <button
            className="small"
            onClick={() => onNavigate("Evidence import")}
          >
            View job details
          </button>
        </p>
      )}
      {!running &&
        pending.map((p) => (
          <PendingImport
            key={p.upload_id}
            upload={p}
            busy={busy}
            onImport={onImport}
          />
        ))}
      {!running && active && !active.assessed && (
        <div className="workflow-action" role="status">
          <span>
            <b>Evidence imported; security analysis has not run</b> for{" "}
            {runLabel(active)}. Dashboards show no evaluations until it does.
          </span>
          <button className="primary" disabled={busy} onClick={onAnalyze}>
            Run security analysis
          </button>
        </div>
      )}
      {!running && active?.assessed && showOpen && (
        <div className="workflow-action" role="status">
          <span>
            <b>Analysis complete:</b> {active.evaluation_count} rule
            evaluations, {active.finding_count} candidate findings awaiting
            analyst review.
          </span>
          <button className="primary" onClick={onOpen}>
            Open assessment results
          </button>
        </div>
      )}
    </section>
  );
}

function PendingImport({
  upload,
  busy,
  onImport,
}: {
  upload: Row;
  busy: boolean;
  onImport: (upload: Row, analyze: boolean, acknowledged: boolean) => void;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const blocked =
    busy ||
    upload.importing ||
    (upload.legacy_acknowledgment_required && !acknowledged);
  return (
    <div className="workflow-action" role="status">
      <span>
        <b>Validated package not yet imported:</b> {pendingLabel(upload)}.
        Validation alone creates no assessment.
      </span>
      {upload.legacy_acknowledgment_required && (
        <label>
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
          />
          I acknowledge this package declares no source checksums; local hashes
          do not authenticate the collector.
        </label>
      )}
      <button
        className="primary"
        disabled={blocked}
        onClick={() => onImport(upload, true, acknowledged)}
      >
        Import and analyze
      </button>
      <button
        disabled={blocked}
        onClick={() => onImport(upload, false, acknowledged)}
      >
        Import only
      </button>
    </div>
  );
}
