// Bulk import of AWS batch-collector packages from one local folder, and business-group
// shards when one enterprise snapshot cannot hold every import. Results come from the API
// (ingestion/bulk.py, enterprise/shards.py); nothing here infers coverage.
import { useEffect, useState } from "react";
import { api, display, type Row } from "./api";

type StartJob = (
  path: string,
  body?: Row,
  after?: (result: Row) => void,
) => Promise<void>;

const STATUS_LABEL: Record<string, string> = {
  IMPORTED: "Imported",
  ALREADY_IMPORTED: "Already imported",
  SUPERSEDED: "Superseded (older collection)",
  REJECTED: "Rejected",
};

export function BulkImport({
  startJob,
  busy,
}: {
  startJob: StartJob;
  busy: boolean;
}) {
  const [folder, setFolder] = useState("");
  const [expected, setExpected] = useState("");
  const [analyze, setAnalyze] = useState(true);
  const [report, setReport] = useState<Row | null>(null);
  const counts = report?.counts || {};
  const recon = report?.reconciliation || {};
  return (
    <section className="panel bulk-import" aria-labelledby="bulk-import-title">
      <h2 id="bulk-import-title">Bulk import (AWS batch collection)</h2>
      <p className="muted">
        Imports every package ZIP in one folder written by the batch collector
        (one account per package). Each package is validated and imported on its
        own; a rejected package never stops the others. For each account the
        latest collection is imported and older ones are shown as superseded.
        Running the same folder again resumes.
      </p>
      <label>
        Package folder on this computer
        <input
          value={folder}
          onChange={(e) => setFolder(e.target.value)}
          placeholder="/path/to/batch-output/evidence"
          aria-describedby="bulk-folder-help"
        />
      </label>
      <p id="bulk-folder-help" className="muted">
        The evidence folder inside the batch output (contains the .zip and
        .zip.sha256 files).
      </p>
      <label>
        Expected account IDs (optional, one per line or the batch accounts CSV)
        <textarea
          rows={4}
          value={expected}
          onChange={(e) => setExpected(e.target.value)}
        />
      </label>
      <label className="inline">
        <input
          type="checkbox"
          checked={analyze}
          onChange={(e) => setAnalyze(e.target.checked)}
        />
        Analyze each package after import
      </label>
      <button
        disabled={busy || !folder.trim()}
        onClick={() =>
          startJob(
            "/bulk-import",
            { folder: folder.trim(), expected_accounts: expected, analyze },
            setReport,
          )
        }
      >
        Import all packages
      </button>
      {report && (
        <div className="bulk-report" role="status">
          <p>
            <strong>
              {counts.IMPORTED || 0} imported, {counts.ALREADY_IMPORTED || 0}{" "}
              already imported, {counts.SUPERSEDED || 0} superseded,{" "}
              {counts.REJECTED || 0} rejected
            </strong>{" "}
            of {report.packages?.length || 0} packages.
          </p>
          {"expected" in recon && (
            <p className={recon.missing?.length ? "warning" : ""}>
              Scope: {recon.matched} of {recon.expected} expected accounts
              collected; missing {recon.missing?.length || 0}, unexpected{" "}
              {recon.unexpected?.length || 0}, accounts with several packages{" "}
              {recon.duplicates?.length || 0}.
              {recon.missing?.length > 0 &&
                ` Missing: ${recon.missing.join(", ")}.`}
              {recon.unexpected?.length > 0 &&
                ` Unexpected: ${recon.unexpected.join(", ")}.`}
            </p>
          )}
          {report.fallbacks?.length > 0 && (
            <div role="alert" className="warning">
              {report.fallbacks.length} account(s): latest package invalid, fell
              back to an older collection.
              <ul>
                {report.fallbacks.map((f: Row) => (
                  <li key={f.account_id}>
                    {f.account_id}: imported {f.imported}; invalid{" "}
                    {f.invalid.join(", ")} ({f.codes.join(", ")})
                  </li>
                ))}
              </ul>
            </div>
          )}
          {report.expected_list_problems?.length > 0 && (
            <p className="warning">
              Expected list: {report.expected_list_problems.join("; ")}
            </p>
          )}
          <table>
            <thead>
              <tr>
                <th scope="col">Package</th>
                <th scope="col">Account</th>
                <th scope="col">Business group</th>
                <th scope="col">Collected</th>
                <th scope="col">Collector</th>
                <th scope="col">Result</th>
              </tr>
            </thead>
            <tbody>
              {(report.packages || []).map((r: Row) => (
                <tr key={r.sha256}>
                  <td>{r.file}</td>
                  <td>{display(r.account_id)}</td>
                  <td>{display(r.business_group)}</td>
                  <td>{display(r.completed_at)}</td>
                  <td>{display(r.collector_version)}</td>
                  <td>
                    {STATUS_LABEL[r.status] || r.status}
                    {r.code ? ` (${r.code})` : ""}
                    {r.superseded_by ? ` — ${r.superseded_by}` : ""}
                    {r.fallback ? ` — ${r.fallback}` : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function ShardPanel({
  startJob,
  busy,
  members,
}: {
  startJob: StartJob;
  busy: boolean;
  members: string[] | null;
}) {
  const [plan, setPlan] = useState<Row | null>(null);
  const [view, setView] = useState<Row | null>(null);
  const [error, setError] = useState("");
  const check = async () => {
    setError("");
    try {
      setPlan(await api("/enterprise/shard-plan", { members }));
    } catch (e: any) {
      setError(e.message);
    }
  };
  const showCombined = async (result: Row) => {
    if (result?.shard_set)
      setView(await api("/enterprise/shards/" + result.shard_set));
  };
  return (
    <section className="panel shard-plan" aria-labelledby="shard-title">
      <h2 id="shard-title">Snapshot size and business-group shards</h2>
      <p className="muted">
        One enterprise snapshot holds at most{" "}
        {plan?.limits?.observations?.toLocaleString() || "250,000"} observations
        and {plan?.limits?.members?.toLocaleString() || "2,048"} imports. Larger
        selections are assessed as one snapshot per business group with a
        combined view; relationships between groups are then not correlated.
      </p>
      <button disabled={busy} onClick={check}>
        Check snapshot size
      </button>
      {error && <p role="alert">{error}</p>}
      {plan && (
        <div role="status">
          <p>
            {plan.members} imports, {plan.observations.toLocaleString()}{" "}
            observations:{" "}
            {plan.single_snapshot_fits
              ? "fits one enterprise snapshot."
              : "exceeds one snapshot; assess by business group."}
          </p>
          <table>
            <thead>
              <tr>
                <th scope="col">Business group</th>
                <th scope="col">Imports</th>
                <th scope="col">Observations</th>
                <th scope="col">Fits</th>
              </tr>
            </thead>
            <tbody>
              {plan.shards.map((s: Row) => (
                <tr key={s.group}>
                  <td>{s.group}</td>
                  <td>{s.members.length}</td>
                  <td>{s.observations.toLocaleString()}</td>
                  <td>{s.fits ? "Yes" : "No — split this group further"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!plan.single_snapshot_fits && (
            <button
              disabled={busy}
              onClick={() =>
                startJob(
                  "/enterprise/assess-sharded",
                  { members, force: false },
                  showCombined,
                )
              }
            >
              Build business-group snapshots
            </button>
          )}
        </div>
      )}
      {view && <CombinedView view={view} />}
    </section>
  );
}

export function CombinedView({ view }: { view: Row }) {
  return (
    <div className="combined-view">
      <p role="alert" className="warning">
        {view.notice}
      </p>
      <table>
        <thead>
          <tr>
            <th scope="col">Business group</th>
            <th scope="col">Accounts</th>
            <th scope="col">Findings</th>
            <th scope="col">Excluded</th>
            <th scope="col">Severity</th>
          </tr>
        </thead>
        <tbody>
          {view.shards.map((s: Row) => (
            <tr key={s.run_id}>
              <td>{s.group}</td>
              <td>{s.accounts}</td>
              <td>{s.findings}</td>
              <td>{s.excluded_findings}</td>
              <td>
                {Object.entries(s.severity)
                  .map(([k, v]) => `${k} ${v}`)
                  .join(", ")}
              </td>
            </tr>
          ))}
          <tr>
            <th scope="row">All groups</th>
            <td>{view.totals.accounts}</td>
            <td>{view.totals.findings}</td>
            <td>{view.totals.excluded_findings}</td>
            <td />
          </tr>
        </tbody>
      </table>
    </div>
  );
}

/** Banner on a shard snapshot: never present a shard as the whole assessment. */
export function ShardBanner({ run }: { run: string }) {
  const [shard, setShard] = useState<Row | null>(null);
  const [view, setView] = useState<Row | null>(null);
  useEffect(() => {
    let live = true;
    setShard(null);
    setView(null);
    if (run)
      api(`/runs/${run}/enterprise/shard`)
        .then((r) => live && setShard(r.shard))
        .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [run]);
  if (!shard) return null;
  return (
    <div role="alert" className="truncation-banner shard-banner">
      <strong>
        Business-group shard: {shard.group}, one of {shard.groups.length}{" "}
        snapshots of this assessment.
      </strong>{" "}
      Relationships with other business groups are not correlated here.{" "}
      <button
        className="link"
        onClick={async () =>
          setView(await api("/enterprise/shards/" + shard.shard_set))
        }
      >
        Show combined view
      </button>
      {view && <CombinedView view={view} />}
    </div>
  );
}
