import React, { useEffect, useRef, useState } from "react";
import { api, type Row } from "./api";

export function SupplementaryAnalysis({ run }: { run: string }) {
  const [imports, setImports] = useState<Row[]>([]);
  const [delta, setDelta] = useState("");
  const [result, setResult] = useState<Row | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const selected = useRef(run);
  selected.current = run;
  useEffect(() => {
    let active = true;
    setDelta("");
    setResult(null);
    setError("");
    api("/supplementary-imports")
      .then((r) => {
        if (active) setImports(r.items.filter((i: Row) => i.run_id !== run));
      })
      .catch((e) => active && setError(e.message));
    return () => {
      active = false;
    };
  }, [run]);
  async function apply() {
    if (busy || !delta) return;
    const base = run;
    setBusy(true);
    setError("");
    try {
      let job = await api(`/runs/${base}/supplementary-analysis`, {
        delta_run: delta,
      });
      while (["RUNNING", "QUEUED"].includes(job.status)) {
        await new Promise((resolve) => setTimeout(resolve, 750));
        job = await api(`/jobs/${job.id}`);
      }
      if (job.status !== "SUCCEEDED")
        throw new Error(job.error || "Supplementary analysis failed");
      if (selected.current === base) setResult(job.result);
    } catch (e: any) {
      if (selected.current === base) setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section aria-label="Supplementary evidence analysis">
      <h3>Apply supplementary evidence</h3>
      <p>
        Import the delta package through Evidence import first, then select its
        immutable snapshot. This creates a new analysis version. Existing
        findings and completed validations remain available. Shared IAM context
        requires the existing security evaluators to run in the new version.
      </p>
      <label>
        Imported supplementary snapshot{" "}
        <select
          aria-label="Imported supplementary snapshot"
          value={delta}
          disabled={busy}
          onChange={(e) => setDelta(e.target.value)}
        >
          <option value="">Select imported delta evidence</option>
          {imports.map((i) => (
            <option key={i.run_id} value={i.run_id}>
              {i.created_at} · {i.run_id}
            </option>
          ))}
        </select>
      </label>
      <button disabled={busy || !delta} onClick={apply}>
        {busy
          ? "Creating analysis version…"
          : "Create affected analysis version"}
      </button>
      {error && <p role="alert">{error}</p>}
      {result && (
        <div role="status">
          <p>
            New analysis version: {result.run_id}. Select it in Active evidence
            run to inspect and export it.
          </p>
          <button onClick={() => window.location.reload()}>
            Refresh assessments
          </button>
          <p>
            Collection dates remain separate. Simultaneous configuration state
            is unverified. Unchanged evidence-bound reviews remain valid;
            changed findings require review.
          </p>
          <table aria-label="Supplementary findings reconciliation">
            <thead>
              <tr>
                <th>Finding</th>
                <th>Reconciliation</th>
                <th>Current validation</th>
              </tr>
            </thead>
            <tbody>
              {result.composition.reconciliation.map((r: Row) => (
                <tr key={r.finding_id}>
                  <td>{r.finding_id}</td>
                  <td>{r.state}</td>
                  <td>{r.current_validation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
