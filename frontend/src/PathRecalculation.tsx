import React, { useEffect, useRef, useState } from "react";
import { api, type Row } from "./api";

/** Independent path-only action on stored evidence, including finalized assessments. */
export function PathRecalculation({ run }: { run: string }) {
  const [result, setResult] = useState<Row | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const selected = useRef(run);
  selected.current = run;
  useEffect(() => {
    let active = true;
    setResult(null);
    setError("");
    api(`/runs/${run}/attack-path-evaluations`)
      .then((value) => active && setResult(value))
      .catch((e) => active && setError(e.message));
    return () => {
      active = false;
    };
  }, [run]);
  const recalculate = async () => {
    if (busy) return;
    const requested = run;
    setBusy(true);
    setError("");
    try {
      await api(`/runs/${requested}/attack-path-evaluations`, {}, 180000);
      const value = await api(`/runs/${requested}/attack-path-evaluations`);
      if (selected.current === requested) setResult(value);
    } catch (e: any) {
      if (selected.current === requested) setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section aria-label="Versioned attack-path recalculation">
      <h3>Recalculate existing assessment paths</h3>
      <p>
        Use the selected assessment’s stored evidence to create a separate path
        evaluation. Findings, analyst and SRE validations, and frozen reports
        remain unchanged.
      </p>
      <button onClick={recalculate} disabled={busy}>
        {busy ? "Recalculating attack paths…" : "Recalculate Attack Paths"}
      </button>
      {busy && (
        <p role="status">Evaluating stored GCP resources and prerequisites…</p>
      )}
      {error && <p role="alert">{error}</p>}
      {result?.latest && (
        <>
          <p role="status">
            Path evaluation saved. Engine {result.latest.engine_version}.{" "}
            {result.latest.new_path_count} qualified paths.
            {result.versions.length} version(s) retained. Existing findings and
            validations preserved.
          </p>
          {result.latest.truncated && (
            <p role="alert">
              Evaluation limits were reached. Results are incomplete; review the
              recorded limitations.
            </p>
          )}
          <p>
            Comparison source: {result.latest.prior_kind}. Configuration support
            does not verify exploitation. New paths require independent review.
          </p>
          <details open>
            <summary>Old versus new attack paths</summary>
            <table aria-label="Old versus new attack paths">
              <thead>
                <tr>
                  <th>Previous path</th>
                  <th>Previous state</th>
                  <th>New path</th>
                  <th>Qualified state</th>
                  <th>Change and reason</th>
                </tr>
              </thead>
              <tbody>
                {result.latest.comparison.map((r: Row, i: number) => (
                  <tr key={i}>
                    <td>{r.old_path_id || "Not previously modelled"}</td>
                    <td>{r.old_state}</td>
                    <td>{r.new_path_id || "Retained in history"}</td>
                    <td>{r.new_state}</td>
                    <td>
                      {r.change}: {r.reason}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
          <details>
            <summary>Current configuration prerequisites</summary>
            {(result.paths || []).map((p: Row) => (
              <article key={p.path_id}>
                <h4>
                  {p.family}: {p.classification}
                </h4>
                <p>
                  {p.entry_point} → {p.target}
                </p>
                <p>
                  {p.potential_impact} Execution: {p.exploitation_verification}.
                  Review: {p.analyst_review}.
                </p>
                <ul>
                  {p.prerequisites.map((c: Row, i: number) => (
                    <li key={i}>
                      {c.name}: {c.state}. {c.reason}
                    </li>
                  ))}
                </ul>
                <p>{p.recommended_remediation}</p>
              </article>
            ))}
          </details>
        </>
      )}
    </section>
  );
}
