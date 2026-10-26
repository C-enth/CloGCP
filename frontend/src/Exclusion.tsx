import { useEffect, useState } from "react";
import { api, type Row } from "./api";
import { useIdentity } from "./FindingView";

const NO_DELETE =
  "Excluding hides this finding from client reporting: lists, counts, charts and Word " +
  "and Excel exports. Evidence and the evaluated finding are kept unchanged, so the " +
  "exclusion can be undone and the trail stays verifiable. Single findings are never " +
  "hard-deleted; to remove data, delete the account or project in Manage Assessment Data.";

function useExclusions(run: string, epoch: number, provider = "") {
  const [data, setData] = useState<Row>();
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    setError("");
    api(`/runs/${run}/exclusions?provider=${provider}`)
      .then((d) => live && setData(d))
      .catch((e) => live && setError(e.message));
    return () => {
      live = false;
    };
  }, [run, epoch, provider]);
  return { data, error };
}

async function change(run: string, finding: string, body: Row) {
  return api(`/runs/${run}/exclusions/${finding}`, body);
}

/** "Exclude from report" in the Client Reporting tab; requires a reason. */
export function ExcludeControl({
  run,
  findingId,
  analyst,
  onChanged,
  onError,
}: {
  run: string;
  findingId: string;
  analyst: string;
  onChanged: () => void;
  onError: (s: string) => void;
}) {
  const [epoch, setEpoch] = useState(0);
  const { data } = useExclusions(run, epoch);
  const [reason, setReason] = useState(""),
    [note, setNote] = useState(""),
    [busy, setBusy] = useState(false);
  if (!data) return null;
  const current = (data.items as Row[]).find((i) => i.id === findingId);
  const submit = async (body: Row) => {
    setBusy(true);
    try {
      await change(run, findingId, { ...body, analyst: analyst || "Analyst" });
      setReason("");
      setNote("");
      setEpoch((e) => e + 1);
      onChanged();
    } catch (e: any) {
      onError(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section
      className="detail-section exclusion"
      aria-label="Exclude from report"
    >
      <h3>Exclude from report</h3>
      {current ? (
        <>
          <p role="status">
            Excluded from client reporting: {current.reason_label}
            {current.note && ` — ${current.note}`} · {current.analyst} ·{" "}
            {String(current.excluded_at).slice(0, 10)}
          </p>
          <button
            disabled={busy}
            onClick={() => submit({ action: "RESTORE" })}
            title="Include this finding in client reporting again"
          >
            Undo exclusion
          </button>
        </>
      ) : (
        <>
          <p className="muted" title={NO_DELETE}>
            Hides the finding from client reports; evidence is kept and the
            exclusion can be undone. ⓘ
          </p>
          <div className="exclusion-fields">
            <label>
              Reason
              <select
                aria-label="Exclusion reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              >
                <option value="">Choose a reason…</option>
                {Object.entries(data.reasons as Record<string, string>).map(
                  ([key, label]) => (
                    <option key={key} value={key}>
                      {label}
                    </option>
                  ),
                )}
              </select>
            </label>
            <label>
              Note{" "}
              {reason === "OTHER" || reason === "FALSE_POSITIVE"
                ? "(required)"
                : "(optional)"}
              <input
                aria-label="Exclusion note"
                value={note}
                maxLength={2000}
                onChange={(e) => setNote(e.target.value)}
              />
            </label>
          </div>
          <button
            className="danger"
            title={NO_DELETE}
            disabled={
              busy ||
              !reason ||
              (["OTHER", "FALSE_POSITIVE"].includes(reason) && !note.trim())
            }
            onClick={() => submit({ action: "EXCLUDE", reason, note })}
          >
            Exclude from report
          </button>
        </>
      )}
    </section>
  );
}

/** Clearly labelled list of excluded findings with Undo; shown in Client Reporting. */
export function ExcludedFindings({
  run,
  provider,
  epoch,
  onChanged,
}: {
  run: string;
  provider: string;
  epoch: number;
  onChanged: () => void;
}) {
  const analyst = useIdentity();
  const [local, setLocal] = useState(0);
  const { data, error } = useExclusions(run, epoch + local, provider);
  const [message, setMessage] = useState("");
  if (!data) return error ? <p role="alert">{error}</p> : null;
  const items = data.items as Row[];
  return (
    <section className="panel" aria-label="Excluded findings">
      <h2>Excluded findings ({items.length})</h2>
      <p className="muted" title={NO_DELETE}>
        Not shown in client reporting, counts, charts or exports. Evidence is
        unchanged; Undo includes a finding again. Frozen editions keep their
        preserved content.
      </p>
      {message && <p role="alert">{message}</p>}
      {items.length === 0 ? (
        <p className="muted">No findings are excluded.</p>
      ) : (
        <div className="table-wrap">
          <table aria-label="Excluded findings list">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Account / project</th>
                <th>Reason</th>
                <th>Excluded</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.id}>
                  <td>
                    <span
                      className={"badge " + String(i.severity).toLowerCase()}
                    >
                      {i.severity}
                    </span>
                  </td>
                  <td>{i.title}</td>
                  <td>
                    {i.provider} {i.scope}
                  </td>
                  <td>
                    {i.reason_label}
                    {i.note && <small className="muted"> — {i.note}</small>}
                  </td>
                  <td>
                    {String(i.excluded_at).slice(0, 10)} · {i.analyst}
                  </td>
                  <td>
                    <button
                      className="small"
                      onClick={async () => {
                        try {
                          await change(run, i.id, {
                            action: "RESTORE",
                            analyst: analyst || "Analyst",
                          });
                          setMessage("");
                          setLocal((n) => n + 1);
                          onChanged();
                        } catch (e: any) {
                          setMessage(e.message);
                        }
                      }}
                    >
                      Undo
                    </button>
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

export const FALSE_POSITIVE_PRESETS = [
  "Google-managed service agent (platform-managed)",
  "AWS service-linked role (platform-managed)",
  "AWS IAM Identity Center reserved role (platform-managed)",
  "AWS Organizations / Control Tower management access role (platform-managed)",
];

/** Reason picker for a false-positive disposition: a preset or free text (required). */
export function FalsePositiveReason({
  value,
  onChange,
  label = "False-positive reason",
}: {
  value: string;
  onChange: (v: string) => void;
  label?: string;
}) {
  const preset = FALSE_POSITIVE_PRESETS.includes(value) ? value : "";
  return (
    <>
      <select
        aria-label={`${label} preset`}
        value={preset}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value="">Free text…</option>
        {FALSE_POSITIVE_PRESETS.map((p) => (
          <option key={p} value={p}>
            {p}
          </option>
        ))}
      </select>
      <input
        aria-label={label}
        placeholder="Reason (required)"
        value={value}
        maxLength={2000}
        onChange={(e) => onChange(e.target.value)}
      />
    </>
  );
}

/** "Mark as false positive" / "Restore" on one finding; the rule result is unchanged. */
export function FalsePositiveControl({
  run,
  findingId,
  analyst,
  onChanged,
  onError,
}: {
  run: string;
  findingId: string;
  analyst: string;
  onChanged: () => void;
  onError: (s: string) => void;
}) {
  const [epoch, setEpoch] = useState(0);
  const { data } = useExclusions(run, epoch);
  const [reason, setReason] = useState(""),
    [busy, setBusy] = useState(false);
  if (!data) return null;
  const current = (data.items as Row[]).find((i) => i.id === findingId);
  const submit = async (body: Row) => {
    setBusy(true);
    try {
      await change(run, findingId, { ...body, analyst: analyst || "Analyst" });
      setReason("");
      setEpoch((e) => e + 1);
      onChanged();
    } catch (e: any) {
      onError(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section
      className="detail-section false-positive"
      aria-label="False-positive disposition"
    >
      <h3>False positive</h3>
      {current?.false_positive ? (
        <>
          <p role="status">
            <span className="badge fp">FP</span> Marked as false positive:{" "}
            {current.note} · {current.analyst} ·{" "}
            {String(current.excluded_at).slice(0, 10)}
            {current.previous_state &&
              ` · previous state ${current.previous_state}`}
          </p>
          {current.carried_from && (
            <p className="muted">
              Carried over from import {current.carried_from}; review that it
              still applies.
            </p>
          )}
          <button disabled={busy} onClick={() => submit({ action: "RESTORE" })}>
            Restore
          </button>
        </>
      ) : current ? (
        <p className="muted">
          Excluded for another reason ({current.reason_label}); undo that
          exclusion first.
        </p>
      ) : (
        <>
          <p className="muted">
            The rule result stays FAIL; the finding leaves confirmed lists,
            severity totals and report sections and is listed in the Excluded
            findings appendix.
          </p>
          <div className="exclusion-fields">
            <FalsePositiveReason value={reason} onChange={setReason} />
          </div>
          <button
            className="danger"
            disabled={busy || !reason.trim()}
            onClick={() =>
              submit({
                action: "EXCLUDE",
                reason: "FALSE_POSITIVE",
                note: reason.trim(),
              })
            }
          >
            Mark as false positive
          </button>
        </>
      )}
    </section>
  );
}
