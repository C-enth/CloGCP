import React, { useEffect, useState } from "react";
import { api, Row } from "./api";
import { PathDiagrams } from "./PathDiagram";

export const STAGE_LABELS: Record<string, string> = {
  TRIAGE: "Analyst triage",
  WITH_SRE: "With SRE",
  SRE_REVALIDATION: "Evidence changed: revalidate with SRE",
  NO_GAP_BAU: "No gap (BAU)",
  SRE_CONFIRMED_GAP: "Gap confirmed by SRE: analyst to confirm",
  CONFIRMED_VULNERABILITY: "Confirmed vulnerability",
  REJECTED: "Rejected by analyst",
};
const VERDICTS: [string, string][] = [
  ["SENT_TO_SRE", "Sent to SRE"],
  ["GAP_CONFIRMED", "Gap confirmed"],
  ["NO_GAP_BAU", "No gap (BAU)"],
  ["NEEDS_INFO", "SRE needs more information"],
];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function StageBadge({ stage }: { stage?: string }) {
  if (!stage) return null;
  return (
    <span className={"badge stage stage-" + stage.toLowerCase()}>
      {STAGE_LABELS[stage] || stage}
    </span>
  );
}

/** Record the SRE verdict for one finding; the analyst decision stays separate. */
export function SreSection({
  run,
  finding: f,
  analyst,
  onSaved,
  onConfirm,
  onError,
}: {
  run: string;
  finding: Row;
  analyst: string;
  onSaved: () => void;
  onConfirm: () => void;
  onError: (s: string) => void;
}) {
  const [verdict, setVerdict] = useState("SENT_TO_SRE"),
    [contact, setContact] = useState(f.sre?.sre_contact || ""),
    [reason, setReason] = useState(""),
    [busy, setBusy] = useState(false);
  const needsReason = verdict === "NO_GAP_BAU";
  const save = async () => {
    try {
      setBusy(true);
      await api(`/runs/${run}/sre`, {
        verdict,
        analyst,
        sre_contact: contact,
        reason,
        finding_ids: [f.finding_id],
      });
      onSaved();
    } catch (e: any) {
      onError(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="detail-section sre-section">
      <h3>SRE validation</h3>
      <p>
        Stage: <StageBadge stage={f.stage} />
      </p>
      {f.sre ? (
        <p>
          Latest SRE verdict:{" "}
          <strong>{VERDICTS.find(([k]) => k === f.sre.verdict)?.[1]}</strong>
          {f.sre.sre_contact && ` by ${f.sre.sre_contact}`} on{" "}
          {String(f.sre.recorded_at).slice(0, 10)} (recorded by{" "}
          {f.sre.recorded_by}){f.sre.reason && `: ${f.sre.reason}`}
        </p>
      ) : (
        <p>Not yet sent to SRE.</p>
      )}
      {f.stage === "SRE_CONFIRMED_GAP" && (
        <p className="sre-callout">
          SRE confirmed this gap.{" "}
          <button className="primary" disabled={busy} onClick={onConfirm}>
            Confirm as vulnerability
          </button>
        </p>
      )}
      <div className="sre-form">
        <label>
          SRE verdict
          <select
            aria-label="SRE verdict"
            value={verdict}
            onChange={(e) => setVerdict(e.target.value)}
          >
            {VERDICTS.map(([k, label]) => (
              <option key={k} value={k}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label>
          SRE name / team
          <input
            aria-label="SRE contact"
            value={contact}
            maxLength={200}
            onChange={(e) => setContact(e.target.value)}
          />
        </label>
        <label>
          {needsReason ? "BAU justification (required)" : "SRE comments"}
          <textarea
            aria-label="SRE comments"
            value={reason}
            maxLength={15900}
            onChange={(e) => setReason(e.target.value)}
          />
        </label>
        <button
          disabled={busy || (needsReason && !reason.trim())}
          onClick={save}
        >
          Record SRE verdict
        </button>
      </div>
    </section>
  );
}

/** Confirmed vulnerabilities only, consolidated, with exports and related attack paths. */
export function Finalized({
  run,
  provider,
  epoch,
  onSelect,
}: {
  run: string;
  provider: string;
  epoch: number;
  onSelect: (id: string) => void;
}) {
  const [data, setData] = useState<Row>(),
    [error, setError] = useState(""),
    [account, setAccount] = useState(""),
    [freezeConfirmed, setFreezeConfirmed] = useState(false),
    [freezeBusy, setFreezeBusy] = useState(false);
  const scope = provider === "Consolidated" ? "" : provider;
  useEffect(() => {
    let active = true;
    setData(undefined);
    setAccount("");
    setError("");
    api(`/runs/${run}/finalized?provider=${scope}`)
      .then((d) => active && setData(d))
      .catch((e) => active && setError(e.message));
    return () => {
      active = false;
    };
  }, [run, scope, epoch]);
  if (!data) return <p className="muted">{error || "Loading…"}</p>;
  const [accountProvider, ...accountRest] = account.split(":");
  const exportQuery = new URLSearchParams(
    account
      ? { provider: accountProvider, scope: accountRest.join(":") }
      : { provider: scope },
  ).toString();
  const shown = (data.findings as Row[]).filter(
    (f) => !account || `${f.provider}:${f.scope}` === account,
  );
  return (
    <>
      <section className="panel">
        <h2>Confirmed vulnerabilities</h2>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        {data.frozen ? (
          <p role="status">
            Frozen edition · {data.frozen_at} · {data.frozen_by}. Exports use
            the preserved content for GCP, AWS and the combined set.
          </p>
        ) : (
          <section aria-label="Freeze assessment edition">
            <p>
              Review is still open. Freeze creates an immutable edition of all
              confirmed findings across every imported account, with GCP, AWS
              and combined reports. Build and reconcile an enterprise snapshot
              containing all active imports first. Existing drafts are
              preserved.
            </p>
            <label>
              <input
                type="checkbox"
                aria-label="Confirm freeze assessment"
                checked={freezeConfirmed}
                onChange={(e) => setFreezeConfirmed(e.target.checked)}
              />
              I confirm the reviewed findings are ready to freeze.
            </label>
            <button
              disabled={!freezeConfirmed || freezeBusy}
              onClick={async () => {
                setFreezeBusy(true);
                try {
                  await api(`/runs/${run}/finalize`, { confirmed: true });
                  setData(
                    await api(`/runs/${run}/finalized?provider=${scope}`),
                  );
                  setError("");
                } catch (e: any) {
                  setError(e.message);
                } finally {
                  setFreezeBusy(false);
                }
              }}
            >
              Freeze finalised assessment
            </button>
          </section>
        )}
        <div className="toolbar">
          {["GCP", "AWS", ""].map((p) => (
            <span key={p}>
              {["xlsx", "docx"].map((format) => (
                <a
                  key={format}
                  className="button"
                  href={`/api/runs/${run}/finalized.${format}?provider=${p}`}
                >
                  {p || "GCP + AWS"} {format.toUpperCase()}
                </a>
              ))}
            </span>
          ))}
        </div>
        <p className="muted">
          Only findings you marked valid. An SRE response is optional; findings
          marked not valid are never listed. Select an account or project to
          download its own Excel and Word report.
        </p>
        <div className="finalized-metrics">
          <div className="metric">
            <span>Total</span>
            <strong>{data.findings.length}</strong>
          </div>
          {SEVERITIES.map((s) => (
            <div className="metric" key={s}>
              <span>{s[0] + s.slice(1).toLowerCase()}</span>
              <strong>{data.severity[s] || 0}</strong>
            </div>
          ))}
          {data.excluded !== undefined && (
            <div
              className="metric excluded-count"
              title="Listed under Excluded findings"
            >
              <span>Excluded</span>
              <strong>{data.excluded}</strong>
            </div>
          )}
        </div>
        <div className="toolbar">
          <a
            className="button"
            href={`/api/runs/${run}/finalized.xlsx?${exportQuery}`}
          >
            Download Excel
            {account ? " (this account)" : ""}
          </a>
          <a
            className="button"
            href={`/api/runs/${run}/finalized.docx?${exportQuery}`}
          >
            Download Word report
            {account ? " (this account)" : ""}
          </a>
          <label>
            Account / project
            <select
              aria-label="Finalized account"
              value={account}
              onChange={(e) => setAccount(e.target.value)}
            >
              <option value="">All accounts / projects</option>
              {(data.accounts as Row[]).map((a) => (
                <option
                  key={`${a.provider}:${a.scope}`}
                  value={`${a.provider}:${a.scope}`}
                >
                  {a.provider} · {a.name ? `${a.name} (${a.scope})` : a.scope} (
                  {a.total})
                </option>
              ))}
            </select>
          </label>
        </div>
      </section>
      {shown.length === 0 ? (
        <div className="empty">
          <p>
            No confirmed vulnerabilities yet. Open a finding in the Findings
            workbench and click Confirm (or tick several and use Mark valid); it
            appears here straight away.
          </p>
        </div>
      ) : (
        <section className="panel">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Vulnerability</th>
                  <th>Account / project</th>
                  <th>Resource</th>
                  <th>Checklist control</th>
                  <th>SRE confirmation</th>
                  <th>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((f) => (
                  <React.Fragment key={f.id}>
                    <tr>
                      <td>
                        <span className={"badge " + f.severity.toLowerCase()}>
                          {f.severity}
                        </span>
                      </td>
                      <td>{f.title}</td>
                      <td>
                        {f.provider} ·{" "}
                        {f.scope_name
                          ? `${f.scope_name} (${f.scope})`
                          : f.scope}
                      </td>
                      <td title={f.resource}>{f.resource}</td>
                      <td>{f.control}</td>
                      <td>
                        {f.sre_contact || "SRE"} · {f.sre_date}
                      </td>
                      <td>
                        <button
                          className="small"
                          onClick={() => onSelect(f.id)}
                        >
                          View
                        </button>
                      </td>
                    </tr>
                    <tr className="finalized-detail">
                      <td colSpan={7}>
                        <div className="explanation">
                          {(
                            [
                              ["Why this is flagged", f.why],
                              ["How it can be misused", f.misuse],
                              ["Impact", f.impact],
                              ["Recommendation", f.recommendation],
                            ] as [string, string][]
                          ).map(([t, v]) => (
                            <div className="explanation-part" key={t}>
                              <h4>{t}</h4>
                              <p>{v}</p>
                            </div>
                          ))}
                        </div>
                        {f.paths && (
                          <p className="muted">
                            Related attack paths: {f.paths}
                          </p>
                        )}
                      </td>
                    </tr>
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
      <section className="panel">
        <h2>Attack paths involving confirmed vulnerabilities</h2>
        <p className="muted">
          Paths, including cross-account and cross-project ones, built from
          observed configuration. FEASIBLE means every checkable prerequisite is
          in evidence; exploitation was not performed.
        </p>
        {data.paths.length === 0 ? (
          <p>No evaluated attack path includes a confirmed vulnerability.</p>
        ) : (
          <PathDiagrams
            paths={(data.paths as Row[]).map((p) => ({
              ...p,
              attack_path: p.path,
            }))}
          />
        )}
      </section>
    </>
  );
}
