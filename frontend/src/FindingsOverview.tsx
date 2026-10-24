import React, { useEffect, useState } from "react";
import { api, Row } from "./api";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const OPEN_STAGES = ["TRIAGE", "WITH_SRE", "SRE_REVALIDATION"];
const STAGE_COLUMNS: [string[], string][] = [
  [["TRIAGE"], "Analyst triage"],
  [["WITH_SRE", "SRE_REVALIDATION"], "With SRE"],
  [["NO_GAP_BAU"], "No gap (BAU)"],
  [["SRE_CONFIRMED_GAP"], "SRE confirmed gap"],
  [["CONFIRMED_VULNERABILITY"], "Confirmed vulnerability"],
  [["REJECTED"], "Rejected"],
];

/** Filter values actually present in the run, with counts and per-account totals. */
export function useFindingFacets(
  run: string,
  provider: string,
  epoch: number,
  enabled = true,
) {
  const [facets, setFacets] = useState<Row>();
  useEffect(() => {
    if (!enabled) return;
    let active = true;
    const scope = provider === "Consolidated" ? "" : provider;
    api(`/runs/${run}/finding-facets?provider=${encodeURIComponent(scope)}`)
      .then((d) => active && setFacets(d))
      .catch(() => active && setFacets(undefined));
    return () => {
      active = false;
    };
  }, [run, provider, epoch, enabled]);
  return facets;
}

export function accountLabel(a: Row): string {
  return `${a.provider} · ${a.name ? `${a.name} (${a.scope})` : a.scope || "Organization-wide"}`;
}

/** Account-wise view: severity and review stage per account, with SRE actions. */
export function FindingsByAccount({
  run,
  facets,
  selected,
  onSelect,
  onChanged,
  onError,
  reportControl,
  reportBusy,
  onReport,
  onManage,
}: {
  run: string;
  facets?: Row;
  selected: string;
  onSelect: (account: Row | null) => void;
  onChanged: () => void;
  onError: (s: string) => void;
  reportControl: React.ReactNode;
  reportBusy: boolean;
  onReport: (account: Row) => void;
  onManage: (account: Row) => void;
}) {
  const [open, setOpen] = useState(false),
    [busy, setBusy] = useState(false);
  const accounts: Row[] = facets?.accounts || [];
  if (accounts.length === 0) return null;
  const toggle = (
    <button aria-expanded={open} onClick={() => setOpen(!open)}>
      {`${open ? "Hide" : "Show"} findings by account (${accounts.length})`}
    </button>
  );
  if (!open) return <div className="account-overview">{toggle}</div>;
  const sendToSre = async (a: Row) => {
    try {
      setBusy(true);
      await api(`/runs/${run}/sre`, {
        verdict: "SENT_TO_SRE",
        provider: a.provider,
        scope: a.scope,
      });
      onChanged();
    } catch (e: any) {
      onError(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="panel account-overview">
      {toggle}
      <h2>Findings by account / project</h2>
      <p className="muted">
        Show filters the findings below to one account. Download an account's
        SRE workbook, share it with the SRE team, then mark its open findings as
        sent to SRE and record each verdict on the finding.
      </p>
      <div className="toolbar">
        <a className="button" href={`/api/runs/${run}/sre-workbooks.zip`}>
          Download all SRE workbooks (ZIP)
        </a>
        {reportControl}
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Account / project</th>
              <th>Total</th>
              {SEVERITIES.map((s) => (
                <th key={s}>{s[0] + s.slice(1).toLowerCase()}</th>
              ))}
              {STAGE_COLUMNS.map(([, label]) => (
                <th key={label}>{label}</th>
              ))}
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((a) => {
              const key = `${a.provider}:${a.scope}`;
              const stage = a.stage || {};
              const openCount = OPEN_STAGES.reduce(
                (n, s) => n + (stage[s] || 0),
                0,
              );
              return (
                <tr
                  key={key}
                  className={selected === key ? "selected-row" : ""}
                >
                  <td>{accountLabel(a)}</td>
                  <td>{a.total}</td>
                  {SEVERITIES.map((s) => (
                    <td key={s}>
                      {a.severity?.[s] ? (
                        <span className={"badge " + s.toLowerCase()}>
                          {a.severity[s]}
                        </span>
                      ) : (
                        0
                      )}
                    </td>
                  ))}
                  {STAGE_COLUMNS.map(([stages, label]) => (
                    <td key={label}>
                      {stages.reduce(
                        (n: number, s: string) => n + (stage[s] || 0),
                        0,
                      )}
                    </td>
                  ))}
                  <td className="account-actions">
                    <button
                      className="small"
                      aria-pressed={selected === key}
                      onClick={() => onSelect(selected === key ? null : a)}
                    >
                      {selected === key ? "Show all" : "Show"}
                    </button>
                    {a.scope && (
                      <>
                        <button
                          className="small"
                          disabled={reportBusy}
                          onClick={() => onReport(a)}
                        >
                          Excel + Word report
                        </button>
                        <button className="small" onClick={() => onManage(a)}>
                          Remove / replace data
                        </button>
                      </>
                    )}
                    {a.scope && openCount > 0 && (
                      <>
                        <a
                          className="button small"
                          href={`/api/runs/${run}/sre-workbook.xlsx?provider=${a.provider}&scope=${encodeURIComponent(a.scope)}`}
                        >
                          SRE workbook
                        </a>
                        <button
                          className="small"
                          disabled={busy}
                          onClick={() => sendToSre(a)}
                        >
                          Mark {openCount} sent to SRE
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/** The four plain-language answers shown at the top of every finding. */
export function FindingExplanation({ explanation }: { explanation?: Row }) {
  if (!explanation) return null;
  const parts: [string, string][] = [
    ["Why this is flagged", explanation.why_flagged],
    ["How it can be misused", explanation.misuse],
    ["Impact", explanation.impact],
    ["Recommendation", explanation.recommendation],
  ];
  return (
    <div className="explanation">
      {parts.map(([title, text]) => (
        <div key={title} className="explanation-part">
          <h4>{title}</h4>
          <p>
            {text ||
              "Not available for this rule; analyst assessment required."}
          </p>
        </div>
      ))}
    </div>
  );
}

export { SEVERITIES };
