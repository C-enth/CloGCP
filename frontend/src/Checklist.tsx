import { ChoiceFilter } from "./Filters";
import React, { useEffect, useMemo, useState } from "react";
import { api, Row } from "./api";

const OUTCOMES = [
  "FAIL",
  "INSUFFICIENT EVIDENCE",
  "MANUAL VALIDATION",
  "PASS",
  "NOT APPLICABLE",
  "NOT ASSESSED",
];
const tone: Record<string, string> = {
  FAIL: "critical",
  "INSUFFICIENT EVIDENCE": "unknown",
  "MANUAL VALIDATION": "needs-validation",
  PASS: "pass",
  "NOT APPLICABLE": "denied-by-evidence",
  "NOT ASSESSED": "",
};

function Outcome({ value }: { value: string }) {
  return <span className={"badge " + (tone[value] || "")}>{value}</span>;
}

/** The approved checklist as the assessment plan: one control list for both clouds. */
export function Checklist({
  run,
  provider,
  epoch,
  openFindings,
}: {
  run: string;
  provider: string;
  epoch: number;
  openFindings: (control: string) => void;
}) {
  const [data, setData] = useState<Row>(),
    [error, setError] = useState(""),
    [domain, setDomain] = useState(""),
    [outcome, setOutcome] = useState(""),
    [scope, setScope] = useState("cloud"),
    [query, setQuery] = useState(""),
    [open, setOpen] = useState("");
  useEffect(() => {
    setError("");
    api(`/runs/${run}/checklist`)
      .then(setData)
      .catch((e) => setError(e.message));
  }, [run, epoch]);
  const clouds: string[] =
    provider === "AWS" || provider === "GCP"
      ? [provider]
      : data?.providers?.length
        ? data.providers
        : ["AWS", "GCP"];
  const items: Row[] = data?.items || [];
  const domains = useMemo(
    () => [...new Set(items.map((r) => r.checklist_domain))],
    [items],
  );
  const visible = items.filter(
    (r) =>
      (!domain || r.checklist_domain === domain) &&
      (scope === "all" || clouds.some((c) => r.applies.includes(c))) &&
      (!outcome ||
        clouds.some((c) => r[c.toLowerCase()].outcome === outcome)) &&
      (!query ||
        `${r.control_id} ${r.checklist_title} ${r.checklist_area} ${r.gcp_check}`
          .toLowerCase()
          .includes(query.toLowerCase())),
  );
  const totals = (cloud: string) => {
    const counts: Record<string, number> = {};
    for (const r of items)
      if (r.applies.includes(cloud)) {
        const o = r[cloud.toLowerCase()].outcome;
        counts[o] = (counts[o] || 0) + 1;
      }
    return counts;
  };
  return (
    <section className="panel" aria-label="Assessment checklist">
      <h2>Assessment checklist</h2>
      <p>
        The approved checklist is the assessment plan for both clouds. Each
        control shows an outcome per cloud derived from rule results. No control
        is reported PASS automatically: when automated checks pass, the
        remaining criteria still need analyst validation. Controls outside cloud
        evidence (directory, on-premises, network devices) are marked NOT
        APPLICABLE for the cloud workstream.
      </p>
      {error && <p className="error">{error}</p>}
      <div className="metric-grid">
        {clouds.map((cloud) => {
          const t = totals(cloud);
          const applicable = items.filter((r) =>
            r.applies.includes(cloud),
          ).length;
          return (
            <div className="metric" key={cloud}>
              <span>{cloud} controls in scope</span>
              <strong>{applicable}</strong>
              <small>
                {OUTCOMES.filter((o) => t[o])
                  .map((o) => `${o} ${t[o]}`)
                  .join(" · ") || "No results"}
              </small>
            </div>
          );
        })}
      </div>
      <div className="toolbar">
        <ChoiceFilter
          label="Search controls"
          value={query}
          options={items.map((r) => r.control_id)}
          all="All controls"
          onChange={setQuery}
        />
        <select
          aria-label="Checklist domain"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
        >
          <option value="">All domains</option>
          {domains.map((d) => (
            <option key={d}>{d}</option>
          ))}
        </select>
        <select
          aria-label="Control outcome"
          value={outcome}
          onChange={(e) => setOutcome(e.target.value)}
        >
          <option value="">All outcomes</option>
          {OUTCOMES.map((o) => (
            <option key={o}>{o}</option>
          ))}
        </select>
        <select
          aria-label="Control scope"
          value={scope}
          onChange={(e) => setScope(e.target.value)}
        >
          <option value="cloud">Cloud controls only</option>
          <option value="all">All 204 controls</option>
        </select>
        <span className="muted">
          {visible.length} of {items.length} controls
        </span>
      </div>
      <div className="table-wrap">
        <table aria-label="Checklist controls">
          <thead>
            <tr>
              <th>Control</th>
              <th>Domain / area</th>
              <th>Control subject</th>
              {clouds.map((c) => (
                <th key={c}>{c} outcome</th>
              ))}
              <th>Findings</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((r) => (
              <React.Fragment key={r.control_id}>
                <tr
                  className="clickable"
                  onClick={() =>
                    setOpen(open === r.control_id ? "" : r.control_id)
                  }
                >
                  <td>
                    <strong>{r.control_id}</strong>
                  </td>
                  <td>
                    {r.checklist_domain}
                    <br />
                    <small className="muted">{r.checklist_area}</small>
                  </td>
                  <td>{r.checklist_title}</td>
                  {clouds.map((c) => (
                    <td key={c}>
                      <Outcome value={r[c.toLowerCase()].outcome} />
                    </td>
                  ))}
                  <td>
                    {clouds.reduce((n, c) => n + (r.findings?.[c] || 0), 0) ? (
                      <button
                        className="small"
                        onClick={(e) => {
                          e.stopPropagation();
                          openFindings(r.control_id);
                        }}
                      >
                        {clouds.reduce((n, c) => n + (r.findings?.[c] || 0), 0)}{" "}
                        findings
                      </button>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
                {open === r.control_id && (
                  <tr>
                    <td colSpan={4 + clouds.length}>
                      {clouds.map((c) => {
                        const cell = r[c.toLowerCase()];
                        return (
                          <p key={c}>
                            <strong>{c}:</strong> {cell.basis}.{" "}
                            {cell.rules.length
                              ? `Rules: ${cell.rules.join(", ")}. `
                              : "No automated rule. "}
                            {Object.keys(cell.results).length
                              ? `Rule results: ${Object.entries(cell.results)
                                  .map(([k, v]) => `${k} ${v}`)
                                  .join(", ")}.`
                              : ""}
                          </p>
                        );
                      })}
                      {r.gcp_check && clouds.includes("GCP") && (
                        <p>
                          <strong>GCP check area:</strong> {r.gcp_check}
                          {r.gcp_evidence.length
                            ? ` (evidence: ${r.gcp_evidence.join(", ")})`
                            : " (interview or admin export)"}
                        </p>
                      )}
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
