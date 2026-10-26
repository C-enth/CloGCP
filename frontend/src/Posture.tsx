import { useEffect, useState } from "react";
import { api, type Row } from "./api";

const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
// Severity colours are theme-independent tokens (style.css); meaning never changes.
const colors = severities.map((s) => `var(--sev-chart-${s.toLowerCase()})`);

export function FindingsPie({
  providers,
  open,
}: {
  providers: Row;
  open: (severity: string) => void;
}) {
  const counts = severities.map((s) =>
    Object.values(providers).reduce(
      (n: number, p: any) => n + (p.severity[s] || 0),
      0,
    ),
  );
  const total = counts.reduce((a, b) => a + b, 0);
  // Findings excluded from client reporting are not in the slices; shown so totals reconcile.
  const excluded = Object.values(providers).reduce(
    (n: number, p: any) => n + (p.excluded_findings || 0),
    0,
  );
  let start = -Math.PI / 2;
  return (
    <section
      className="findings-posture"
      aria-label="Observed findings by criticality"
    >
      <div>
        <h3>Findings observed</h3>
        <p className="posture-total">{total}</p>
        <p
          className="excluded-count"
          title="Excluded from client reporting by the assessor; see Finalized findings"
        >
          {excluded} excluded from reporting · {total + excluded} observed in
          total
        </p>
        <p>Technical severity · select a slice to review matching findings.</p>
      </div>
      <svg
        viewBox="0 0 220 220"
        role="group"
        aria-label="Criticality pie chart"
      >
        {!total && (
          <circle
            cx="110"
            cy="110"
            r="92"
            style={{ fill: "var(--chart-empty)" }}
          />
        )}
        {counts.map((count, i) => {
          if (!count) return null;
          const end = start + (2 * Math.PI * count) / total;
          const x1 = 110 + 92 * Math.cos(start),
            y1 = 110 + 92 * Math.sin(start);
          const x2 = 110 + 92 * Math.cos(end),
            y2 = 110 + 92 * Math.sin(end);
          const d = `M110,110 L${x1},${y1} A92,92 0 ${end - start > Math.PI ? 1 : 0},1 ${x2},${y2} Z`;
          start = end;
          const common = {
            style: { fill: colors[i] },
            role: "button",
            tabIndex: 0,
            "aria-label": `${severities[i]} findings: ${count}`,
            onClick: () => open(severities[i]),
            onKeyDown: (e: any) => {
              if (["Enter", " "].includes(e.key)) {
                e.preventDefault();
                open(severities[i]);
              }
            },
          };
          return count === total ? (
            <circle key={i} cx="110" cy="110" r="92" {...common}>
              <title>
                {severities[i]} {count}
              </title>
            </circle>
          ) : (
            <path key={i} d={d} {...common}>
              <title>
                {severities[i]} {count}
              </title>
            </path>
          );
        })}
      </svg>
      <div className="severity-legend">
        {severities.map((s, i) => (
          <button key={s} onClick={() => open(s)} disabled={!counts[i]}>
            <span style={{ background: colors[i] }} />
            {s} <b>{counts[i]}</b>
          </button>
        ))}
      </div>
    </section>
  );
}

export function EstateSummary({
  epoch,
  provider,
}: {
  epoch: number;
  provider: string;
}) {
  const [data, setData] = useState<Row>(),
    [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    api("/workspace/scope-summary")
      .then((d) => {
        if (live) {
          setData(d);
          setError("");
        }
      })
      .catch((e) => {
        if (live) setError(e.message);
      });
    return () => {
      live = false;
    };
  }, [epoch]);
  if (error) return <p role="alert">{error}</p>;
  if (!data) return <p>Loading imported account summary…</p>;
  const clouds = provider === "Consolidated" ? ["GCP", "AWS"] : [provider];
  return (
    <section aria-label="Static account summary">
      <h3>Accounts and projects imported</h3>
      <p>
        {data.qualification} This summary stays independent of the active
        account or run selection.
      </p>
      <div className="cloud-cards">
        {clouds.map((p) => (
          <div className="metric" key={p}>
            <span>{p} imported scopes</span>
            <strong>{data.providers[p].length}</strong>
            <p>{data.providers[p].join(", ") || "None imported"}</p>
          </div>
        ))}
      </div>
      <div className="table-wrap">
        <table aria-label="Accounts covered per domain">
          <thead>
            <tr>
              <th>Domain</th>
              {clouds.map((p) => (
                <th key={p}>{p} accounts / projects</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.domains.map((d: Row) => (
              <tr key={d.domain}>
                <td>{d.domain}</td>
                {clouds.map((p) => (
                  <td key={p}>
                    {d[p].join(", ") || "No domain evidence imported"}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function PostureSummary({ data }: { data: Row }) {
  const validation = data.snapshot_validation;
  return (
    <>
      <section aria-label="Security posture">
        <h3>Security posture rating</h3>
        <p className="posture-rating">{data.posture.rating}</p>
        <p>{data.posture.basis}</p>
        <h3>STRIDE coverage</h3>
        <p>
          Evaluated rule criteria linked through existing control metadata.
          Every category remains partial or not assessed; path mappings are
          proposed, and exploitation is unverified.
        </p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Category</th>
                <th>Coverage</th>
                <th>Evaluations</th>
                <th>Known criterion outcomes</th>
                <th>Mapped paths</th>
              </tr>
            </thead>
            <tbody>
              {data.stride.map((s: Row) => (
                <tr key={s.category}>
                  <td>{s.category}</td>
                  <td>{s.state.replaceAll("_", " ")}</td>
                  <td>{s.evaluations}</td>
                  <td>{s.known}</td>
                  <td>{s.paths}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p>
          Finding readiness: {data.finding_quality.ready} ready for confirmation
          · {data.finding_quality.needs_validation} need validation. Automated
          checks do not approve findings.
        </p>
      </section>
      {validation.status !== "ORIGINAL_IMPORT" && (
        <section aria-label="Enterprise build validation">
          <h3>Enterprise build validation · {validation.status}</h3>
          <p>{validation.qualification}</p>
          {validation.status === "ERROR" && (
            <p role="alert">
              Snapshot discrepancy detected. Review missing and unexpected
              records before reporting.
            </p>
          )}
          {validation.missing_imports.length > 0 && (
            <p role="alert">
              {validation.missing_imports.length} active import(s) are outside
              this snapshot. Build a new enterprise assessment to include them.
            </p>
          )}
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Records</th>
                  <th>Expected union</th>
                  <th>In snapshot</th>
                  <th>Duplicates merged</th>
                  <th>Missing</th>
                  <th>Unexpected</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {validation.checks.map((c: Row) => (
                  <tr key={c.stage}>
                    <td>{c.stage}</td>
                    <td>{c.expected}</td>
                    <td>{c.actual}</td>
                    <td>{c.deduplicated_occurrences}</td>
                    <td>{c.missing}</td>
                    <td>{c.unexpected}</td>
                    <td>{c.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <details>
            <summary>Projects, accounts and omitted imports</summary>
            <pre>
              {JSON.stringify(
                {
                  scopes: validation.scopes,
                  omitted: validation.missing_imports,
                },
                null,
                2,
              )}
            </pre>
          </details>
        </section>
      )}
      <details className="coverage-legend">
        <summary>Effective Coverage, Partial and Error explained</summary>
        <dl>
          {Object.entries(data.coverage_definitions).map(([k, v]) => (
            <div key={k}>
              <dt>{k.replaceAll("_", " ")}</dt>
              <dd>{String(v)}</dd>
            </div>
          ))}
        </dl>
      </details>
    </>
  );
}
