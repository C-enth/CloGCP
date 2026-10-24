import { ChoiceFilter, ChoiceNotice } from "./Filters";
import React, { useEffect, useState } from "react";
import { api, display, type Row } from "./api";

export function EnterpriseMetrics({
  run,
  epoch,
}: {
  run: string;
  epoch: number;
}) {
  const [data, setData] = useState<Row>();
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    setData(undefined);
    api(`/runs/${run}/enterprise/dashboard`)
      .then((d) => {
        if (live) setData(d);
      })
      .catch((e) => setError(e.message));
    return () => {
      live = false;
    };
  }, [run, epoch]);
  if (error) return <p role="alert">{error}</p>;
  if (!data) return <p>Loading enterprise coverage…</p>;
  return (
    <section className="panel enterprise-summary">
      <h2>Enterprise scope</h2>
      {data.projection?.not_correlated && (
        <p className="notice">
          This original import has no enterprise relationship projection. Build
          an enterprise assessment; zero persisted edges here does not establish
          absence of cross-account access.
        </p>
      )}
      <p>
        Selected immutable assessment · {data.member_runs.length} original
        import runs. Referenced accounts are shown separately from collected
        accounts.
      </p>
      <div className="metric-grid">
        {[
          ["Accounts assessed", data.assessed_accounts],
          ["Referenced accounts", data.referenced_accounts],
          [
            "Approved accounts missing evidence",
            data.missing_registry_accounts,
          ],
          ["Cross-account relationships", data.cross_account_relationships],
          [
            "Authorization/exposure relationships",
            data.relationship_categories?.authorization_or_exposure,
          ],
          [
            "Structural references",
            data.relationship_categories?.structural_configuration_references,
          ],
          ["Shared investigations", data.systemic_investigations],
          [
            "Collection spread (hours)",
            data.collection_window?.spread_hours ?? "n/a",
          ],
          [
            "Stale accounts",
            data.collection_window?.stale_accounts?.length ?? 0,
          ],
        ].map(([label, value]) => (
          <div className="metric" key={String(label)}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
      {data.collection_window?.stale_accounts?.length > 0 && (
        <p className="env-banner" role="note">
          Stale evidence: {data.collection_window.stale_accounts.length}{" "}
          account(s) were collected more than{" "}
          {data.collection_window.stale_after_days} days before the newest
          collection in this snapshot (
          {data.collection_window.stale_accounts.join(", ")}). Relationships
          combine different points in time; recollect before treating them as
          current.
        </p>
      )}
      {data.additional_imports.length > 0 && (
        <p className="notice">
          {data.additional_imports.length} additional imports are available.
          Build a new enterprise assessment to include them.
        </p>
      )}
      {data.projection?.truncation?.length > 0 && (
        <p role="alert">{data.projection.truncation.join("; ")}</p>
      )}
      <details>
        <summary>Account groups with HIGH / CRITICAL candidates</summary>
        <p className="muted">
          Counts are affected collected accounts per approved group or evidenced
          OU, based on candidate severity; they do not establish business risk
          or approved vulnerabilities.
        </p>
        <pre>{JSON.stringify(data.high_risk_groups, null, 2)}</pre>
      </details>
      <details>
        <summary>Repeated control observations (independent causes)</summary>
        <pre>{JSON.stringify(data.repeated_control_observations, null, 2)}</pre>
      </details>
      <p>
        Collection completeness: {display(data.collections)}. Candidate status
        and authorization conclusions remain independent.
      </p>
    </section>
  );
}

function Graph({
  graph,
  inspect,
}: {
  graph: Row;
  inspect: (row: Row) => void;
}) {
  const [scale, setScale] = useState(1),
    [shift, setShift] = useState({ x: 0, y: 0 });
  const [active, setActive] = useState("");
  const [drag, setDrag] = useState<{
    x: number;
    y: number;
    startX: number;
    startY: number;
  }>();
  const positions = new Map<string, { x: number; y: number }>();
  const width = 1000,
    height = Math.max(420, Math.ceil(graph.nodes.length / 5) * 100);
  graph.nodes.forEach((n: Row, i: number) =>
    positions.set(n.id, {
      x: 110 + (i % 5) * 195,
      y: 60 + Math.floor(i / 5) * 100,
    }),
  );
  return (
    <section className="panel">
      <h2>Bounded relationship graph</h2>
      <div className="toolbar">
        <button
          aria-label="Zoom in graph"
          onClick={() => setScale(Math.min(2.5, scale + 0.2))}
        >
          Zoom +
        </button>
        <button
          aria-label="Zoom out graph"
          onClick={() => setScale(Math.max(0.4, scale - 0.2))}
        >
          Zoom −
        </button>
        <button
          onClick={() => {
            setScale(1);
            setShift({ x: 0, y: 0 });
            setActive("");
          }}
        >
          Reset graph
        </button>
        <span>
          {graph.nodes.length} nodes · {graph.edges.length} relationships
        </span>
      </div>
      <p className="muted">
        Drag to pan. Select a node to highlight incoming/outgoing references;
        select an edge for evidence. Arrows follow the typed relationship, not
        traffic or exploit flow.
      </p>
      {graph.truncated && (
        <p role="status" className="notice">
          Graph is incomplete at the selected limits. Filter further or use the
          paginated table ({graph.selection_total} matching relationships).
        </p>
      )}
      <div className="enterprise-graph">
        <svg
          viewBox={`0 0 ${width} ${Math.min(height, 700)}`}
          role="img"
          aria-label="Enterprise relationship graph"
          onPointerDown={(e) => {
            if ((e.target as Element).closest(".graph-node,.graph-edge"))
              return;
            e.currentTarget.setPointerCapture(e.pointerId);
            setDrag({
              x: e.clientX,
              y: e.clientY,
              startX: shift.x,
              startY: shift.y,
            });
          }}
          onPointerMove={(e) => {
            if (drag)
              setShift({
                x: drag.startX + (e.clientX - drag.x),
                y: drag.startY + (e.clientY - drag.y),
              });
          }}
          onPointerUp={() => setDrag(undefined)}
        >
          <defs>
            <marker
              id="enterprise-arrow"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path className="graph-marker" d="M 0 0 L 10 5 L 0 10 z" />
            </marker>
          </defs>
          <g transform={`translate(${shift.x},${shift.y}) scale(${scale})`}>
            {graph.edges.map((e: Row) => {
              const a = positions.get(e.graph_source),
                b = positions.get(e.graph_destination);
              if (!a || !b) return null;
              const dx = b.x - a.x,
                dy = b.y - a.y;
              const horizontal = Math.abs(dx) >= Math.abs(dy);
              const start = {
                x: a.x + (horizontal ? Math.sign(dx) * 87 : 0),
                y: a.y + (horizontal ? 0 : Math.sign(dy) * 26),
              };
              const end = {
                x: b.x - (horizontal ? Math.sign(dx) * 87 : 0),
                y: b.y - (horizontal ? 0 : Math.sign(dy) * 26),
              };
              const curve = `M ${start.x} ${start.y} Q ${(start.x + end.x) / 2 + (Math.abs(dx) < 2 ? 28 : 0)} ${(start.y + end.y) / 2 - 28} ${end.x} ${end.y}`;
              const highlighted =
                !active ||
                active === e.graph_source ||
                active === e.graph_destination;
              return (
                <g
                  key={e.relationship_id}
                  className={"graph-edge " + e.status.toLowerCase()}
                  opacity={highlighted ? 1 : 0.15}
                  role="button"
                  tabIndex={0}
                  aria-label={`Inspect ${e.relationship_type} ${e.status}`}
                  onClick={() => inspect(e)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") inspect(e);
                  }}
                >
                  <title>
                    {e.relationship_type}: {e.status}
                  </title>
                  <path d={curve} markerEnd="url(#enterprise-arrow)" />
                  <path d={curve} className="edge-hit" />
                </g>
              );
            })}
            {graph.nodes.map((n: Row) => {
              const p = positions.get(n.id)!;
              return (
                <g
                  key={n.id}
                  transform={`translate(${p.x},${p.y})`}
                  className={
                    "graph-node " + (active === n.id ? "selected" : "")
                  }
                  role="button"
                  tabIndex={0}
                  aria-label={`Select node ${n.identity}`}
                  onClick={() => setActive(active === n.id ? "" : n.id)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") setActive(n.id);
                  }}
                >
                  <title>
                    {n.identity} · {n.partition} ·{" "}
                    {n.account ?? "ownership unresolved"}
                  </title>
                  <rect x="-85" y="-24" width="170" height="48" rx="9" />
                  <text textAnchor="middle" y="-3">
                    {n.account ?? "Referenced endpoint"}
                  </text>
                  <text textAnchor="middle" y="13" className="node-identity">
                    {n.identity.length > 23
                      ? n.identity.slice(-23)
                      : n.identity}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
      </div>
      <p>
        Observed: blue · supported predicate: green · potential: amber ·
        blocked: red · unknown: gray. {graph.limitation}
      </p>
    </section>
  );
}

export function CrossAccount({
  run,
  epoch,
  inspect,
  accounts = "",
  initialDomain = "",
}: {
  run: string;
  epoch: number;
  inspect: (row: Row) => void;
  accounts?: string;
  initialDomain?: string;
}) {
  const [filters, setFilters] = useState<Row>({
    source: "",
    destination: "",
    kind: "",
    domain: initialDomain,
    status: "",
    group: "",
    q: "",
    outside: false,
    missing_only: false,
    privileged: false,
  });
  const [data, setData] = useState<Row>(),
    [graph, setGraph] = useState<Row>(),
    [offset, setOffset] = useState(0),
    [error, setError] = useState("");
  const [nodeLimit, setNodeLimit] = useState(60);
  const [choices, setChoices] = useState<Row>();
  useEffect(() => {
    let live = true;
    api(`/runs/${run}/enterprise/filter-choices`)
      .then((d) => {
        if (live) setChoices(d);
      })
      .catch((e) => {
        if (live) setChoices({ error: e.message });
      });
    return () => {
      live = false;
    };
  }, [run, epoch]);
  useEffect(() => {
    setOffset(0);
  }, [filters, accounts, run]);
  useEffect(() => {
    let live = true;
    setData(undefined);
    setGraph(undefined);
    setError("");
    const timer = setTimeout(() => {
      const query = new URLSearchParams({
        ...Object.fromEntries(
          Object.entries(filters).map(([k, v]) => [k, String(v)]),
        ),
        account: accounts,
      });
      Promise.all([
        api(
          `/runs/${run}/enterprise/relationships?${query}&offset=${offset}&limit=30`,
        ),
        api(
          `/runs/${run}/enterprise/graph?${query}&node_limit=${nodeLimit}&edge_limit=100`,
        ),
      ])
        .then(([d, g]) => {
          if (live) {
            setData(d);
            setGraph(g);
          }
        })
        .catch((e) => {
          if (live) setError(e.message);
        });
    }, 180);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [run, epoch, filters, offset, accounts, nodeLimit]);
  const change = (key: string, value: any) =>
    setFilters({ ...filters, [key]: value });
  return (
    <>
      <section className="panel">
        <h2>AWS cross-account explorer</h2>
        <ChoiceNotice data={choices} />
        <p>
          Explicit references and evaluated IAM predicates. Source means
          referencing principal/resource; destination means referenced endpoint.
          Network reachability remains unevaluated.
        </p>
        <div className="form-grid">
          {[
            ["source", "Source account"],
            ["destination", "Destination account"],
            ["kind", "Relationship type"],
            ["group", "Approved group / evidenced OU"],
            ["q", "Relationship search"],
          ].map(([key, label]) => (
            <label key={key}>
              {label}
              <ChoiceFilter
                label={label}
                value={filters[key]}
                options={choices?.choices?.[key]}
                onChange={(v) => change(key, v)}
              />
            </label>
          ))}
          <label>
            Security domain
            <select
              aria-label="Relationship domain"
              value={filters.domain}
              onChange={(e) => change("domain", e.target.value)}
            >
              <option value="">All domains</option>
              {[
                "IAM",
                "RESOURCE_ACCESS",
                "NETWORK",
                "MONITORING",
                "ORGANIZATION",
              ].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </label>
          <label>
            Evaluation status
            <select
              aria-label="Relationship status"
              value={filters.status}
              onChange={(e) => change("status", e.target.value)}
            >
              <option value="">All statuses</option>
              {[
                "DIRECTLY_OBSERVED",
                "DERIVED_SUPPORTED",
                "POTENTIAL",
                "BLOCKED",
                "UNKNOWN",
              ].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </label>
          <label>
            Graph node budget
            <select
              aria-label="Graph node budget"
              value={nodeLimit}
              onChange={(e) => setNodeLimit(Number(e.target.value))}
            >
              {[30, 60, 100, 150].map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          </label>
          {[
            ["missing_only", "Missing evidence dependencies"],
            ["privileged", "Privileged or potentially privileged target"],
          ].map(([key, label]) => (
            <label key={key}>
              <input
                type="checkbox"
                checked={filters[key]}
                onChange={(e) => change(key, e.target.checked)}
              />{" "}
              {label}
            </label>
          ))}
          <label>
            <input
              type="checkbox"
              checked={filters.outside}
              onChange={(e) => change("outside", e.target.checked)}
            />{" "}
            Outside approved registry (requires loaded registry)
          </label>
        </div>
      </section>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {graph && <Graph graph={graph} inspect={inspect} />}
      <section className="panel">
        <h2>Relationship evidence register</h2>
        {!data ? (
          <p>Loading persisted relationships…</p>
        ) : (
          <>
            <p>
              {data.total} matching relationships · each row retains its
              qualification.
            </p>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    {[
                      "Source",
                      "Destination",
                      "Type",
                      "Status",
                      "Authorization",
                      "Evidence",
                      "Inspect",
                    ].map((h) => (
                      <th key={h}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((e: Row) => (
                    <tr key={e.relationship_id}>
                      <td>
                        {e.source_account ?? "Unknown"}
                        <small>{e.source}</small>
                      </td>
                      <td>
                        {e.destination_account ?? "Unknown"}
                        <small>{e.destination}</small>
                      </td>
                      <td>{e.relationship_type}</td>
                      <td>
                        <span className={"badge " + e.status.toLowerCase()}>
                          {e.status}
                        </span>
                      </td>
                      <td>{e.authorization ?? "Reference only"}</td>
                      <td>{e.evidence.length}</td>
                      <td>
                        <button onClick={() => inspect(e)}>
                          Inspect relationship
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <footer className="pagination">
              <button
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - 30))}
              >
                Previous relationships
              </button>
              <span>
                {data.total
                  ? `${offset + 1}–${Math.min(offset + 30, data.total)} of ${data.total}`
                  : "0 relationships"}
              </span>
              <button
                disabled={offset + 30 >= data.total}
                onClick={() => setOffset(offset + 30)}
              >
                Next relationships
              </button>
            </footer>
          </>
        )}
      </section>
    </>
  );
}

export function EnterpriseAccounts({
  run,
  epoch,
  inspect,
}: {
  run: string;
  epoch: number;
  inspect: (row: Row) => void;
}) {
  const [rows, setRows] = useState<Row>(),
    [selected, setSelected] = useState<string[]>([]),
    [offset, setOffset] = useState(0),
    [error, setError] = useState("");
  const [filters, setFilters] = useState<Row>({
    q: "",
    group: "",
    region: "",
    severity: "",
    coverage: "",
  });
  useEffect(() => {
    let live = true;
    const timer = setTimeout(() => {
      const qs = new URLSearchParams({
        ...filters,
        offset: String(offset),
        limit: "50",
      });
      api(`/runs/${run}/enterprise/accounts?${qs}`)
        .then((d) => {
          if (live) setRows(d);
        })
        .catch((e) => setError(e.message));
    }, 150);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [run, epoch, filters, offset]);
  useEffect(() => {
    setSelected([]);
    setOffset(0);
  }, [run]);
  const [choices, setChoices] = useState<Row>();
  useEffect(() => {
    let live = true;
    api(`/runs/${run}/enterprise/filter-choices`)
      .then((d) => {
        if (live) setChoices(d);
      })
      .catch((e) => {
        if (live) setChoices({ error: e.message });
      });
    return () => {
      live = false;
    };
  }, [run, epoch]);
  const selectAllMatching = async () => {
    if (!rows) return;
    if (rows.total > 512) {
      setError(
        "Selection is bounded to 512 accounts; filter the assessment scope further.",
      );
      return;
    }
    try {
      const ids: string[] = [];
      for (let at = 0; at < rows.total; at += 100) {
        const qs = new URLSearchParams({
          ...filters,
          offset: String(at),
          limit: "100",
        });
        const page = await api(`/runs/${run}/enterprise/accounts?${qs}`);
        ids.push(...page.items.map((r: Row) => r.account));
      }
      setSelected(ids);
    } catch (e: any) {
      setError(e.message);
    }
  };
  return (
    <section className="panel">
      <h2>AWS enterprise account selection</h2>
      <ChoiceNotice data={choices} />
      <p>
        Collected accounts, approved mappings and referenced-only accounts
        retain separate identity bases. Select multiple accounts to inspect
        incoming and outgoing relationships.
      </p>
      <div className="form-grid">
        {[
          ["q", "Account ID / approved alias"],
          ["group", "Account group / OU"],
          ["region", "Account Region"],
          ["severity", "Account finding severity"],
          ["coverage", "Account evidence coverage"],
        ].map(([k, l]) => (
          <label key={k}>
            {l}
            <ChoiceFilter
              label={l}
              value={filters[k]}
              options={choices?.choices?.[k]}
              onChange={(v) => {
                setFilters({ ...filters, [k]: v });
                setOffset(0);
              }}
            />
          </label>
        ))}
      </div>
      {error && <p role="alert">{error}</p>}
      {rows && (
        <>
          <button
            onClick={() =>
              setSelected([
                ...new Set([
                  ...selected,
                  ...rows.items.map((r: Row) => r.account),
                ]),
              ])
            }
          >
            Select all displayed accounts
          </button>
          <button onClick={selectAllMatching}>
            Select all matching accounts
          </button>
          <button onClick={() => setSelected([])}>
            Clear account selection
          </button>
          <p>
            {rows.total} matching accounts · {selected.length} selected
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Select</th>
                  <th>Account</th>
                  <th>Identity basis</th>
                  <th>Resources</th>
                  <th>Coverage</th>
                </tr>
              </thead>
              <tbody>
                {rows.items.map((r: Row) => (
                  <tr key={r.account}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Select account ${r.account}`}
                        checked={selected.includes(r.account)}
                        onChange={(e) =>
                          setSelected(
                            e.target.checked
                              ? [...selected, r.account]
                              : selected.filter((a) => a !== r.account),
                          )
                        }
                      />
                    </td>
                    <td>
                      {r.account}
                      <small>{r.alias}</small>
                    </td>
                    <td>{r.identity_basis}</td>
                    <td>{r.resources}</td>
                    <td>{display(r.coverage)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <button
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - 50))}
          >
            Previous accounts
          </button>
          <button
            disabled={offset + 50 >= rows.total}
            onClick={() => setOffset(offset + 50)}
          >
            Next accounts
          </button>
        </>
      )}
      {selected.length > 0 && (
        <CrossAccount
          key={run}
          run={run}
          epoch={epoch}
          accounts={selected.join(",")}
          inspect={inspect}
        />
      )}
    </section>
  );
}

export function SharedInvestigations({
  run,
  epoch,
  onError,
  onSaved,
}: {
  run: string;
  epoch: number;
  onError: (message: string) => void;
  onSaved: () => void;
}) {
  const [data, setData] = useState<Row>(),
    [selected, setSelected] = useState<Row>(),
    [offset, setOffset] = useState(0),
    [analyst, setAnalyst] = useState(""),
    [note, setNote] = useState("");
  useEffect(() => {
    let live = true;
    api(`/runs/${run}/enterprise/investigations?offset=${offset}&limit=30`)
      .then((d) => {
        if (live) setData(d);
      })
      .catch((e) => onError(e.message));
    return () => {
      live = false;
    };
  }, [run, epoch, offset]);
  const save = async (status: string, exception = false) => {
    try {
      await api(
        `/runs/${run}/enterprise/review/${selected!.investigation_id}`,
        { status, analyst, note, exception },
      );
      setSelected(undefined);
      onSaved();
    } catch (e: any) {
      onError(e.message);
    }
  };
  return (
    <section className="panel">
      <h2>Shared-root investigations</h2>
      <p>
        Grouped only by the same evidenced shared resource. Matching controls or
        policy text do not establish a shared root cause. Unlinked configuration
        dependencies have no suggested severity.
      </p>
      {data && (
        <>
          <p>{data.total} investigations</p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Shared resource</th>
                  <th>Affected accounts</th>
                  <th>Candidate findings</th>
                  <th>Severity</th>
                  <th>Analyst status</th>
                  <th>Review</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((i: Row) => (
                  <tr key={i.investigation_id}>
                    <td>{i.anchor}</td>
                    <td>{i.affected_account_count}</td>
                    <td>{i.finding_ids.length}</td>
                    <td>{i.suggested_severity ?? "UNASSESSED"}</td>
                    <td>{i.analyst_status}</td>
                    <td>
                      <button
                        onClick={() => {
                          setSelected(i);
                          setAnalyst(i.decision?.analyst ?? "");
                          setNote(i.decision?.note ?? "");
                        }}
                      >
                        Review shared investigation
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <button
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - 30))}
          >
            Previous investigations
          </button>
          <button
            disabled={offset + 30 >= data.total}
            onClick={() => setOffset(offset + 30)}
          >
            Next investigations
          </button>
        </>
      )}
      {selected && (
        <div className="drawer-backdrop">
          <aside
            className="drawer"
            role="dialog"
            aria-label="Shared investigation"
          >
            <header>
              <h2>Shared investigation</h2>
              <button onClick={() => setSelected(undefined)}>
                Close investigation
              </button>
            </header>
            <pre>{JSON.stringify(selected, null, 2)}</pre>
            <label>
              Analyst identity
              <input
                aria-label="Shared investigation analyst"
                value={analyst}
                onChange={(e) => setAnalyst(e.target.value)}
              />
            </label>
            <label>
              Remarks
              <textarea
                aria-label="Shared investigation remarks"
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </label>
            <p>
              Confirmation records an analyst decision; it does not establish
              effective access or a confirmed vulnerability.
            </p>
            {[
              ["CONFIRMED", "Confirm investigation"],
              ["REJECTED", "Reject investigation"],
              ["NEEDS_VALIDATION", "Validate investigation"],
            ].map(([status, label]) => (
              <button
                key={status}
                disabled={!analyst.trim()}
                onClick={() => save(status)}
              >
                {label}
              </button>
            ))}
            <button
              disabled={!analyst.trim() || !note.trim()}
              onClick={() => save("NEEDS_VALIDATION", true)}
            >
              Record investigation exception
            </button>
          </aside>
        </div>
      )}
    </section>
  );
}
