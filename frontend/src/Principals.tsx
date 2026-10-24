import React, { useEffect, useState } from "react";
import { api, Row } from "./api";

const EVENT = "closec:open-principal";

/** Ask the application to show a principal in the IAM intelligence view. */
export function openPrincipal(principal: string) {
  window.dispatchEvent(new CustomEvent(EVENT, { detail: principal }));
}

/** Subscribe to openPrincipal requests (used once by the application shell). */
export function usePrincipalRequests(onOpen: (principal: string) => void) {
  useEffect(() => {
    const listener = (e: Event) =>
      onOpen(String((e as CustomEvent).detail || ""));
    window.addEventListener(EVENT, listener);
    return () => window.removeEventListener(EVENT, listener);
  }, [onOpen]);
}

/** Members and attached service accounts named by a finding, linked to their roles. */
export function PrincipalLinks({ principals }: { principals?: Row[] }) {
  if (!principals?.length) return null;
  return (
    <div className="principal-links" aria-label="Principals in this finding">
      <h4>Principals in this finding</h4>
      <ul>
        {principals.map((p) => (
          <li key={p.principal}>
            <code>{p.principal}</code>{" "}
            <span className="muted">({p.relation})</span>{" "}
            <button
              className="small"
              onClick={() => openPrincipal(p.principal)}
              aria-label={`View roles of ${p.principal}`}
            >
              View roles
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

const STATUS_TEXT: Record<string, string> = {
  RESOLVED: "Resolved: project and parent IAM collected",
  UNRESOLVED:
    "Unresolved: not every project and parent IAM policy was collected",
};
const PRIVILEGE_TEXT: Record<string, string> = {
  PRIVILEGED: "Privileged role observed",
  NARROW: "Only non-privileged roles observed (resolved)",
  NONE_OBSERVED: "No binding observed (resolved)",
  UNRESOLVED: "Unresolved: do not treat as narrow",
};

function roleTag(b: Row): string {
  if (b.role_type === "CUSTOM")
    return b.role_status === "RESOLVED"
      ? "custom (permissions listed, not classified)"
      : "custom: UNRESOLVED (detail not collected)";
  if (b.role_type === "UNKNOWN") return "UNRESOLVED";
  return b.privileged ? "privileged" : "not privileged";
}

function PrincipalDetail({
  run,
  principal,
}: {
  run: string;
  principal: string;
}) {
  const [d, setD] = useState<Row>(),
    [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    setD(undefined);
    setError("");
    api(`/runs/${run}/gcp/principal?principal=${encodeURIComponent(principal)}`)
      .then((r) => active && setD(r))
      .catch((e) => active && setError(e.message));
    return () => {
      active = false;
    };
  }, [run, principal]);
  if (error) return <p role="alert">{error}</p>;
  if (!d) return <p role="status">Loading roles…</p>;
  return (
    <section className="panel" aria-label={`Roles of ${principal}`}>
      <h3>
        Roles of <code>{principal}</code>
      </h3>
      <dl className="facts">
        <dt>Resolution</dt>
        <dd className={`principal-status ${d.status.toLowerCase()}`}>
          {STATUS_TEXT[d.status] || d.status}
        </dd>
        <dt>Privilege</dt>
        <dd>{PRIVILEGE_TEXT[d.privilege] || d.privilege}</dd>
        <dt>Principal type</dt>
        <dd>{(d.principal_kinds || []).join(", ") || "unknown"}</dd>
        <dt>Observed bindings</dt>
        <dd>{d.binding_count}</dd>
      </dl>
      <ul className="muted">
        {d.notes.map((n: string) => (
          <li key={n}>{n}</li>
        ))}
      </ul>
      <div className="table-wrap">
        <table aria-label="Observed role bindings">
          <thead>
            <tr>
              <th scope="col">Role</th>
              <th scope="col">Classification</th>
              <th scope="col">Scope</th>
              <th scope="col">Resource</th>
              <th scope="col">Condition</th>
              <th scope="col">Account class / trust</th>
              <th scope="col">Source dataset</th>
            </tr>
          </thead>
          <tbody>
            {d.bindings.length === 0 && (
              <tr>
                <td colSpan={7}>
                  No binding observed in the collected evidence.
                </td>
              </tr>
            )}
            {d.bindings.map((b: Row, i: number) => (
              <tr key={`${b.member}-${b.role}-${b.resource}-${i}`}>
                <td>
                  <code>{b.role}</code>
                  {b.permissions && (
                    <details>
                      <summary>{b.permissions.length} permissions</summary>
                      <ul>
                        {b.permissions.slice(0, 200).map((p: string) => (
                          <li key={p}>
                            <code>{p}</code>
                          </li>
                        ))}
                      </ul>
                    </details>
                  )}
                </td>
                <td>{roleTag(b)}</td>
                <td>{b.scope}</td>
                <td>
                  <code>{b.resource}</code>
                  {b.project_id && (
                    <div className="muted">project {b.project_id}</div>
                  )}
                </td>
                <td>
                  {b.conditional
                    ? b.condition?.title ||
                      b.condition?.expression ||
                      "conditional"
                    : "none"}
                </td>
                <td>
                  {b.account_class ? (
                    <div>{b.account_class}</div>
                  ) : (
                    "n/a (not a service account)"
                  )}
                  {b.trust && <div>{b.trust}</div>}
                  {b.home_project && (
                    <div className="muted">owner project {b.home_project}</div>
                  )}
                </td>
                <td>{(b.datasets || [b.dataset]).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h4>Resolution by project</h4>
      <div className="table-wrap">
        <table aria-label="Resolution by project">
          <thead>
            <tr>
              <th scope="col">Project</th>
              <th scope="col">Status</th>
              <th scope="col">Reason</th>
            </tr>
          </thead>
          <tbody>
            {d.projects.map((p: Row) => (
              <tr key={p.project_id}>
                <td>{p.project_id}</td>
                <td>{p.status}</td>
                <td>{p.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/** Per-principal view: search observed principals, then show every collected binding. */
export function PrincipalRoles({
  run,
  epoch,
  selected,
  onSelect,
}: {
  run: string;
  epoch: number;
  selected?: string;
  onSelect: (principal: string) => void;
}) {
  const [q, setQ] = useState(""),
    [list, setList] = useState<Row>(),
    [lookup, setLookup] = useState(selected || ""),
    [error, setError] = useState("");
  useEffect(() => setLookup(selected || ""), [selected]);
  useEffect(() => {
    let active = true;
    const timer = setTimeout(() => {
      api(`/runs/${run}/gcp/principals?q=${encodeURIComponent(q)}&limit=50`)
        .then((r) => active && setList(r))
        .catch((e) => active && setError(e.message));
    }, 200);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [run, q, epoch]);
  return (
    <section className="panel" aria-label="Principal roles">
      <h2>Principal roles</h2>
      <p className="muted">
        Every role binding observed for a service account, user or group across
        the imported projects. Group members are never listed or inferred.
      </p>
      {error && <p role="alert">{error}</p>}
      <div className="toolbar">
        <label>
          Filter principals
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="serviceAccount:, user:, group: or part of an email"
            spellCheck={false}
          />
        </label>
        <label>
          Look up a principal
          <input
            value={lookup}
            onChange={(e) => setLookup(e.target.value)}
            placeholder="serviceAccount:name@project.iam.gserviceaccount.com"
            spellCheck={false}
          />
        </label>
        <button
          disabled={!lookup.trim()}
          onClick={() => onSelect(lookup.trim())}
        >
          Show roles
        </button>
      </div>
      {list && (
        <div className="table-wrap">
          <table aria-label="Observed principals">
            <thead>
              <tr>
                <th scope="col">Principal</th>
                <th scope="col">Type</th>
                <th scope="col">Bindings</th>
                <th scope="col">Privileged</th>
                <th scope="col">Projects</th>
                <th scope="col">Trust</th>
              </tr>
            </thead>
            <tbody>
              {list.items.map((p: Row) => (
                <tr key={p.member}>
                  <td>
                    <button
                      className="link"
                      onClick={() => onSelect(p.member)}
                      aria-label={`Show roles of ${p.member}`}
                    >
                      {p.member}
                    </button>
                  </td>
                  <td>{p.principal_kind}</td>
                  <td>{p.bindings}</td>
                  <td>{p.privileged_bindings}</td>
                  <td>{p.projects}</td>
                  <td>{p.trust.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted">
            Showing {list.items.length} of {list.total} principals.
          </p>
        </div>
      )}
      {selected && <PrincipalDetail run={run} principal={selected} />}
    </section>
  );
}
