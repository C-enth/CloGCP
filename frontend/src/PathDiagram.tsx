import React, { useState } from "react";
import { Row } from "./api";

export const STRIDE = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege",
];
const STRIDE_LETTER: Record<string, string> = {
  Spoofing: "S",
  Tampering: "T",
  Repudiation: "R",
  "Information Disclosure": "I",
  "Denial of Service": "D",
  "Elevation of Privilege": "E",
};

type Links = {
  onEvidence?: (observationId: string) => void;
  onFinding?: (findingId: string) => void;
};

const statusClass = (s: string) =>
  String(s || "")
    .toLowerCase()
    .replaceAll("_", "-");

export function StrideBadges({ values }: { values: string[] }) {
  return (
    <span className="stride-badges">
      {(values || []).map((s) => (
        <span key={s} className="badge stride" title={s}>
          <abbr title={s}>{STRIDE_LETTER[s] || "?"}</abbr> {s}
        </span>
      ))}
    </span>
  );
}

function HopLinks({ hop, onEvidence, onFinding }: Links & { hop: Row }) {
  const observations: string[] = hop.observation_ids || [];
  const findings: string[] = hop.finding_ids || [];
  return (
    <span className="hop-links">
      {onEvidence &&
        observations.slice(0, 3).map((oid, i) => (
          <button
            key={oid}
            className="small"
            onClick={() => onEvidence(oid)}
            aria-label={`Inspect evidence ${i + 1} of hop ${hop.index}`}
          >
            Evidence {observations.length > 1 ? i + 1 : ""}
          </button>
        ))}
      {observations.length > 3 && (
        <span className="muted">+{observations.length - 3} more</span>
      )}
      {onFinding &&
        findings.slice(0, 3).map((fid, i) => (
          <button
            key={fid}
            className="small"
            onClick={() => onFinding(fid)}
            aria-label={`Open finding ${i + 1} of hop ${hop.index}`}
          >
            Finding {findings.length > 1 ? i + 1 : ""}
          </button>
        ))}
      {!observations.length && !findings.length && (
        <span className="muted">No source record cited</span>
      )}
    </span>
  );
}

/** Hops as a vertical chain: node, directed edge (type, status, STRIDE, why), node. */
function HopChain({ hops, ...links }: Links & { hops: Row[] }) {
  return (
    <ol className="hop-chain" aria-label="Attack path hops">
      {hops.map((h, i) => (
        <li key={h.index} className="hop">
          {i === 0 && (
            <div className="path-node hop-node">
              <span className="path-step">Entry</span>
              <span className="path-label">{h.source}</span>
            </div>
          )}
          <div className={"hop-edge hop-" + statusClass(h.status)}>
            <span className="hop-arrow" aria-hidden="true">
              ↓
            </span>
            <div className="hop-body">
              <div className="hop-title">
                <strong>
                  Hop {h.index}: {h.edge_type}
                </strong>{" "}
                <span className={"badge " + statusClass(h.status)}>
                  {h.status}
                </span>{" "}
                <StrideBadges values={h.stride} />
              </div>
              <p className="hop-direction">
                <span className="visually-hidden">Direction: </span>
                {h.direction}
              </p>
              <p className="hop-why">{h.justification}</p>
              {h.rule_ids?.length > 0 && (
                <span className="path-rules">
                  Rule: {h.rule_ids.join(", ")}
                </span>
              )}
              {h.missing_evidence?.length > 0 && (
                <p className="hop-missing">
                  Missing evidence: {h.missing_evidence.join("; ")}
                </p>
              )}
              <HopLinks hop={h} {...links} />
            </div>
          </div>
          <div
            className={
              "path-node hop-node" +
              (i === hops.length - 1 ? " hop-objective" : "")
            }
          >
            <span className="path-step">
              {i === hops.length - 1 ? "Objective" : `After hop ${h.index}`}
            </span>
            <span className="path-label">{h.target}</span>
          </div>
        </li>
      ))}
    </ol>
  );
}

/** Table fallback for the same hops (screen readers, printing, narrow screens). */
export function HopTable({
  hops,
  label,
  ...links
}: Links & { hops: Row[]; label: string }) {
  return (
    <div className="table-wrap">
      <table aria-label={label}>
        <thead>
          <tr>
            <th>#</th>
            <th>From</th>
            <th>Edge</th>
            <th>To</th>
            <th>Status</th>
            <th>STRIDE</th>
            <th>Direction justification</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {hops.map((h) => (
            <tr key={h.index}>
              <td>{h.index}</td>
              <td>{h.source}</td>
              <td>{h.edge_type}</td>
              <td>{h.target}</td>
              <td>
                <span className={"badge " + statusClass(h.status)}>
                  {h.status}
                </span>
              </td>
              <td>{(h.stride || []).join(", ")}</td>
              <td>
                {h.justification}
                {h.missing_evidence?.length > 0 && (
                  <span className="hop-missing">
                    {" "}
                    Missing: {h.missing_evidence.join("; ")}
                  </span>
                )}
              </td>
              <td>
                {h.rule_ids?.length > 0 && (
                  <span className="path-rules">
                    Rule: {h.rule_ids.join(", ")}{" "}
                  </span>
                )}
                <HopLinks hop={h} {...links} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Pre-hop records (frozen editions created before the hop model): the stored chain. */
function LegacyChain({ chart }: { chart: Row }) {
  return (
    <div className="path-chain">
      {chart.nodes.map((node: Row, i: number) => (
        <React.Fragment key={i}>
          {i > 0 && (
            <div className="path-edge" aria-hidden={!chart.edges[i - 1]?.label}>
              <span className="path-arrow">→</span>
              {chart.edges[i - 1]?.label && (
                <span className="path-edge-label">
                  {chart.edges[i - 1].label}
                  {chart.edges[i - 1].status &&
                    ` (${chart.edges[i - 1].status})`}
                </span>
              )}
            </div>
          )}
          <div
            className={
              "path-node" +
              (node.status ? " path-" + statusClass(node.status) : "")
            }
          >
            <span className="path-step">{i === 0 ? "Start" : `Step ${i}`}</span>
            <span className="path-label">{node.label}</span>
            {node.status && <span className="path-status">{node.status}</span>}
            {node.rules?.length > 0 && (
              <span className="path-rules">Rule: {node.rules.join(", ")}</span>
            )}
          </div>
        </React.Fragment>
      ))}
    </div>
  );
}

/** One attack path: header, entry → objective, hop chain or hop table, assumptions, review. */
export function PathDiagram({
  path,
  onReview,
  ...links
}: Links & {
  path: Row;
  onReview?: (id: string, status: string) => void;
}) {
  const [view, setView] = useState("Diagram");
  const hops: Row[] = path.hops || [];
  const chart = path.diagram;
  if (!hops.length && !chart?.nodes?.length) return null;
  const name =
    `${path.attack_path || path.path || ""} ${path.title || ""}`.trim();
  return (
    <figure
      className="path-diagram"
      aria-label={`Attack path ${path.title || ""}`}
    >
      <figcaption>
        <span className={"badge " + statusClass(path.feasibility)}>
          {path.feasibility}
        </span>{" "}
        {path.proof_status && (
          <span className={"badge " + statusClass(path.proof_status)}>
            Proof: {path.proof_status}
          </span>
        )}{" "}
        <strong>{name}</strong>{" "}
        <span className="muted">
          {path.provider}{" "}
          {path.project_id || path.account_id || path.scope || ""}
          {path.scope === "cross-cloud" || path.scope === "cross-project"
            ? ` · ${path.scope}`
            : ""}
        </span>
      </figcaption>
      {path.entry_point && (
        <p className="path-summary">
          <strong>Entry:</strong> {path.entry_point} →{" "}
          <strong>Objective:</strong> {path.objective}
          {path.impact ? (
            <>
              {" "}
              · <strong>Impact:</strong> {path.impact}
            </>
          ) : null}
        </p>
      )}
      <p className="muted">
        STRIDE:{" "}
        {(path.hop_stride || path.stride || []).join(", ") || "Unmapped"} ·
        Scenarios: {(path.stride_scenarios || []).join(", ") || "Unmapped"}.
        Mapping is proposed; exploitation is unverified.
      </p>
      {hops.length > 0 ? (
        <>
          <div
            className="toolbar view-toggle"
            role="group"
            aria-label={`View of ${name}`}
          >
            {["Diagram", "Hop table"].map((v) => (
              <button
                key={v}
                className={"small" + (view === v ? " primary" : "")}
                aria-pressed={view === v}
                onClick={() => setView(v)}
              >
                {v}
              </button>
            ))}
          </div>
          {view === "Diagram" ? (
            <HopChain hops={hops} {...links} />
          ) : (
            <HopTable hops={hops} label={`Hops of ${name}`} {...links} />
          )}
        </>
      ) : (
        <LegacyChain chart={chart} />
      )}
      {path.assumptions?.length > 0 && (
        <p className="path-assumptions">
          Attacker-side assumptions (never verified):{" "}
          {path.assumptions.join("; ")}
        </p>
      )}
      {path.proof_status &&
        path.proof_status !== "PROVEN" &&
        path.missing_evidence_named?.length > 0 && (
          <p className="hop-missing">
            {path.proof_status === "BLOCKED"
              ? "Also unresolved"
              : "Missing evidence"}
            : {path.missing_evidence_named.join("; ")}
          </p>
        )}
      {path.false_positive_dependency && (
        <p className="fp-flag" role="note">
          <span className="badge fp">FP</span>{" "}
          {path.false_positive_dependency.flag}: excluded from report sections
          until the finding is restored.
        </p>
      )}
      {path.analyst_review && (
        <p>
          Analyst path interpretation: {path.analyst_review}. Confirmation
          records the interpretation of observed steps, not exploitation.
        </p>
      )}
      {onReview && (
        <div className="toolbar">
          <button onClick={() => onReview(path.path_id, "CONFIRMED")}>
            Confirm path interpretation
          </button>
          <button onClick={() => onReview(path.path_id, "REJECTED")}>
            Reject path interpretation
          </button>
        </div>
      )}
      {path.feasibility_reason && (
        <p className="muted">{path.feasibility_reason}</p>
      )}
    </figure>
  );
}

const PROOF_ORDER: Record<string, number> = {
  PROVEN: 0,
  HYPOTHESIS: 1,
  BLOCKED: 2,
};
const FEASIBILITY_ORDER: Record<string, number> = {
  FEASIBLE: 0,
  INSUFFICIENT_EVIDENCE: 1,
};

/** Diagrams for a list of paths, proven/feasible first, bounded with "show all". */
export function PathDiagrams({
  paths,
  limit = 10,
  onReview,
  ...links
}: Links & {
  paths: Row[];
  limit?: number;
  onReview?: (id: string, status: string) => void;
}) {
  const [all, setAll] = useState(false);
  const sorted = [...paths].sort(
    (a, b) =>
      (FEASIBILITY_ORDER[a.feasibility] ?? 2) -
        (FEASIBILITY_ORDER[b.feasibility] ?? 2) ||
      (PROOF_ORDER[a.proof_status] ?? 3) - (PROOF_ORDER[b.proof_status] ?? 3),
  );
  const shown = all ? sorted : sorted.slice(0, limit);
  if (!paths.length) return null;
  return (
    <div className="path-diagrams">
      {shown.map((p, i) => (
        <PathDiagram
          key={p.path_id || i}
          path={p}
          onReview={onReview}
          {...links}
        />
      ))}
      {sorted.length > limit && (
        <button className="small" onClick={() => setAll(!all)}>
          {all ? "Show fewer paths" : `Show all ${sorted.length} paths`}
        </button>
      )}
    </div>
  );
}

/** Attack surface grouped by STRIDE: every hop counted under each category it maps to. */
export function StrideSurface({
  paths,
  selected,
  onSelect,
}: {
  paths: Row[];
  selected: string;
  onSelect: (category: string) => void;
}) {
  const rows = STRIDE.map((category) => {
    const hops = paths.flatMap((p) =>
      (p.hops || [])
        .filter((h: Row) => (h.stride || []).includes(category))
        .map((h: Row) => ({ ...h, path: p })),
    );
    const count = (s: string) => hops.filter((h) => h.status === s).length;
    const pathsIn = new Set(hops.map((h) => h.path.path_id));
    const entries = [
      ...new Set(hops.map((h) => h.path.entry_point).filter(Boolean)),
    ];
    return { category, hops, count, paths: pathsIn.size, entries };
  });
  return (
    <div className="table-wrap">
      <table aria-label="Attack surface by STRIDE">
        <thead>
          <tr>
            <th>STRIDE category</th>
            <th>Paths</th>
            <th>Proven hops</th>
            <th>Hypothesis hops</th>
            <th>Blocked hops</th>
            <th>Entry points</th>
            <th>Filter</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr
              key={r.category}
              className={selected === r.category ? "selected-row" : ""}
            >
              <td>
                <StrideBadges values={[r.category]} />
              </td>
              <td>{r.paths}</td>
              <td>{r.count("PROVEN")}</td>
              <td>{r.count("HYPOTHESIS")}</td>
              <td>{r.count("BLOCKED")}</td>
              <td>
                {r.entries.length ? (
                  <details>
                    <summary>{r.entries.length} entry point(s)</summary>
                    <ul className="path-entries">
                      {r.entries.map((e) => (
                        <li key={e}>{e}</li>
                      ))}
                    </ul>
                  </details>
                ) : r.category === "Repudiation" ? (
                  "No edge type maps to Repudiation."
                ) : (
                  "—"
                )}
              </td>
              <td>
                {r.paths > 0 && (
                  <button
                    className="small"
                    aria-pressed={selected === r.category}
                    onClick={() =>
                      onSelect(selected === r.category ? "" : r.category)
                    }
                  >
                    {selected === r.category ? "Show all" : "Show these paths"}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Why path kinds were or were not formed (counts from the evidence, never a verdict). */
export function PathCoverage({
  reasons,
  open,
}: {
  reasons: Row[];
  open: boolean;
}) {
  if (!reasons?.length) return null;
  const body = (
    <ul className="path-coverage">
      {reasons.map((r) => (
        <li key={r.kind}>
          <strong>
            {r.kind}: {r.formed} formed.
          </strong>{" "}
          {r.reason}
        </li>
      ))}
    </ul>
  );
  return open ? (
    <div className="path-empty" role="status">
      <p>
        <strong>No attack path was formed for this cloud.</strong> This is the
        result of the collected evidence, not a display error:
      </p>
      {body}
    </div>
  ) : (
    <details className="path-coverage-details">
      <summary>Why other path kinds were not formed</summary>
      {body}
    </details>
  );
}
