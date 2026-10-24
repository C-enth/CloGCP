import React, { useEffect, useState } from "react";
import { api, Row } from "./api";
import { PrincipalLinks } from "./Principals";

let identityCache: Promise<string> | undefined;
/** The local login name recorded with decisions; never asked for. */
export function useIdentity(): string {
  const [name, setName] = useState("");
  useEffect(() => {
    identityCache ??= api("/identity")
      .then((d) => d.analyst as string)
      .catch(() => "Assessor");
    identityCache.then(setName);
  }, []);
  return name;
}

function List({ items, empty }: { items?: string[]; empty: string }) {
  const values = (items || []).filter(Boolean);
  if (!values.length) return <p className="muted">{empty}</p>;
  return (
    <ul>
      {values.map((v, i) => (
        <li key={i}>{v}</li>
      ))}
    </ul>
  );
}

function Fold({
  title,
  open = false,
  children,
}: {
  title: string;
  open?: boolean;
  children: React.ReactNode;
}) {
  return (
    <details className="analysis-section" open={open}>
      <summary>{title}</summary>
      <div className="analysis-body">{children}</div>
    </details>
  );
}

/** JSON snippet with the lines holding the responsible fields highlighted. */
function Snippet({ text, highlight }: { text: string; highlight: string[] }) {
  const marks = highlight.map((h) => `"${h}":`);
  return (
    <pre className="evidence-snippet">
      {text.split("\n").map((line, i) => (
        <span
          key={i}
          className={marks.some((m) => line.includes(m)) ? "hl" : undefined}
        >
          {line + "\n"}
        </span>
      ))}
    </pre>
  );
}

function Copy({ text, label }: { text: string; label: string }) {
  const [state, setState] = useState("");
  return (
    <>
      <button
        className="small"
        onClick={() =>
          navigator.clipboard
            .writeText(text)
            .then(() => setState("Copied"))
            .catch(() =>
              setState("Copy blocked by the browser; select the text below."),
            )
        }
      >
        {label}
      </button>
      {state && <span className="muted"> {state}</span>}
    </>
  );
}

/** Quick summary plus expandable technical analysis, all from collected evidence. */
export function FindingAnalysis({
  run,
  findingId,
  epoch,
  decision,
}: {
  run: string;
  findingId: string;
  epoch?: number;
  decision: React.ReactNode;
}) {
  const [d, setD] = useState<Row>(),
    [error, setError] = useState(""),
    [showText, setShowText] = useState(false);
  useEffect(() => {
    let active = true;
    api(`/runs/${run}/findings/${encodeURIComponent(findingId)}/detail`)
      .then((r) => active && setD(r))
      .catch((e) => active && setError(e.message));
    return () => {
      active = false;
    };
  }, [run, findingId, epoch]);
  if (error) return <p className="error">{error}</p>;
  if (!d) return <p className="muted">Loading analysis…</p>;
  const o = d.overview,
    ob = d.observed,
    g = d.gap,
    m = d.misuse,
    im = d.impact,
    r = d.remediation,
    v = d.validation,
    c = d.completeness;
  return (
    <>
      {d.quality && (
        <section aria-label="Automatic finding validation">
          <h3>Automatic finding validation</h3>
          <p>{d.quality.state.replaceAll("_", " ")}</p>
          <p>{d.quality.qualification}</p>
          {d.quality.missing_fields.length > 0 && (
            <p>Missing fields: {d.quality.missing_fields.join(", ")}</p>
          )}
          {d.quality.unresolved.length > 0 && (
            <p>Unresolved: {d.quality.unresolved.join(", ")}</p>
          )}
          {d.frozen && (
            <p>
              This assessment edition is frozen. Further changes require a new
              enterprise snapshot.
            </p>
          )}
        </section>
      )}
      <section className="quick-summary" aria-label="Quick summary">
        <h3>Quick summary</h3>
        <p className="muted">
          ID {o.finding_id} · {o.provider} {o.service} · {o.account_or_project}{" "}
          · {o.region} · {o.resource_name}
        </p>
        <div className="explanation">
          {(
            [
              ["What is wrong", ob.observation],
              ["How it can be misused", m.scenario],
              ["Potential impact", im.technical],
              ["Recommended action", r.recommended_action],
            ] as [string, string][]
          ).map(([title, text]) => (
            <div key={title} className="explanation-part">
              <h4>{title}</h4>
              <p>{text}</p>
            </div>
          ))}
        </div>
        <PrincipalLinks principals={d.principals} />
        <div className="summary-actions">
          <Copy text={d.technical_finding} label="Copy technical finding" />
          <button className="small" onClick={() => setShowText(!showText)}>
            {showText ? "Hide report entry" : "Show report entry"}
          </button>
        </div>
        {showText && <pre className="report-entry">{d.technical_finding}</pre>}
      </section>
      {decision}
      <section className="technical-analysis" aria-label="Technical analysis">
        <h3>Technical analysis</h3>
        <Fold title="1. Finding overview">
          <dl className="facts">
            {(
              [
                ["Title", o.title],
                ["Finding ID", o.finding_id],
                ["Provider / service", `${o.provider} / ${o.service}`],
                ["Account / project", o.account_or_project],
                ["Region", o.region],
                ["Resource", `${o.resource_name} (${o.resource_id})`],
                ["Severity / confidence", `${o.severity} / ${o.confidence}`],
                ["Status", `${o.analyst_status} · ${o.stage}`],
                ["Control", `${o.control} ${o.control_subject}`],
                ["Domain", o.domain],
                ["Rule", o.rule],
              ] as [string, string][]
            ).map(([k, val]) => (
              <React.Fragment key={k}>
                <dt>{k}</dt>
                <dd>{val}</dd>
              </React.Fragment>
            ))}
          </dl>
          <p>{o.summary}</p>
        </Fold>
        <Fold title="2. What was observed" open>
          <p>{ob.observation}</p>
          {ob.exposure && <p className="muted">{ob.exposure}</p>}
          {ob.parameters.length > 0 && (
            <div className="table-wrap">
              <table aria-label="Actual versus expected configuration">
                <thead>
                  <tr>
                    <th>Parameter</th>
                    <th>Actual (from evidence)</th>
                    <th>Expected secure value</th>
                  </tr>
                </thead>
                <tbody>
                  {ob.parameters.map((p: Row) => (
                    <tr key={p.field}>
                      <td>{p.field}</td>
                      <td className="actual">{p.actual}</td>
                      <td>{p.expected}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p>
            <strong>Expected posture:</strong> {ob.expected_posture}
          </p>
        </Fold>
        <Fold title="3. What is wrong and the security gap">
          <p>
            <strong>Weakness:</strong> {g.weakness}
          </p>
          <p>
            <strong>Principle violated:</strong> {g.principle_violated}
          </p>
          <p>
            <strong>What is wrong:</strong> {g.what_is_wrong}
          </p>
          <p>
            <strong>Why it is insecure:</strong> {g.why_insecure}
          </p>
          <p>
            <strong>Confirmed or potential:</strong> {g.classification}
          </p>
        </Fold>
        <Fold title="4. Actual configuration evidence (collected)" open>
          {d.evidence.length === 0 && (
            <p className="muted">No evidence reference is recorded.</p>
          )}
          {d.evidence.map((e: Row, i: number) => (
            <div key={i} className="evidence-block">
              <p className="muted">
                {e.operation} · file {e.file} · path {e.locator} · collected{" "}
                {e.collected_at || "unrecorded"} · integrity{" "}
                {e.integrity_verified ? "verified" : "NOT verified"}
                {e.coverage && ` · coverage ${e.coverage}`}
              </p>
              {e.snippet ? (
                <Snippet text={e.snippet} highlight={e.highlight} />
              ) : (
                <p className="muted">{e.note}</p>
              )}
              {e.snippet && e.note && <p className="muted">{e.note}</p>}
            </div>
          ))}
          <p className="muted">
            Original collected values; credentials and secrets are masked.
            Highlighted lines hold the fields responsible for the finding.
          </p>
        </Fold>
        <Fold title="5. How can this be misused?">
          <p>{m.scenario}</p>
          <h4>Confirmed by evidence</h4>
          <List
            items={m.confirmed_by_evidence}
            empty="Nothing beyond the observation."
          />
          <h4>Not verified (prerequisites)</h4>
          <List
            items={m.unverified_prerequisites}
            empty="No open prerequisites recorded."
          />
          {m.attack_paths.length > 0 && (
            <p className="muted">
              Related attack-path patterns: {m.attack_paths.join(", ")}
            </p>
          )}
        </Fold>
        <Fold title="6. Potential security and business impact">
          <p>{im.technical}</p>
          <p>
            <strong>Severity {im.severity}:</strong> {im.severity_rationale}
          </p>
          <p className="muted">{im.business}</p>
        </Fold>
        <Fold title="7. Recommended remediation">
          <p>
            <strong>Recommended action:</strong> {r.recommended_action}
          </p>
          {r.immediate_mitigation && (
            <p>
              <strong>Immediate mitigation:</strong> {r.immediate_mitigation}
            </p>
          )}
          <p>
            <strong>Permanent remediation:</strong> {r.permanent_remediation}
          </p>
          {r.implementation_guidance && (
            <p>
              <strong>Implementation guidance:</strong>{" "}
              {r.implementation_guidance}
            </p>
          )}
          {r.operational_considerations && (
            <p>
              <strong>Dependencies and precautions:</strong>{" "}
              {r.operational_considerations}
            </p>
          )}
          {r.command && (
            <>
              <pre className="command">{r.command}</pre>
              <Copy text={r.command} label="Copy command" />
            </>
          )}
          <p className="muted">{r.command_note}</p>
          <List items={r.references} empty="" />
        </Fold>
        <Fold title="8. How to validate the remediation">
          <p>{v.procedure}</p>
          {v.command && (
            <>
              <pre className="command">{v.command}</pre>
              <Copy text={v.command} label="Copy verification command" />
            </>
          )}
          <h4>Expected secure state</h4>
          <List items={v.expected_state} empty="" />
          <p className="muted">{v.closure}</p>
        </Fold>
        <Fold title="9. Evidence completeness and validation">
          {c.needs_analyst_validation && (
            <p className="sre-callout">
              Evidence is incomplete or not high-confidence: validate before
              marking valid.
            </p>
          )}
          <p>Supporting observations: {c.confirmed_observations}</p>
          <h4>Missing information</h4>
          <List items={c.missing_information} empty="None recorded." />
          <h4>Collection errors or insufficient permissions</h4>
          <List items={c.collection_errors} empty="None for this evidence." />
          <h4>Potential false-positive conditions</h4>
          <List items={c.false_positive_conditions} empty="None recorded." />
          <h4>Additional validation</h4>
          <List items={c.additional_validation} empty="None recorded." />
        </Fold>
      </section>
    </>
  );
}
