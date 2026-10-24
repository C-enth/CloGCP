import { useEffect, useState } from "react";
import { api, Row } from "./api";

const fields = [
  ["title", "Finding title"],
  ["severity_rationale", "Severity rationale"],
  ["technical_observation", "Technical observation"],
  ["expected_posture", "Expected security posture"],
  ["risk", "Security risk and potential impact"],
  ["attack_scenario", "Conditional attack scenario"],
  ["root_cause", "Root cause"],
  ["remediation", "Recommended remediation"],
  ["considerations", "Implementation considerations"],
  ["validation", "Remediation validation"],
];

export function ReportFinding({
  run,
  finding,
  onError,
  reviewer = "",
}: {
  run: string;
  finding: string;
  onError: (s: string) => void;
  /** Pre-fills the reviewer with the local login name; editable, never required to type. */
  reviewer?: string;
}) {
  const [data, setData] = useState<Row>(),
    [sections, setSections] = useState<Row>({}),
    [analyst, setAnalyst] = useState(""),
    [members, setMembers] = useState(finding),
    [basis, setBasis] = useState(""),
    [include, setInclude] = useState(false),
    [rationale, setRationale] = useState(""),
    [message, setMessage] = useState(""),
    [busy, setBusy] = useState(false),
    [dirty, setDirty] = useState(false),
    [choices, setChoices] = useState<Row[]>([]);
  const path = `/runs/${run}/report-findings/${finding}`;
  const load = async () => {
    const d = await api(path),
      r = d.revision;
    setData(d);
    setSections(r?.sections || d.sections);
    setInclude(r?.include_in_report || false);
    setMembers(
      r ? r.snapshots.map((s: Row) => s.finding_id).join("\n") : finding,
    );
    setBasis(r?.consolidation_basis || "");
    setDirty(false);
  };
  useEffect(() => {
    load().catch((e) => onError(e.message));
  }, [run, finding]);
  useEffect(() => {
    if (!analyst && reviewer) setAnalyst(reviewer);
  }, [reviewer]);
  const perform = async (action: () => Promise<void>) => {
    setBusy(true);
    setMessage("");
    try {
      await action();
    } catch (e: any) {
      onError(e.message);
    } finally {
      setBusy(false);
    }
  };
  const approve = (kind: string) =>
    perform(async () => {
      await api(path + "/approve", {
        expected_revision: data?.revision?.revision,
        analyst,
        kind,
        rationale,
      });
      await load();
      setMessage(`${kind.toLowerCase()} approval recorded.`);
    });
  if (!data) return <p>Loading report draft…</p>;
  const revision = data.revision;
  return (
    <section className="panel" aria-label="Report finding editor">
      <h3>Client report finding</h3>
      {data.frozen && (
        <p>This edition is frozen. The preserved report cannot be edited.</p>
      )}
      <fieldset disabled={data.frozen}>
        <p>
          Technical confirmation, recommendation approval and narrative approval
          are separate. Saving an edit resets report approvals. Refreshed
          evidence can require review; historical text remains preserved.
        </p>
        <p>
          Revision: {revision?.revision || "Unsaved"} · Evidence:{" "}
          {data.evidence_state || "Draft"} · Export:{" "}
          {data.eligible ? "APPROVED" : "NOT APPROVED"}
        </p>
        <details>
          <summary>Versioned remediation template</summary>
          <p>
            {data.recommendation?.status} · {data.recommendation?.version}
          </p>
          {Object.entries(data.recommendation || {})
            .filter(([k]) => !["references", "version", "status"].includes(k))
            .map(([k, v]) => (
              <p key={k}>
                <b>{k.replaceAll("_", " ")}: </b>
                {String(v)}
              </p>
            ))}
        </details>
        <label>
          Report reviewer
          <input
            aria-label="Report reviewer"
            value={analyst}
            onChange={(e) => setAnalyst(e.target.value)}
            maxLength={200}
          />
        </label>
        <label>
          Approved severity
          <select
            aria-label="Report severity"
            value={sections.severity}
            onChange={(e) => {
              setSections({ ...sections, severity: e.target.value });
              setDirty(true);
            }}
          >
            {["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        {fields.map(([key, label]) => (
          <label key={key}>
            {label}
            <textarea
              aria-label={`Report ${label.toLowerCase()}`}
              value={sections[key] || ""}
              maxLength={key === "title" ? 500 : 16000}
              onChange={(e) => {
                setSections({ ...sections, [key]: e.target.value });
                setDirty(true);
              }}
            />
          </label>
        ))}
        <label>
          Applicable cloud references (one per line)
          <textarea
            aria-label="Report references"
            value={(sections.references || []).join("\n")}
            onChange={(e) => {
              setSections({
                ...sections,
                references: e.target.value.split("\n").filter(Boolean),
              });
              setDirty(true);
            }}
          />
        </label>
        <details>
          <summary>Consolidate related findings</summary>
          <p>
            Select only findings with a shared root cause and remediation scope.
            Every member requires current technical confirmation. Evidence is
            preserved per account and asset.
          </p>
          <button
            onClick={() =>
              perform(async () => {
                const g = await api(`/runs/${run}/finding-groups`);
                const group = (g.items as Row[]).find((x) =>
                  (x.members as string[]).includes(finding),
                );
                if (group) {
                  setMembers(
                    [
                      finding,
                      ...(group.members as string[]).filter(
                        (id) => id !== finding,
                      ),
                    ].join("\n"),
                  );
                  setDirty(true);
                }
              })
            }
          >
            Use root-cause group members
          </button>
          <button
            onClick={() =>
              perform(async () => {
                const p = await api(`/runs/${run}/records/findings?limit=100`);
                setChoices(p.items);
              })
            }
          >
            Load finding choices (first 100)
          </button>
          {choices.map((c) => (
            <label key={c.finding_id}>
              <input
                type="checkbox"
                disabled={c.finding_id === finding}
                checked={members.split("\n").includes(c.finding_id)}
                onChange={(e) => {
                  setMembers(
                    e.target.checked
                      ? members + "\n" + c.finding_id
                      : members
                          .split("\n")
                          .filter((id) => id !== c.finding_id)
                          .join("\n"),
                  );
                  setDirty(true);
                }}
              />
              {c.account_id} · {c.native_id} · {c.title}
            </label>
          ))}
          <label>
            Member finding IDs (one per line)
            <textarea
              aria-label="Report member finding IDs"
              value={members}
              onChange={(e) => {
                setMembers(e.target.value);
                setDirty(true);
              }}
            />
          </label>
          <label>
            Consolidation rationale
            <textarea
              aria-label="Consolidation rationale"
              value={basis}
              onChange={(e) => {
                setBasis(e.target.value);
                setDirty(true);
              }}
            />
          </label>
        </details>
        <label>
          <input
            type="checkbox"
            aria-label="Include in client report"
            checked={include}
            onChange={(e) => {
              setInclude(e.target.checked);
              setDirty(true);
            }}
          />
          Include in client report after all approvals
        </label>
        <button
          disabled={busy || !analyst.trim()}
          onClick={() =>
            perform(async () => {
              await api(path, {
                expected_revision: revision?.revision || 0,
                analyst,
                sections,
                member_ids: members.split(/\s+/).filter(Boolean),
                include_in_report: include,
                consolidation_basis: basis,
              });
              await load();
              setMessage(
                `Report draft saved in ${data.storage}; finding ${finding}. Report approvals reset.`,
              );
            })
          }
        >
          Save report draft
        </button>
        <label>
          Approval / risk acceptance rationale
          <textarea
            aria-label="Report approval rationale"
            value={rationale}
            onChange={(e) => setRationale(e.target.value)}
            maxLength={16000}
          />
        </label>
        <div className="review-actions">
          <button
            disabled={busy || dirty || !revision || !analyst.trim()}
            onClick={() => approve("RECOMMENDATION")}
          >
            Approve recommendation
          </button>
          <button
            disabled={busy || dirty || !revision || !analyst.trim()}
            onClick={() => approve("NARRATIVE")}
          >
            Approve report narrative
          </button>
          <button
            disabled={
              busy ||
              dirty ||
              !revision ||
              !analyst.trim() ||
              revision.snapshots.length < 2
            }
            onClick={() => approve("CONSOLIDATION")}
          >
            Approve consolidation
          </button>
          <button
            disabled={
              busy ||
              dirty ||
              !revision ||
              !analyst.trim() ||
              rationale.trim().length < 20
            }
            onClick={() => approve("RISK_ACCEPTANCE")}
          >
            Record risk acceptance
          </button>
          <button
            disabled={busy || dirty || !data.eligible}
            onClick={() =>
              perform(async () => {
                const r = await api(path + "/copy");
                await navigator.clipboard.writeText(r.text);
                setMessage(`Approved revision ${r.revision} copied.`);
              })
            }
          >
            Copy Report Finding
          </button>
        </div>
        <p role="status">{message}</p>
        {revision && (
          <p className="muted">
            Saved locally in {data.storage}. Draft key: {data.draft_key};
            revision {revision.revision}. Preserved across application restarts.
            Download the consolidated draft in Report center with GCP, AWS or
            both selected.
          </p>
        )}
        <p>
          Recommendation:{" "}
          {revision?.recommendation_approval ? "Approved" : "Unapproved"} ·
          Narrative: {revision?.narrative_approval ? "Approved" : "Unapproved"}
        </p>
        {revision && (
          <details>
            <summary>Saved report preview</summary>
            <pre className="report-preview">{revision.report_text}</pre>
          </details>
        )}
        <details>
          <summary>Historical report revisions ({data.history.length})</summary>
          {data.history.map((r: Row) => (
            <details key={r.revision}>
              <summary>
                Revision {r.revision} · {r.created_at} · {r.author}
              </summary>
              <pre className="report-preview">{r.report_text}</pre>
            </details>
          ))}
        </details>
      </fieldset>
    </section>
  );
}

export function ApprovedReports({
  run,
  epoch,
  busy,
  startJob,
}: {
  run: string;
  epoch: number;
  busy: boolean;
  startJob: (path: string, body?: Row) => Promise<void>;
}) {
  const [items, setItems] = useState<Row[]>([]),
    [selected, setSelected] = useState<string[]>([]),
    [error, setError] = useState("");
  useEffect(() => {
    setSelected([]);
    api(`/runs/${run}/report-findings`)
      .then(setItems)
      .catch((e) => setError(e.message));
  }, [run, epoch]);
  return (
    <section className="panel">
      <h2>Approved client findings</h2>
      <p>
        Only current, included findings with technical confirmation and
        independent report approvals can be exported. DOCX opens in Microsoft
        Word. Existing Excel remains comprehensive and includes candidates.
      </p>
      {error && <p className="error">{error}</p>}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Select</th>
              <th>Finding</th>
              <th>Revision</th>
              <th>Assets</th>
              <th>Evidence / approval</th>
            </tr>
          </thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.report_id}>
                <td>
                  <input
                    type="checkbox"
                    aria-label={`Select report ${r.title}`}
                    disabled={!r.eligible}
                    checked={selected.includes(r.primary_finding)}
                    onChange={(e) =>
                      setSelected(
                        e.target.checked
                          ? [...selected, r.primary_finding]
                          : selected.filter((id) => id !== r.primary_finding),
                      )
                    }
                  />
                </td>
                <td>{r.title}</td>
                <td>{r.revision}</td>
                <td>{r.members}</td>
                <td>
                  {r.evidence_state} ·{" "}
                  {r.eligible ? "APPROVED" : "NOT APPROVED"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="review-actions">
        <button
          disabled={busy || !selected.length}
          onClick={() =>
            startJob(`/runs/${run}/reports`, {
              kind: "approved-docx",
              selected,
            })
          }
        >
          Export selected approved findings
        </button>
        <button
          disabled={busy || !items.some((r) => r.eligible)}
          onClick={() =>
            startJob(`/runs/${run}/reports`, { kind: "approved-docx" })
          }
        >
          Export all approved findings (Word DOCX)
        </button>
        <button
          disabled={busy || !items.some((r) => r.eligible)}
          onClick={() =>
            startJob(`/runs/${run}/reports`, { kind: "approved-text" })
          }
        >
          Export all approved findings (text)
        </button>
      </div>
    </section>
  );
}
