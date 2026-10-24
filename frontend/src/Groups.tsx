import { useEffect, useState } from "react";
import { api, type Row } from "./api";
import { FalsePositiveReason } from "./Exclusion";
import { useIdentity } from "./FindingView";

const MAX_BULK = 2000;
const REASONS: [string, string][] = [
  ["FALSE_POSITIVE", "False positive"],
  ["ACCEPTED_RISK", "Risk accepted by the client"],
  ["OUT_OF_SCOPE", "Out of assessment scope"],
  ["COMPENSATING_CONTROL", "Mitigated by a compensating control"],
  ["DUPLICATE", "Duplicate of another finding"],
  ["NOT_APPLICABLE", "Not applicable to this environment"],
  ["OTHER", "Other (see note)"],
];

/** One root-cause group with bulk actions on its member findings. */
function GroupRow({
  run,
  group,
  onDone,
  onError,
}: {
  run: string;
  group: Row;
  onDone: () => void;
  onError: (s: string) => void;
}) {
  const analyst = useIdentity();
  const [reason, setReason] = useState("FALSE_POSITIVE"),
    [note, setNote] = useState(""),
    [busy, setBusy] = useState(false);
  const ids: string[] = group.members;
  const tooMany = ids.length > MAX_BULK;
  const act = async (path: string, body: Row) => {
    setBusy(true);
    try {
      await api(path, { ...body, finding_ids: ids });
      onDone();
    } catch (e: any) {
      onError(e.message);
    } finally {
      setBusy(false);
    }
  };
  const needsNote = ["FALSE_POSITIVE", "OTHER"].includes(reason);
  const disabled = busy || tooMany;
  return (
    <tr>
      <td>
        <span className={"badge " + String(group.severity).toLowerCase()}>
          {group.severity}
        </span>
      </td>
      <td>
        {group.title}
        <div className="muted">
          {group.rule_id} · {group.key_kind === "rule" ? "rule" : group.key}
        </div>
      </td>
      <td>{group.member_count}</td>
      <td>
        {group.affected_resources} / {group.affected_scopes}
      </td>
      <td>
        {Object.entries(group.status_mix as Record<string, number>)
          .map(([k, v]) => `${k.replaceAll("_", " ").toLowerCase()} ${v}`)
          .join(", ")}
        {group.excluded_members > 0 && (
          <div className="muted">{group.excluded_members} excluded</div>
        )}
      </td>
      <td className="group-actions" aria-label={`Actions for ${group.title}`}>
        {tooMany && (
          <p role="alert">
            {ids.length} members exceed the bulk limit of {MAX_BULK}; narrow the
            scope first.
          </p>
        )}
        <button
          className="small primary"
          disabled={disabled}
          onClick={() =>
            act(`/runs/${run}/review-bulk`, { status: "CONFIRMED", note: "" })
          }
        >
          Mark valid
        </button>
        <button
          className="small"
          disabled={disabled}
          onClick={() =>
            act(`/runs/${run}/sre`, { verdict: "SENT_TO_SRE", reason: "" })
          }
        >
          Send to SRE
        </button>
        <select
          aria-label="Group exclusion reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        >
          {REASONS.map(([k, label]) => (
            <option key={k} value={k}>
              {label}
            </option>
          ))}
        </select>
        {reason === "FALSE_POSITIVE" ? (
          <FalsePositiveReason
            value={note}
            onChange={setNote}
            label="Group false-positive reason"
          />
        ) : (
          <input
            aria-label="Group exclusion note"
            placeholder={needsNote ? "Note (required)" : "Note (optional)"}
            value={note}
            maxLength={2000}
            onChange={(e) => setNote(e.target.value)}
          />
        )}
        <button
          className="small danger"
          disabled={disabled || (needsNote && !note.trim())}
          onClick={() =>
            act(`/runs/${run}/exclusions`, {
              action: "EXCLUDE",
              reason,
              note: note.trim(),
              analyst: analyst || "Analyst",
            })
          }
        >
          Exclude group
        </button>
      </td>
    </tr>
  );
}

/** Root-cause groups (rule, principal, firewall rule or organization node). */
export function FindingGroups({
  run,
  epoch,
  onChanged,
  onError,
}: {
  run: string;
  epoch: number;
  onChanged: () => void;
  onError: (s: string) => void;
}) {
  const [data, setData] = useState<Row>();
  useEffect(() => {
    let live = true;
    api(`/runs/${run}/finding-groups`)
      .then((r) => live && setData(r))
      .catch((e) => live && onError(e.message));
    return () => {
      live = false;
    };
  }, [run, epoch]);
  const items: Row[] = data?.items || [];
  return (
    <details className="panel finding-groups">
      <summary>Root-cause groups ({items.length})</summary>
      <p className="muted">
        Findings sharing a root cause: the same rule, principal, firewall rule
        or organization node, across projects and accounts. Actions apply to
        every member finding; excluded findings are not members.
      </p>
      <div className="table-wrap">
        <table aria-label="Root-cause groups">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Group</th>
              <th>Findings</th>
              <th>Resources / scopes</th>
              <th>Status mix</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((g) => (
              <GroupRow
                key={g.group_id}
                run={run}
                group={g}
                onDone={onChanged}
                onError={onError}
              />
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
