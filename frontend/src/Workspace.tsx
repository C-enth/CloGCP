import React, { useState } from "react";
import { api, Row } from "./api";

const SOURCES: Record<string, string> = {
  DEFAULT: "Default location (nothing chosen)",
  REMEMBERED: "Location you chose (remembered)",
  COMMAND_LINE: "Set when CloSec was started (command line)",
  ENVIRONMENT: "Set by the CLOSEC_WORKSPACE environment variable",
  SETUP: "No workspace open",
};
const COUNT_LABELS: [string, string][] = [
  ["runs", "Evidence runs"],
  ["sources", "Collected sources"],
  ["findings", "Findings"],
  ["confirmations", "Confirmations"],
  ["exclusion_records", "Exclusion records"],
  ["report_drafts", "Report drafts"],
  ["finalised_editions", "Finalised editions"],
  ["path_reviews", "Path reviews"],
];
const ACTIONS: {
  purpose: string;
  title: string;
  label: string;
  help: string;
  confirm: string;
  button: string;
}[] = [
  {
    purpose: "open",
    title: "Open existing workspace (recovery)",
    label: "Existing workspace folder",
    help: "Opens a workspace folder, for example after a crash or from another location. It is checked read-only first; nothing is changed until you confirm and restart.",
    confirm: "I confirm: open this workspace after restarting CloSec.",
    button: "Open this workspace",
  },
  {
    purpose: "create",
    title: "Create new workspace",
    label: "New workspace folder",
    help: "Creates an empty workspace in a new or empty folder (owner-only permissions). The current workspace is kept unchanged.",
    confirm:
      "I confirm: create this workspace and switch to it after restarting.",
    button: "Create and switch",
  },
  {
    purpose: "change",
    title: "Move this workspace to a new location (copy)",
    label: "Destination folder for the copy",
    help: "Copies the whole workspace (database and journal included), verifies sizes, hashes and counts, then switches to the copy. The current folder is never modified or deleted; remove it yourself once satisfied.",
    confirm:
      "I confirm: copy this workspace there and switch to the copy after restarting.",
    button: "Copy, verify and switch",
  },
  {
    purpose: "backup",
    title: "Back up now",
    label: "Backup destination folder",
    help: "Copies the whole workspace into a new timestamped subfolder of the folder you choose and verifies it. Nothing is overwritten.",
    confirm: "I confirm: back up this workspace to that folder.",
    button: "Back up now",
  },
];

/** Active workspace path in the header, with a copy button. */
export function WorkspacePath({ path }: { path?: string }) {
  const [copied, setCopied] = useState(false);
  if (!path) return null;
  return (
    <span className="workspace-path" aria-label="Active workspace">
      <span className="muted">Workspace</span> <code title={path}>{path}</code>{" "}
      <button
        className="small"
        onClick={() =>
          navigator.clipboard
            ?.writeText(path)
            .then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
            })
            .catch(() => setCopied(false))
        }
      >
        {copied ? "Copied" : "Copy path"}
      </button>
    </span>
  );
}

function Counts({ counts, label }: { counts?: Row; label: string }) {
  if (!counts) return null;
  return (
    <div className="table-wrap">
      <table aria-label={label}>
        <tbody>
          {COUNT_LABELS.map(([key, name]) => (
            <tr key={key}>
              <th scope="row">{name}</th>
              <td>{counts[key] ?? 0}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Checks({ checks }: { checks?: Row }) {
  if (!checks) return null;
  const blocked: string[] = checks.blocked || [];
  const warnings: string[] = checks.warnings || [];
  if (!blocked.length && !warnings.length)
    return <p className="success">No location warnings.</p>;
  return (
    <>
      {blocked.length > 0 && (
        <div role="alert" className="error">
          <strong>Not allowed:</strong>
          <ul>
            {blocked.map((c) => (
              <li key={c}>{checks.messages[c]}</li>
            ))}
          </ul>
        </div>
      )}
      {warnings.length > 0 && (
        <div className="location-warnings" role="status">
          <strong>Location warnings:</strong>
          <ul>
            {warnings.map((c) => (
              <li key={c}>{checks.messages[c]}</li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

function Action({
  action,
  onDone,
}: {
  action: (typeof ACTIONS)[number];
  onDone: (result: Row) => void;
}) {
  const [path, setPath] = useState(""),
    [check, setCheck] = useState<Row>(),
    [accept, setAccept] = useState(false),
    [confirm, setConfirm] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [result, setResult] = useState<Row>();
  const reset = () => {
    setCheck(undefined);
    setAccept(false);
    setConfirm(false);
    setResult(undefined);
    setError("");
  };
  const inspection = check?.inspection;
  const refused =
    !!check?.checks?.blocked?.length ||
    !!check?.refusal ||
    (inspection && !inspection.ok);
  const needsAccept = !!check?.checks?.warnings?.length;
  const ready =
    !!check && !refused && confirm && (!needsAccept || accept) && !busy;
  return (
    <section className="panel" aria-label={action.title}>
      <h3>{action.title}</h3>
      <p className="muted">{action.help}</p>
      <div className="toolbar">
        <label>
          {action.label}
          <input
            value={path}
            onChange={(e) => {
              setPath(e.target.value);
              reset();
            }}
            placeholder="/full/path/to/folder or D:\folder"
            spellCheck={false}
          />
        </label>
        <button
          disabled={!path.trim() || busy}
          onClick={async () => {
            reset();
            try {
              setCheck(
                await api("/workspace/check", {
                  purpose: action.purpose,
                  path: path.trim(),
                }),
              );
            } catch (e: any) {
              setError(e.message);
            }
          }}
        >
          Check location
        </button>
      </div>
      {error && <p role="alert">{error}</p>}
      {check && (
        <div className="location-check" aria-label={`${action.title} check`}>
          <Checks checks={check.checks} />
          {check.refusal && <p role="alert">{check.refusal.message}</p>}
          {inspection && !inspection.ok && (
            <p role="alert">
              {inspection.message}
              {inspection.locked_by_pid
                ? ` (CloSec process ${inspection.locked_by_pid})`
                : ""}
            </p>
          )}
          {inspection?.ok && (
            <>
              <p>
                Workspace found: schema {inspection.schema}
                {inspection.schema === "OLDER" &&
                  " (a verified backup is taken beside it, then it is upgraded additively when opened)"}
                {inspection.unclean_shutdown &&
                  ". It was not closed cleanly; CloSec recovers it when opened and reports the counts again"}
                .
              </p>
              <Counts
                counts={inspection.counts}
                label="Counts in the selected workspace"
              />
            </>
          )}
          {!refused && needsAccept && (
            <label className="confirm">
              <input
                type="checkbox"
                checked={accept}
                onChange={(e) => setAccept(e.target.checked)}
              />{" "}
              I have read these warnings and accept them for this folder.
            </label>
          )}
          {!refused && (
            <label className="confirm">
              <input
                type="checkbox"
                checked={confirm}
                onChange={(e) => setConfirm(e.target.checked)}
              />{" "}
              {action.confirm}
            </label>
          )}
          <button
            className="primary"
            disabled={!ready}
            onClick={async () => {
              setBusy(true);
              setError("");
              try {
                const done = await api(
                  "/workspace/apply",
                  {
                    purpose: action.purpose,
                    path: path.trim(),
                    confirm: true,
                    accept_warnings: accept,
                  },
                  600000,
                );
                setResult(done);
                onDone(done);
              } catch (e: any) {
                setError(e.message);
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? "Working…" : action.button}
          </button>
        </div>
      )}
      {result && (
        <div role="status" className="location-result">
          {result.destination && (
            <p>
              Backup written and verified: <code>{result.destination}</code> (
              {result.files} files, counts{" "}
              {result.counts_match ? "match" : "DO NOT match"}).
            </p>
          )}
          {result.previous_path && (
            <p>
              Copy verified ({result.files} files, counts{" "}
              {result.counts_match ? "match" : "DO NOT match"}). The previous
              folder is unchanged and still exists:{" "}
              <code>{result.previous_path}</code>. Remove it yourself when you
              no longer need it.
            </p>
          )}
          {result.counts && (
            <Counts counts={result.counts} label="Counts in the copy" />
          )}
          {result.restart_required && (
            <p>Restart CloSec to open the selected workspace.</p>
          )}
        </div>
      )}
    </section>
  );
}

/** Workspace location screen: active path, open report, and the five actions. */
export function WorkspaceLocation({ info }: { info?: Row }) {
  const [restartNeeded, setRestartNeeded] = useState(false),
    [restarting, setRestarting] = useState(false),
    [error, setError] = useState("");
  if (!info) return <p role="status">Loading workspace location…</p>;
  const report = info.open_report || {};
  const restart = async () => {
    setRestarting(true);
    try {
      const r = await api("/workspace/restart", {});
      if (!r.restarting)
        setError("Stop CloSec and start it again to open the workspace.");
    } catch (e: any) {
      setError(e.message);
      setRestarting(false);
    }
  };
  return (
    <>
      {info.setup_required && (
        <p role="alert">
          The remembered workspace location is missing or no longer a CloSec
          workspace. Open an existing workspace, create a new one, or return to
          the default location.
        </p>
      )}
      <section className="panel" aria-label="Active workspace details">
        <h2>Active workspace</h2>
        {!info.setup_required && (
          <>
            <p>
              <WorkspacePath path={info.path} />
            </p>
            <p className="muted">{SOURCES[info.source] || info.source}</p>
          </>
        )}
        {report.recovered && (
          <p role="status">
            The workspace was not closed cleanly last time. CloSec recovered it
            and checked its integrity: {report.integrity}.
          </p>
        )}
        {report.migrated && (
          <p role="status">
            The workspace was upgraded additively; a verified backup was taken
            first ({report.backup?.files} files).
          </p>
        )}
        {report.counts && (
          <Counts counts={report.counts} label="Counts at opening" />
        )}
        {!info.setup_required && <Checks checks={info.checks} />}
        <p className="muted">{info.backup_note}</p>
      </section>
      {error && <p role="alert">{error}</p>}
      {restartNeeded && (
        <div role="status" className="panel">
          <p>The new workspace opens after CloSec restarts.</p>
          <button className="primary" disabled={restarting} onClick={restart}>
            {restarting ? "Restarting…" : "Restart CloSec now"}
          </button>
          {restarting && (
            <p className="muted">
              A new browser tab opens when CloSec is ready; close this one.
            </p>
          )}
        </div>
      )}
      <section className="panel" aria-label="Use the default location">
        <h3>Use current (default)</h3>
        {info.source === "REMEMBERED" || info.setup_required ? (
          <>
            <p className="muted">
              Forget the chosen location and open the default workspace after
              restarting: <code>{info.default_path}</code>. No files are moved
              or deleted.
            </p>
            <button
              onClick={async () => {
                try {
                  await api("/workspace/apply", {
                    purpose: "default",
                    confirm: true,
                  });
                  setRestartNeeded(true);
                } catch (e: any) {
                  setError(e.message);
                }
              }}
            >
              Return to the default location
            </button>
          </>
        ) : (
          <p className="muted">
            CloSec keeps using the current workspace. Nothing to do.
          </p>
        )}
      </section>
      {ACTIONS.filter(
        (a) => !info.setup_required || ["open", "create"].includes(a.purpose),
      ).map((a) => (
        <Action
          key={a.purpose}
          action={a}
          onDone={(r) => r.restart_required && setRestartNeeded(true)}
        />
      ))}
    </>
  );
}
