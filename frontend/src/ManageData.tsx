import { ChoiceFilter } from "./Filters";
import { useEffect, useRef, useState } from "react";
import {
  api,
  PREVIEW_TIMEOUT_MS,
  upload,
  relativePaths,
  type Row,
} from "./api";

type Props = {
  epoch: number;
  /** Preselect one account/project, e.g. from "Remove / replace data" in Findings. */
  initialScope?: Row;
  environment: string;
  onError: (s: string) => void;
  onJob: (job: Row) => void;
  onBusy: (busy: boolean) => void;
  startJob: (
    path: string,
    body?: Row,
    after?: (r: Row) => void,
  ) => Promise<void>;
};
export function ManageData({
  epoch,
  initialScope,
  environment,
  onError,
  startJob,
  onJob,
  onBusy,
}: Props) {
  const [scopes, setScopes] = useState<Row[]>([]),
    [search, setSearch] = useState(""),
    [scope, setScope] = useState<Row>(),
    [preview, setPreview] = useState<Row>(),
    [typed, setTyped] = useState(""),
    [confirmed, setConfirmed] = useState(false),
    [replacement, setReplacement] = useState<Row>(),
    [ack, setAck] = useState(false),
    [mode, setMode] = useState(""),
    [busy, setBusy] = useState(false),
    [backup, setBackup] = useState(true),
    [override, setOverride] = useState<Override>(NO_OVERRIDE),
    [purged, setPurged] = useState<Row>(),
    [previewing, setPreviewing] = useState(false);
  const file = useRef<HTMLInputElement>(null),
    folder = useRef<HTMLInputElement>(null);
  useEffect(() => {
    api("/assessment-data/scopes")
      .then((rows) => {
        setScopes(rows);
        setScope((current) =>
          rows.find(
            (s: Row) =>
              (current || initialScope) &&
              s.provider === (current || initialScope)!.provider &&
              s.scope_id === (current || initialScope)!.scope_id,
          ),
        );
        setPreview(undefined);
        setTyped("");
        setConfirmed(false);
      })
      .catch((e) => onError(e.message));
  }, [epoch, initialScope]);
  const select = (s: Row) => {
    setScope(s);
    setPreview(undefined);
    setReplacement(undefined);
    setTyped("");
    setConfirmed(false);
    setAck(false);
    setMode("");
  };
  const body = scope
    ? { provider: scope.provider, scope_id: scope.scope_id }
    : {};
  const choose = async (files: FileList | null) => {
    if (!files || !scope) return;
    setBusy(true);
    onBusy(true);
    setAck(false);
    setReplacement(undefined);
    try {
      const items = Array.from(files);
      setReplacement(
        await upload(
          items,
          relativePaths(items),
          {
            provider: scope.provider,
            origin:
              environment === "ASSESSMENT" ? "tool-generated" : "synthetic",
          },
          () => {},
          onJob,
        ),
      );
    } catch (e: any) {
      onError(e.message);
    } finally {
      setBusy(false);
      onBusy(false);
    }
  };
  const legacy =
    replacement?.diagnostics.integrity_assurance ===
    "LOCAL_HASH_ONLY_NO_SOURCE_CHECKSUMS";
  const matching =
    replacement?.can_import &&
    replacement.sources.every(
      (s: Row) =>
        (scope?.provider === "GCP" ? s.project_id : s.account_id) ===
        scope?.scope_id,
    );
  return (
    <section className="panel" aria-label="Manage Assessment Data">
      <h2>Manage Assessment Data</h2>
      <p>
        Select one exact account or project. Replacement retains historical
        evidence and activates only after successful analysis. Deletion affects
        managed workspace data; external exports/backups cannot be recalled.
        Counts include retained snapshots.
      </p>
      <label>
        Search canonical scope
        <ChoiceFilter
          label="Search assessment scopes"
          value={search}
          options={scopes.map((s) => s.scope_id)}
          onChange={setSearch}
        />
      </label>
      <div className="table-wrap">
        <table aria-label="Assessed scopes">
          <thead>
            <tr>
              <th>Provider</th>
              <th>Account / project</th>
              <th>Name / number</th>
              <th>Resources</th>
              <th>Findings</th>
              <th>Snapshots</th>
              <th>Latest collection</th>
            </tr>
          </thead>
          <tbody>
            {scopes
              .filter((s) =>
                JSON.stringify(s).toLowerCase().includes(search.toLowerCase()),
              )
              .map((s) => (
                <tr
                  key={s.provider + s.scope_id}
                  aria-selected={
                    scope?.provider === s.provider &&
                    scope?.scope_id === s.scope_id
                  }
                >
                  <td>{s.provider}</td>
                  <td>
                    <button
                      aria-pressed={
                        scope?.provider === s.provider &&
                        scope?.scope_id === s.scope_id
                      }
                      onClick={() => select(s)}
                    >
                      {s.scope_id}
                    </button>
                  </td>
                  <td>
                    {s.display_name || "Unrecorded"}
                    <br />
                    {s.project_number || ""}
                  </td>
                  <td>{s.resources}</td>
                  <td>{s.findings}</td>
                  <td>{s.snapshots.length}</td>
                  <td>{s.latest_collection || "Unknown"}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
      {purged && <PurgeResult result={purged} />}
      {scope && (
        <section className="panel" aria-label="Selected assessment scope">
          <h3>
            {scope.provider} · {scope.scope_id}
          </h3>
          <p>
            {scope.provider === "AWS" ? "Regions" : "Datasets"}:{" "}
            {(scope.provider === "AWS" ? scope.regions : scope.datasets).join(
              ", ",
            )}
          </p>
          <p>Related investigations: {scope.investigations}</p>
          <details>
            <summary>Evidence snapshots and import history</summary>
            <ul>
              {scope.snapshots.map((s: string) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
          </details>
          <div className="toolbar">
            <button
              className="primary"
              onClick={() => {
                setMode("replace");
                setPreview(undefined);
              }}
            >
              Replace Assessment Data
            </button>
            <button
              className="danger"
              disabled={previewing}
              onClick={async () => {
                setMode("delete");
                setTyped("");
                setConfirmed(false);
                setBackup(true);
                setOverride(NO_OVERRIDE);
                setPurged(undefined);
                setPreview(undefined);
                setPreviewing(true);
                try {
                  setPreview(
                    await api(
                      "/assessment-data/delete-preview",
                      body,
                      PREVIEW_TIMEOUT_MS,
                    ),
                  );
                } catch (e: any) {
                  onError(e.message);
                } finally {
                  setPreviewing(false);
                }
              }}
            >
              {" "}
              {previewing
                ? "Preparing deletion preview…"
                : scope.provider === "AWS"
                  ? "Delete Account Data"
                  : "Delete Project Data"}
            </button>
            <button
              className="danger"
              onClick={() => {
                setMode("file");
                setPreview(undefined);
              }}
            >
              Delete One Imported File
            </button>
          </div>
          {mode === "file" && (
            <FileRemoval
              scope={scope}
              epoch={epoch}
              onError={onError}
              startJob={startJob}
            />
          )}
          {mode === "replace" && (
            <section aria-label="Replace selected scope">
              <p>
                Choose a package containing exactly {scope.provider}{" "}
                {scope.scope_id}. The previous assessment remains available if
                verification or analysis fails.
              </p>
              <input
                hidden
                ref={file}
                type="file"
                accept=".zip"
                onChange={(e) => choose(e.target.files)}
              />
              <input
                hidden
                ref={folder}
                type="file"
                multiple
                {...({ webkitdirectory: "" } as any)}
                onChange={(e) => choose(e.target.files)}
              />
              <div className="toolbar">
                <button disabled={busy} onClick={() => file.current?.click()}>
                  Choose replacement ZIP
                </button>
                <button disabled={busy} onClick={() => folder.current?.click()}>
                  Choose replacement folder
                </button>
              </div>
              {replacement && (
                <>
                  <p>
                    {matching
                      ? "Verified package identity matches the selected scope."
                      : "Package identity does not match the selected scope."}
                  </p>
                  <p>{replacement.diagnostics.qualification}</p>
                  {legacy && (
                    <label>
                      <input
                        type="checkbox"
                        checked={ack}
                        onChange={(e) => setAck(e.target.checked)}
                      />
                      I acknowledge that this legacy package has no declared
                      source checksums.
                    </label>
                  )}
                  <button
                    className="primary"
                    disabled={!matching || busy || (legacy && !ack)}
                    onClick={() =>
                      startJob(
                        "/assessment-data/replace",
                        {
                          ...body,
                          upload_id: replacement.upload_id,
                          acknowledge_legacy_integrity: ack,
                        },
                        () => {
                          setMode("");
                          setReplacement(undefined);
                        },
                      )
                    }
                  >
                    Verify, assess and activate replacement
                  </button>
                </>
              )}
            </section>
          )}
          {mode === "delete" && preview && (
            <section className="deletion-preview" aria-label="Deletion preview">
              <h3>Permanent scoped deletion preview</h3>
              <p>
                {preview.provider} · <strong>{preview.scope_id}</strong>
                {scope.project_number && (
                  <> · project number {scope.project_number}</>
                )}
              </p>
              <p>Workspace: {preview.workspace}</p>
              {preview.frozen_decision_required && (
                <SupersedeOverride
                  editions={preview.frozen_editions}
                  idLabel={
                    scope.provider === "AWS"
                      ? "12-digit account ID"
                      : "project ID"
                  }
                  value={override}
                  onChange={(o) => {
                    setOverride(o);
                    if (o.on) setBackup(true);
                  }}
                />
              )}
              <h4>Will be removed</h4>
              <CountList label="Removed data" counts={preview.removed} />
              <h4>Affected but kept</h4>
              <CountList
                label="Affected but kept"
                counts={preview.retained_affected}
              />
              <p className="muted">
                Consolidated drafts that also cover other accounts or projects
                keep their other members, lose this scope's assets and must be
                reviewed again. Rebuilt snapshots keep the other scopes.
              </p>
              {preview.relationship_edges_truncated && (
                <p>
                  Relationship count is a bounded lower limit; all affected
                  relationships are recomputed.
                </p>
              )}
              <details>
                <summary>
                  Managed files affected ({preview.files.length})
                </summary>
                <ul>
                  {preview.files.map((p: string) => (
                    <li key={p}>{p}</li>
                  ))}
                </ul>
              </details>
              {preview.limitations.map((s: string) => (
                <p key={s}>{s}</p>
              ))}
              {preview.shared_raw_blocked && (
                <p role="alert">
                  Deletion is blocked: a raw response contains configurations
                  from more than one scope. No data will be deleted.
                </p>
              )}
              <label>
                Type the exact{" "}
                {scope.provider === "AWS"
                  ? "12-digit account ID"
                  : "project ID"}
                <input
                  aria-label="Deletion confirmation identifier"
                  autoComplete="off"
                  value={typed}
                  onChange={(e) => setTyped(e.target.value)}
                />
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(e) => setConfirmed(e.target.checked)}
                />
                I confirm permanently deleting this selected scope's managed
                data.
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={backup}
                  disabled={override.on}
                  onChange={(e) => setBackup(e.target.checked)}
                />
                Back up the workspace first (recommended; required to mark an
                edition superseded). The backup holds the purged data: store and
                delete it under the same rules as the evidence.
              </label>
              <button
                className="danger"
                disabled={
                  typed !== scope.scope_id ||
                  !confirmed ||
                  preview.shared_raw_blocked ||
                  (preview.frozen_decision_required &&
                    !overrideReady(override, [scope.scope_id]))
                }
                onClick={() =>
                  startJob(
                    "/assessment-data/delete",
                    {
                      ...body,
                      preview_token: preview.preview_token,
                      confirmation: typed,
                      confirmed,
                      backup,
                      ...overrideBody(override, preview),
                    },
                    (result) => {
                      setPurged(result);
                      setScope(undefined);
                      setPreview(undefined);
                    },
                  )
                }
              >
                Permanently delete selected scope
              </button>
            </section>
          )}
        </section>
      )}
    </section>
  );
}

function CountList({ label, counts }: { label: string; counts?: Row }) {
  return (
    <dl aria-label={label}>
      {Object.entries(counts || {}).map(([k, v]) => (
        <div key={k}>
          <dt>{k.replaceAll("_", " ")}</dt>
          <dd>{String(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

type Override = { on: boolean; typed: string; reason: string };
const NO_OVERRIDE: Override = { on: false, typed: "", reason: "" };

function overrideReady(o: Override, ids: string[]) {
  return o.on && ids.includes(o.typed) && o.reason.trim().length >= 10;
}

function overrideBody(o: Override, preview: Row) {
  return preview.frozen_decision_required && o.on
    ? {
        supersede_frozen: true,
        supersede_confirmation: o.typed,
        supersede_reason: o.reason,
      }
    : {};
}

/** Frozen editions block removal; the only override keeps them and marks them superseded. */
function SupersedeOverride({
  editions,
  idLabel,
  value,
  onChange,
}: {
  editions: number;
  idLabel: string;
  value: Override;
  onChange: (o: Override) => void;
}) {
  return (
    <section className="error" aria-label="Frozen edition decision">
      <div>
        <p role="alert">
          A finalised (frozen) edition includes this data ({editions}). It is
          never altered or deleted automatically, so removal is blocked.
        </p>
        <label>
          <input
            type="checkbox"
            checked={value.on}
            onChange={(e) => onChange({ ...value, on: e.target.checked })}
          />
          Purge and mark edition superseded (the edition record is kept, marked
          superseded with time and reason, and held in the pre-purge backup)
        </label>
        {value.on && (
          <>
            <label>
              Type the {idLabel} to mark the edition superseded
              <input
                aria-label="Supersede confirmation identifier"
                autoComplete="off"
                value={value.typed}
                onChange={(e) => onChange({ ...value, typed: e.target.value })}
              />
            </label>
            <label>
              Reason (required)
              <textarea
                aria-label="Supersede reason"
                maxLength={2000}
                value={value.reason}
                onChange={(e) => onChange({ ...value, reason: e.target.value })}
              />
            </label>
          </>
        )}
      </div>
    </section>
  );
}

/** Backup location and the separated post-purge search of every backend store. */
function PurgeResult({ result }: { result: Row }) {
  const v = result.verification || {};
  const drafts = v.analyst_drafts_mentioning || { drafts: [], revisions: 0 };
  const evidence = v.cross_account_evidence_retained || {};
  const other = v.other_retained || {};
  return (
    <section className="panel" aria-label="Purge result">
      <h3>Scope data purged</h3>
      <p>
        {result.backup
          ? `Backup before purging: ${result.backup.path} (${result.backup.files} files). It holds the purged data: store and delete it under the same rules as the evidence.`
          : "No backup was taken (declined)."}
      </p>
      {result.superseded_editions > 0 && (
        <p>
          Frozen editions marked superseded (records kept):{" "}
          {result.superseded_editions}
        </p>
      )}
      <p role="status" className={v.clean ? "success" : "error"}>
        {v.clean
          ? "Verification: no remaining reference in the database, its files or the workspace."
          : `Verification: not clean. ${v.references} reference(s) remain, listed by category below.`}
      </p>
      <h4>References removed ({v.references_removed?.total ?? 0})</h4>
      <CountList
        label="References removed: database rows"
        counts={v.references_removed?.database_rows}
      />
      <CountList
        label="References removed: files"
        counts={v.references_removed?.files}
      />
      <h4>
        Cross-account references retained in other accounts' evidence (
        {evidence.total ?? 0})
      </h4>
      <p className="muted">
        Kept: other accounts' or projects' own evidence names this scope (for
        example an Organizations account list or a policy resource).
      </p>
      <CountList
        label="Retained evidence: database rows"
        counts={evidence.database_rows}
      />
      <CountList label="Retained evidence: files" counts={evidence.files} />
      <h4>
        Analyst-written drafts that still mention the identifier (
        {drafts.revisions} revision(s))
      </h4>
      {drafts.drafts.length ? (
        <ul aria-label="Drafts mentioning the identifier">
          {drafts.drafts.map((d: Row) => (
            <li key={d.report_id}>
              {d.draft} · {d.revisions} revision(s)
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">None.</p>
      )}
      {v.superseded_frozen_editions_retained > 0 && (
        <p>
          Superseded frozen editions retained by decision:{" "}
          {v.superseded_frozen_editions_retained}
        </p>
      )}
      {other.total > 0 && (
        <>
          <h4>Other retained references ({other.total})</h4>
          <CountList
            label="Other: database rows"
            counts={other.database_rows}
          />
          <CountList label="Other: files" counts={other.files} />
        </>
      )}
      <h4>Removed records</h4>
      <CountList label="Removed" counts={result.removed} />
    </section>
  );
}

/** One imported file is removed only after its own preview and exact confirmation. */
function FileRemoval({
  scope,
  epoch,
  onError,
  startJob,
}: {
  scope: Row;
  epoch: number;
  onError: (s: string) => void;
  startJob: Props["startJob"];
}) {
  const [files, setFiles] = useState<Row[]>([]),
    [preview, setPreview] = useState<Row>(),
    [typed, setTyped] = useState(""),
    [confirmed, setConfirmed] = useState(false),
    [override, setOverride] = useState<Override>(NO_OVERRIDE),
    [done, setDone] = useState<Row>(),
    [previewing, setPreviewing] = useState(false);
  useEffect(() => {
    setPreview(undefined);
    api(
      "/assessment-data/files",
      {
        provider: scope.provider,
        scope_id: scope.scope_id,
      },
      PREVIEW_TIMEOUT_MS,
    )
      .then(setFiles)
      .catch((e) => onError(e.message));
  }, [scope, epoch]);
  const review = async (sha256: string) => {
    setTyped("");
    setConfirmed(false);
    setOverride(NO_OVERRIDE);
    setDone(undefined);
    setPreview(undefined);
    setPreviewing(true);
    try {
      setPreview(
        await api(
          "/assessment-data/file-delete-preview",
          { sha256 },
          PREVIEW_TIMEOUT_MS,
        ),
      );
    } catch (e: any) {
      onError(e.message);
    } finally {
      setPreviewing(false);
    }
  };
  return (
    <section aria-label="Delete one imported file">
      <p>
        Choose one imported evidence file. Nothing is removed until you review
        its preview and confirm it explicitly.
      </p>
      {previewing && <p role="status">Preparing file deletion preview…</p>}
      <div className="table-wrap">
        <table aria-label="Imported files">
          <thead>
            <tr>
              <th>File</th>
              <th>Operations</th>
              <th>Regions</th>
              <th>Snapshots</th>
              <th>Digest</th>
            </tr>
          </thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.sha256} aria-selected={preview?.sha256 === f.sha256}>
                <td>
                  <button
                    disabled={previewing}
                    onClick={() => review(f.sha256)}
                  >
                    {f.paths.join(", ")}
                  </button>
                </td>
                <td>{f.operations.join(", ")}</td>
                <td>{f.regions.join(", ")}</td>
                <td>{f.snapshots}</td>
                <td>
                  <code>{f.sha256.slice(0, 12)}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {preview && (
        <section
          className="deletion-preview"
          aria-label="File deletion preview"
        >
          <h3>Permanent file deletion preview</h3>
          <p>
            {preview.paths.join(", ")} · digest <code>{preview.sha256}</code>
          </p>
          <p>
            Scopes:{" "}
            {preview.scopes
              .map((s: Row) => `${s.provider} ${s.scope_id}`)
              .join(", ")}
          </p>
          <p>Workspace: {preview.workspace}</p>
          {preview.frozen_decision_required && (
            <SupersedeOverride
              editions={preview.frozen_editions}
              idLabel="account or project ID of this file"
              value={override}
              onChange={setOverride}
            />
          )}
          <dl>
            {[
              "snapshots",
              "observations",
              "resources",
              "findings",
              "analyst_reviews",
              "report_revisions",
              "frozen_editions",
              "path_reviews",
              "managed_exports",
            ].map((k) => (
              <div key={k}>
                <dt>{k.replaceAll("_", " ")}</dt>
                <dd>{preview[k]}</dd>
              </div>
            ))}
          </dl>
          <details>
            <summary>Managed files affected ({preview.files.length})</summary>
            <ul>
              {preview.files.map((p: string) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </details>
          {preview.limitations.map((s: string) => (
            <p key={s}>{s}</p>
          ))}
          <label>
            Type the first 12 characters of the digest
            <input
              aria-label="File deletion confirmation digest"
              autoComplete="off"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
            />
          </label>
          <label>
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            I confirm permanently deleting this imported file and the data
            derived from it.
          </label>
          <button
            className="danger"
            disabled={
              typed !== preview.sha256.slice(0, 12) ||
              !confirmed ||
              (preview.frozen_decision_required &&
                !overrideReady(
                  override,
                  preview.scopes.map((s: Row) => s.scope_id),
                ))
            }
            onClick={() =>
              startJob(
                "/assessment-data/file-delete",
                {
                  sha256: preview.sha256,
                  preview_token: preview.preview_token,
                  confirmation: typed,
                  confirmed,
                  ...overrideBody(override, preview),
                },
                (result) => {
                  setDone(result);
                  setPreview(undefined);
                },
              )
            }
          >
            Permanently delete selected file
          </button>
        </section>
      )}
      {done && done.superseded_editions > 0 && (
        <p role="status">
          File removed. Frozen editions marked superseded (records kept):{" "}
          {done.superseded_editions}. Backup before removal: {done.backup?.path}
          . It holds the removed data: store and delete it under the same rules
          as the evidence.
        </p>
      )}
    </section>
  );
}

/** Removing a browser/source selection never silently deletes retained backend evidence. */
export function ImportedRemoval({
  epoch,
  onSelect,
}: {
  epoch: number;
  onSelect: (scope: Row) => void;
}) {
  const [scopes, setScopes] = useState<Row[]>([]),
    [selected, setSelected] = useState(""),
    [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    api("/assessment-data/scopes")
      .then((d) => {
        if (live) setScopes(d);
      })
      .catch((e) => {
        if (live) setError(e.message);
      });
    return () => {
      live = false;
    };
  }, [epoch]);
  return (
    <section className="panel" aria-label="Remove retained import">
      <h2>Removed a local evidence file?</h2>
      <p>
        Removing a local file or clearing a browser selection leaves the
        imported backend copy intact. You can also remove its account or project
        from the backend, or one imported file, using the deletion preview and
        two explicit confirmations. Individual files can support several
        findings; backend deletion follows exactly what the preview shows.
      </p>
      {error && <p role="alert">{error}</p>}
      <ChoiceFilter
        label="Backend removal scope"
        value={selected}
        options={scopes.map((s) => `${s.provider}:${s.scope_id}`)}
        all="Choose imported account or project"
        onChange={setSelected}
      />
      <button
        disabled={!selected}
        onClick={() => {
          const s = scopes.find(
            (s) => `${s.provider}:${s.scope_id}` === selected,
          );
          if (s) onSelect({ provider: s.provider, scope_id: s.scope_id });
        }}
      >
        Review optional backend removal
      </button>
    </section>
  );
}
