// GCP frozen-edition feed: export a finalized GCP edition (signed bundle, key shown once),
// import it read-only into this workspace and link it to an AWS run for consolidated views.
// All checks (hashes, signature, reconciliation) run in the API (reporting/gcp_feed.py).
import { useEffect, useState } from "react";
import { api, display, type Row } from "./api";

type StartJob = (
  path: string,
  body?: Row,
  after?: (result: Row) => void,
) => Promise<void>;

export function GcpEditionPanel({
  run,
  startJob,
  busy,
}: {
  run: string;
  startJob: StartJob;
  busy: boolean;
}) {
  const [items, setItems] = useState<Row[]>([]);
  const [linked, setLinked] = useState<Row | null>(null);
  const [exported, setExported] = useState<Row | null>(null);
  const [path, setPath] = useState("");
  const [key, setKey] = useState("");
  const [error, setError] = useState("");
  const refresh = async () => {
    try {
      setItems((await api("/gcp-editions")).items || []);
      if (run) setLinked((await api(`/runs/${run}/gcp-edition`)).edition);
    } catch (e: any) {
      setError(e.message);
    }
  };
  useEffect(() => {
    refresh();
  }, [run]);
  const act = async (fn: () => Promise<void>) => {
    setError("");
    try {
      await fn();
      await refresh();
    } catch (e: any) {
      setError(e.message);
    }
  };
  return (
    <section className="panel gcp-edition" aria-labelledby="gcp-edition-title">
      <h2 id="gcp-edition-title">GCP frozen edition feed</h2>
      <p className="muted">
        A finalized GCP edition can be exported as a signed bundle (findings,
        STRIDE mapping, attack paths with hops, coverage and limitations; no raw
        evidence) and imported read-only into an AWS workspace. The consolidated
        dashboard and reports then show GCP results labelled by edition, and
        report export is blocked unless AWS live plus GCP frozen equals the
        consolidated total.
      </p>
      {error && <p role="alert">{error}</p>}
      <h3>Export the finalized GCP edition of this run</h3>
      <button
        disabled={busy || !run}
        onClick={() =>
          act(async () =>
            setExported(await api(`/runs/${run}/gcp-edition/export`, {})),
          )
        }
      >
        Export GCP frozen edition
      </button>
      {exported && (
        <div role="status" className="warning">
          <p>
            Bundle {exported.file} ({exported.findings} findings), SHA-256{" "}
            <code>{exported.sha256}</code>.{" "}
            <a href={`/api/gcp-editions/exports/${exported.file}`}>Download</a>
          </p>
          <p>
            Signing key (shown once; give it to the importing assessor through a
            separate channel): <code>{exported.key}</code>
          </p>
        </div>
      )}
      <h3>Import a GCP frozen edition</h3>
      <label>
        Bundle file on this computer
        <input value={path} onChange={(e) => setPath(e.target.value)} />
      </label>
      <label>
        Signing key
        <input
          value={key}
          onChange={(e) => setKey(e.target.value.trim())}
          autoComplete="off"
        />
      </label>
      <button
        disabled={busy || !path.trim() || key.length !== 64}
        onClick={() =>
          startJob("/gcp-editions/import", { path: path.trim(), key }, refresh)
        }
      >
        Import edition
      </button>
      {items.length > 0 && (
        <table>
          <thead>
            <tr>
              <th scope="col">Edition</th>
              <th scope="col">Frozen</th>
              <th scope="col">Findings</th>
              <th scope="col">Projects</th>
              <th scope="col">Collector</th>
              <th scope="col">Linked</th>
              <th scope="col" />
            </tr>
          </thead>
          <tbody>
            {items.map((e) => (
              <tr key={e.edition_id}>
                <td>{e.edition_id.slice(-16)}</td>
                <td>{display(e.frozen_at)}</td>
                <td>{e.counts?.findings}</td>
                <td>{e.projects}</td>
                <td>{(e.collector_versions || []).join(", ")}</td>
                <td>{e.linked_runs?.includes(run) ? "This run" : "—"}</td>
                <td>
                  {!linked && run && (
                    <button
                      disabled={busy}
                      onClick={() =>
                        act(async () => {
                          await api(`/runs/${run}/gcp-edition`, {
                            edition_id: e.edition_id,
                          });
                        })
                      }
                    >
                      Use for this run
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

/** Dashboard notice: the GCP part of this view is a read-only frozen edition. */
export function GcpEditionBanner({ run }: { run: string }) {
  const [edition, setEdition] = useState<Row | null>(null);
  useEffect(() => {
    let live = true;
    setEdition(null);
    if (run)
      api(`/runs/${run}/gcp-edition`)
        .then((r) => live && setEdition(r.edition))
        .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [run]);
  if (!edition) return null;
  return (
    <div role="note" className="truncation-banner gcp-edition-banner">
      <strong>
        GCP results: frozen edition {edition.edition_id.slice(-16)} (frozen{" "}
        {String(edition.frozen_at).slice(0, 10)}, collector{" "}
        {(edition.collector_versions || []).join(", ")}), read-only.
      </strong>{" "}
      {edition.counts?.findings} GCP findings across {edition.projects}{" "}
      projects. Cross-cloud relationships with the live AWS data are not
      correlated.
    </div>
  );
}
