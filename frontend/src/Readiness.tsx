import { useState } from "react";
import { type Row } from "./api";

export function Readiness({ data }: { data: Row }) {
  const [filters, setFilters] = useState<Row>({});
  const fields = [
    ["account_id", "Readiness account"],
    ["region", "Readiness Region"],
    ["domain", "Readiness domain"],
    ["status", "Collection status"],
    ["source_type", "Source type"],
  ];
  const rows = data.sources.filter((row: Row) =>
    fields.every(([key]) => !filters[key] || row[key] === filters[key]),
  );
  const accounts = data.accounts.filter(
    (a: Row) => !filters.account_id || a.account_id === filters.account_id,
  );
  return (
    <section className="panel">
      <h2>Evidence collection readiness</h2>
      <p>
        Selected assessment run: {data.run_id.slice(0, 24)}. Collection, parsing
        and evidence sufficiency are separate. Sufficiency covers only evaluated
        rule criteria.
      </p>
      <div className="toolbar">
        {fields.map(([key, title]) => (
          <label key={key}>
            {title}
            <select
              aria-label={title}
              value={filters[key] || ""}
              onChange={(e) =>
                setFilters({ ...filters, [key]: e.target.value })
              }
            >
              <option value="">All</option>
              {[
                ...new Set<string>(
                  data.sources.map((r: Row) => r[key]).filter(Boolean),
                ),
              ]
                .sort()
                .map((v) => (
                  <option key={v}>{v}</option>
                ))}
            </select>
          </label>
        ))}
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Account / approved alias</th>
              <th>Last collection / Regions</th>
              <th>Complete / partial</th>
              <th>Access denied / API failures</th>
              <th>Unsupported</th>
              <th>Missing required operations</th>
              <th>Parsed records</th>
              <th>Sufficient evaluations / manual / incomplete</th>
              <th>Readiness</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((a: Row) => (
              <tr key={a.account_id}>
                <td>
                  {a.account_id}
                  <small>{a.alias || "No approved alias"}</small>
                </td>
                <td>
                  {a.last_collection || "Not recorded"}
                  <small>{a.regions.join(", ")}</small>
                  <small>Declared: {a.declared_regions.join(", ")}</small>
                </td>
                <td>
                  {a.completed_operations} / {a.partial_collections}
                </td>
                <td>
                  {a.access_denied} / {a.api_failures}
                </td>
                <td>{a.unsupported_evidence}</td>
                <td>
                  {a.missing_required_operations.length}
                  <details>
                    <summary>Operations</summary>
                    {a.missing_required_operations.join("; ")}
                  </details>
                </td>
                <td>{a.parsed_records}</td>
                <td>
                  {a.sufficient_evaluations} /{" "}
                  {a.evaluations.MANUAL_VALIDATION_REQUIRED || 0} /{" "}
                  {(a.evaluations.UNKNOWN || 0) +
                    (a.evaluations.COLLECTION_ERROR || 0)}
                </td>
                <td>{a.readiness}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p>
        {rows.length} source records match filters. Account totals describe the
        selected run; operation filters apply to the source table.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Account</th>
              <th>Region</th>
              <th>Operation</th>
              <th>Collection</th>
              <th>Parsed records</th>
              <th>Status</th>
              <th>Limits / errors</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 200).map((r: Row, i: number) => (
              <tr key={i}>
                <td>{r.account_id}</td>
                <td>{r.region}</td>
                <td>{r.operation}</td>
                <td>{r.collected ? "Artifact retained" : "No artifact"}</td>
                <td>{r.parsed_records}</td>
                <td>{r.status}</td>
                <td>{[...r.errors, ...r.limitations].join("; ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > 200 && (
        <p>
          Showing the first 200 matching source records; narrow filters for
          more.
        </p>
      )}
      <p>
        {data.manual_validation.length} manual evidence requirements remain
        separate from AWS collection requests.
      </p>
      <a
        className="button"
        href={`/api/runs/${data.run_id}/evidence-requests.json`}
        download
      >
        Download collector requests (JSON)
      </a>
    </section>
  );
}
