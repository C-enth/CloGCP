import { useEffect, useState } from "react";
import { api, Row } from "./api";

export function SecurityCoverage({
  run,
  epoch,
}: {
  run: string;
  epoch: number;
}) {
  const [data, setData] = useState<Row>(),
    [error, setError] = useState("");
  useEffect(() => {
    api(`/runs/${run}/security-coverage`)
      .then(setData)
      .catch((e) => setError(e.message));
  }, [run, epoch]);
  return (
    <section className="panel">
      <h2>Security assessment coverage</h2>
      <p>
        Counts reflect persisted records in this run. Collected files,
        normalized evidence occurrences, canonical resources, implemented checks
        and evaluations have different units. They do not measure complete AWS
        service coverage.
      </p>
      {error && <p className="error">{error}</p>}
      {data && (
        <>
          <h3>Security domains</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Checks implemented</th>
                  <th>Evaluations</th>
                  <th>Findings</th>
                  <th>Analyst confirmed</th>
                  <th>Unresolved evaluations</th>
                </tr>
              </thead>
              <tbody>
                {data.domains.map((d: Row) => (
                  <tr key={d.domain}>
                    <td>{d.domain}</td>
                    {[
                      "security_checks_implemented",
                      "checks_evaluated",
                      "findings_generated",
                      "analyst_validated",
                      "unresolved_evaluations",
                    ].map((k) => (
                      <td key={k}>{d[k] || 0}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {[
                    "Service",
                    "Evidence collected",
                    "Evidence understood",
                    "Resources",
                    "Checks implemented",
                    "Checks evaluated",
                    "Findings generated",
                    "Analyst validated",
                    "Unresolved evaluations",
                  ].map((h) => (
                    <th key={h}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.services.map((s: Row) => (
                  <tr key={s.service}>
                    <td>{s.service}</td>
                    {[
                      "evidence_collected",
                      "evidence_understood",
                      "canonical_resources",
                      "security_checks_implemented",
                      "checks_evaluated",
                      "findings_generated",
                      "analyst_validated",
                      "unresolved_evaluations",
                    ].map((k) => (
                      <td key={k}>{s[k] || 0}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <details>
            <summary>Operation capability matrix and limitations</summary>
            <p>{data.capabilities.definitions}</p>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Operation / parser</th>
                    <th>Normalization</th>
                    <th>Security checks / domain</th>
                    <th>Path prerequisites</th>
                    <th>Real exports</th>
                  </tr>
                </thead>
                <tbody>
                  {data.capabilities.operations.map((o: Row) => (
                    <tr key={o.operation + o.format}>
                      <td>
                        {o.operation}
                        <br />
                        {o.format}
                      </td>
                      <td>{o.normalization_status}</td>
                      <td>
                        {o.rule_availability}
                        <br />
                        {o.rules
                          .map((r: Row) => `${r.rule_id}: ${r.security_domain}`)
                          .join("; ")}
                      </td>
                      <td>{o.attack_prerequisite_support}</td>
                      <td>{o.actual_export_compatibility}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        </>
      )}
    </section>
  );
}
