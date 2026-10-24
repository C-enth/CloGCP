import React, { useEffect, useState } from "react";
import { DASHBOARD_TIMEOUT_MS, api, display, type Row } from "./api";
import { PathCoverage, PathDiagrams, StrideSurface } from "./PathDiagram";
import { CrossAccount } from "./Enterprise";
import { ChoiceFilter, ChoiceNotice, useRecordChoices } from "./Filters";
import { EstateSummary, FindingsPie, PostureSummary } from "./Posture";

const domains = [
  "Identity and Access",
  "Credentials and API Security",
  "Network and Exposure",
  "Data Protection",
  "Workload Security",
  "Monitoring and Detection",
  "Governance",
  "Vulnerability and Risk",
  "Attack-Path Investigations",
];
const sections = [
  "Overview",
  "Assessment Coverage",
  "Inventory",
  "Security Findings",
  "Attack Paths",
  "Cross Account Explorer",
  "Recommendations",
  "Security Command Center",
];

export function CloudDashboard({
  run,
  provider,
  epoch,
  finding,
  inspect,
  onEvidence,
  onFinding,
}: {
  run: string;
  provider: string;
  epoch: number;
  finding: (r: Row) => void;
  inspect: (r: Row) => void;
  onEvidence?: (observationId: string) => void;
  onFinding?: (findingId: string) => void;
}) {
  const [summary, setSummary] = useState<Row>(),
    [section, setSection] = useState("Overview"),
    [error, setError] = useState(""),
    [domain, setDomain] = useState(""),
    [severity, setSeverity] = useState("");
  useEffect(() => {
    setSection("Overview");
    setDomain("");
  }, [provider]);
  useEffect(() => {
    let active = true;
    // Summary counts first; STRIDE, snapshot validation and readiness load separately.
    const base = `/runs/${run}/cloud/dashboard?provider=${provider}`;
    api(`${base}&part=summary`, undefined, DASHBOARD_TIMEOUT_MS)
      .then((d) => {
        if (!active) return;
        setSummary(d);
        return api(`${base}&part=panels`, undefined, DASHBOARD_TIMEOUT_MS).then(
          (panels) => {
            if (active)
              setSummary((current) =>
                current && current.run_id === d.run_id
                  ? { ...current, ...panels, running_job: panels.running_job }
                  : current,
              );
          },
        );
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [run, provider, epoch]);
  return (
    <section
      className="panel cloud-dashboard"
      aria-label={`${provider} assessment`}
    >
      <h2>{provider} assessment</h2>
      <div
        className="toolbar section-tabs"
        role="tablist"
        aria-label="Assessment sections"
      >
        {sections.map((s) => (
          <button
            key={s}
            className={section === s ? "primary" : ""}
            role="tab"
            aria-selected={section === s}
            onClick={() => setSection(s)}
          >
            {s}
          </button>
        ))}
      </div>
      {error && <p role="alert">{error}</p>}
      {summary?.running_job && (
        <p role="status" className="truncation-banner">
          {summary.running_job.kind} is running. This view shows the last
          completed assessment state and updates when the job finishes.
        </p>
      )}
      {!summary || summary.provider !== provider || summary.run_id !== run ? (
        <p>Loading assessment records…</p>
      ) : (
        <>
          <p className="muted">{summary.qualification}</p>
          {section === "Overview" && (
            <>
              <PathSummary
                run={run}
                provider={provider}
                epoch={epoch}
                open={() => setSection("Attack Paths")}
              />
              <FindingsPie
                providers={summary.providers}
                open={(value) => {
                  setSeverity(value);
                  setSection("Security Findings");
                }}
              />
              <PostureSummary data={summary} />
              <EstateSummary epoch={epoch} provider={provider} />
              <div className="cloud-cards">
                {Object.entries(summary.providers).map(([p, m]) => {
                  const metrics = m as Row;
                  return (
                    <article
                      className="panel"
                      key={p}
                      aria-label={`${p} scope summary`}
                    >
                      <h3>{p}</h3>
                      <dl>
                        {[
                          ["Scopes expected", "expected_scope_count"],
                          ["Scopes imported", "imported_scope_count"],
                          [
                            "Scopes with resource evaluations",
                            "assessed_scope_count",
                          ],
                          ["Supported inventory entities", "resources"],
                          [
                            "Retained unsupported observations",
                            "unsupported_observations",
                          ],
                          ["Evaluation records", "evaluations"],
                          ["Candidate findings", "candidate_findings"],
                          ["Confirmed findings", "confirmed_findings"],
                          ["Approved findings", "approved_findings"],
                        ].map(([label, key]) => (
                          <React.Fragment key={key}>
                            <dt>{label}</dt>
                            <dd>{metrics[key]}</dd>
                          </React.Fragment>
                        ))}
                      </dl>
                      <p>
                        Complete collections: {metrics.complete_collections} /{" "}
                        {metrics.source_collections}
                      </p>
                      <p>Findings by severity: {display(metrics.severity)}</p>
                      <details>
                        <summary>
                          Scope identities and remediation themes
                        </summary>
                        <pre>
                          {JSON.stringify(
                            {
                              expected: metrics.expected_scopes,
                              imported: metrics.imported_scopes,
                              assessed: metrics.assessed_scopes,
                              themes: metrics.remediation_themes,
                            },
                            null,
                            2,
                          )}
                        </pre>
                      </details>
                    </article>
                  );
                })}
              </div>
              <h3>Security domain comparison</h3>
              <div className="table-wrap">
                <table aria-label="Security domain comparison">
                  <thead>
                    <tr>
                      <th>Security domain</th>
                      <th>AWS</th>
                      <th>GCP</th>
                      <th>Comparable finding totals</th>
                      <th>Drilldown</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.domains.map((d: Row) => (
                      <tr key={d.domain}>
                        <td>{d.domain}</td>
                        {["AWS", "GCP"].map((p) => (
                          <td key={p}>
                            {d[p].assessment_status.replaceAll("_", " ")}
                            <br />
                            {d[p].resource_evaluations || 0} resource
                            evaluations · {d[p].candidates || 0} candidates
                            <br />
                            {d[p].declared_operations || 0} declared collector
                            operations · {d[p].incomplete_operations || 0}{" "}
                            incomplete · {d[p].NOT_EVALUATED || 0} without
                            evaluation
                            <br />
                            {["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"]
                              .map(
                                (k) =>
                                  `${k === "NOT_APPLICABLE" ? "N/A" : k} ${d[p][k] || 0}`,
                              )
                              .join(" · ")}
                          </td>
                        ))}
                        <td>
                          {d.comparable_totals.candidates} candidates
                          <br />
                          {d.comparable_totals.confirmed} confirmed ·{" "}
                          {d.comparable_totals.approved} approved
                        </td>
                        <td>
                          <button
                            onClick={() => {
                              setDomain(d.domain);
                              setSection("Security Findings");
                            }}
                          >
                            Findings
                          </button>
                          <button
                            onClick={() => {
                              setDomain(d.domain);
                              setSection("Assessment Coverage");
                            }}
                          >
                            Evaluations
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {section === "Assessment Coverage" && (
            <>
              <h3>Collection gaps</h3>
              <details>
                <summary>Collector-to-assessment coverage</summary>
                <p>
                  Each row is one declared collection operation. Inventory
                  without a supported security evaluation is NOT EVALUATED; this
                  is not a security pass.
                </p>
                <DataTable
                  inspect={inspect}
                  rows={summary.datasets || []}
                  columns={[
                    "provider",
                    "domain",
                    "dataset",
                    "collection_status",
                    "parser_supported",
                    "normalized_observations",
                    "retained_unsupported_observations",
                    "evaluations_using_source",
                    "assessment_state",
                  ]}
                />
              </details>
              <p>
                Failed, partial, uncollected and unsupported evidence blocks
                conclusions. Missing domains remain NOT ASSESSED.
              </p>
              <DataTable
                rows={summary.gaps}
                columns={[
                  "provider",
                  "scope",
                  "operation",
                  "dataset",
                  "domain",
                  "exit_code",
                  "status",
                  "effective_coverage",
                  "provenance",
                  "integrity_assurance",
                  "error_category",
                  "coverage_reason",
                  "collection_correction_required",
                ]}
                inspect={inspect}
              />
              <a
                className="button"
                download
                href={`/api/runs/${run}/cloud/requests`}
              >
                Download GCP collection requests
              </a>
              <h3>Underlying evaluations</h3>
              <CloudRecords
                run={run}
                provider={provider}
                kind="evaluations"
                domain={domain}
                setDomain={setDomain}
                epoch={epoch}
                inspect={inspect}
              />
            </>
          )}
          {section === "Inventory" && (
            <>
              <h3>Organization and project resource inventory</h3>
              <p>
                Enabled services and unsupported native resource types remain
                evidence observations. Inventory is not control coverage.
              </p>
              <CloudRecords
                run={run}
                provider={provider}
                kind="resources"
                domain={domain}
                setDomain={setDomain}
                epoch={epoch}
                inspect={inspect}
              />
            </>
          )}
          {["Security Findings", "Recommendations"].includes(section) && (
            <>
              <h3>
                {section === "Recommendations"
                  ? "Remediation candidates"
                  : "Enterprise findings register"}
              </h3>
              <p>
                Select a finding to review evidence, validate the observation,
                edit report text and approve recommendations and narratives
                independently.
              </p>
              <CloudRecords
                run={run}
                provider={provider}
                kind="findings"
                key={severity}
                severity={severity}
                domain={domain}
                setDomain={setDomain}
                epoch={epoch}
                inspect={finding}
              />
            </>
          )}
          {section === "Attack Paths" && (
            <CloudPaths
              run={run}
              provider={provider}
              epoch={epoch}
              inspect={inspect}
              onEvidence={onEvidence}
              onFinding={onFinding}
            />
          )}
          {section === "Cross Account Explorer" && (
            <>
              {provider !== "GCP" && (
                <CrossAccount run={run} epoch={epoch} inspect={inspect} />
              )}
              {provider !== "AWS" && (
                <section aria-label="GCP cross-project explorer">
                  <h3>GCP project relationships</h3>
                  <CloudRecords
                    run={run}
                    provider="GCP"
                    epoch={epoch}
                    kind="relationships"
                    domain={domain}
                    setDomain={setDomain}
                    inspect={inspect}
                  />
                </section>
              )}
            </>
          )}
          {section === "Security Command Center" && (
            <CloudSCC run={run} epoch={epoch} inspect={inspect} />
          )}
        </>
      )}
    </section>
  );
}

function DataTable({
  rows,
  columns,
  inspect,
}: {
  rows: Row[];
  columns: string[];
  inspect: (r: Row) => void;
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c}>{c.replaceAll("_", " ")}</th>
            ))}
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr
              key={
                r.finding_id ||
                r.evaluation_id ||
                r.relationship_id ||
                r.path_id ||
                i
              }
            >
              {columns.map((c) => (
                <td key={c}>
                  {display(
                    r[c] ??
                      (c === "provider"
                        ? "AWS"
                        : c === "scope"
                          ? r.project_id || r.account_id
                          : null),
                  )}
                </td>
              ))}
              <td>
                <button onClick={() => inspect(r)}>View</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!rows.length && (
        <p className="empty">
          No records for this scope. No assurance is inferred.
        </p>
      )}
    </div>
  );
}

function CloudRecords({
  run,
  provider,
  kind,
  domain,
  setDomain,
  epoch,
  inspect,
  severity = "",
}: {
  run: string;
  provider: string;
  kind: string;
  severity?: string;
  domain: string;
  setDomain: (d: string) => void;
  epoch: number;
  inspect: (r: Row) => void;
}) {
  const [filters, setFilters] = useState<Row>({ value: severity }),
    [offset, setOffset] = useState(0),
    [data, setData] = useState<Row>(),
    [error, setError] = useState("");
  useEffect(() => {
    setOffset(0);
  }, [run, provider, kind, domain]);
  useEffect(() => {
    let active = true;
    const query = new URLSearchParams({
      ...filters,
      domain,
      provider:
        filters.provider || (provider === "Consolidated" ? "" : provider),
      offset: String(offset),
      limit: "30",
    });
    api(`/runs/${run}/records/${kind}?${query}`)
      .then((d) => {
        if (active) setData(d);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [run, provider, kind, domain, filters, offset, epoch]);
  const choices = useRecordChoices(run, kind, provider, epoch);
  const change = (key: string, value: string) => {
    setFilters({ ...filters, [key]: value });
    setOffset(0);
  };
  const columns =
    kind === "relationships"
      ? [
          "provider",
          "project_id",
          "source",
          "destination",
          "relationship",
          "status",
          "authorization",
        ]
      : kind === "findings"
        ? [
            "provider",
            "scope",
            "title",
            "security_domain",
            "suggested_severity",
            "evidence_confidence",
            "analyst_status",
          ]
        : kind === "evaluations"
          ? [
              "provider",
              "scope",
              "rule_id",
              "native_id",
              "outcome",
              "confidence",
            ]
          : [
              "provider",
              "scope",
              "project_number",
              "organization_id",
              "folder_id",
              "native_id",
              "resource_type",
              "region",
              "collected_at",
            ];
  return (
    <div className="cloud-records">
      <div className="toolbar">
        <label>
          Cloud provider
          <select
            aria-label="Cloud provider filter"
            value={filters.provider || ""}
            onChange={(e) => change("provider", e.target.value)}
          >
            <option value="">{provider}</option>
            {(provider === "Consolidated" ? ["AWS", "GCP"] : [provider]).map(
              (p) => (
                <option key={p}>{p}</option>
              ),
            )}
          </select>
        </label>
        <label>
          Security domain
          <select
            aria-label="Cloud security domain"
            value={domain}
            onChange={(e) => {
              setDomain(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">All domains</option>
            {domains.map((d) => (
              <option key={d}>{d}</option>
            ))}
          </select>
        </label>
        {[
          ["project", "Project ID"],
          ["account", "AWS account"],
          ["project_number", "Project number"],
          ["organization", "Organization"],
          ["folder", "Folder"],
          ["region", "Location"],
          ["service", "Service"],
          ["q", "Search"],
        ].map(([key, label]) => (
          <label key={key}>
            {label}
            <ChoiceFilter
              label={`Cloud ${label}`}
              value={filters[key] || ""}
              options={choices?.choices?.[key]}
              onChange={(value) => change(key, value)}
            />
          </label>
        ))}
        {kind === "findings" && (
          <>
            <label>
              Severity
              <select
                aria-label="Cloud severity"
                value={filters.value || ""}
                onChange={(e) => change("value", e.target.value)}
              >
                <option value="">All</option>
                {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            <label>
              Validation
              <select
                aria-label="Cloud validation"
                value={filters.validation || ""}
                onChange={(e) => change("validation", e.target.value)}
              >
                <option value="">All</option>
                {[
                  "CANDIDATE",
                  "CONFIRMED",
                  "REJECTED",
                  "NEEDS_VALIDATION",
                  "NEEDS_REVALIDATION",
                ].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            <label>
              Confidence
              <select
                aria-label="Cloud confidence"
                value={filters.confidence || ""}
                onChange={(e) => change("confidence", e.target.value)}
              >
                <option value="">All</option>
                {["HIGH", "MEDIUM", "LOW", "UNASSESSED"].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
          </>
        )}
      </div>
      <ChoiceNotice data={choices} />
      {error && <p role="alert">{error}</p>}
      <DataTable rows={data?.items || []} columns={columns} inspect={inspect} />
      <div className="pagination">
        <button
          disabled={!offset}
          onClick={() => setOffset(Math.max(0, offset - 30))}
        >
          Previous
        </button>
        <span>{data?.total || 0} records</span>
        <button
          disabled={!data || offset + 30 >= data.total}
          onClick={() => setOffset(offset + 30)}
        >
          Next
        </button>
      </div>
    </div>
  );
}

/** Overview card: how many attack paths exist and their proof status, linking to the tab. */
function PathSummary({
  run,
  provider,
  epoch,
  open,
}: {
  run: string;
  provider: string;
  epoch: number;
  open: () => void;
}) {
  const [paths, setPaths] = useState<Row[]>();
  useEffect(() => {
    let active = true;
    api(`/runs/${run}/cloud/paths?project=`)
      .then(
        (p) =>
          active &&
          setPaths(
            p.items.filter(
              (i: Row) =>
                provider === "Consolidated" || i.provider === provider,
            ),
          ),
      )
      .catch(() => active && setPaths(undefined));
    return () => {
      active = false;
    };
  }, [run, provider, epoch]);
  if (!paths) return null;
  const count = (s: string) => paths.filter((p) => p.proof_status === s).length;
  return (
    <section className="path-overview" aria-label="Attack path summary">
      <h3>Attack paths</h3>
      <p>
        {paths.length
          ? `${paths.length} path(s): ${count("PROVEN")} proven, ${count("HYPOTHESIS")} hypothesis, ${count("BLOCKED")} blocked.`
          : "No attack path was formed from the collected evidence; the Attack Paths tab explains why."}{" "}
        <button className="small" onClick={open}>
          Open attack paths
        </button>
      </p>
    </section>
  );
}

function CloudPaths({
  run,
  provider,
  epoch,
  inspect,
  onEvidence,
  onFinding,
}: {
  run: string;
  provider: string;
  epoch: number;
  inspect: (r: Row) => void;
  onEvidence?: (observationId: string) => void;
  onFinding?: (findingId: string) => void;
}) {
  const [paths, setPaths] = useState<Row[]>([]),
    [edges, setEdges] = useState<Row[]>([]),
    [coverage, setCoverage] = useState<Row>({}),
    [loaded, setLoaded] = useState(false),
    [error, setError] = useState(""),
    [project, setProject] = useState(""),
    [stride, setStride] = useState(""),
    [revision, setRevision] = useState(0),
    [pathsTruncated, setPathsTruncated] = useState(false),
    [edgesTruncated, setEdgesTruncated] = useState(false);
  useEffect(() => {
    let active = true;
    setError("");
    // Paths and relationships load independently: a relationship failure never hides paths.
    api(`/runs/${run}/cloud/paths?project=${encodeURIComponent(project)}`)
      .then((p) => {
        if (!active) return;
        setPathsTruncated(!!p.truncated);
        setCoverage(p.coverage || {});
        setPaths(
          p.items.filter(
            (i: Row) => provider === "Consolidated" || i.provider === provider,
          ),
        );
      })
      .catch((e) => active && setError(e.message))
      .finally(() => active && setLoaded(true));
    if (provider !== "AWS")
      api(
        `/runs/${run}/cloud/relationships?project=${encodeURIComponent(project)}`,
      )
        .then((e) => {
          if (!active) return;
          setEdgesTruncated(!!e.truncated);
          setEdges(e.items);
        })
        .catch((e) => active && setError(e.message));
    else setEdges([]);
    return () => {
      active = false;
    };
  }, [run, provider, project, epoch, revision]);
  const choices = useRecordChoices(run, "accounts", "GCP", epoch);
  const filtered = (
    stride
      ? paths.filter((p) =>
          (p.hops || []).some((h: Row) => (h.stride || []).includes(stride)),
        )
      : paths
  ).map(
    (p): Row => ({
      ...p,
      false_positive: p.false_positive_dependency
        ? "FP: depends on a false-positive finding"
        : "",
    }),
  );
  const groups =
    provider === "Consolidated"
      ? [
          {
            label: "GCP attack paths",
            title: "GCP paths (single project and cross-project)",
            reasons: coverage.GCP,
            rows: filtered.filter(
              (p) => p.provider === "GCP" && p.scope !== "cross-cloud",
            ),
          },
          {
            label: "AWS attack paths",
            title: "AWS paths (single account and cross-account)",
            reasons: coverage.AWS,
            rows: filtered.filter((p) => p.provider === "AWS"),
          },
          {
            label: "Cross-cloud attack paths",
            title: "Cross-cloud paths (AWS ↔ GCP)",
            reasons: (coverage.GCP || []).filter((r: Row) =>
              String(r.kind).startsWith("XC"),
            ),
            rows: filtered.filter((p) => p.scope === "cross-cloud"),
          },
        ]
      : [
          {
            label: `${provider} attack paths`,
            title: `${provider} attack paths`,
            reasons: coverage[provider],
            rows: filtered.filter((p) => p.provider === provider),
          },
        ];
  const review = async (id: string, status: string) => {
    try {
      await api(`/runs/${run}/path-review/${id}`, { status });
      setRevision((v) => v + 1);
    } catch (e: any) {
      setError(e.message);
    }
  };
  return (
    <>
      <h3>Attack-path investigations</h3>
      <div className="toolbar">
        <label>
          Project scope
          <ChoiceFilter
            label="Path project scope"
            value={project}
            options={choices?.choices?.project}
            onChange={setProject}
          />
        </label>
      </div>
      <details className="path-help">
        <summary>How to read attack paths</summary>
        <p>
          Each path is a chain of directed hops, read top to bottom from the
          entry point to the objective. A hop is PROVEN when the configuration
          that creates it is in collected evidence, HYPOTHESIS when evidence is
          missing (named on the hop) and BLOCKED when evidence shows it does not
          exist. Every hop states its direction, why access flows that way, its
          STRIDE categories and the evidence and findings behind it; Hop table
          shows the same content as a table.
        </p>
        <p>
          FEASIBLE means every prerequisite that evidence can establish is
          verified; attacker-side steps (credential possession, workload
          compromise) and exploitation are never assumed. No AWS-to-GCP
          transition is inferred without trust and federation evidence.
        </p>
      </details>
      {error && <p role="alert">{error}</p>}
      {pathsTruncated && (
        <p role="alert">
          The attack-path list is truncated. Narrow the project scope; the
          displayed paths are not a complete attack-path assessment.
        </p>
      )}
      {!loaded ? (
        <p role="status">Loading attack paths…</p>
      ) : (
        <>
          <h3>Attack path diagrams</h3>
          {stride && (
            <p role="status">
              Showing paths with a {stride} hop.{" "}
              <button className="small" onClick={() => setStride("")}>
                Show all paths
              </button>
            </p>
          )}
          {groups.map((g) => (
            <section key={g.label} aria-label={g.label}>
              <h4>{g.title}</h4>
              <PathDiagrams
                paths={g.rows}
                onReview={review}
                onEvidence={onEvidence}
                onFinding={onFinding}
              />
              {!g.rows.length &&
                (stride ? (
                  <p>No path in this group has a {stride} hop.</p>
                ) : g.reasons?.length ? (
                  <PathCoverage reasons={g.reasons} open />
                ) : (
                  <p>No evaluated path for this cloud.</p>
                ))}
              {g.rows.length > 0 && !stride && (
                <PathCoverage reasons={g.reasons} open={false} />
              )}
            </section>
          ))}
          {paths.length > 0 && (
            <section aria-label="Attack surface">
              <h3>Attack surface by STRIDE</h3>
              <p className="muted">
                Every hop counted under each STRIDE category its edge type maps
                to (proposed mapping). Select a category to show only the paths
                with such a hop.
              </p>
              <StrideSurface
                paths={paths}
                selected={stride}
                onSelect={setStride}
              />
            </section>
          )}
          <h3>Attack path list</h3>
          <DataTable
            rows={filtered}
            columns={[
              "feasibility",
              "proof_status",
              "provider",
              "project_id",
              "account_id",
              "title",
              "entry_point",
              "objective",
              "severity",
              "feasibility_reason",
              "stride",
              "false_positive",
            ]}
            inspect={inspect}
          />
        </>
      )}
      {provider !== "AWS" && (
        <>
          <h3>Evidence-backed relationships (bounded view)</h3>
          {edgesTruncated && (
            <p className="muted">
              Showing the first {edges.length} relationships; narrow the project
              scope to see the rest. This bound applies to the relationship list
              only, not to the attack paths above.
            </p>
          )}
        </>
      )}
      <DataTable
        rows={edges}
        columns={[
          "provider",
          "source",
          "destination",
          "relationship",
          "status",
          "confidence",
        ]}
        inspect={inspect}
      />
    </>
  );
}

function CloudSCC({
  run,
  epoch,
  inspect,
}: {
  run: string;
  epoch: number;
  inspect: (r: Row) => void;
}) {
  const [data, setData] = useState<Row>(),
    [offset, setOffset] = useState(0),
    [error, setError] = useState("");
  useEffect(() => {
    api(`/runs/${run}/cloud/scc?offset=${offset}&limit=30`)
      .then(setData)
      .catch((e) => setError(e.message));
  }, [run, epoch, offset]);
  return (
    <>
      <h3>Security Command Center observations</h3>
      <p>
        Original detector severity, state and event times remain supplementary
        evidence. Exact native correlation does not approve a customer finding.
      </p>
      {error && <p role="alert">{error}</p>}
      <DataTable
        rows={data?.items || []}
        columns={[
          "project_id",
          "category",
          "original_severity",
          "state",
          "event_time",
          "status",
        ]}
        inspect={inspect}
      />
      <div className="pagination">
        <button
          disabled={!offset}
          onClick={() => setOffset(Math.max(0, offset - 30))}
        >
          Previous
        </button>
        <span>{data?.total || 0} observations</span>
        <button
          disabled={!data || offset + 30 >= data.total}
          onClick={() => setOffset(offset + 30)}
        >
          Next
        </button>
      </div>
    </>
  );
}
