import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  api,
  connect,
  display,
  relativePaths,
  upload,
  pollJob,
  type Row,
  type Page,
} from "./api";
import "./style.css";
import { JobDetails } from "./JobDetails";
import { WorkflowPanel, runLabel } from "./Workflow";
import { CloudDashboard } from "./CloudDashboard";
import { Checklist } from "./Checklist";
import { ManageData, ImportedRemoval } from "./ManageData";
import { ChoiceFilter, ChoiceNotice, useRecordChoices } from "./Filters";
import { Readiness } from "./Readiness";
import { ReportFinding, ApprovedReports } from "./ReportFinding";
import { SecurityCoverage } from "./SecurityCoverage";
import {
  FindingsByAccount,
  accountLabel,
  useFindingFacets,
} from "./FindingsOverview";
import { Finalized, SreSection, StageBadge, STAGE_LABELS } from "./SreReview";
import { FindingAnalysis, useIdentity } from "./FindingView";
import { PrincipalRoles, usePrincipalRequests } from "./Principals";
import { FindingGroups } from "./Groups";
import { ThemeToggle } from "./Theme";
import { WorkspaceLocation, WorkspacePath } from "./Workspace";
import {
  ExcludeControl,
  ExcludedFindings,
  FalsePositiveControl,
  FalsePositiveReason,
} from "./Exclusion";
import {
  EnterpriseMetrics,
  EnterpriseAccounts,
  CrossAccount,
  SharedInvestigations,
} from "./Enterprise";

// Workflow order first (import -> review -> finalize -> report), then analysis tools.
const screens = [
  "Dashboard",
  "Evidence import",
  "Findings workbench",
  "Finalized findings",
  "Report center",
  "Assessment checklist",
  "Account explorer",
  "IAM intelligence",
  "Network analysis",
  "Cross-account explorer",
  "Evidence explorer",
  "Security investigations",
  "Manage Assessment Data",
  "Workspace location",
];
const icons = [
  "◫",
  "↥",
  "◇",
  "✔",
  "↧",
  "☑",
  "▦",
  "⌘",
  "⌁",
  "⤧",
  "▤",
  "⌕",
  "⚙",
  "⌂",
];
// The menu shows a divider before the analysis tools.
const TOOLS_FROM = 5;
const ProviderContext = React.createContext("Consolidated");
function Badge({ value }: { value: any }) {
  return (
    <span
      className={"badge " + String(value).toLowerCase().replaceAll("_", "-")}
    >
      {display(value)}
    </span>
  );
}
function Empty({ text = "No records match this scope." }: { text?: string }) {
  return (
    <div className="empty">
      <span>◫</span>
      <p>{text}</p>
    </div>
  );
}
function CounterBars({ data }: { data: Row }) {
  const entries = Object.entries(data);
  const total = entries.reduce((s, [, v]) => s + Number(v), 0);
  return (
    <div className="bars">
      {entries.length ? (
        entries.map(([k, v]) => (
          <div key={k}>
            <div>
              <span>{k.replaceAll("_", " ")}</span>
              <b>{v}</b>
            </div>
            <progress value={Number(v)} max={total || 1} />
          </div>
        ))
      ) : (
        <p className="muted">No assessed records yet.</p>
      )}
    </div>
  );
}
function Json({ value }: { value: any }) {
  return <pre>{JSON.stringify(value, null, 2)}</pre>;
}
function Detail({
  title,
  close,
  children,
}: {
  title: string;
  close: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="drawer-backdrop" onClick={close}>
      <aside
        className="drawer"
        role="dialog"
        aria-label={title}
        onClick={(e) => e.stopPropagation()}
      >
        <header>
          <h2>{title}</h2>
          <button aria-label="Close details" onClick={close}>
            ×
          </button>
        </header>
        {children}
      </aside>
    </div>
  );
}
function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="detail-section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}
type RecordsProps = {
  run: string;
  kind: string;
  columns: [string, string][];
  epoch?: number;
  account?: string;
  project?: string;
  onSelect?: (row: Row) => void;
  filterValues?: string[];
  initialQuery?: string;
  initialFilters?: Row;
  /** Findings only: enables row selection and bulk marking; called after a bulk action. */
  onChanged?: () => void;
};
function Records(props: RecordsProps) {
  const provider = React.useContext(ProviderContext);
  return (
    <RecordTable
      key={JSON.stringify([
        props.run,
        props.kind,
        provider,
        props.account,
        props.project,
        props.initialQuery,
        props.initialFilters,
      ])}
      {...props}
    />
  );
}
function RecordTable({
  run,
  kind,
  columns,
  epoch = 0,
  account = "",
  project = "",
  onSelect,
  filterValues = [],
  initialQuery = "",
  initialFilters,
  onChanged,
}: RecordsProps) {
  const provider = React.useContext(ProviderContext);
  const [q, setQ] = useState(initialQuery),
    [value, setValue] = useState(""),
    [offset, setOffset] = useState(0),
    [data, setData] = useState<Page>(),
    [findingFilters, setFindingFilters] = useState<Row>(initialFilters || {}),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const isFindings = kind.endsWith("findings");
  const facets = useFindingFacets(run, provider, epoch, isFindings);
  const recordChoices = useRecordChoices(run, kind, provider, epoch);
  const facetOptions = (key: string, fallback: string[]): string[] =>
    facets?.[key]?.map((f: Row) => f.value) || fallback;
  const accountValue = findingFilters.account
    ? `AWS:${findingFilters.account}`
    : findingFilters.project
      ? `GCP:${findingFilters.project}`
      : account
        ? `AWS:${account}`
        : project
          ? `GCP:${project}`
          : "";
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const bulk = kind === "findings" && !!onChanged;
  const query = (from: number, size: number) =>
    `/runs/${run}/records/${kind}?q=${encodeURIComponent(q)}&value=${value}&offset=${from}&limit=${size}&${new URLSearchParams({ ...findingFilters, account: findingFilters.account || account, project: findingFilters.project || project, ...(provider === "Consolidated" ? {} : { provider }) }).toString()}`;
  const selectAllMatching = async () => {
    const ids = new Set<string>();
    for (let from = 0; from < Math.min(data?.total || 0, 2000); from += 100) {
      const page = await api(query(from, 100));
      page.items.forEach((r: Row) => ids.add(r.finding_id));
    }
    setSelected(ids);
  };
  useEffect(() => {
    setSelected(new Set());
  }, [run, kind, q, value, account, project, provider, findingFilters, epoch]);
  useEffect(() => {
    let active = true;
    setBusy(true);
    setError("");
    setData(undefined);
    const timeout = setTimeout(() => {
      api(query(offset, 30))
        .then((d) => {
          if (active) setData(d);
        })
        .catch((e) => {
          if (active) setError(e.message);
        })
        .finally(() => {
          if (active) setBusy(false);
        });
    }, 150);
    return () => {
      active = false;
      clearTimeout(timeout);
    };
  }, [
    run,
    kind,
    q,
    value,
    account,
    project,
    provider,
    offset,
    epoch,
    findingFilters,
  ]);
  useEffect(() => {
    setOffset(0);
  }, [run, provider, project, account]);
  return (
    <div className="records">
      <ChoiceNotice data={recordChoices} />
      <div className="toolbar">
        <ChoiceFilter
          label={`Search ${kind}`}
          value={q}
          options={recordChoices?.choices?.q}
          all={`All ${kind}`}
          onChange={(v) => {
            setQ(v);
            setOffset(0);
          }}
        />
        {filterValues.length > 0 && (
          <select
            aria-label={`Filter ${kind}`}
            value={value}
            onChange={(e) => {
              setValue(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">All outcomes</option>
            {filterValues.map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
        )}
        {["evidence", "coverage", "resources", "network"].includes(kind) && (
          <>
            {[
              ["project", "Project"],
              ["dataset", "Dataset"],
              ["collection_domain", "Collection domain"],
            ].map(([key, label]) => (
              <ChoiceFilter
                key={key}
                label={`${label} ${kind}`}
                value={findingFilters[key] || ""}
                options={recordChoices?.choices?.[key]}
                onChange={(v) => {
                  setFindingFilters({ ...findingFilters, [key]: v });
                  setOffset(0);
                }}
              />
            ))}
            <select
              aria-label={`Support ${kind}`}
              value={findingFilters.support || ""}
              onChange={(e) => {
                setFindingFilters({
                  ...findingFilters,
                  support: e.target.value,
                });
                setOffset(0);
              }}
            >
              <option value="">All parser support</option>
              <option>SUPPORTED</option>
              <option>UNSUPPORTED</option>
            </select>
          </>
        )}
        <span className="muted">
          {busy || !data ? "Loading…" : `${data.total} records`}
        </span>
        {kind.endsWith("findings") && (
          <>
            {[
              [
                "finding_class",
                "Finding class",
                [
                  "BASELINE_DEVIATION",
                  "POTENTIAL_EXPOSURE",
                  "SUPPORTED_SECURITY_GAP",
                ],
              ],
              [
                "domain",
                "Security domain",
                facetOptions("domain", [
                  "Data Protection",
                  "Identity and Access",
                  "Monitoring and Detection",
                  "Network and Exposure",
                  "Workload Security",
                ]),
              ],
              ["control", "Checklist control", facetOptions("control", [])],
              ["region", "Region", facetOptions("region", [])],
              [
                "confidence",
                "Evidence confidence",
                ["HIGH", "MEDIUM", "LOW", "UNASSESSED"],
              ],
              [
                "validation",
                "Validation status",
                facetOptions("validation", [
                  "CANDIDATE",
                  "CONFIRMED",
                  "REJECTED",
                  "NEEDS_VALIDATION",
                  "NEEDS_REVALIDATION",
                ]),
              ],
              [
                "stage",
                "Stage",
                facetOptions("stage", Object.keys(STAGE_LABELS)),
              ],
            ].map(([key, title, options]) => (
              <label key={key as string}>
                {title}
                <select
                  aria-label={title as string}
                  value={findingFilters[key as string] || ""}
                  onChange={(e) => {
                    setFindingFilters({
                      ...findingFilters,
                      [key as string]: e.target.value,
                    });
                    setOffset(0);
                  }}
                >
                  <option value="">All</option>
                  {[
                    ...new Set([
                      ...(options as string[]),
                      ...(findingFilters[key as string]
                        ? [findingFilters[key as string]]
                        : []),
                    ]),
                  ].map((v) => (
                    <option key={v} value={v}>
                      {key === "stage" ? STAGE_LABELS[v] || v : v}
                    </option>
                  ))}
                </select>
              </label>
            ))}
            <label>
              Account / project
              <select
                aria-label="Finding account"
                value={accountValue}
                onChange={(e) => {
                  const [p, ...rest] = e.target.value.split(":");
                  const scope = rest.join(":");
                  setFindingFilters({
                    ...findingFilters,
                    account: p === "AWS" ? scope : "",
                    project: p === "GCP" ? scope : "",
                  });
                  setOffset(0);
                }}
              >
                <option value="">All accounts / projects</option>
                {accountValue &&
                  !(facets?.accounts || []).some(
                    (a: Row) => `${a.provider}:${a.scope}` === accountValue,
                  ) && <option value={accountValue}>{accountValue}</option>}
                {(facets?.accounts || []).map((a: Row) => (
                  <option
                    key={`${a.provider}:${a.scope}`}
                    value={`${a.provider}:${a.scope}`}
                  >
                    {accountLabel(a)} ({a.total})
                  </option>
                ))}
              </select>
            </label>
            <ChoiceFilter
              label="Finding resource"
              value={findingFilters.resource || ""}
              options={recordChoices?.choices?.resource}
              onChange={(v) => {
                setFindingFilters({ ...findingFilters, resource: v });
                setOffset(0);
              }}
            />
            <label>
              False positives
              <select
                aria-label="False positives"
                value={findingFilters.false_positive || "hide"}
                onChange={(e) => {
                  setFindingFilters({
                    ...findingFilters,
                    false_positive: e.target.value,
                  });
                  setOffset(0);
                }}
              >
                <option value="hide">Hide false positives</option>
                <option value="show">Show false positives (FP tag)</option>
                <option value="only">Only false positives</option>
              </select>
            </label>
            {!!data?.false_positive_excluded && (
              <span className="muted" role="status">
                {data.false_positive_excluded} excluded as false positive
              </span>
            )}
            <button
              onClick={() => {
                setFindingFilters({
                  validation: "CANDIDATE",
                  priority: "true",
                });
                setValue("");
                setQ("");
                setOffset(0);
              }}
            >
              Priority review queue
            </button>
            <button
              onClick={() => {
                setFindingFilters({});
                setValue("");
                setQ("");
                setOffset(0);
              }}
            >
              Clear filters
            </button>
          </>
        )}
      </div>
      {bulk && (
        <BulkBar
          run={run}
          selected={selected}
          total={data?.total || 0}
          onSelectAll={selectAllMatching}
          onClear={() => setSelected(new Set())}
          onDone={() => {
            setSelected(new Set());
            onChanged!();
          }}
          onError={setError}
        />
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {data?.items.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                {bulk && (
                  <th>
                    <input
                      type="checkbox"
                      aria-label="Select all findings on this page"
                      checked={
                        data.items.length > 0 &&
                        data.items.every((r) => selected.has(r.finding_id))
                      }
                      onChange={(e) => {
                        const next = new Set(selected);
                        data.items.forEach((r) =>
                          e.target.checked
                            ? next.add(r.finding_id)
                            : next.delete(r.finding_id),
                        );
                        setSelected(next);
                      }}
                    />
                  </th>
                )}
                {columns.map(([key, label]) => (
                  <th key={key}>{label}</th>
                ))}
                {onSelect && <th>Inspect</th>}
              </tr>
            </thead>
            <tbody>
              {data.items.map((row, i) => (
                <tr
                  key={row.finding_id || row.observation_id || row.account || i}
                >
                  {bulk && (
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Select ${row.title}`}
                        checked={selected.has(row.finding_id)}
                        onChange={(e) => {
                          const next = new Set(selected);
                          if (e.target.checked) next.add(row.finding_id);
                          else next.delete(row.finding_id);
                          setSelected(next);
                        }}
                      />
                    </td>
                  )}
                  {columns.map(([key]) => (
                    <td key={key}>
                      {key === "stage" ? (
                        <StageBadge stage={row.stage} />
                      ) : [
                          "suggested_severity",
                          "outcome",
                          "analyst_status",
                          "state",
                          "effective_coverage",
                          "basis",
                        ].includes(key) ? (
                        <Badge value={row[key]} />
                      ) : (
                        <span title={display(row[key])}>
                          {key === "title" && row.false_positive && (
                            <span
                              className="badge fp"
                              title={`False positive: ${row.false_positive.reason}`}
                            >
                              FP
                            </span>
                          )}{" "}
                          {display(row[key])}
                        </span>
                      )}
                    </td>
                  ))}
                  {onSelect && (
                    <td>
                      <button className="small" onClick={() => onSelect(row)}>
                        View
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        !busy &&
        !error &&
        data && (
          <Empty
            text={
              data.total
                ? "No rows on this page. Return to the first page or adjust the filters."
                : "No persisted records match this scope. Review collection coverage and supported evaluations before drawing a security conclusion."
            }
          />
        )
      )}
      <footer className="pagination">
        <button
          disabled={offset === 0 || busy}
          onClick={() => setOffset(Math.max(0, offset - 30))}
        >
          Previous
        </button>
        <span>
          {data?.total
            ? `${offset + 1}–${Math.min(offset + 30, data.total)} of ${data.total}`
            : "0 records"}
        </span>
        <button
          disabled={!data || offset + 30 >= data.total || busy}
          onClick={() => setOffset(offset + 30)}
        >
          Next
        </button>
      </footer>
    </div>
  );
}
const findingColumns: [string, string][] = [
  ["title", "Candidate finding"],
  ["provider", "Provider"],
  ["project_id", "Project"],
  ["account_id", "Account"],
  ["suggested_severity", "Severity"],
  ["methodology_id", "Checklist control"],
  ["checklist_domain", "Checklist domain"],
  ["checklist_title", "Control subject"],
  ["finding_class", "Class"],
  ["evidence_confidence", "Confidence"],
  ["analyst_status", "Analyst status"],
  ["stage", "Stage"],
];
const evidenceColumns: [string, string][] = [
  ["native_id", "Resource"],
  ["provider", "Provider"],
  ["project_id", "Project"],
  ["account_id", "Account"],
  ["resource_type", "Type"],
  ["dataset", "Dataset"],
  ["support_status", "Parser support"],
  ["source_status", "Collection result"],
  ["region", "Region"],
  ["operation", "Operation"],
  ["collected_at", "Collected"],
];
const evaluationColumns: [string, string][] = [
  ["rule_id", "Rule"],
  ["native_id", "Resource"],
  ["region", "Region"],
  ["outcome", "Outcome"],
  ["confidence", "Confidence"],
];

function App() {
  const jobActive = useRef(false);
  const navigationEpoch = useRef(0);
  const selectionKey = useRef("");
  const savedSelection = () => {
    try {
      const saved = JSON.parse(
        localStorage.getItem(selectionKey.current) || "{}",
      );
      return saved && typeof saved === "object" ? saved : {};
    } catch {
      return {};
    }
  };
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    const bootstrap = () => {
      if (new URLSearchParams(location.hash.slice(1)).has("token"))
        location.reload();
    };
    window.addEventListener("hashchange", bootstrap);
    return () => {
      clearInterval(timer);
      window.removeEventListener("hashchange", bootstrap);
    };
  }, []);
  const [connected, setConnected] = useState(false),
    [screen, setScreen] = useState("Dashboard"),
    [controlQuery, setControlQuery] = useState(""),
    [manageScope, setManageScope] = useState<Row>(),
    [provider, setProvider] = useState("AWS"),
    [runs, setRuns] = useState<Row[]>([]),
    [run, setRun] = useState(""),
    [epoch, setEpoch] = useState(0),
    [error, setError] = useState(""),
    [job, setJob] = useState<Row>(),
    [sessionJob, setSessionJob] = useState(""),
    [pending, setPending] = useState<Row[]>([]),
    [completedRun, setCompletedRun] = useState(""),
    [jobBusy, setJobBusy] = useState(false),
    [finding, setFinding] = useState<Row>(),
    [evidence, setEvidence] = useState<Row>(),
    [generic, setGeneric] = useState<Row>(),
    [memberSelection, setMemberSelection] = useState<string[]>([]),
    [environment, setEnvironment] = useState<Row>({ label: "UNLABELED" }),
    [workspaceInfo, setWorkspaceInfo] = useState<Row>();
  const [runtime, setRuntime] = useState<Row>();
  const navigate = (target: string, query = "") => {
    navigationEpoch.current += 1;
    setControlQuery(query);
    setScreen(target);
  };
  const [principal, setPrincipal] = useState("");
  const showPrincipal = React.useCallback((selected: string) => {
    setPrincipal(selected);
    setFinding(undefined);
    setProvider((current) => (current === "AWS" ? "GCP" : current));
    navigationEpoch.current += 1;
    setScreen("IAM intelligence");
  }, []);
  usePrincipalRequests(showPrincipal);
  const holdJob = (busy: boolean) => {
    jobActive.current = busy;
    setJobBusy(busy);
  };
  const loadRuns = async (preferred?: string) => {
    const saved = savedSelection();
    const all = await api("/runs");
    setRuns(all);
    api("/workflow")
      .then((state) => setPending(state.pending_imports))
      .catch(() => setPending([]));
    setMemberSelection((selected) =>
      selected.filter((id) =>
        all.some((r: Row) => r.run_id === id && !r.historical),
      ),
    );
    setRun((r) =>
      preferred && all.some((a: Row) => a.run_id === preferred)
        ? preferred
        : all.some((a: Row) => a.run_id === r)
          ? r
          : all.some((a: Row) => a.run_id === saved.run && !a.historical)
            ? saved.run
            : all.find((a: Row) => !a.historical)?.run_id || "",
    );
  };
  useEffect(() => {
    if (connected && selectionKey.current) {
      try {
        localStorage.setItem(
          selectionKey.current,
          JSON.stringify({ run, provider }),
        );
      } catch {
        // Storage may be disabled; the live selected context still works.
      }
    }
  }, [connected, run, provider]);
  useEffect(() => {
    setFinding(undefined);
    setEvidence(undefined);
    setGeneric(undefined);
  }, [run, provider]);
  useEffect(() => {
    connect()
      .then(async (identity) => {
        setRuntime(identity);
        const workspace = await api("/environment");
        setEnvironment(workspace);
        setWorkspaceInfo(await api("/workspace"));
        selectionKey.current = "closec-selection:" + workspace.workspace_id;
        const saved = savedSelection();
        if (["AWS", "GCP", "Consolidated"].includes(saved.provider))
          setProvider(saved.provider);
        const history = await api("/jobs");
        const running = history.find((j: Row) =>
          ["QUEUED", "RUNNING"].includes(j.status),
        );
        const latest = running || history[0];
        if (latest) setJob(await api("/jobs/" + latest.id));
        if (running) {
          holdJob(true);
          pollJob(running, setJob)
            .then((current) => {
              loadRuns(current.result?.run_id);
              setEpoch((e) => e + 1);
            })
            .catch((error) => setError(error.message))
            .finally(() => holdJob(false));
        }
        await loadRuns();
        setConnected(true);
      })
      .catch((e) => setError(e.message));
  }, []);
  const refresh = () => {
    setEpoch((e) => e + 1);
    loadRuns().catch((e) => setError(e.message));
  };
  const startJob = async (
    path: string,
    body: Row = {},
    after?: (result: Row) => void,
  ) => {
    if (jobActive.current) return;
    const submittedNavigation = navigationEpoch.current;
    jobActive.current = true;
    setJobBusy(true);
    try {
      setError("");
      const initial = await api(path, body);
      setSessionJob(initial.id);
      const current = await pollJob(initial, setJob);
      if (current.status === "SUCCEEDED") {
        await loadRuns(current.result?.run_id);
        setEpoch((e) => e + 1);
        after?.(current.result);
        if (
          ["Import", "Import and analysis"].includes(current.kind) &&
          ["AWS", "GCP"].includes(current.provider)
        )
          setProvider(current.provider);
        if (
          [
            "Assessment",
            "Import and analysis",
            "Enterprise assessment",
          ].includes(current.kind)
        )
          setCompletedRun(current.result?.run_id || "");
        if (
          ["Assessment", "Import and analysis"].includes(current.kind) &&
          navigationEpoch.current === submittedNavigation
        ) {
          setScreen("Dashboard");
          if (["AWS", "GCP", "Consolidated"].includes(current.provider))
            setProvider(current.provider);
        }
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      jobActive.current = false;
      setJobBusy(false);
    }
  };
  const inspectEvidence = async (row: Row) => {
    try {
      setEvidence(await api(`/runs/${run}/evidence/${row.observation_id}`));
    } catch (e: any) {
      setError(e.message);
    }
  };
  const openFindingById = async (id: string) => {
    try {
      const page = await api(
        `/runs/${run}/records/findings?q=${encodeURIComponent(id)}&limit=5`,
      );
      const row = page.items.find((r: Row) => r.finding_id === id);
      if (row) setFinding(row);
      else setError("FINDING_NOT_FOUND");
    } catch (e: any) {
      setError(e.message);
    }
  };
  const active = runs.find((r) => r.run_id === run);
  const running = !!job && ["QUEUED", "RUNNING"].includes(job.status);
  const workflowStage = running
    ? job?.kind === "Package validation"
      ? 1
      : job?.kind === "Import"
        ? 2
        : job?.kind === "Import and analysis" &&
            !["SOURCE_INTEGRITY", "SECURITY_ANALYSIS", "CORRELATION"].includes(
              job?.stage,
            )
          ? 2
          : 3
    : pending.length
      ? 2
      : active
        ? active.assessed
          ? 4
          : 3
        : 0;
  const openResults = () => {
    if (active)
      setProvider(
        active.enterprise || active.provider === "Consolidated"
          ? "Consolidated"
          : active.provider === "GCP"
            ? "GCP"
            : "AWS",
      );
    setCompletedRun("");
    navigate("Dashboard");
  };
  return (
    <div className="app">
      <nav className="sidebar">
        <div className="brand">
          <span className="brand-mark">C</span>
          <div>CloSec</div>
        </div>
        <div
          className={"workspace-label env-" + environment.label.toLowerCase()}
          aria-label="Workspace environment"
        >
          {environment.label} WORKSPACE
          {environment.name ? <small>{environment.name}</small> : null}
        </div>
        <div
          className="cloud-navigation"
          role="tablist"
          aria-label="Cloud dashboards"
        >
          {["AWS", "GCP", "Consolidated"].map((p) => (
            <button
              key={p}
              className={provider === p ? "nav active" : "nav"}
              role="tab"
              aria-selected={provider === p}
              tabIndex={provider === p ? 0 : -1}
              onKeyDown={(e) => {
                const items = ["AWS", "GCP", "Consolidated"];
                const i = items.indexOf(p);
                const next =
                  e.key === "ArrowRight"
                    ? (i + 1) % 3
                    : e.key === "ArrowLeft"
                      ? (i + 2) % 3
                      : e.key === "Home"
                        ? 0
                        : e.key === "End"
                          ? 2
                          : -1;
                if (next >= 0) {
                  e.preventDefault();
                  setProvider(items[next]);
                  navigate("Dashboard");
                  (
                    e.currentTarget.parentElement?.children[next] as HTMLElement
                  )?.focus();
                }
              }}
              onClick={() => {
                setProvider(p);
                navigate("Dashboard");
              }}
            >
              {p}
            </button>
          ))}
        </div>
        {screens.map((s, i) => (
          <React.Fragment key={s}>
            {i === TOOLS_FROM && (
              <div className="nav-divider" role="separator">
                Analysis tools
              </div>
            )}
            <button
              className={screen === s ? "nav active" : "nav"}
              aria-current={screen === s ? "page" : undefined}
              key={s}
              onClick={() => navigate(s)}
            >
              <span aria-hidden="true">{icons[i]}</span>
              {s}
            </button>
          </React.Fragment>
        ))}
        <div className="sidebar-footer">
          <span className="dot" />
          Local processing only<small>No cloud calls · No hosted AI</small>
        </div>
      </nav>
      <div className="main">
        <header className="topbar">
          <span>
            Security operations <span className="muted">/ {screen}</span>
          </span>
          <div>
            <WorkspacePath
              path={
                workspaceInfo?.setup_required ? undefined : workspaceInfo?.path
              }
            />
            <Badge value={environment.label} />
            <Badge value="OFFLINE" />
            <ThemeToggle />
            <button className="small" onClick={refresh} disabled={!connected}>
              Refresh
            </button>
            <button
              className="small"
              onClick={() => {
                if (
                  confirm(
                    "Stop the local application? Running work will finish safely.",
                  )
                )
                  api("/shutdown", {}).then(() =>
                    setError("Application stopped. Relaunch to continue."),
                  );
              }}
            >
              Stop app
            </button>
          </div>
        </header>
        <div className="runbar">
          <label>
            Active evidence run{" "}
            <select
              aria-label="Active evidence run"
              disabled={jobBusy}
              title={
                jobBusy
                  ? "Wait for the current job to complete or cancel it in job details."
                  : "Select persisted evidence"
              }
              value={run}
              onChange={(e) => setRun(e.target.value)}
            >
              <option value="">Select an imported run</option>
              {runs.map((r) => (
                <option key={r.run_id} value={r.run_id}>
                  {runLabel(r)} · origin {r.origin}
                </option>
              ))}
            </select>
          </label>
          {run && (
            <button
              className="primary"
              disabled={jobBusy}
              onClick={() => startJob(`/runs/${run}/assess`)}
            >
              Run assessment
            </button>
          )}
        </div>
        <ProviderContext.Provider value={provider}>
          <main>
            <div className="page-heading">
              <div className="eyebrow">EVIDENCE-LED SECURITY ANALYSIS</div>
              <h1>{screen}</h1>
              <p>
                {screen === "Dashboard"
                  ? "A scoped view of collected evidence, evaluated controls and analyst decisions."
                  : screen === "Finalized findings"
                    ? "Vulnerabilities you marked valid, consolidated across accounts and projects."
                    : "Inspect source-backed records and preserve the evidence trail."}
              </p>
            </div>
            {environment.label !== "ASSESSMENT" && (
              <div className="env-banner" role="note">
                {environment.label === "SYNTHETIC"
                  ? "SYNTHETIC WORKSPACE — demonstration/test data. Results are not customer findings."
                  : "UNLABELED WORKSPACE — not approved for customer reporting. Relaunch with --environment assessment for a pilot."}
              </div>
            )}
            {active && active.origin !== "tool-generated" && (
              <div className="env-banner" role="note">
                Active run origin: {active.origin}. Not eligible as customer
                findings.
              </div>
            )}
            <div className="notice">
              <span>◉</span>Real-export compatibility remains unverified.
              Candidates require analyst validation; partial criteria never
              establish a control-level Pass.
            </div>
            {error && (
              <div className="error" role="alert">
                {error}
                <button onClick={() => setError("")}>Dismiss</button>
              </div>
            )}
            {connected && (
              <WorkflowPanel
                stage={workflowStage}
                job={job}
                pending={
                  screen === "Evidence import"
                    ? pending.filter(
                        (p) =>
                          !(
                            job?.kind === "Package validation" &&
                            job.status === "SUCCEEDED" &&
                            job.result &&
                            job.id === p.upload_id
                          ),
                      )
                    : []
                }
                active={active}
                busy={jobBusy}
                showOpen={
                  !!active?.assessed &&
                  completedRun === run &&
                  !(screen === "Dashboard" && provider === active.provider)
                }
                onImport={(upload, analyze, acknowledged) =>
                  startJob("/import", {
                    upload_id: upload.upload_id,
                    acknowledge_legacy_integrity: acknowledged,
                    analyze,
                  })
                }
                onAnalyze={() => startJob(`/runs/${run}/assess`)}
                onOpen={openResults}
                onNavigate={navigate}
              />
            )}
            {job &&
              (["Evidence import", "Manage Assessment Data"].includes(screen) ||
                ["QUEUED", "RUNNING"].includes(job.status) ||
                (job.id === sessionJob &&
                  job.kind !== "Package validation")) && (
                <JobDetails
                  job={job}
                  now={now}
                  onJob={setJob}
                  onError={setError}
                />
              )}
            {runtime && (
              <p className="muted" aria-label="Application revision">
                CloSec {runtime.application_version} · source{" "}
                {runtime.git_revision || "packaged"}
                {runtime.working_tree_modified ? " (modified checkout)" : ""} ·
                frontend/backend compatible
              </p>
            )}
            {!connected ? (
              <Empty text="Connecting to the protected local session…" />
            ) : workspaceInfo?.setup_required ||
              screen === "Workspace location" ? (
              <WorkspaceLocation info={workspaceInfo} />
            ) : screen === "Manage Assessment Data" ? (
              <ManageData
                epoch={epoch}
                initialScope={manageScope}
                environment={environment.label}
                onError={setError}
                startJob={startJob}
                onJob={setJob}
                onBusy={holdJob}
              />
            ) : screen === "Evidence import" ? (
              <ImportScreen
                startJob={startJob}
                jobBusy={jobBusy}
                job={job}
                pendingIds={pending.map((p) => p.upload_id)}
                onValidated={() => loadRuns().catch((e) => setError(e.message))}
                onJob={setJob}
                onBusy={holdJob}
                onError={setError}
                environment={environment.label}
              />
            ) : !run ? (
              <div className="empty">
                <span>◫</span>
                <p>
                  {pending.length
                    ? "A validated package has not been imported yet. Open Evidence import to resume; validation alone creates no assessment."
                    : runs.length
                      ? "Select an evidence run in the Active evidence run list to view its assessment data."
                      : "No assessment imported. Start with Evidence import: select an AWS or GCP collector evidence folder."}
                </p>
                {(pending.length > 0 || !runs.length) && (
                  <button
                    className="primary"
                    onClick={() => navigate("Evidence import")}
                  >
                    Go to Evidence import
                  </button>
                )}
              </div>
            ) : active && !active.assessed && screen !== "Evidence explorer" ? (
              <Empty text="Security analysis has not run for this evidence run, so there are no evaluations or findings yet. Use Run security analysis above." />
            ) : (
              <>
                {screen === "Dashboard" && (
                  <CloudDashboard
                    key={JSON.stringify([run, provider])}
                    run={run}
                    provider={provider}
                    epoch={epoch}
                    finding={setFinding}
                    inspect={setGeneric}
                    onEvidence={(oid) =>
                      inspectEvidence({ observation_id: oid })
                    }
                    onFinding={openFindingById}
                  />
                )}
                {screen === "Dashboard" && provider !== "GCP" && (
                  <details className="panel">
                    <summary>Detailed metrics and collection records</summary>
                    <EnterpriseMetrics run={run} epoch={epoch} />
                    {provider === "AWS" && (
                      <>
                        <Dashboard
                          run={run}
                          epoch={epoch}
                          assessed={active?.assessed}
                        />
                        <Collection run={run} epoch={epoch} />
                      </>
                    )}
                  </details>
                )}
                {screen === "Account explorer" && provider !== "GCP" && (
                  <EnterpriseAccounts
                    run={run}
                    epoch={epoch}
                    inspect={setGeneric}
                  />
                )}
                {screen === "Cross-account explorer" && provider !== "GCP" && (
                  <CrossAccount run={run} epoch={epoch} inspect={setGeneric} />
                )}
                {screen === "Security investigations" && (
                  <Records
                    run={run}
                    kind="security_investigations"
                    epoch={epoch}
                    columns={[
                      ["security_domain", "Domain"],
                      ["provider", "Provider"],
                      ["project_id", "Project"],
                      ["account_id", "Account"],
                      ["region", "Region"],
                      ["technical_hypothesis", "Observation"],
                      ["analyst_status", "Review"],
                    ]}
                    onSelect={setGeneric}
                  />
                )}
                {screen === "Security investigations" &&
                  provider === "Consolidated" && (
                    <ProviderContext.Provider value="GCP">
                      <h2>GCP candidate investigations</h2>
                      <Records
                        run={run}
                        kind="security_investigations"
                        epoch={epoch}
                        columns={[
                          ["project_id", "Project"],
                          ["technical_hypothesis", "Observation"],
                          ["status", "Prerequisites"],
                          ["analyst_status", "Review"],
                        ]}
                        onSelect={setGeneric}
                      />
                    </ProviderContext.Provider>
                  )}
                {screen === "Findings workbench" && provider !== "GCP" && (
                  <SharedInvestigations
                    run={run}
                    epoch={epoch}
                    onError={setError}
                    onSaved={() => setEpoch((e) => e + 1)}
                  />
                )}
                {screen === "IAM intelligence" &&
                  provider !== "GCP" &&
                  active?.enterprise && (
                    <CrossAccount
                      run={run}
                      epoch={epoch}
                      inspect={setGeneric}
                      initialDomain="IAM"
                    />
                  )}
                {screen === "Account explorer" && (
                  <Accounts
                    run={run}
                    epoch={epoch}
                    finding={setFinding}
                    evidence={inspectEvidence}
                    generic={setGeneric}
                  />
                )}
                {screen === "Assessment checklist" && (
                  <Checklist
                    run={run}
                    provider={provider}
                    epoch={epoch}
                    openFindings={(control) =>
                      navigate(
                        "Findings workbench",
                        `"methodology_id":"${control}"`,
                      )
                    }
                  />
                )}
                {screen === "Findings workbench" && (
                  <FindingsWorkbench
                    run={run}
                    epoch={epoch}
                    initialQuery={controlQuery}
                    onSelect={setFinding}
                    onChanged={() => setEpoch((e) => e + 1)}
                    onError={setError}
                    startJob={startJob}
                    busy={jobBusy}
                    onManage={(a) => {
                      setManageScope({
                        provider: a.provider,
                        scope_id: a.scope,
                      });
                      navigate("Manage Assessment Data");
                    }}
                  />
                )}
                {screen === "Finalized findings" && (
                  <Finalized
                    run={run}
                    provider={provider}
                    epoch={epoch}
                    onSelect={openFindingById}
                  />
                )}
                {screen === "Finalized findings" && (
                  <ExcludedFindings
                    run={run}
                    provider={provider === "Consolidated" ? "" : provider}
                    epoch={epoch}
                    onChanged={() => setEpoch((e) => e + 1)}
                  />
                )}
                {screen === "IAM intelligence" && provider !== "GCP" && (
                  <ProviderContext.Provider value="AWS">
                    <Iam
                      run={run}
                      epoch={epoch}
                      onSelect={setGeneric}
                      onFinding={setFinding}
                    />
                  </ProviderContext.Provider>
                )}
                {provider !== "AWS" &&
                  ["IAM intelligence", "Cross-account explorer"].includes(
                    screen,
                  ) && (
                    <>
                      {screen === "IAM intelligence" && (
                        <PrincipalRoles
                          run={run}
                          epoch={epoch}
                          selected={principal}
                          onSelect={setPrincipal}
                        />
                      )}
                      <GcpIdentity
                        run={run}
                        epoch={epoch}
                        inspect={setGeneric}
                        evidence={inspectEvidence}
                        finding={setFinding}
                      />
                    </>
                  )}
                {screen === "Evidence explorer" && (
                  <>
                    <Records
                      run={run}
                      kind="evidence"
                      columns={evidenceColumns}
                      epoch={epoch}
                      onSelect={inspectEvidence}
                    />
                    <h2>Collection coverage and failures</h2>
                    <Records
                      run={run}
                      kind="coverage"
                      columns={[
                        ["operation", "Operation"],
                        ["provider", "Provider"],
                        ["project_id", "Project"],
                        ["dataset", "Dataset"],
                        ["collection_status", "Collection result"],
                        ["analysis_support", "Analysis support"],
                        ["account_id", "Account"],
                        ["region", "Region"],
                        ["effective_coverage", "Completeness"],
                        ["errors", "Collection errors"],
                        ["record_count", "Records"],
                      ]}
                      epoch={epoch}
                      onSelect={setGeneric}
                      filterValues={[
                        "COMPLETE",
                        "PARTIAL",
                        "ERROR",
                        "NOT_COLLECTED",
                      ]}
                    />
                  </>
                )}
                {screen === "Network analysis" && (
                  <Network
                    run={run}
                    epoch={epoch}
                    evidence={inspectEvidence}
                    finding={setFinding}
                  />
                )}
                {screen === "Report center" && (
                  <Reports
                    run={run}
                    epoch={epoch}
                    startJob={startJob}
                    busy={jobBusy}
                  />
                )}
              </>
            )}
            {connected && screen === "Evidence import" && (
              <ImportedRemoval
                epoch={epoch}
                onSelect={(scope) => {
                  setManageScope(scope);
                  navigate("Manage Assessment Data");
                }}
              />
            )}
            {connected && runs.length > 0 && screen === "Dashboard" && (
              <section className="panel enterprise-build">
                <h2>Enterprise assessment workspace</h2>
                <p>
                  Combine selected original imports into a new immutable
                  assessment. Zero selected means all original imports; existing
                  runs and decisions remain available. Conflicting observations
                  remain unresolved.
                </p>
                <details>
                  <summary>
                    Select original imports ({memberSelection.length} selected)
                  </summary>
                  <div className="member-list">
                    {runs
                      .filter((r) => !r.enterprise && !r.historical)
                      .map((r) => (
                        <label key={r.run_id}>
                          <input
                            type="checkbox"
                            checked={memberSelection.includes(r.run_id)}
                            onChange={(e) =>
                              setMemberSelection(
                                e.target.checked
                                  ? [...memberSelection, r.run_id]
                                  : memberSelection.filter(
                                      (id) => id !== r.run_id,
                                    ),
                              )
                            }
                          />
                          {r.enterprise ? "Enterprise · " : "Import · "}
                          {r.created_at} · {r.run_id.slice(0, 20)}
                          {r.superseded_by?.length > 0 && (
                            <span className="muted">
                              {" "}
                              · superseded, not included (select to include)
                            </span>
                          )}
                        </label>
                      ))}
                  </div>
                </details>
                <button
                  disabled={!runs.length || jobBusy}
                  onClick={() =>
                    startJob("/enterprise/assess", {
                      members: memberSelection.length ? memberSelection : null,
                    })
                  }
                >
                  Build enterprise assessment
                </button>
                {active?.enterprise && (
                  <button
                    disabled={!memberSelection.length || jobBusy}
                    onClick={() =>
                      startJob("/enterprise/refresh", {
                        baseline: run,
                        replacements: memberSelection,
                      })
                    }
                  >
                    Refresh selected accounts
                  </button>
                )}
                {active?.enterprise && (
                  <p className="muted">
                    To refresh: select every new package for the updated
                    accounts above. CloSec replaces their prior collections in a
                    new snapshot and fully recomputes. Historical runs and
                    reviews remain available; other accounts are retained.
                  </p>
                )}
                <span className="muted">
                  {" "}
                  Historical imports are preserved; select coherent collection
                  runs for the intended assessment window.
                </span>
              </section>
            )}
          </main>
        </ProviderContext.Provider>
        <footer className="footnote">
          Deterministic analyzer · Source integrity and provenance retained ·
          Methodology mappings proposed
        </footer>
      </div>
      {finding && (
        <FindingDetail
          finding={finding}
          close={() => setFinding(undefined)}
          run={run}
          onSaved={() => {
            setFinding(undefined);
            refresh();
          }}
          onEvidence={async (oid) => {
            await inspectEvidence({ observation_id: oid });
          }}
          onError={setError}
        />
      )}{" "}
      {evidence && (
        <Detail
          title="Evidence traceability"
          close={() => setEvidence(undefined)}
        >
          <p className="muted">{evidence.inspection}</p>
          <Section title="Integrity and source locators">
            <Json value={evidence.provenance} />
          </Section>
          <Section title="Normalized source inspection">
            <Json value={evidence.observation} />
          </Section>
          <Section title="Linked enterprise relationships">
            <Json value={evidence.relationships} />
          </Section>
          <Section title="Linked control evaluations">
            <Json value={evidence.evaluations} />
          </Section>
          <Section title="Linked finding IDs">
            <Json value={evidence.findings} />
          </Section>
        </Detail>
      )}
      {generic && (
        <Detail title="Record details" close={() => setGeneric(undefined)}>
          {generic.source && generic.target && <Relationship row={generic} />}
          {generic.relationship_id && (
            <>
              <h3>Typed relationship qualification</h3>
              <Badge value={generic.status} />
              <p>{generic.detail}</p>
              <p>Authorization: {generic.authorization ?? "Reference only"}</p>
              <h3>Blocking predicates</h3>
              <Json value={generic.blocking} />
              <h3>Missing evidence</h3>
              <Json value={generic.missing} />
              <h3>Supporting observations</h3>
              {(generic.observation_ids || []).map((oid: string) => (
                <button
                  key={oid}
                  onClick={() => inspectEvidence({ observation_id: oid })}
                >
                  Inspect relationship evidence {oid.slice(0, 16)}
                </button>
              ))}
            </>
          )}
          <Json value={generic} />
        </Detail>
      )}
    </div>
  );
}

function Dashboard({
  run,
  epoch,
  assessed,
}: {
  run: string;
  epoch: number;
  assessed: boolean;
}) {
  const [d, setD] = useState<Row>(),
    [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    setD(undefined);
    setError("");
    api(`/runs/${run}/dashboard`)
      .then((x) => {
        if (live) setD(x);
      })
      .catch((e) => setError(e.message));
    return () => {
      live = false;
    };
  }, [run, epoch]);
  if (error) return <p className="error">{error}</p>;
  if (!d) return <Empty text="Loading persisted assessment metrics…" />;
  return (
    <>
      {!d.assessed && (
        <div className="notice">
          Evidence is imported. Run assessment to generate control evaluations
          and candidates.
        </div>
      )}
      <div className="metric-grid">
        {[
          [
            "Accounts represented",
            d.unique_accounts,
            "Evidence scope, not enterprise completion",
          ],
          [
            "Candidate findings",
            d.candidate_findings,
            "Separate from analyst confirmation",
          ],
          [
            "Control evaluations",
            d.control_evaluation_records,
            "Resource + collection-scope records",
          ],
          [
            "IAM investigations",
            d.iam_investigations,
            "Existing evaluated authorization context",
          ],
          [
            "Evidence files",
            d.evidence_files,
            `${d.normalized_observations} normalized observations`,
          ],
          [
            "Collection gaps",
            d.unresolved_collection_gaps,
            `${d.source_collections_with_errors} sources with errors`,
          ],
        ].map(([label, n, caption]) => (
          <article className="metric" key={String(label)}>
            <span>{label}</span>
            <strong>{n}</strong>
            <small>{caption}</small>
          </article>
        ))}
      </div>
      <div className="panel-grid">
        {[
          ["Control outcomes", d.outcomes],
          ["Findings by severity", d.severity],
          ["Findings by domain", d.domains],
          ["Analyst review progress", d.reviews],
          ["Source completeness", d.coverage],
          ["IAM authorization conclusions", d.iam_states],
        ].map(([label, data]) => (
          <section className="panel" key={String(label)}>
            <h2>{label}</h2>
            <CounterBars data={data} />
          </section>
        ))}
      </div>
      <SecurityCoverage run={run} epoch={epoch} />
    </>
  );
}
function ImportScreen({
  startJob,
  jobBusy,
  job,
  pendingIds,
  onValidated,
  onJob,
  onBusy,
  onError,
  environment,
}: {
  startJob: (
    path: string,
    body?: Row,
    after?: (result: Row) => void,
  ) => Promise<void>;
  jobBusy: boolean;
  job?: Row;
  pendingIds: string[];
  onValidated: () => void;
  onJob: (job: Row) => void;
  onBusy: (busy: boolean) => void;
  onError: (s: string) => void;
  environment: string;
}) {
  const folderInput = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<File[]>([]),
    [preview, setPreview] = useState<Row>(),
    [legacyAck, setLegacyAck] = useState(false),
    [busy, setBusy] = useState(false),
    [progress, setProgress] = useState(0),
    [ctx, setCtx] = useState<Row>({
      provider: "AWS",
      project_id: "",
      project_number: "",
      expected_projects: "",
      evidence_category: "native-json",
      origin: environment === "ASSESSMENT" ? "tool-generated" : "synthetic",
      format: "",
      operation: "",
      account_id: "",
      region: "",
      collected_at: "",
      collector_version: "",
      request_parameters: "{}",
    }),
    [profiles, setProfiles] = useState<Row>();
  useEffect(() => {
    // Restore a preview only for a validated upload that has not been imported;
    // an already-imported validation is history, not a current next step.
    if (
      job?.kind === "Package validation" &&
      job.status === "SUCCEEDED" &&
      job.result &&
      pendingIds.includes(job.id)
    )
      setPreview(job.result);
  }, [job?.id, job?.status, pendingIds.join(",")]);
  useEffect(() => {
    api("/profiles")
      .then(setProfiles)
      .catch((e) => onError(e.message));
  }, []);
  const validate = async () => {
    try {
      setBusy(true);
      onBusy(true);
      onError("");
      setPreview(undefined);
      setLegacyAck(false);
      const context = { ...ctx };
      if (!context.format) delete context.format;
      if (!context.operation) delete context.operation;
      const packaged = files.some(
        (file) =>
          file.name.endsWith(".zip") ||
          [
            "manifest.json",
            "collector-manifest.json",
            "collection_manifest.json",
          ].includes(file.name),
      );
      if (packaged) context.request_parameters = {};
      else {
        try {
          context.request_parameters = JSON.parse(ctx.request_parameters);
        } catch {
          throw new Error(
            "Request parameters must be valid JSON for guided individual exports.",
          );
        }
      }
      if (ctx.provider === "GCP" && ctx.expected_projects)
        context.expected_projects = ctx.expected_projects
          .split(",")
          .map((p: string) => p.trim())
          .filter(Boolean);
      else delete context.expected_projects;
      setPreview(
        await upload(files, relativePaths(files), context, setProgress, onJob),
      );
      onValidated();
    } catch (e: any) {
      onError(e.message);
    } finally {
      setBusy(false);
      onBusy(false);
    }
  };
  // Only packages without verified source checksums need the integrity acknowledgment.
  const ackRequired = String(
    preview?.diagnostics?.integrity_assurance || "",
  ).startsWith("LOCAL_HASH_ONLY");
  const choose = (list: FileList | null) => {
    setFiles(Array.from(list || []));
    setPreview(undefined);
    setLegacyAck(false);
    onError("");
  };
  return (
    <>
      <CollectorDownloads />
      <section className="panel import-panel">
        <h2>2. Import collected evidence</h2>
        <p>
          Select the collection-run folder the collector wrote (for example
          evidence / AccountName__AccountID__run). CloSec discovers the
          manifest, operation journal, native responses and checksums locally.
          All processing stays on this computer.
        </p>
        <div className="file-actions">
          <button
            className="primary"
            disabled={busy || jobBusy}
            onClick={() => {
              setCtx({ ...ctx, provider: "AWS" });
              if (folderInput.current) folderInput.current.value = "";
              folderInput.current?.click();
            }}
          >
            Import AWS Evidence Folder
          </button>
          <input
            ref={folderInput}
            hidden
            aria-label="Select package folder"
            type="file"
            {...({ webkitdirectory: "", directory: "" } as any)}
            multiple
            onChange={(e) => choose(e.target.files)}
          />
          <button
            className="primary"
            disabled={busy || jobBusy}
            onClick={() => {
              setCtx({ ...ctx, provider: "GCP" });
              if (folderInput.current) folderInput.current.value = "";
              folderInput.current?.click();
            }}
          >
            Import GCP Evidence Folder
          </button>
          <span>
            {files.length
              ? `${files.length} selected files`
              : "No evidence selected"}
          </span>
          <button
            className="primary"
            disabled={!files.length || busy || jobBusy}
            onClick={validate}
          >
            {busy
              ? `Local transfer ${progress}% · see job stage above`
              : "Validate evidence"}
          </button>
        </div>
        {files.length > 0 && (
          <p role="status">
            Selected {ctx.provider}{" "}
            {files.length === 1
              ? files[0].name
              : (files[0] as any).webkitRelativePath?.split("/")[0] || "folder"}
            . Next: Validate evidence, inspect the preview, then Import
            validated evidence. Security analysis is a separate action.
          </p>
        )}
        <p className="muted">
          Select → Validate → Import and analyze → Open assessment results →
          Review findings → Export report. The manifest and journal identify
          evidence; individual service files are not required.
        </p>
        <div className="form-grid">
          <label>
            Origin declaration
            <select
              value={ctx.origin}
              onChange={(e) => setCtx({ ...ctx, origin: e.target.value })}
            >
              <option value="synthetic" disabled={environment === "ASSESSMENT"}>
                Synthetic / test evidence
              </option>
              <option
                value="tool-generated"
                disabled={environment === "SYNTHETIC"}
              >
                Actual tool-generated evidence
              </option>
            </select>
          </label>
        </div>
        <details>
          <summary>Advanced: individual exports and legacy packages</summary>
          <label className="file-button secondary">
            Select JSON files
            <input
              aria-label="Select JSON files"
              type="file"
              accept=".json"
              multiple
              onChange={(e) => choose(e.target.files)}
            />
          </label>
          <div className="form-grid">
            <label>
              Provider for guided JSON
              <select
                aria-label="Guided JSON provider"
                value={ctx.provider}
                onChange={(e) =>
                  setCtx({ ...ctx, provider: e.target.value, operation: "" })
                }
              >
                <option>AWS</option>
                <option>GCP</option>
              </select>
            </label>
            <label>
              Format (single file)
              <select
                value={ctx.format}
                onChange={(e) => setCtx({ ...ctx, format: e.target.value })}
              >
                <option value="">Detect from backend structure</option>
                {profiles?.formats.map((v: string) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </label>
            <label>
              Operation (single file)
              <select
                value={ctx.operation}
                onChange={(e) => setCtx({ ...ctx, operation: e.target.value })}
              >
                <option value="">Detect when unambiguous</option>
                {(ctx.provider === "GCP"
                  ? profiles?.gcp_operations
                  : profiles?.operations
                )?.map((v: string) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </label>
            {[
              ["project_id", "GCP project ID (guided JSON)"],
              ["project_number", "GCP project number"],
              ["expected_projects", "Expected GCP projects (comma separated)"],
              ["evidence_category", "Evidence category"],
              ["account_id", "Collection account"],
              ["region", "Collection Region"],
              ["collected_at", "Collection timestamp (ISO + timezone)"],
              ["collector_version", "Collector version"],
            ].map(([key, label]) => (
              <label key={key}>
                {label}
                <input
                  value={ctx[key]}
                  onChange={(e) => setCtx({ ...ctx, [key]: e.target.value })}
                />
              </label>
            ))}
          </div>
          <label>
            Request parameters (single file)
            <textarea
              aria-label="Request parameters"
              value={ctx.request_parameters}
              onChange={(e) =>
                setCtx({ ...ctx, request_parameters: e.target.value })
              }
            />
          </label>
        </details>
        <p className="muted">
          For packages, identity, timestamps and request scope come from the
          manifest. Single exports remain partial. Origin declaration is not
          independent proof of authenticity.
        </p>
      </section>
      {preview && (
        <section className="panel">
          <h2>Validation preview</h2>
          <p role="status">
            Validation passed. Validation alone does not create an assessment:
            choose Import and analyze to import this evidence and run the
            security analysis, or Import validated evidence to analyze later.
          </p>
          <div className="toolbar">
            <Badge
              value={preview.can_import ? "PARSER ACCEPTED" : "REJECTED"}
            />
            <span>{preview.diagnostics.sources.length} source descriptors</span>
            <Badge value={preview.diagnostics.real_export_validation} />
            <a
              className="button"
              href={`/api/reports/${preview.compatibility_report}/download`}
              download
            >
              Download sanitized compatibility summary
            </a>
            <button
              className="primary"
              disabled={
                !preview.can_import ||
                busy ||
                jobBusy ||
                (ackRequired && !legacyAck)
              }
              onClick={() =>
                startJob(
                  "/import",
                  {
                    upload_id: preview.upload_id,
                    acknowledge_legacy_integrity: legacyAck,
                    analyze: true,
                  },
                  () => setPreview(undefined),
                )
              }
            >
              Import and analyze
            </button>
            <button
              disabled={
                !preview.can_import ||
                busy ||
                jobBusy ||
                (ackRequired && !legacyAck)
              }
              onClick={() =>
                startJob(
                  "/import",
                  {
                    upload_id: preview.upload_id,
                    acknowledge_legacy_integrity: legacyAck,
                  },
                  () => setPreview(undefined),
                )
              }
            >
              Import validated evidence
            </button>
          </div>
          <p>
            Parser acceptance does not prove complete collection or supported
            security conclusions. Reimport of identical bytes retains the run
            and analyst decisions.
          </p>
          {ackRequired && (
            <label>
              <input
                type="checkbox"
                checked={legacyAck}
                onChange={(e) => setLegacyAck(e.target.checked)}
              />
              I acknowledge that this legacy package has no declared source
              checksums; local hashes do not authenticate the collector.
            </label>
          )}
          {preview.diagnostics.original_status_totals && (
            <p>
              Original collection outcomes:{" "}
              {JSON.stringify(preview.diagnostics.original_status_totals)}.{" "}
              {preview.diagnostics.qualification}
            </p>
          )}
          {preview.collection && (
            <CollectorPackage summary={preview.collection} />
          )}
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Operation</th>
                  <th>Account / Region</th>
                  <th>Accepted</th>
                  <th>Completeness</th>
                  <th>Normalized records</th>
                  <th>Errors / limitations</th>
                </tr>
              </thead>
              <tbody>
                {preview.diagnostics.sources.map((s: Row, i: number) => (
                  <tr key={i}>
                    <td>{s.operation}</td>
                    <td>
                      {preview.sources[i]?.project_id ||
                        preview.sources[i]?.account_id ||
                        "Unresolved"}{" "}
                      / {preview.sources[i]?.region || "Unresolved"}
                    </td>
                    <td>{String(s.parser_accepted)}</td>
                    <td>
                      <Badge value={s.effective_coverage || "REJECTED"} />
                    </td>
                    <td>{s.normalized_resource_records ?? 0}</td>
                    <td>
                      {s.rejection_code || display(s.coverage_diagnostics)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <details>
            <summary>
              Required fields, identity resolution and provenance diagnostics
            </summary>
            <Json value={preview.diagnostics} />
          </details>
        </section>
      )}
    </>
  );
}
function CollectorDownloads() {
  const [items, setItems] = useState<Row[]>();
  useEffect(() => {
    api("/collectors")
      .then(setItems)
      .catch(() => setItems([]));
  }, []);
  return (
    <section className="panel" aria-label="Collectors">
      <h2>1. Collect evidence</h2>
      <p>
        Download the read-only collectors bundled with this release, run them in
        the authorized environment, then bring the resulting evidence folder
        back unchanged and import it below. AWS: unzip on the approved
        collection host and follow README.md (one account per run). GCP: run the
        PowerShell script on the authorized Windows workstation with gcloud.
      </p>
      {items === undefined ? (
        <p className="muted">Loading collectors…</p>
      ) : items.length === 0 ? (
        <p role="alert">
          Collectors are not available in this installation; use the collectors
          folder of the release ZIP.
        </p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Collector</th>
                <th>Version</th>
                <th>Purpose</th>
                <th>SHA-256</th>
                <th>Download</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id}>
                  <td>
                    {item.provider} · {item.name}
                  </td>
                  <td>{item.version}</td>
                  <td>{item.description}</td>
                  <td>
                    <code>{item.sha256.slice(0, 16)}…</code>
                  </td>
                  <td>
                    <a
                      className="button"
                      href={`/api/collectors/${item.id}/download`}
                      download={item.name}
                    >
                      Download
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
function CollectorPackage({ summary }: { summary: Row }) {
  const t = summary.totals;
  return (
    <section aria-label="Collector package">
      <h3>
        Collector package {summary.package_id} · {summary.collector.name}{" "}
        {summary.collector.version} · account {summary.account_id}
      </h3>
      <p>
        {t.operations} operations: {t.succeeded} succeeded, {t.failed} failed,{" "}
        {t.skipped} skipped, {t.truncated} truncated, {t.unsupported_operations}{" "}
        unsupported (retained, not parsed), {t.unlisted_files} unlisted files.
      </p>
      {summary.original_outcomes && (
        <p>
          Original collector outcomes:{" "}
          {Object.entries(summary.original_outcomes)
            .map(([status, count]) => `${status}: ${count}`)
            .join(" · ")}
          . These facts are retained separately from analyzer coverage.
          Collector schema ID remains unverified.
        </p>
      )}
      {summary.ancillary_files_verified_not_imported > 0 && (
        <p>
          {summary.ancillary_files_verified_not_imported} supporting files
          checksum-verified and retained. Collection summaries, retry requests,
          scanner logs and CSV outputs do not generate findings.
        </p>
      )}
      {summary.unlisted_files.length > 0 && (
        <p className="error">
          Files present but not listed in the collector manifest were not
          imported: {summary.unlisted_files.join(", ")}
        </p>
      )}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Operation</th>
              <th>Region</th>
              <th>Status</th>
              <th>Pages</th>
              <th>Pagination</th>
              <th>Error</th>
              <th>Handling</th>
            </tr>
          </thead>
          <tbody>
            {summary.operations.map((o: Row, i: number) => (
              <tr key={i}>
                <td>{o.operation}</td>
                <td>{o.region}</td>
                <td>
                  <Badge value={o.original_outcome || o.status} />
                </td>
                <td>{o.pages}</td>
                <td>{o.pagination}</td>
                <td>{o.original_error_code || o.error_code || ""}</td>
                <td>
                  <Badge value={o.import_handling} />
                  {o.interpretation && <small>{o.interpretation}</small>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Collection({ run, epoch }: { run: string; epoch: number }) {
  const [c, setC] = useState<Row>(),
    [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    setC(undefined);
    api(`/runs/${run}/collection`)
      .then((x) => live && setC(x))
      .catch((e) => setError(e.message));
    return () => {
      live = false;
    };
  }, [run, epoch]);
  if (error) return <p className="error">{error}</p>;
  if (!c) return null;
  const requests: Row[] = c.evidence_requests;
  return (
    <>
      <Readiness data={c} />
      <section className="panel">
        <h2>Collection by operation</h2>
        <p className="muted">
          Partial, failed and uncollected operations are not clean results.
        </p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Operation</th>
                <th>Sources</th>
                <th>Complete</th>
                <th>Partial</th>
                <th>Error</th>
                <th>Not collected</th>
                <th>Records</th>
                <th>Errors</th>
              </tr>
            </thead>
            <tbody>
              {c.operations.map((o: Row) => (
                <tr key={o.operation}>
                  <td>{o.operation}</td>
                  <td>{o.sources}</td>
                  <td>{o.COMPLETE ?? 0}</td>
                  <td>{o.PARTIAL ?? 0}</td>
                  <td>{o.ERROR ?? 0}</td>
                  <td>{o.NOT_COLLECTED ?? 0}</td>
                  <td>{o.records}</td>
                  <td>{o.errors.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {c.collector_packages.length > 0 && (
          <details>
            <summary>
              {c.collector_packages.length} collector package(s) with
              operation-level records
            </summary>
            {c.collector_packages.map((p: Row) => (
              <CollectorPackage
                key={p.package_id + p.account_id}
                summary={{ ...p, unlisted_files: [] }}
              />
            ))}
          </details>
        )}
      </section>
      <section className="panel">
        <h2>Targeted evidence requests</h2>
        <div className="toolbar">
          <span>{requests.length} requests</span>
          <a
            className="button"
            href={`/api/runs/${run}/evidence-requests.csv`}
            download
          >
            Download evidence request list (CSV)
          </a>
        </div>
        {requests.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Account</th>
                  <th>Region</th>
                  <th>Operation / dependency</th>
                  <th>State</th>
                  <th>Reason</th>
                  <th>Request</th>
                </tr>
              </thead>
              <tbody>
                {requests.slice(0, 100).map((r, i) => (
                  <tr key={i}>
                    <td>{r.account_id ?? "Unresolved"}</td>
                    <td>{r.region ?? "Unresolved"}</td>
                    <td>{r.operation}</td>
                    <td>
                      <Badge value={r.state} />
                    </td>
                    <td>{r.reason}</td>
                    <td>{r.request}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty text="No incomplete collections or missing evidence dependencies." />
        )}
        {requests.length > 100 && (
          <p className="muted">
            Showing 100 of {requests.length}; download the CSV for the full
            list.
          </p>
        )}
      </section>
    </>
  );
}

/** Mark many findings at once: analyst valid / not valid, or SRE status. */
function BulkBar({
  run,
  selected,
  total,
  onSelectAll,
  onClear,
  onDone,
  onError,
}: {
  run: string;
  selected: Set<string>;
  total: number;
  onSelectAll: () => void;
  onClear: () => void;
  onDone: () => void;
  onError: (s: string) => void;
}) {
  const [note, setNote] = useState(""),
    [fpReason, setFpReason] = useState(""),
    [busy, setBusy] = useState(false);
  const analyst = useIdentity();
  const ids = [...selected];
  const run_ = async (path: string, body: Row) => {
    try {
      setBusy(true);
      await api(path, { ...body, finding_ids: ids });
      setNote("");
      onDone();
    } catch (e: any) {
      onError(e.message);
    } finally {
      setBusy(false);
    }
  };
  const disabled = busy || !ids.length;
  return (
    <div className="bulk-bar" aria-label="Bulk marking">
      <strong>{ids.length} selected</strong>
      <button className="small" onClick={onSelectAll} disabled={!total}>
        Select all {Math.min(total, 2000)} matching
      </button>
      {ids.length > 0 && (
        <button className="small" onClick={onClear}>
          Clear selection
        </button>
      )}
      <input
        aria-label="Bulk note"
        placeholder="Note / reason (required for not valid and BAU)"
        value={note}
        maxLength={15900}
        onChange={(e) => setNote(e.target.value)}
      />
      <button
        className="primary small"
        disabled={disabled}
        onClick={() =>
          run_(`/runs/${run}/review-bulk`, { status: "CONFIRMED", note })
        }
      >
        Mark valid
      </button>
      <button
        className="small"
        disabled={disabled || !note.trim()}
        onClick={() =>
          run_(`/runs/${run}/review-bulk`, { status: "REJECTED", note })
        }
      >
        Mark not valid
      </button>
      <button
        className="small"
        disabled={disabled}
        onClick={() =>
          run_(`/runs/${run}/sre`, { verdict: "SENT_TO_SRE", reason: note })
        }
      >
        Send to SRE
      </button>
      <button
        className="small"
        disabled={disabled}
        onClick={() =>
          run_(`/runs/${run}/sre`, { verdict: "GAP_CONFIRMED", reason: note })
        }
      >
        SRE: gap confirmed
      </button>
      <button
        className="small"
        disabled={disabled || !note.trim()}
        onClick={() =>
          run_(`/runs/${run}/sre`, { verdict: "NO_GAP_BAU", reason: note })
        }
      >
        SRE: no gap (BAU)
      </button>
      <span className="bulk-fp" aria-label="Bulk false positive">
        <FalsePositiveReason
          value={fpReason}
          onChange={setFpReason}
          label="Bulk false-positive reason"
        />
        <button
          className="small danger"
          disabled={disabled || !fpReason.trim()}
          onClick={async () => {
            await run_(`/runs/${run}/exclusions`, {
              action: "EXCLUDE",
              reason: "FALSE_POSITIVE",
              note: fpReason.trim(),
              analyst: analyst || "Analyst",
            });
            setFpReason("");
          }}
        >
          Mark as false positive
        </button>
        <button
          className="small"
          disabled={disabled}
          onClick={() =>
            run_(`/runs/${run}/exclusions`, {
              action: "RESTORE",
              analyst: analyst || "Analyst",
            })
          }
        >
          Restore
        </button>
      </span>
    </div>
  );
}
/** Generate the Excel + Word assessment report as a job, then hand over the file. */
function downloadReport(startJob: StartJob, run: string, options: Row = {}) {
  return startJob(
    `/runs/${run}/reports`,
    { kind: "assessment", ...options },
    (result: Row) => {
      const link = document.createElement("a");
      link.href = `/api/reports/${result.id}/download`;
      link.download = result.name;
      document.body.appendChild(link);
      link.click();
      link.remove();
    },
  );
}
type StartJob = (
  path: string,
  body?: Row,
  after?: (r: Row) => void,
) => Promise<void>;
const INCLUDE_OPTIONS: [string, string][] = [
  ["confirmed", "Only findings marked valid (confirmed) — default"],
  ["valid", "Exclude findings marked not valid / No gap (BAU)"],
  ["all", "All findings"],
];
/** Analyst scope-limitation text for this run's reports (after the fixed limitations). */
function CustomLimitations({ run }: { run: string }) {
  const analyst = useIdentity();
  const [text, setText] = useState(""),
    [saved, setSaved] = useState(""),
    [message, setMessage] = useState("");
  useEffect(() => {
    let live = true;
    api(`/runs/${run}/report-limitations`)
      .then((r) => {
        if (!live) return;
        setText(r.text || "");
        setSaved(r.text || "");
      })
      .catch((e) => live && setMessage(e.message));
    return () => {
      live = false;
    };
  }, [run]);
  return (
    <section className="panel" aria-label="Custom scope limitations">
      <h3>Custom scope limitations</h3>
      <p className="muted">
        Shown in &quot;Coverage and limitations&quot; after the fixed
        limitations, one paragraph per line. Kept with this run; frozen editions
        keep the text they were frozen with.
      </p>
      <textarea
        aria-label="Custom scope limitations text"
        value={text}
        maxLength={4000}
        rows={4}
        onChange={(e) => setText(e.target.value)}
      />
      <button
        disabled={text === saved}
        onClick={async () => {
          try {
            await api(`/runs/${run}/report-limitations`, {
              text,
              analyst: analyst || "Analyst",
            });
            setSaved(text);
            setMessage("Saved.");
          } catch (e: any) {
            setMessage(e.message);
          }
        }}
      >
        Save limitations
      </button>
      {message && <p role="status">{message}</p>}
    </section>
  );
}
/** Word / report Excel: one entry per root-cause group (default) or per finding. */
function GroupedToggle({
  value,
  onChange,
}: {
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="confirm">
      <input
        type="checkbox"
        checked={value}
        onChange={(e) => onChange(e.target.checked)}
      />{" "}
      Group findings by root cause
    </label>
  );
}
/** Shown whenever a report would contain findings that are not analyst-confirmed. */
function ScopeWarning({ include }: { include: string }) {
  if (include === "confirmed") return null;
  return (
    <p role="alert" className="scope-warning">
      This report will include findings that are not analyst-confirmed (
      {INCLUDE_OPTIONS.find(([k]) => k === include)?.[1]}). The cover states
      this scope.
    </p>
  );
}
function IncludeSelect({
  value,
  onChange,
  label = "Report contents",
}: {
  value: string;
  onChange: (v: string) => void;
  label?: string;
}) {
  return (
    <label>
      {label}
      <select
        aria-label={label}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {INCLUDE_OPTIONS.map(([k, text]) => (
          <option key={k} value={k}>
            {text}
          </option>
        ))}
      </select>
    </label>
  );
}
function FindingsWorkbench({
  run,
  epoch,
  initialQuery,
  onSelect,
  onChanged,
  onError,
  startJob,
  busy,
  onManage,
}: {
  run: string;
  epoch: number;
  initialQuery: string;
  onSelect: (row: Row) => void;
  onChanged: () => void;
  onError: (s: string) => void;
  startJob: StartJob;
  busy: boolean;
  onManage: (account: Row) => void;
}) {
  const [include, setInclude] = useState("confirmed"),
    [grouped, setGrouped] = useState(true);
  const provider = React.useContext(ProviderContext);
  const facets = useFindingFacets(run, provider, epoch);
  const [scope, setScope] = useState<Row | null>(null);
  useEffect(() => setScope(null), [run, provider]);
  const initialFilters = scope
    ? scope.provider === "GCP"
      ? { project: scope.scope }
      : { account: scope.scope }
    : undefined;
  return (
    <>
      <FindingsByAccount
        run={run}
        facets={facets}
        selected={scope ? `${scope.provider}:${scope.scope}` : ""}
        onSelect={setScope}
        onChanged={onChanged}
        onError={onError}
        reportControl={
          <>
            <IncludeSelect value={include} onChange={setInclude} />
            <GroupedToggle value={grouped} onChange={setGrouped} />
            <ScopeWarning include={include} />
          </>
        }
        reportBusy={busy}
        onReport={(a) =>
          downloadReport(startJob, run, {
            include,
            grouped,
            provider: a.provider,
            scope: a.scope,
          })
        }
        onManage={onManage}
      />
      <FindingGroups
        run={run}
        epoch={epoch}
        onChanged={onChanged}
        onError={onError}
      />
      <Records
        run={run}
        kind="findings"
        initialQuery={initialQuery}
        initialFilters={initialFilters}
        columns={findingColumns}
        epoch={epoch}
        onSelect={onSelect}
        onChanged={onChanged}
        filterValues={["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
      />
    </>
  );
}
function Accounts({
  run,
  epoch,
  finding,
  evidence,
  generic,
}: {
  run: string;
  epoch: number;
  finding: (r: Row) => void;
  evidence: (r: Row) => void;
  generic: (r: Row) => void;
}) {
  const provider = React.useContext(ProviderContext);
  const [selected, setSelected] = useState(""),
    [selectedProvider, setSelectedProvider] = useState("AWS"),
    [tab, setTab] = useState("resources");
  useEffect(() => setSelected(""), [run, provider]);
  const cols: Record<string, [string, string][]> = {
    resources: evidenceColumns,
    coverage: [
      ["operation", "Operation"],
      ["region", "Region"],
      ["effective_coverage", "Coverage"],
      ["errors", "Errors"],
    ],
    evaluations: evaluationColumns,
    findings: findingColumns,
    relationships: [
      ["kind", "Relationship"],
      ["source", "Source"],
      ["target", "Target"],
      ["basis", "Basis"],
    ],
  };
  return (
    <>
      <Records
        run={run}
        kind="accounts"
        epoch={epoch}
        columns={[
          ["account", "Account / project"],
          ["provider", "Provider"],
          ["resources", "Unique resources"],
          ["findings", "Findings"],
          ["coverage", "Evidence coverage"],
          ["registry", "Tracker key"],
        ]}
        onSelect={(r) => {
          setSelected(r.account);
          setSelectedProvider(r.provider || "AWS");
        }}
      />
      {selected && (
        <section className="panel account-panel">
          <h2>
            {selectedProvider === "GCP" ? "Project" : "Account"} {selected}
          </h2>
          <p className="muted">
            Independent account collection is supported. Organizations data is
            not required to view evidence.
          </p>
          <div className="tabs">
            {Object.keys(cols).map((t) => (
              <button
                className={tab === t ? "selected" : ""}
                aria-pressed={tab === t}
                key={t}
                onClick={() => setTab(t)}
              >
                {t}
              </button>
            ))}
          </div>
          <Records
            key={tab}
            run={run}
            kind={tab}
            account={selectedProvider === "AWS" ? selected : ""}
            project={selectedProvider === "GCP" ? selected : ""}
            columns={cols[tab]}
            epoch={epoch}
            onSelect={
              tab === "findings"
                ? finding
                : tab === "resources"
                  ? evidence
                  : generic
            }
          />
        </section>
      )}
    </>
  );
}
function FindingDetail({
  finding: f,
  close,
  run,
  onSaved,
  onEvidence,
  onError,
}: {
  finding: Row;
  close: () => void;
  run: string;
  onSaved: () => void;
  onEvidence: (oid: string) => void;
  onError: (s: string) => void;
}) {
  const identity = useIdentity();
  const [detailTab, setDetailTab] = useState("Technical Analysis");
  const [analyst, setAnalyst] = useState(f.decision?.analyst || ""),
    [note, setNote] = useState(f.decision?.note || ""),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!analyst && identity) setAnalyst(identity);
  }, [identity]);
  const review = async (status: string, exception = false) => {
    try {
      setBusy(true);
      await api(`/runs/${run}/review/${f.finding_id}`, {
        status,
        analyst,
        note,
        exception,
      });
      onSaved();
    } catch (e: any) {
      onError(e.message);
    } finally {
      setBusy(false);
    }
  };
  const decision = (
    <section className="detail-section decision" aria-label="Your decision">
      <h3>Your decision</h3>
      <p className="muted">
        Confirm = valid: a confirmed vulnerability, listed in Finalized
        findings. Reject = not valid (for example known or accepted): excluded
        from reports. An SRE response is optional.
      </p>
      <label>
        Remarks
        <textarea
          aria-label="Analyst remarks"
          value={note}
          placeholder="Optional; required to record an exception"
          onChange={(e) => setNote(e.target.value)}
          maxLength={15900}
        />
      </label>
      <div className="review-actions">
        <button
          className="primary"
          disabled={busy}
          title="Mark valid: confirmed vulnerability"
          onClick={() => review("CONFIRMED")}
        >
          Confirm
        </button>
        <button
          disabled={busy}
          title="Mark not valid: excluded from reports"
          onClick={() => review("REJECTED")}
        >
          Reject
        </button>
        <button disabled={busy} onClick={() => review("NEEDS_VALIDATION")}>
          Mark for validation
        </button>
        <button
          disabled={!note.trim() || busy}
          onClick={() => review("NEEDS_VALIDATION", true)}
        >
          Record exception
        </button>
      </div>
      <label className="recorded-as">
        Recorded as
        <input
          aria-label="Analyst identity"
          value={analyst}
          onChange={(e) => setAnalyst(e.target.value)}
          maxLength={200}
        />
      </label>
      {f.decision && (
        <p className="muted">
          Current decision: {f.decision.status} by {f.decision.analyst} on{" "}
          {String(f.decision.decided_at).slice(0, 10)}
          {f.decision.note && `: ${f.decision.note}`}
        </p>
      )}
    </section>
  );
  return (
    <Detail title="Finding details" close={close}>
      <div className="finding-title">
        <Badge value={f.suggested_severity} />
        <Badge value={f.analyst_status} />
        <StageBadge stage={f.stage} />
        {f.false_positive && (
          <span className="badge fp" title="Marked as false positive">
            FP
          </span>
        )}
        <h2>{f.title}</h2>
        <p>
          {f.provider || "AWS"} · {f.project_id || f.account_id} · {f.region} ·{" "}
          {f.native_id}
        </p>
      </div>
      <div className="tabs" role="tablist" aria-label="Finding views">
        {["Technical Analysis", "Client Reporting"].map((t) => (
          <button
            role="tab"
            aria-selected={detailTab === t}
            key={t}
            onClick={() => setDetailTab(t)}
          >
            {t}
          </button>
        ))}
      </div>
      {detailTab === "Technical Analysis" ? (
        <>
          <p className="muted">
            Read-only evidence and analysis. Use Client Reporting to edit
            narratives and record review decisions.
          </p>
          <FindingAnalysis run={run} findingId={f.finding_id} decision={null} />
        </>
      ) : (
        <>
          {decision}
          <FalsePositiveControl
            run={run}
            findingId={f.finding_id}
            analyst={analyst || identity}
            onChanged={onSaved}
            onError={onError}
          />
          <ExcludeControl
            run={run}
            findingId={f.finding_id}
            analyst={analyst || identity}
            onChanged={onSaved}
            onError={onError}
          />
          <details className="analysis-section sre-optional">
            <summary>
              SRE response (optional)
              {f.sre ? ` · ${STAGE_LABELS[f.stage] || ""}` : ""}
            </summary>
            <SreSection
              run={run}
              finding={f}
              analyst={analyst || identity}
              onSaved={onSaved}
              onConfirm={() => review("CONFIRMED")}
              onError={onError}
            />
          </details>
          <ReportFinding
            run={run}
            finding={f.finding_id}
            onError={onError}
            reviewer={analyst || identity}
          />
        </>
      )}
      <details className="analysis-section">
        <summary>
          More context: methodology, cross-account links, raw references
        </summary>
        <Section title="Methodology and confidence">
          <p>
            {f.methodology_id ||
              "Additional security observation requiring analyst review"}{" "}
            · {display(f.methodology_criteria)} · {f.mapping_status}
          </p>
          <p>
            Evidence confidence: {f.evidence_confidence}. Technical severity:{" "}
            {f.suggested_severity}. <Badge value={f.finding_class} />
          </p>
        </Section>
        <Section title="Cross-account context">
          <p>{f.cross_account_classification}</p>
          <p>Affected accounts: {display(f.affected_accounts)}</p>
          <p>
            Source accounts: {display(f.source_accounts)} · Destination
            accounts: {display(f.destination_accounts)}
          </p>
          <Json value={f.relationships} />
        </Section>
        <Section title="Linked observations">
          <Json value={f.source_timestamps} />
          {f.supporting_observations?.map((oid: string) => (
            <button className="small" key={oid} onClick={() => onEvidence(oid)}>
              Inspect {oid.slice(0, 20)}
            </button>
          ))}
          {f.contradictory_observations.length > 0 && (
            <>
              <h4>Contradictory observations</h4>
              {f.contradictory_observations.map((oid: string) => (
                <button key={oid} onClick={() => onEvidence(oid)}>
                  {oid.slice(0, 24)}
                </button>
              ))}
            </>
          )}
        </Section>
      </details>
    </Detail>
  );
}
function Relationship({ row }: { row: Row }) {
  return (
    <div className="relationship">
      <div>
        <b>Source</b>
        <p>{row.source}</p>
      </div>
      <span>
        →<small>{row.kind}</small>
      </span>
      <div>
        <b>Target</b>
        <p>{row.target}</p>
      </div>
      <p>
        <Badge value={row.basis} /> Existing analyzer relationship; no inferred
        edges.
      </p>
    </div>
  );
}
function Iam({
  run,
  epoch,
  onSelect,
  onFinding,
}: {
  run: string;
  epoch: number;
  onSelect: (r: Row) => void;
  onFinding: (r: Row) => void;
}) {
  const [tab, setTab] = useState("investigations"),
    [context, setContext] = useState<Row>();
  const [contextError, setContextError] = useState("");
  useEffect(() => {
    let live = true;
    setContext(undefined);
    setContextError("");
    api(`/runs/${run}/iam-context`)
      .then((d) => {
        if (live) setContext(d);
      })
      .catch((e) => {
        if (live) setContextError(e.message);
      });
    return () => {
      live = false;
    };
  }, [run, epoch]);
  const columns: Record<string, [string, string][]> = {
    investigations: [
      ["kind", "Investigation"],
      ["principal", "Source principal"],
      ["target", "Target role"],
      ["state", "Authorization"],
      ["classification", "Classification"],
    ],
    roles: [
      ["role", "Role"],
      ["account", "Account"],
      ["privilege", "Privilege conclusion"],
      ["missing", "Missing evidence"],
    ],
    policies: [
      ["arn", "Policy ARN"],
      ["default_version", "Default version"],
      ["document_resolved", "Document resolved"],
      ["gap", "Gap"],
    ],
    relationships: [
      ["kind", "Relationship"],
      ["source", "Source"],
      ["target", "Target"],
      ["basis", "Basis"],
    ],
    gaps: [
      ["category", "Category"],
      ["scope", "Scope"],
      ["missing", "Missing evidence"],
    ],
  };
  return (
    <>
      <div className="panel">
        <h2>IAM authorization intelligence</h2>
        {contextError && <p role="alert">{contextError}</p>}
        <p>
          Cross-account AssumeRole and EC2/Lambda PassRole use the existing
          evaluator. Supported prerequisites do not confirm exploitation.
          Same-account resource-policy authorization is excluded.
        </p>
        {context && (
          <p className="muted">
            Organizations evidence:{" "}
            {context.organization_observed ? "Observed" : "Not supplied"} ·{" "}
            {context.root_count} roots · {context.policy_count} policies ·{" "}
            {display(context.truncation)}
          </p>
        )}
        <div className="tabs">
          {Object.keys(columns).map((t) => (
            <button
              key={t}
              className={tab === t ? "selected" : ""}
              aria-pressed={tab === t}
              onClick={() => setTab(t)}
            >
              {t}
            </button>
          ))}
        </div>
      </div>
      <Records
        key={tab}
        run={run}
        kind={tab}
        columns={columns[tab]}
        epoch={epoch}
        onSelect={onSelect}
        filterValues={
          tab === "investigations"
            ? [
                "ALLOWED_WITH_SUPPORTED_CONTEXT",
                "DENIED_BY_EVIDENCE",
                "POTENTIALLY_ALLOWED",
                "UNKNOWN",
              ]
            : []
        }
      />
      <h2>Related candidate findings</h2>
      <Records
        run={run}
        kind="iam_findings"
        columns={findingColumns}
        epoch={epoch}
        onSelect={onFinding}
      />
    </>
  );
}
function GcpIdentity({
  run,
  epoch,
  inspect,
  evidence,
  finding,
}: {
  run: string;
  epoch: number;
  inspect: (r: Row) => void;
  evidence: (r: Row) => void;
  finding: (r: Row) => void;
}) {
  return (
    <ProviderContext.Provider value="GCP">
      <div className="panel">
        <h2>Observed GCP identity and project relationships</h2>
        <p>
          Service accounts, keys, role bindings and policy metadata from the
          selected assessment. Inherited policies, deny policies, principal
          access boundaries and conditional context may be incomplete. Effective
          permission and exploitable attack paths are not established.
        </p>
      </div>
      <h2>Identity evidence</h2>
      <Records
        run={run}
        epoch={epoch}
        kind="roles"
        columns={evidenceColumns}
        onSelect={evidence}
      />
      <h2>Policy evidence</h2>
      <Records
        run={run}
        epoch={epoch}
        kind="policies"
        columns={evidenceColumns}
        onSelect={evidence}
      />
      <h2>Observed relationships</h2>
      <Records
        run={run}
        epoch={epoch}
        kind="relationships"
        columns={[
          ["relationship", "Relationship"],
          ["source", "Source"],
          ["destination", "Destination"],
          ["status", "Classification"],
          ["authorization", "Authorization"],
        ]}
        onSelect={inspect}
      />
      <h2>IAM evidence limitations</h2>
      <Records
        run={run}
        epoch={epoch}
        kind="gaps"
        columns={[
          ["project_id", "Project"],
          ["category", "Limitation"],
          ["missing", "Required evidence"],
        ]}
        onSelect={inspect}
      />
      <h2>IAM candidate findings</h2>
      <Records
        run={run}
        epoch={epoch}
        kind="iam_findings"
        columns={findingColumns}
        onSelect={finding}
      />
    </ProviderContext.Provider>
  );
}

function Network({
  run,
  epoch,
  evidence,
  finding,
}: {
  run: string;
  epoch: number;
  evidence: (r: Row) => void;
  finding: (r: Row) => void;
}) {
  const provider = React.useContext(ProviderContext);
  return (
    <>
      <div className="panel">
        <h2>Observed network configuration</h2>
        <p>
          {provider === "Consolidated" ? (
            <p>
              Observed AWS and GCP network configurations. Filters select the
              imported cloud and scope; structural references do not establish
              end-to-end reachability.
            </p>
          ) : provider === "AWS" ? (
            <>
              Instances, security groups, interfaces, route tables and RDS
              observations. This is configuration context; NACLs, gateway
              associations, host firewalls and end-to-end reachability are not
              evaluated.
            </>
          ) : (
            <>
              Observed GCP networks, subnets, firewalls, routes and supported
              networking metadata. These records do not establish end-to-end
              exposure or reachability. Missing or failed collection remains a
              coverage limitation; inventory without a security rule is not
              evaluated.
            </>
          )}
        </p>
      </div>
      <Records
        run={run}
        kind="network"
        columns={evidenceColumns}
        epoch={epoch}
        onSelect={evidence}
      />
      <h2>Network candidate findings</h2>
      <Records
        run={run}
        kind="network_findings"
        columns={findingColumns}
        epoch={epoch}
        onSelect={finding}
      />
    </>
  );
}
function Reports({
  run,
  epoch,
  startJob,
  busy,
}: {
  run: string;
  epoch: number;
  busy: boolean;
  startJob: (
    path: string,
    body?: Row,
    after?: (r: Row) => void,
  ) => Promise<void>;
}) {
  const [reports, setReports] = useState<Row[]>([]);
  const [reconciled, setReconciled] = useState<Row>();
  useEffect(() => {
    api("/reports").then(setReports);
    api(`/runs/${run}/reconciliation`)
      .then(setReconciled)
      .catch(() => setReconciled(undefined));
  }, [epoch, run]);
  const provider = React.useContext(ProviderContext);
  const facets = useFindingFacets(run, provider, epoch);
  const [include, setInclude] = useState("confirmed"),
    [grouped, setGrouped] = useState(true),
    [reportScope, setReportScope] = useState("");
  const downloadAssessment = () => {
    const [p, ...rest] = reportScope.split(":");
    return downloadReport(startJob, run, {
      include,
      grouped,
      ...(reportScope ? { provider: p, scope: rest.join(":") } : {}),
    });
  };
  return (
    <>
      <section className="panel" aria-label="Assessment report">
        <p>
          For all imported accounts, build Enterprise Assessment with no import
          subset selected. A cloud filter applies to findings, account summaries
          and attack paths together. Downloads contain a native .xlsx workbook
          and a .docx report.
        </p>
        <h2>Assessment report</h2>
        <p>
          One download for the selected assessment, as a Word report and a
          matching Excel workbook: cover, 1. Executive summary, 2. Coverage and
          limitations (including UNKNOWN areas), 3. Attack surface, 4. Attack
          paths with a hop table (Excel: one row per hop and a STRIDE matrix),
          5. STRIDE and direction justification, 6. Findings, and an appendix.
          Choose which findings to include based on your valid / not valid
          marking, the cloud (GCP, AWS or both) and optionally one account or
          project. Excluded findings are never included.
        </p>
        <div className="toolbar">
          <IncludeSelect value={include} onChange={setInclude} />
          <GroupedToggle value={grouped} onChange={setGrouped} />
          <ScopeWarning include={include} />
          <label>
            Account / project
            <select
              aria-label="Report account"
              value={reportScope}
              onChange={(e) => setReportScope(e.target.value)}
            >
              <option value="">
                GCP + AWS — all imported scopes in this snapshot
              </option>
              <option value="GCP:">
                GCP only — all projects in this snapshot
              </option>
              <option value="AWS:">
                AWS only — all accounts in this snapshot
              </option>
              {(facets?.accounts || [])
                .filter((a: Row) => a.scope)
                .map((a: Row) => (
                  <option
                    key={`${a.provider}:${a.scope}`}
                    value={`${a.provider}:${a.scope}`}
                  >
                    {accountLabel(a)}
                  </option>
                ))}
            </select>
          </label>
        </div>
        <button
          className="primary"
          disabled={busy}
          onClick={downloadAssessment}
        >
          Download assessment report (Excel + Word)
        </button>
      </section>
      <CustomLimitations run={run} />
      {reconciled && (
        <section className="panel" aria-label="Assessment reconciliation">
          <h2>Assessment reconciliation</h2>
          <p>
            Every count below is measured for the selected run, from the
            collector journal to the newest Excel export. Differences carry the
            exact reason; nothing is inferred.
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Stage</th>
                  <th>Actual record count</th>
                  <th>Status</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {reconciled.stages.map((stage: Row) => (
                  <tr key={stage.stage}>
                    <td>{stage.stage}</td>
                    <td>{stage.count ?? "—"}</td>
                    <td>
                      <Badge value={stage.status} />
                    </td>
                    <td>{stage.explanation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
      <ApprovedReports
        run={run}
        epoch={epoch}
        busy={busy}
        startJob={startJob}
      />
      <section className="panel">
        <h2>Generate an assessment export</h2>
        <p>
          Reports are generated from persisted analyzer results. Existing
          workbooks and customer trackers are never overwritten. Exports contain
          customer identities; retain them within your approved environment.
        </p>
        {busy && (
          <p className="notice" role="note">
            A report is being generated. Progress is shown above; completed
            reports appear below. Interrupted exports never publish a partial
            file.
          </p>
        )}
        <div className="report-options">
          {[
            [
              "excel",
              "Assessment Excel workbook",
              "Full findings, coverage, IAM and evidence sheets",
            ],
            [
              "findings",
              "Consolidated findings",
              "JSON with independent analyst status",
            ],
            [
              "accounts",
              "Account assessment results",
              "JSON control evaluations with account/Region scope",
            ],
            [
              "coverage",
              "Coverage register",
              "JSON source completeness and failures",
            ],
            [
              "evidence",
              "Evidence register",
              "JSON normalized observation provenance",
            ],
          ].map(([kind, label, desc]) => (
            <article key={kind}>
              <h3>{label}</h3>
              <p>{desc}</p>
              <button
                className="primary"
                disabled={busy}
                onClick={() => startJob(`/runs/${run}/reports`, { kind })}
              >
                Generate {kind === "excel" ? "Excel" : kind}
              </button>
            </article>
          ))}
        </div>
      </section>
      <section className="panel">
        <h2>Generated reports</h2>
        {reports.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Report</th>
                  <th>Run</th>
                  <th>Size</th>
                  <th>Download</th>
                </tr>
              </thead>
              <tbody>
                {reports.map((r) => (
                  <tr key={r.id}>
                    <td>
                      {r.name}
                      {r.kind === "compatibility" && (
                        <span className="muted">
                          {" "}
                          · sanitized verifier summary
                        </span>
                      )}
                    </td>
                    <td>
                      {r.run_id ? r.run_id.slice(0, 20) : "evidence validation"}
                    </td>
                    <td>{r.bytes.toLocaleString()} bytes</td>
                    <td>
                      <a
                        className="button"
                        href={`/api/reports/${r.id}/download`}
                        download
                      >
                        Download
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty text="No reports generated in this workspace yet." />
        )}
      </section>
    </>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
