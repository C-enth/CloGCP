export type Row = Record<string, any>;
export type Page = {
  items: Row[];
  total: number;
  offset: number;
  limit: number;
  /** Findings: false positives matching the other filters (hidden by default). */
  false_positive_excluded?: number;
};
let csrf = "";
declare const __CLOSEC_BUILD__: {
  application_version: string;
  frontend_build_id: string;
  transport_version: string;
};
function failure(data: Row, fallback: string): string {
  return [
    data.error || (typeof data.detail === "string" ? data.detail : fallback),
    data.message,
    data.action,
    data.identity_context
      ? `File ${data.identity_context.file}; declared project ${data.identity_context.declared_project}; field ${data.identity_context.field}; observed identity ${data.identity_context.observed_identity}.`
      : null,
    data.limit
      ? `Limit ${data.limit.allowed} bytes; observed ${data.limit.observed} bytes (${data.limit.name}).`
      : null,
  ]
    .filter(Boolean)
    .join(" — ");
}
/** Deletion previews and file lists read a whole scope; allow more than a normal read. */
export const PREVIEW_TIMEOUT_MS = 180000;
/** Dashboard parts of large estates (secondary measure; reads also retry on timeout). */
export const DASHBOARD_TIMEOUT_MS = 60000;
/** A read that times out is retried with a longer timeout instead of failing. */
const READ_TIMEOUT_RETRIES = 2;
/** Reads refused only because a local job owns the database are retried until it ends. */
const BUSY = "WORKSPACE_OPERATION_IN_PROGRESS";
const TIMEOUT = "LOCAL_API_TIMEOUT";
const BUSY_RETRY_MS = 750;
const BUSY_WAIT_LIMIT_MS = 60 * 60 * 1000; // The local job time budget.
export async function api(
  path: string,
  body?: any,
  timeoutMs = 15000,
): Promise<any> {
  const started = Date.now();
  let timeouts = 0;
  for (;;) {
    try {
      return await request(path, body, timeoutMs * (timeouts + 1));
    } catch (error: any) {
      if (
        body === undefined &&
        error.code === TIMEOUT &&
        timeouts < READ_TIMEOUT_RETRIES
      ) {
        timeouts += 1; // the view keeps its loading state while the read is retried
        continue;
      }
      if (
        body !== undefined ||
        error.code !== BUSY ||
        Date.now() - started > BUSY_WAIT_LIMIT_MS
      )
        throw error;
      await new Promise((resolve) => setTimeout(resolve, BUSY_RETRY_MS));
    }
  }
}
async function request(
  path: string,
  body: any,
  timeoutMs: number,
): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch("/api" + path, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin",
      headers:
        body === undefined
          ? {}
          : { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    const data = await response.json();
    if (!response.ok)
      throw Object.assign(new Error(failure(data, "Operation failed")), {
        code: data.error,
      });
    return data;
  } catch (error: any) {
    if (error.name === "AbortError")
      throw Object.assign(
        new Error(
          `Local API did not answer within ${Math.round(timeoutMs / 1000)} seconds. View job details or retry; keep the workspace intact.`,
        ),
        { code: TIMEOUT },
      );
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
export async function connect() {
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  history.replaceState(null, "", location.pathname);
  const response = await fetch("/api/session", {
    method: token ? "POST" : "GET",
    credentials: "same-origin",
    headers: token
      ? { "X-Bootstrap-Token": token, "Content-Type": "application/json" }
      : {},
    body: token ? "{}" : undefined,
  });
  const data = await response.json();
  if (!response.ok)
    throw new Error("Open the interface using the Python launcher.");
  csrf = data.csrf;
  let runtime;
  try {
    runtime = await api("/runtime");
  } catch {
    throw new Error(
      "This backend is older or unavailable. Stop the existing CloSec launcher and restart from the updated checkout.",
    );
  }
  if (
    !runtime.compatible ||
    runtime.frontend_build_id !== __CLOSEC_BUILD__.frontend_build_id ||
    runtime.transport_version !== __CLOSEC_BUILD__.transport_version
  )
    throw new Error(
      "Frontend/backend revision mismatch. Stop CloSec, rebuild the frontend if needed, and restart the launcher; your workspace is preserved.",
    );
  return runtime;
}
export async function pollJob(
  initial: Row,
  onJob: (job: Row) => void,
): Promise<Row> {
  let job = initial;
  onJob(job);
  while (["QUEUED", "RUNNING"].includes(job.status)) {
    await new Promise((resolve) => setTimeout(resolve, 350));
    job = await api("/jobs/" + job.id);
    onJob(job);
  }
  if (job.status !== "SUCCEEDED")
    throw new Error(
      failure(
        job.explanation || { error: job.error || job.status },
        "Local job failed",
      ),
    );
  return job;
}
export function upload(
  files: File[],
  paths: string[],
  context: Row,
  onProgress: (percent: number) => void,
  onJob: (job: Row) => void = () => {},
  signal?: AbortSignal,
): Promise<any> {
  return (async () => {
    const mode =
      files.length === 1 && files[0].name.endsWith(".zip")
        ? "ZIP"
        : files.some((file) => (file as any).webkitRelativePath)
          ? "FOLDER"
          : "GUIDED_JSON";
    const initial = await api("/uploads/start", {
      provider: context.provider || "UNRESOLVED",
      import_mode: mode,
      files_total: files.length,
    });
    onJob(initial);
    try {
      const submitted: Row = await new Promise((resolve, reject) => {
        const form = new FormData();
        files.forEach((f) => form.append("files", f));
        form.append("paths", JSON.stringify(paths));
        form.append(
          "context",
          JSON.stringify({ ...context, background_validation: true }),
        );
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/uploads");
        xhr.setRequestHeader("X-CSRF-Token", csrf);
        xhr.setRequestHeader("X-Upload-Job", initial.id);
        xhr.timeout = 90000;
        xhr.ontimeout = () =>
          reject(
            new Error(
              "Local transfer timed out. Retry the unchanged package; view job details for the safety limits.",
            ),
          );
        xhr.onabort = () => reject(new Error("Local transfer cancelled."));
        const abort = () => {
          xhr.abort();
          api("/jobs/" + initial.id + "/cancel", {}).catch(() => {});
        };
        signal?.addEventListener("abort", abort, { once: true });
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable)
            onProgress(Math.round((e.loaded / e.total) * 100));
        };
        xhr.onerror = () => reject(new Error("Local upload failed"));
        xhr.onload = () => {
          signal?.removeEventListener("abort", abort);
          try {
            const data = JSON.parse(xhr.responseText);
            xhr.status < 300
              ? resolve(data)
              : reject(new Error(failure(data, "Validation failed")));
          } catch {
            reject(new Error("Invalid local response"));
          }
        };
        xhr.send(form);
      });
      return (await pollJob(submitted, onJob)).result;
    } catch (error) {
      let current = await api("/jobs/" + initial.id).catch(() => null);
      if (current && ["QUEUED", "RUNNING"].includes(current.status))
        current = await api("/jobs/" + initial.id + "/cancel", {}).catch(
          () => current,
        );
      if (current) onJob(current);
      throw error;
    }
  })();
}
export function display(v: any): string {
  return v == null
    ? "Unresolved"
    : typeof v === "object"
      ? JSON.stringify(v)
      : String(v);
}
export function relativePaths(files: File[]): string[] {
  const names = files.map((f) => (f as any).webkitRelativePath || f.name);
  if (names.every((n) => n.includes("/"))) {
    const roots = new Set(names.map((n) => n.split("/")[0]));
    if (roots.size === 1) return names.map((n) => n.slice(n.indexOf("/") + 1));
  }
  return names;
}
