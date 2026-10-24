"""Loopback transport only; reasoning stays in existing services."""

import asyncio
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from offline_analyzer.api.coordinator import Coordinator
from offline_analyzer.api.services import Views
from offline_analyzer.contracts.exclusion import BulkExclusionRequest, ExclusionRequest
from offline_analyzer.contracts.models import Identifier
from offline_analyzer.contracts.r0 import AWS_OPERATIONS, stable_id
from offline_analyzer.contracts.report_finding import ReportApproval, ReportEdit
from offline_analyzer.enterprise.queries import EnterpriseViews
from offline_analyzer.enterprise.snapshot import assess_enterprise
from offline_analyzer.findings import exclusions as exclusion
from offline_analyzer.findings import report_ready
from offline_analyzer.findings.generate import record_decision
from offline_analyzer.ingestion.gcp_legacy import integrity_acknowledgment_required
from offline_analyzer.ingestion.importer import import_package
from offline_analyzer.ingestion.json_input import (
    MAX_PACKAGE_BYTES,
    InputError,
)
from offline_analyzer.ingestion.safety import resolve_under
from offline_analyzer.inventory.environment import (
    check_origin,
    enterprise_origin,
    record_run_origin,
    run_origins,
    workspace_environment,
)
from offline_analyzer.rules.engine import assess

ASSETS = Path(__file__).parent / "assets"
KINDS = {
    "findings",
    "iam_findings",
    "network_findings",
    "evaluations",
    "evidence",
    "resources",
    "coverage",
    "accounts",
    "network",
    "roles",
    "policies",
    "investigations",
    "relationships",
    "gaps",
    "security_investigations",
}


# GET views that only read the database: served on reader connections (last committed
# state), also while a job runs.
READ_ROUTES = re.compile(
    r"/api/runs/[^/]+/(cloud/(dashboard|paths|relationships|scc)|dashboard|records/[a-z]+|"
    r"finding-groups|reconciliation|collection|report-limitations|iam-context|gcp/principals?|"
    r"enterprise/(dashboard|accounts|relationships|graph|investigations|filter-choices))"
)


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ImportBody(Body):
    upload_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    acknowledge_legacy_integrity: bool = False
    # Guided workflow: run the existing assessment on the imported run in the same job.
    analyze: bool = False


def local_analyst() -> str:
    """Who records a decision when no name is typed: the local login name (never asked)."""
    import getpass

    try:
        name = re.sub(r"[^A-Za-z0-9._@ -]", "", getpass.getuser())[:200].strip()
    except (OSError, KeyError):
        name = ""
    return name or "Assessor"


class ReviewBody(Body):
    status: Literal["CONFIRMED", "REJECTED", "NEEDS_VALIDATION"]
    analyst: str = Field(default="", max_length=200)
    note: str = Field(default="", max_length=16000)
    exception: bool = False


class EnterpriseBody(Body):
    members: list[str] | None = Field(default=None, max_length=2048)


class RefreshBody(Body):
    baseline: str = Field(pattern=r"^run-[0-9a-f]{64}$")
    replacements: list[str] = Field(min_length=1, max_length=2048)


class LimitationsBody(Body):
    text: str = Field(max_length=4000)
    analyst: str = Field(min_length=1, max_length=200)


class ReportBody(Body):
    kind: Literal[
        "assessment",
        "excel",
        "findings",
        "accounts",
        "coverage",
        "evidence",
        "approved-rtf",
        "approved-docx",
        "approved-text",
    ]
    selected: list[Identifier] | None = Field(default=None, min_length=1, max_length=200)
    # Assessment report only: which findings by analyst/SRE marking, and one account.
    include: Literal["valid", "confirmed", "all"] = "confirmed"
    # Root-cause grouped Word/Excel findings (default); False renders one entry per finding.
    grouped: bool = True
    provider: Literal["", "AWS", "GCP"] = ""
    scope: str = Field(default="", max_length=200)


class BulkReviewBody(Body):
    status: Literal["CONFIRMED", "REJECTED", "NEEDS_VALIDATION"]
    analyst: str = Field(default="", max_length=200)
    note: str = Field(default="", max_length=16000)
    finding_ids: list[str] = Field(min_length=1, max_length=2000)


def create_app(
    workspace: Path,
    *,
    origin: str,
    bootstrap: str,
    stop: Callable[[], None] | None = None,
    restart: Callable[[], None] | None = None,
    location: dict | None = None,
) -> FastAPI:
    if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", origin):
        raise ValueError("loopback origin required")
    workspace = workspace.resolve()
    coordinator = Coordinator(workspace)
    from offline_analyzer.api.runtime import RuntimeIdentity

    runtime = RuntimeIdentity()
    # Interrupted exports never publish; discard their private partial files at startup.
    if (workspace / "reports").is_dir():
        for stale in (workspace / "reports").glob("*.partial"):
            stale.unlink(missing_ok=True)
    views = Views(workspace)
    enterprise = EnterpriseViews()
    cookie, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    upload_ids: set[str] = set()

    from offline_analyzer.assessment import manage
    from offline_analyzer.contracts.management import (
        FileDelete,
        FileRequest,
        ScopeDelete,
        ScopeReplace,
        ScopeRequest,
    )
    from offline_analyzer.storage.scope_journal import checked_file

    @asynccontextmanager
    async def lifespan(app):
        try:
            await coordinator.call(lambda store: None)
            yield
        finally:
            coordinator.close()

    app = FastAPI(
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        telemetry={
            "tracing": False,
            "metrics": False,
            "logs": False,
            "operation_spans": False,
            "auto_configure": False,
        },
    )
    app.state.coordinator, app.state.views = coordinator, views

    def forget_session_copies(job_ids: list[str], scope: str) -> None:
        """Purged job records and session-only identity diagnostics naming the scope."""
        with coordinator.lock:
            for job_id in job_ids:
                coordinator.jobs.pop(job_id, None)
            for job_id, details in list(coordinator.identity_details.items()):
                if job_id in job_ids or scope in json.dumps(details):
                    del coordinator.identity_details[job_id]

    @app.get("/api/assessment-data/scopes")
    async def assessment_scopes():
        return await coordinator.call(manage.scopes)

    @app.post("/api/assessment-data/delete-preview")
    async def scope_delete_preview(body: ScopeRequest):
        return await coordinator.call(
            lambda store: manage.plan(store, body.provider, body.scope_id)
        )

    @app.post("/api/assessment-data/delete")
    def scope_delete(body: ScopeDelete):
        def execute(store):
            result = manage.delete_scope(
                store,
                body.provider,
                body.scope_id,
                body.preview_token,
                body.confirmation,
                body.confirmed,
                backup=body.backup,
                supersede=body.supersede_frozen,
                supersede_confirmation=body.supersede_confirmation,
                supersede_reason=body.supersede_reason,
            )
            views.iam_cache.clear()
            views.gcp_iam_cache.clear()
            forget_session_copies(result["removed_job_records"], body.scope_id)
            return result

        return coordinator.submit("Delete scope data", execute)

    @app.post("/api/assessment-data/files")
    async def scope_files(body: ScopeRequest):
        return await coordinator.call(
            lambda store: manage.files(store, body.provider, body.scope_id)
        )

    @app.post("/api/assessment-data/file-delete-preview")
    async def file_delete_preview(body: FileRequest):
        return await coordinator.call(lambda store: manage.file_plan(store, body.sha256))

    @app.post("/api/assessment-data/file-delete")
    def file_delete(body: FileDelete):
        def execute(store):
            result = manage.delete_file(
                store,
                body.sha256,
                body.preview_token,
                body.confirmation,
                body.confirmed,
                supersede=body.supersede_frozen,
                supersede_confirmation=body.supersede_confirmation,
                supersede_reason=body.supersede_reason,
            )
            views.iam_cache.clear()
            return result

        return coordinator.submit("Delete imported file", execute)

    @app.post("/api/assessment-data/replace")
    def scope_replace(body: ScopeReplace):
        if body.upload_id not in upload_ids:
            raise InputError("UPLOAD_NOT_FOUND")

        def execute(store):
            root = checked_file(workspace, "uploads/" + body.upload_id)
            if (
                root / "collection_manifest.json"
            ).is_file() and not body.acknowledge_legacy_integrity:
                raise InputError("LEGACY_INTEGRITY_ACKNOWLEDGMENT_REQUIRED")
            origin_label = (workspace / "uploads" / f"{body.upload_id}.origin").read_text()
            result = manage.replace_scope(
                store, body.provider, body.scope_id, root, origin_label, upload_id=body.upload_id
            )
            views.iam_cache.clear()
            return result

        return coordinator.submit("Replace scope data", execute)

    from offline_analyzer.api.coordinator import READ_ONLY
    from offline_analyzer.api.run_cache import RunCache

    cache = RunCache()
    app.state.run_cache = cache

    @app.middleware("http")
    async def read_routes(request: Request, call_next):
        # Pure read views use reader connections: never queued behind jobs or writes.
        token = READ_ONLY.set(
            request.method == "GET" and bool(READ_ROUTES.fullmatch(request.url.path))
        )
        try:
            return await call_next(request)
        finally:
            READ_ONLY.reset(token)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = request.headers.get("host", "")
        remote_origin = request.headers.get("origin")
        if (
            host != origin.removeprefix("http://")
            or (remote_origin is not None and remote_origin != origin)
            or request.headers.get("sec-fetch-site") == "cross-site"
        ):
            return JSONResponse({"error": "LOCAL_ACCESS_ONLY"}, status_code=403)
        path = request.url.path
        mutating = request.method not in {"GET", "HEAD"}
        if mutating:
            size = request.headers.get("content-length", "")
            bound = MAX_PACKAGE_BYTES + 2 * 1024 * 1024 if path == "/api/uploads" else 65536
            if not size.isdigit() or int(size) > bound:
                return JSONResponse({"error": "REQUEST_SIZE_LIMIT"}, status_code=413)
            if remote_origin != origin:
                return JSONResponse({"error": "ORIGIN_REQUIRED"}, status_code=403)
        if path.startswith("/api/") and path not in {"/api/session", "/api/health"}:
            if not hmac.compare_digest(request.cookies.get("assessment_session", ""), cookie):
                return JSONResponse({"error": "SESSION_REQUIRED"}, status_code=401)
            if mutating and not hmac.compare_digest(request.headers.get("x-csrf-token", ""), csrf):
                return JSONResponse({"error": "CSRF_REQUIRED"}, status_code=403)
        if (
            mutating
            and path not in {"/api/session", "/api/shutdown"}
            and runtime.status()["source_changed_since_startup"]
        ):
            from offline_analyzer.ingestion.errors import explanation

            return JSONResponse(explanation("APPLICATION_REVISION_CHANGED"), status_code=409)
        transfer_job = request.headers.get("x-upload-job") if path == "/api/uploads" else None
        if transfer_job:
            from starlette.formparsers import MultiPartException

            try:
                if coordinator.status(transfer_job)["kind"] != "Package validation":
                    raise InputError("UPLOAD_JOB_NOT_PENDING")
            except InputError:
                return JSONResponse({"error": "UPLOAD_JOB_NOT_PENDING"}, status_code=400)
            receive = request._receive
            received = 0

            async def bounded_receive():
                nonlocal received
                try:
                    message = await asyncio.wait_for(receive(), timeout=30)
                except TimeoutError:
                    coordinator.transfer_failed(transfer_job, "TRANSFER_IDLE_TIMEOUT")
                    raise MultiPartException("TRANSFER_IDLE_TIMEOUT") from None
                if message["type"] == "http.disconnect":
                    coordinator.transfer_failed(transfer_job, "UPLOAD_TRANSFER_INTERRUPTED")
                    raise MultiPartException("UPLOAD_TRANSFER_INTERRUPTED")
                if message["type"] == "http.request":
                    received += len(message.get("body", b""))
                    if received > MAX_PACKAGE_BYTES + 2 * 1024 * 1024:
                        coordinator.transfer_failed(transfer_job, "REQUEST_SIZE_LIMIT")
                        raise MultiPartException("REQUEST_SIZE_LIMIT")
                    try:
                        coordinator.transfer_progress(
                            transfer_job, received, int(request.headers["content-length"])
                        )
                    except InputError as exc:
                        coordinator.transfer_failed(transfer_job, str(exc))
                        raise MultiPartException(str(exc)) from None
                return message

            request._receive = bounded_receive
        try:
            response = await call_next(request)
        except InputError as exc:
            if transfer_job:
                coordinator.transfer_failed(transfer_job, str(exc))
            response = JSONResponse({"error": str(exc)}, status_code=400)
        except Exception:
            if transfer_job:
                coordinator.transfer_failed(transfer_job, "UPLOAD_TRANSFER_INTERRUPTED")
            response = JSONResponse({"error": "OPERATION_FAILED"}, status_code=500)
        if (
            transfer_job
            and response.status_code >= 400
            and coordinator.status(transfer_job)["status"] in {"QUEUED", "RUNNING"}
            and transfer_job not in coordinator.futures
        ):
            coordinator.transfer_failed(transfer_job, "MULTIPART_REJECTED")
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                "frame-ancestors 'none'; "
                "object-src 'none'; base-uri 'none'; form-action 'self'",
            }
        )
        return response

    @app.exception_handler(InputError)
    async def input_error(request, exc):
        code = str(exc)
        from offline_analyzer.ingestion.errors import explanation

        data = explanation(code if re.fullmatch(r"[A-Z_]{1,80}", code) else "INVALID_INPUT")
        if exc.limit:
            data["limit"] = exc.limit
        if exc.identity_context:
            data["identity_context"] = exc.identity_context
        return JSONResponse(data, status_code=400)

    @app.exception_handler(RequestValidationError)
    async def invalid_body(request, exc):
        return JSONResponse({"error": "INVALID_REQUEST"}, status_code=422)

    @app.get("/api/health")
    def health():
        return {"ready": True}

    @app.get("/api/runtime")
    def runtime_status():
        return runtime.status()

    @app.get("/api/jobs/{job_id}/diagnostic")
    def diagnostic(job_id: str):
        from offline_analyzer.api.diagnostics import job_diagnostic

        data = job_diagnostic(runtime, coordinator.status(job_id))
        return JSONResponse(
            data,
            headers={
                "Content-Disposition": f'attachment; filename="CloSec-diagnostic-{job_id}.json"'
            },
        )

    @app.api_route("/api/session", methods=["GET", "POST"])
    def session(request: Request):
        authenticated = hmac.compare_digest(request.cookies.get("assessment_session", ""), cookie)
        if not authenticated and not (
            request.method == "POST"
            and hmac.compare_digest(request.headers.get("x-bootstrap-token", ""), bootstrap)
        ):
            return JSONResponse({"error": "OPEN_FROM_LAUNCHER"}, status_code=401)
        response = JSONResponse({"csrf": csrf, "offline": True})
        response.set_cookie(
            "assessment_session", cookie, httponly=True, samesite="strict", path="/"
        )
        return response

    @app.get("/api/environment")
    def environment():
        current = workspace_environment(workspace)
        return {
            # Opaque local browser preference scope; never expose the workspace path.
            "workspace_id": hashlib.sha256(str(workspace).encode()).hexdigest(),
            "label": current.label if current else "UNLABELED",
            "name": current.name if current else "",
            "customer_reporting_approved": bool(current and current.label == "ASSESSMENT"),
        }

    def compatibility_report(result: dict, origin_label: str) -> str:
        """Persist the sanitized verifier summary (no values, names or paths)."""
        from offline_analyzer.api.diagnostics import compatibility_diagnostic

        result = compatibility_diagnostic(result)
        report_id = secrets.token_hex(16)
        directory = resolve_under(workspace, "reports")
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / (report_id + ".json")
        with path.open("x", encoding="utf-8") as output:
            json.dump(result, output, indent=2)
        metadata = {
            "id": report_id,
            "run_id": None,
            "kind": "compatibility",
            "name": f"CloSec-compatibility-{origin_label}.json",
            "bytes": path.stat().st_size,
        }
        (directory / (report_id + ".meta")).write_text(json.dumps(metadata))
        return report_id

    @app.get("/api/profiles")
    def profiles():
        from offline_analyzer.normalization.gcp import PROFILES

        return {
            "formats": ["aws-json-v1", "prowler-ocsf-5.10", "prowler-ocsf-5.26.1"],
            "operations": list(AWS_OPERATIONS),
            "gcp_operations": list(PROFILES),
            "real_export_compatibility": "UNVERIFIED",
        }

    @app.get("/api/runs")
    async def runs():
        items = await coordinator.call(views.runs)
        origins = run_origins(workspace)
        return [{**item, "origin": origins.get(item["run_id"], "unrecorded")} for item in items]

    @app.get("/api/runs/{run}/collection")
    async def collection(run: str):
        return await coordinator.call(lambda store: views.collection(store, run))

    @app.get("/api/runs/{run}/evidence-requests.csv")
    async def evidence_requests(run: str):
        text = await coordinator.call(lambda store: views.evidence_requests_csv(store, run))
        return Response(
            text,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="CloSec-evidence-requests.csv"'},
        )

    @app.get("/api/runs/{run}/evidence-requests.json")
    async def evidence_requests_json(run: str):
        result = await coordinator.call(lambda store: views.collection(store, run))
        return JSONResponse(
            {
                "schema": "closec-evidence-request-1",
                "run_id": run,
                "requests": result["evidence_requests"],
                "manual_validation": result["manual_validation"],
                "execution": "OFFLINE_REQUEST_ONLY_COLLECTOR_ENFORCES_APPROVED_SCOPE",
            },
            headers={"Content-Disposition": 'attachment; filename="CloSec-evidence-requests.json"'},
        )

    @app.post("/api/enterprise/assess")
    def enterprise_assessment(body: EnterpriseBody):
        def execute(store):
            origin_label = enterprise_origin(store, body.members)
            run = assess_enterprise(store, body.members)
            record_run_origin(workspace, run, origin_label)
            return {"run_id": run}

        return coordinator.submit(
            "Enterprise assessment",
            execute,
            cancellable=True,
            key="enterprise:" + ",".join(sorted(body.members or [])),
            context={"provider": "Consolidated"},
        )

    @app.post("/api/enterprise/refresh-preview")
    async def refresh_preview(body: RefreshBody):
        from offline_analyzer.enterprise.refresh import refresh_plan

        return await coordinator.call(
            lambda store: refresh_plan(store, body.baseline, body.replacements)
        )

    @app.post("/api/enterprise/refresh")
    def refresh(body: RefreshBody):
        from offline_analyzer.enterprise.refresh import refresh_enterprise

        return coordinator.submit(
            "Enterprise refresh",
            lambda store: refresh_enterprise(store, body.baseline, body.replacements),
            key="refresh:" + body.baseline + ":" + ",".join(sorted(body.replacements)),
            cancellable=True,
            context={"provider": "Consolidated"},
        )

    @app.get("/api/runs/{run}/enterprise/dashboard")
    async def enterprise_dashboard(run: str):
        return await coordinator.call(lambda store: enterprise.dashboard(store, run))

    @app.get("/api/runs/{run}/enterprise/accounts")
    async def enterprise_accounts(
        run: str,
        q: str = "",
        group: str = "",
        region: str = "",
        severity: str = "",
        coverage: str = "",
        offset: int = 0,
        limit: int = 50,
    ):
        if not 0 <= offset <= 1000000 or not 1 <= limit <= 100 or len(q) > 200:
            raise InputError("INVALID_PAGE")

        def execute(store):
            items = [
                a
                for a in enterprise.accounts(store, run)
                if (not q or q.lower() in (a["account"] + " " + (a["alias"] or "")).lower())
                and (not group or group in a["groups"])
                and (not region or region in a["regions"])
                and (not severity or a["severity"].get(severity))
                and (not coverage or coverage in a["coverage"])
            ]
            return {
                "items": items[offset : offset + limit],
                "total": len(items),
                "offset": offset,
                "limit": limit,
            }

        return await coordinator.call(execute)

    @app.get("/api/runs/{run}/enterprise/relationships")
    async def enterprise_relationships(
        run: str,
        source: str = "",
        destination: str = "",
        account: str = "",
        kind: str = "",
        domain: str = "",
        status: str = "",
        q: str = "",
        group: str = "",
        outside: bool = False,
        missing_only: bool = False,
        privileged: bool = False,
        offset: int = 0,
        limit: int = 50,
    ):
        return await coordinator.call(
            lambda store: enterprise.relationships(
                store,
                run,
                source=source,
                destination=destination,
                account=account,
                kind=kind,
                domain=domain,
                status=status,
                q=q,
                group=group,
                outside=outside,
                missing_only=missing_only,
                privileged=privileged,
                offset=offset,
                limit=limit,
            )
        )

    @app.get("/api/runs/{run}/enterprise/graph")
    async def enterprise_graph(
        run: str,
        source: str = "",
        destination: str = "",
        account: str = "",
        kind: str = "",
        domain: str = "",
        status: str = "",
        q: str = "",
        group: str = "",
        outside: bool = False,
        missing_only: bool = False,
        privileged: bool = False,
        node_limit: int = 80,
        edge_limit: int = 150,
        depth: int = 2,
        focus: str = "",
    ):
        return await coordinator.call(
            lambda store: enterprise.graph(
                store,
                run,
                source=source,
                destination=destination,
                account=account,
                kind=kind,
                domain=domain,
                status=status,
                q=q,
                group=group,
                outside=outside,
                missing_only=missing_only,
                privileged=privileged,
                node_limit=node_limit,
                edge_limit=edge_limit,
                depth=depth,
                focus=focus,
            )
        )

    @app.get("/api/runs/{run}/enterprise/investigations")
    async def enterprise_issues(run: str, offset: int = 0, limit: int = 50):
        return await coordinator.call(lambda store: enterprise.issues(store, run, offset, limit))

    @app.post("/api/runs/{run}/enterprise/review/{issue}")
    async def enterprise_review(run: str, issue: str, body: ReviewBody):
        note = ("EXCEPTION RECORDED — requires validation: " if body.exception else "") + body.note
        status = "NEEDS_VALIDATION" if body.exception else body.status
        decision = await coordinator.call(
            lambda store: enterprise.review(store, run, issue, status, body.analyst, note)
        )
        return {"decision_id": decision}

    @app.get("/api/collectors")
    def collector_listing():
        from offline_analyzer.api.collectors import listing

        return listing()

    @app.get("/api/collectors/{key}/download")
    def collector_download(key: str):
        from offline_analyzer.api.collectors import download

        name, media, data = download(key)
        return Response(
            data,
            media_type=media,
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )

    @app.get("/api/gcp/contract")
    def gcp_contract():
        from offline_analyzer.ingestion.gcp import contract

        return contract()

    @app.get("/api/methodology/cloud")
    def cloud_methodology():
        from offline_analyzer.reporting.cloud import methodology_matrix

        return methodology_matrix()

    @app.get("/api/runs/{run}/checklist")
    async def checklist(run: str):
        """Assessment checklist (both clouds) with per-provider control outcomes."""
        from offline_analyzer.methodology.cloud_checklist import matrix

        def execute(store):
            store.require_run(run)
            formats = {s.get("format") for s in store.source_data(run)}
            assessed = {"GCP" if f == "gcp-json-v1" else "AWS" for f in formats if f}
            rows = matrix(store.results(run), assessed=assessed)
            findings: dict[str, dict] = {}
            from offline_analyzer.findings.exclusions import excluded

            hidden = excluded(store, run)
            for finding in store.candidates(run):
                if finding.methodology_id and finding.finding_id not in hidden:
                    entry = findings.setdefault(finding.methodology_id, {"AWS": 0, "GCP": 0})
                    entry[finding.provider] += 1
            for row in rows:
                row["findings"] = findings.get(row["control_id"], {"AWS": 0, "GCP": 0})
            return {"items": rows, "providers": sorted(assessed)}

        return await coordinator.call(execute)

    @app.get("/api/runs/{run}/cloud/dashboard")
    async def cloud_dashboard(run: str, provider: str = "Consolidated", part: str = "full"):
        if provider not in {"AWS", "GCP", "Consolidated"}:
            raise InputError("INVALID_PROVIDER")
        from offline_analyzer.reporting.cloud import dashboard

        if part not in {"full", "summary", "panels"}:
            raise InputError("INVALID_PAGE")

        def execute(store):
            store.require_run(run)
            running = coordinator.running_job()
            view = cache.get(
                store,
                run,
                f"dashboard:{provider}:{part}",
                lambda: dashboard(store, run, provider, part),
                coordinator.generation(),
                job_running=running is not None,
            )
            # Reads come from the last completed state; say so while a job is running.
            return {**view, "running_job": running}

        return await coordinator.call(execute)

    @app.get("/api/runs/{run}/cloud/relationships")
    async def cloud_relationships(run: str, project: str = "", limit: int = 200):
        if not 1 <= limit <= 500 or len(project) > 100:
            raise InputError("INVALID_PAGE")
        from offline_analyzer.inventory.cloud import relationships

        return await coordinator.call(lambda store: relationships(store, run, project, limit))

    @app.get("/api/runs/{run}/cloud/scc")
    async def cloud_scc(run: str, offset: int = 0, limit: int = 50):
        if not 0 <= offset <= 100000 or not 1 <= limit <= 100:
            raise InputError("INVALID_PAGE")
        from offline_analyzer.correlation.gcp import scc_correlations

        def execute(store):
            rows = scc_correlations(store, run)
            return {"items": rows[offset : offset + limit], "total": len(rows)}

        return await coordinator.call(execute)

    @app.get("/api/runs/{run}/cloud/paths")
    async def cloud_paths(run: str, project: str = "", limit: int = 100):
        if not 1 <= limit <= 100 or len(project) > 100:
            raise InputError("INVALID_PAGE")
        from offline_analyzer.attack_paths.diagram import diagram
        from offline_analyzer.attack_paths.feasibility import attack_paths

        def execute(store):
            def compute():
                result = attack_paths(store, run, project)
                for path in result["items"]:
                    path["diagram"] = diagram(path)
                return result

            store.require_run(run)
            return cache.get(
                store,
                run,
                f"paths:{project}",
                compute,
                coordinator.generation(),
                job_running=coordinator.running_job() is not None,
            )

        return await coordinator.call(execute)

    @app.get("/api/runs/{run}/cloud/requests")
    async def cloud_requests(run: str):
        from offline_analyzer.reporting.cloud import collection_requests

        return await coordinator.call(lambda store: collection_requests(store, run))

    class PathReviewBody(Body):
        status: Literal["CONFIRMED", "REJECTED"]

    @app.post("/api/runs/{run}/path-review/{path_id}")
    async def path_review(run: str, path_id: str, body: PathReviewBody):
        from offline_analyzer.attack_paths.review import record

        return await coordinator.call(
            lambda store: record(store, run, path_id, body.status, local_analyst())
        )

    @app.get("/api/runs/{run}/enterprise/filter-choices")
    async def enterprise_filter_choices(run: str):
        from offline_analyzer.api.facets import choices

        def execute(store):
            accounts = enterprise.accounts(store, run)
            edges = [
                json.loads(raw)
                for (raw,) in store.rows("SELECT data FROM enterprise_edges WHERE run_id=?", [run])
            ]
            result = choices([*accounts, *edges])
            return result

        return await coordinator.call(execute)

    @app.get("/api/runs/{run}/reconciliation")
    async def run_reconciliation(run: str):
        return await coordinator.call(lambda store: views.reconciliation(store, run))

    @app.get("/api/runs/{run}/dashboard")
    async def dashboard(run: str):
        return await coordinator.call(lambda store: views.dashboard(store, run))

    @app.get("/api/runs/{run}/iam-context")
    async def iam_context(run: str):
        return await coordinator.call(lambda store: views.iam(store, run)["organization"])

    @app.get("/api/runs/{run}/gcp/principals")
    async def gcp_principals(run: str, q: str = "", offset: int = 0, limit: int = 50):
        from offline_analyzer.iam.gcp_principals import directory

        if not 0 <= offset <= 1000000 or not 1 <= limit <= 100 or len(q) > 320:
            raise InputError("INVALID_PAGE")
        return await coordinator.call(
            lambda store: (store.require_run(run), directory(store, run, q, offset, limit))[1]
        )

    @app.get("/api/runs/{run}/gcp/principal")
    async def gcp_principal(run: str, principal: str):
        from offline_analyzer.iam.gcp_principals import lookup

        return await coordinator.call(
            lambda store: (store.require_run(run), lookup(store, run, principal))[1]
        )

    @app.get("/api/runs/{run}/security-coverage")
    async def security_coverage(run: str):
        from offline_analyzer.reporting.capabilities import coverage

        return await coordinator.call(lambda store: coverage(store, run))

    @app.get("/api/runs/{run}/report-findings")
    async def report_findings(run: str):
        return await coordinator.call(lambda store: report_ready.register(store, run))

    @app.get("/api/runs/{run}/report-findings/{finding}")
    async def report_finding(run: str, finding: str):
        return await coordinator.call(lambda store: report_ready.report_detail(store, run, finding))

    @app.post("/api/runs/{run}/report-findings/{finding}")
    async def report_edit(run: str, finding: str, body: ReportEdit):
        return await coordinator.call(
            lambda store: report_ready.save_revision(store, run, finding, body)
        )

    @app.post("/api/runs/{run}/report-findings/{finding}/approve")
    async def report_approve(run: str, finding: str, body: ReportApproval):
        return await coordinator.call(
            lambda store: report_ready.approve_revision(store, run, finding, body)
        )

    @app.get("/api/runs/{run}/finding-groups")
    async def finding_groups(run: str):
        from offline_analyzer.findings.groups import groups

        return await coordinator.call(
            lambda store: (store.require_run(run), {"items": groups(store, run)})[1]
        )

    @app.get("/api/runs/{run}/report-limitations")
    async def report_limitations(run: str):
        from offline_analyzer.reporting.limitations import latest

        return await coordinator.call(
            lambda store: (store.require_run(run), {"text": latest(store, run)})[1]
        )

    @app.post("/api/runs/{run}/report-limitations")
    async def report_limitations_save(run: str, body: LimitationsBody):
        from offline_analyzer.reporting.limitations import save

        return await coordinator.call(lambda store: save(store, run, body.text, body.analyst))

    @app.get("/api/runs/{run}/exclusions")
    async def exclusions(run: str, provider: str = ""):
        if provider not in {"", "AWS", "GCP"}:
            raise InputError("INVALID_PROVIDER")
        return await coordinator.call(lambda store: exclusion.listing(store, run, provider))

    @app.post("/api/runs/{run}/exclusions")
    async def exclusion_bulk(run: str, body: BulkExclusionRequest):
        result = await coordinator.call(lambda store: exclusion.record_many(store, run, body))
        return {"recorded": len(result)}

    @app.post("/api/runs/{run}/exclusions/{finding}")
    async def exclusion_record(run: str, finding: str, body: ExclusionRequest):
        result = await coordinator.call(lambda store: exclusion.record(store, run, finding, body))
        return result.model_dump(mode="json")

    @app.get("/api/runs/{run}/report-findings/{finding}/copy")
    async def report_copy(run: str, finding: str):
        def execute(store):
            revisions = report_ready.approved_revisions(store, run, [finding])
            report_ready.verify_snapshots(store, revisions)
            return {"text": revisions[0].report_text, "revision": revisions[0].revision}

        return await coordinator.call(execute)

    @app.get("/api/runs/{run}/records/{kind}")
    async def records(
        run: str,
        kind: str,
        q: str = "",
        account: str = "",
        value: str = "",
        offset: int = 0,
        limit: int = 50,
        provider: str = "",
        project: str = "",
        project_number: str = "",
        organization: str = "",
        folder: str = "",
        region: str = "",
        service: str = "",
        finding_class: str = "",
        domain: str = "",
        confidence: str = "",
        validation: str = "",
        resource: str = "",
        priority: bool = False,
        dataset: str = "",
        collection_domain: str = "",
        collection_status: str = "",
        support: str = "",
        control: str = "",
        stage: str = "",
        false_positive: str = "",
    ):
        if kind not in KINDS or not 0 <= offset <= 1000000 or not 1 <= limit <= 100 or len(q) > 200:
            raise InputError("INVALID_PAGE")
        return await coordinator.call(
            lambda store: views.records(
                store,
                run,
                kind,
                q,
                account,
                value,
                offset,
                limit,
                {
                    "provider": provider,
                    "project_id": project,
                    "project_number": project_number,
                    "organization_id": organization,
                    "folder_id": folder,
                    "region": region,
                    "service": service,
                    "finding_class": finding_class,
                    "security_domain": domain,
                    "evidence_confidence": confidence,
                    "validation": validation,
                    "resource": resource,
                    "priority": priority,
                    "dataset": dataset,
                    "collection_domain": collection_domain,
                    "collection_status": collection_status,
                    "support": support,
                    "methodology_id": control,
                    "stage": stage,
                    "false_positive": false_positive,
                },
            )
        )

    @app.get("/api/runs/{run}/finding-facets")
    async def finding_facets(run: str, provider: str = ""):
        if provider not in {"", "AWS", "GCP"}:
            raise InputError("INVALID_PROVIDER")
        return await coordinator.call(lambda store: views.finding_facets(store, run, provider))

    @app.get("/api/workspace/scope-summary")
    async def scope_summary():
        from offline_analyzer.reporting.cloud import workspace_scope_summary

        return await coordinator.call(workspace_scope_summary)

    @app.get("/api/runs/{run}/record-facets/{kind}")
    async def record_facets(run: str, kind: str, provider: str = ""):
        from offline_analyzer.api.facets import facets

        if kind not in KINDS or provider not in {"", "AWS", "GCP"}:
            raise InputError("INVALID_FILTER_SCOPE")
        return await coordinator.call(lambda store: facets(views, store, run, kind, provider))

    @app.get("/api/runs/{run}/finding-quality")
    async def finding_quality(run: str):
        from offline_analyzer.findings.quality import run_quality

        return await coordinator.call(
            lambda store: {k: v for k, v in run_quality(store, run).items() if k != "items"}
        )

    @app.get("/api/runs/{run}/evidence/{oid}")
    async def evidence(run: str, oid: str):
        return await coordinator.call(lambda store: views.evidence_detail(store, run, oid))

    @app.get("/api/identity")
    async def identity():
        return {"analyst": local_analyst()}

    @app.get("/api/runs/{run}/findings/{finding}/detail")
    async def finding_detail(run: str, finding: str):
        from offline_analyzer.findings.detail import finding_detail as build
        from offline_analyzer.findings.finalisation import frozen
        from offline_analyzer.findings.quality import run_quality

        def execute(store):
            detail = build(store, run, finding)
            detail["quality"] = run_quality(store, run)["items"].get(finding)
            detail["frozen"] = frozen(store, run) is not None
            return detail

        return await coordinator.call(execute)

    @app.post("/api/runs/{run}/review-bulk")
    async def review_bulk(run: str, body: BulkReviewBody):
        from offline_analyzer.findings.generate import record_decisions

        recorded = await coordinator.call(
            lambda store: record_decisions(
                store,
                run,
                body.finding_ids,
                body.status,
                body.analyst.strip() or local_analyst(),
                body.note,
            )
        )
        views.iam_cache.pop(run, None)
        views.gcp_iam_cache.pop(run, None)
        return {"recorded": len(recorded)}

    @app.post("/api/runs/{run}/review/{finding}")
    async def review(run: str, finding: str, body: ReviewBody):
        note = ("EXCEPTION RECORDED — requires validation: " if body.exception else "") + body.note
        status = "NEEDS_VALIDATION" if body.exception else body.status
        analyst = body.analyst.strip() or local_analyst()
        decision = await coordinator.call(
            lambda store: record_decision(store, run, finding, status, analyst, note)
        )
        views.iam_cache.pop(run, None)
        views.gcp_iam_cache.pop(run, None)
        return {"decision_id": decision}

    class SreBody(Body):
        verdict: Literal["SENT_TO_SRE", "GAP_CONFIRMED", "NO_GAP_BAU", "NEEDS_INFO"]
        analyst: str = Field(default="", max_length=200)
        sre_contact: str = Field(default="", max_length=200)
        reason: str = Field(default="", max_length=16000)
        finding_ids: list[str] = Field(default_factory=list, max_length=2000)
        # Alternatively every finding of one account/project still open for SRE.
        provider: Literal["", "AWS", "GCP"] = ""
        scope: str = Field(default="", max_length=200)

    @app.post("/api/runs/{run}/sre")
    async def sre_verdict(run: str, body: SreBody):
        from offline_analyzer.findings.sre import record_sre
        from offline_analyzer.reporting.sre_reports import OPEN_FOR_SRE, rows

        def execute(store):
            ids = body.finding_ids
            if not ids and body.provider and body.scope:
                ids = [
                    r["id"]
                    for r in rows(store, run, body.provider)
                    if r["scope"] == body.scope and r["stage"] in OPEN_FOR_SRE
                ]
            return record_sre(
                store,
                run,
                ids,
                body.verdict,
                body.analyst.strip() or local_analyst(),
                body.sre_contact,
                body.reason,
            )

        recorded = await coordinator.call(execute)
        views.iam_cache.pop(run, None)
        views.gcp_iam_cache.pop(run, None)
        return {"recorded": len(recorded)}

    def attachment(data: bytes, name: str, media: str) -> Response:
        return Response(
            data,
            media_type=media,
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )

    XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    @app.get("/api/runs/{run}/sre-workbook.xlsx")
    async def sre_workbook(run: str, provider: str, scope: str):
        from offline_analyzer.reporting.sre_reports import sre_workbook as build

        name, data = await coordinator.call(lambda store: build(store, run, provider, scope))
        return attachment(data, name, XLSX)

    @app.get("/api/runs/{run}/sre-workbooks.zip")
    async def sre_workbooks(run: str, provider: str = ""):
        from offline_analyzer.reporting.sre_reports import sre_workbooks_zip

        if provider not in {"", "AWS", "GCP"}:
            raise InputError("INVALID_PROVIDER")
        data = await coordinator.call(lambda store: sre_workbooks_zip(store, run, provider))
        return attachment(data, "CloSec-SRE-workbooks.zip", "application/zip")

    @app.get("/api/runs/{run}/finalized")
    async def finalized(run: str, provider: str = "", scope: str = ""):
        from offline_analyzer.reporting.sre_reports import finalized as build

        if provider not in {"", "AWS", "GCP"} or len(scope) > 200:
            raise InputError("INVALID_PROVIDER")
        return await coordinator.call(lambda store: build(store, run, provider, scope))

    class FreezeBody(Body):
        confirmed: bool = False

    @app.post("/api/runs/{run}/finalize")
    async def freeze_assessment(run: str, body: FreezeBody):
        from offline_analyzer.findings.finalisation import freeze

        record = await coordinator.call(
            lambda store: freeze(store, run, local_analyst(), body.confirmed)
        )
        return {"frozen": True, "frozen_at": record["created_at"], "run_id": run}

    @app.get("/api/runs/{run}/finalized.{kind}")
    async def finalized_export(run: str, kind: str, provider: str = "", scope: str = ""):
        from offline_analyzer.reporting import sre_reports

        if (
            provider not in {"", "AWS", "GCP"}
            or kind not in {"xlsx", "rtf", "docx"}
            or len(scope) > 200
        ):
            raise InputError("INVALID_EXPORT")
        data = await coordinator.call(
            lambda store: sre_reports.finalized_document(store, run, provider, scope)
        )
        content = sre_reports.finalized_files(data, kind)
        label = re.sub(r"[^A-Za-z0-9_.-]+", "_", scope)[:60] if scope else "all"
        name = f"CloSec-confirmed-vulnerabilities-{label}.{kind}"
        return attachment(
            content,
            name,
            XLSX
            if kind == "xlsx"
            else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            if kind == "docx"
            else "application/rtf",
        )

    from offline_analyzer.api.uploads import Uploads

    uploads = Uploads(workspace, coordinator, upload_ids, compatibility_report)

    class UploadStart(Body):
        provider: Literal["AWS", "GCP", "UNRESOLVED"]
        import_mode: Literal["ZIP", "FOLDER", "GUIDED_JSON"]
        files_total: int = Field(ge=1, le=20000)

    @app.post("/api/uploads/start")
    def start_upload(body: UploadStart):
        return uploads.start(body.provider, body.import_mode, body.files_total)

    @app.post("/api/uploads")
    async def upload(
        request: Request,
    ):
        from starlette.datastructures import UploadFile as FormFile

        async with request.form(
            max_files=20000, max_fields=2, max_part_size=4 * 1024 * 1024
        ) as form:
            files = form.getlist("files")
            paths, context = form.get("paths"), form.get("context", "{}")
            if (
                not files
                or not all(isinstance(file, FormFile) for file in files)
                or not isinstance(paths, str)
                or not isinstance(context, str)
            ):
                return JSONResponse({"error": "INVALID_REQUEST"}, status_code=422)
            return await uploads.receive(
                files, paths, context, job_id=request.headers.get("x-upload-job")
            )

    @app.get("/api/workflow")
    async def workflow():
        """Guided-workflow state: validated packages awaiting import, and run readiness."""
        imported = await coordinator.call(views.imported_uploads)
        active = {
            j["key"].split(":", 1)[1]
            for j in coordinator.history()
            if j["status"] in {"QUEUED", "RUNNING"} and (j.get("key") or "").startswith("import:")
        }
        pending = []
        for job in coordinator.history():
            if (
                job["kind"] == "Package validation"
                and job["status"] == "SUCCEEDED"
                and job["id"] in upload_ids
                and job["id"] not in imported
            ):
                pending.append(
                    {
                        "upload_id": job["id"],
                        "provider": job["provider"],
                        "scopes": job["scopes"],
                        "manifest_version": job["manifest_version"],
                        "import_mode": job["import_mode"],
                        "validated_at": job["finished_at"],
                        "importing": job["id"] in active,
                        "legacy_acknowledgment_required": integrity_acknowledgment_required(
                            workspace / "uploads" / job["id"]
                        ),
                    }
                )
        return {"pending_imports": pending}

    @app.get("/api/jobs")
    def job_history():
        return coordinator.history()

    @app.post("/api/import")
    def import_upload(body: ImportBody):
        if body.upload_id not in upload_ids:
            raise InputError("UPLOAD_NOT_FOUND")
        root = workspace / "uploads" / body.upload_id
        if integrity_acknowledgment_required(root) and not body.acknowledge_legacy_integrity:
            raise InputError("LEGACY_INTEGRITY_ACKNOWLEDGMENT_REQUIRED")

        def execute(store):
            # Validation is repeated by importer; no trusted cached raw bytes.
            origin_label = (workspace / "uploads" / f"{body.upload_id}.origin").read_text()
            check_origin(workspace, origin_label)
            run = import_package(store, root)
            record_run_origin(workspace, run, origin_label)
            store.db.execute(
                "INSERT INTO scope_uploads VALUES (?,?) ON CONFLICT DO NOTHING",
                [run, body.upload_id],
            )
            views.iam_cache.pop(run, None)
            views.gcp_iam_cache.pop(run, None)
            if body.analyze:
                # The import transaction is committed; a failed analysis leaves an
                # imported, not-yet-assessed run that the workflow offers to analyze.
                assess(store, run)
                views.iam_cache.pop(run, None)
            return {"run_id": run, "analyzed": body.analyze}

        return coordinator.submit(
            "Import and analysis" if body.analyze else "Import",
            execute,
            key=f"import:{body.upload_id}",
            context={
                key: coordinator.jobs.get(body.upload_id, {}).get(key, default)
                for key, default in (
                    ("provider", "UNRESOLVED"),
                    ("import_mode", "NONE"),
                    ("scopes", []),
                    ("manifest_version", None),
                    ("collection_id", None),
                )
            },
            cancellable=True,
        )

    @app.post("/api/runs/{run}/assess")
    def assessment(run: str):
        def execute(store):
            sources = list(store.source_data(run))
            providers = {
                "GCP" if source["format"] == "gcp-json-v1" else "AWS" for source in sources
            }
            if coordinator.running and providers:
                coordinator.describe(
                    coordinator.running,
                    provider=next(iter(providers)) if len(providers) == 1 else "Consolidated",
                    scopes=sorted(
                        {
                            source.get("project_id") or source.get("account_id")
                            for source in sources
                            if source.get("project_id") or source.get("account_id")
                        }
                    ),
                )
            assess(store, run)
            views.iam_cache.pop(run, None)
            return {"run_id": run}

        return coordinator.submit("Assessment", execute, key=f"assess:{run}", cancellable=True)

    @app.get("/api/jobs/{job}")
    def job_status(job: str):
        return coordinator.status(job)

    @app.post("/api/jobs/{job}/cancel")
    def cancel(job: str):
        return coordinator.cancel(job)

    @app.post("/api/runs/{run}/reports")
    def report(run: str, body: ReportBody):
        if body.selected is not None and not body.kind.startswith("approved-"):
            raise InputError("SELECTED_SCOPE_ONLY_FOR_APPROVED_REPORTS")
        if body.kind != "assessment" and (body.include != "confirmed" or body.scope):
            raise InputError("REPORT_OPTIONS_ONLY_FOR_ASSESSMENT_REPORT")
        if body.scope and not body.provider:
            raise InputError("INVALID_REPORT_SCOPE")
        if body.provider and body.kind != "assessment":
            raise InputError("REPORT_OPTIONS_ONLY_FOR_ASSESSMENT_REPORT")
        options = {
            "include": body.include,
            "provider": body.provider,
            "scope": body.scope,
            "grouped": body.grouped,
        }
        scope = stable_id(
            "report-scope",
            [sorted(set(body.selected)) if body.selected else None, options],
        )
        return coordinator.submit(
            "Report",
            lambda store: views.export(
                store,
                run,
                body.kind,
                progress=coordinator.progress,
                selected=body.selected,
                options=options,
            ),
            key=f"report:{run}:{body.kind}:{scope}",
            cancellable=True,
        )

    @app.get("/api/reports")
    async def reports():
        def execute(store):
            result = []
            # Newest first by write time; report IDs are random and carry no order.
            metas = sorted(
                (workspace / "reports").glob("*.meta"),
                key=lambda p: (p.stat().st_mtime_ns, p.name),
                reverse=True,
            )
            for path in metas[:200]:
                if re.fullmatch(r"[0-9a-f]{32}\.meta", path.name):
                    record = json.loads(path.read_text())
                    # PDF output was withdrawn; earlier PDF reports are no longer offered.
                    if record.get("kind") != "approved-pdf":
                        result.append(record)
            return result

        return await coordinator.call(execute)

    @app.get("/api/reports/{report_id}/download")
    def download(report_id: str):
        if not re.fullmatch(r"[0-9a-f]{32}", report_id):
            raise InputError("REPORT_NOT_FOUND")
        metadata = workspace / "reports" / (report_id + ".meta")
        if not metadata.is_file():
            raise InputError("REPORT_NOT_FOUND")
        report = json.loads(metadata.read_text())
        if report.get("kind") == "approved-pdf":
            raise InputError("REPORT_FORMAT_WITHDRAWN")
        suffix = {
            "assessment": ".zip",
            "excel": ".xlsx",
            "approved-rtf": ".rtf",
            "approved-docx": ".docx",
            "approved-text": ".txt",
        }.get(report["kind"], ".json")
        path = resolve_under(workspace, f"reports/{report_id}{suffix}")
        return FileResponse(path, filename=report["name"])

    from offline_analyzer.api.workspace import register as register_workspace

    register_workspace(
        app,
        workspace=workspace,
        coordinator=coordinator,
        location=location or {"source": "COMMAND_LINE"},
        restart=restart,
    )

    @app.post("/api/shutdown")
    def shutdown():
        if stop:
            stop()
        return {"stopping": True}

    @app.get("/{path:path}")
    def frontend(path: str):
        if path.startswith("api/"):
            return JSONResponse({"error": "NOT_FOUND"}, status_code=404)
        if path:
            try:
                candidate = resolve_under(ASSETS, path)
                if candidate.is_file():
                    return FileResponse(candidate)
            except Exception:
                return JSONResponse({"error": "NOT_FOUND"}, status_code=404)
        index = ASSETS / "index.html"
        if not index.is_file():
            return JSONResponse({"error": "FRONTEND_BUILD_REQUIRED"}, status_code=503)
        return FileResponse(index)

    return app
