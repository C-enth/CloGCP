"""Only enumerated configuration reads; no discovery of unspecified client resources."""

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, build_opener
from urllib.request import Request as HTTPRequest

from .models import Manifest, Plan, Request, Result
from .rate import RateLimit, api_name

LIMIT = 16 * 1024 * 1024


class DeltaError(ValueError):
    pass


def load(path: Path):
    if path.stat().st_size > LIMIT:
        raise DeltaError("JSON_BYTE_LIMIT")
    return decode(path.read_bytes())


def decode(raw: bytes):
    if len(raw) > LIMIT:
        raise DeltaError("JSON_BYTE_LIMIT")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise DeltaError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DeltaError("INVALID_JSON") from exc
    pending, count = [(data, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 40 or count > 500000:
            raise DeltaError("JSON_COMPLEXITY_LIMIT")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    return data


def semantic(value):
    if isinstance(value, dict):
        result = {k: semantic(v) for k, v in value.items()}
        for key in ("bindings", "members"):
            if isinstance(result.get(key), list):
                result[key] = sorted(result[key], key=lambda v: json.dumps(v, sort_keys=True))
        return result
    if isinstance(value, list):
        return sorted((semantic(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    return value


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clean(value) -> tuple[object, int]:
    count = 0
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if re.fullmatch(
                (
                    "(?i)(password|credentials|private_?key(?:_?data)?|client_?secret|access_?token|"
                    "refresh_?token|secret(?:value|string)?|keyString|api_?key|secretAccessKey|"
                    "aws_secret_access_key|aws_session_token)"
                ),
                key,
            ):
                count += 1
                result["redacted_sensitive_field_" + str(count)] = "[REDACTED]"
            else:
                result[key], n = clean(item)
                count += n
        return result, count
    if isinstance(value, list):
        rows = [clean(v) for v in value]
        return [v for v, _ in rows], sum(n for _, n in rows)
    if isinstance(value, str) and re.search(
        r"-----BEGIN .*PRIVATE KEY|ya29\.[A-Za-z0-9_-]+|(?:AKIA|ASIA)[A-Z0-9]{16}|"
        r"AIza[A-Za-z0-9_-]{35}",
        value,
    ):
        return "[REDACTED]", 1
    return value, 0


def command(request: Request, quota: str | None) -> list[str] | None:
    if request.operation == "BUCKET_IAM":
        args = ["storage", "buckets", "get-iam-policy", "gs://" + request.resource]
    elif request.operation == "FOLDER_IAM":
        args = ["resource-manager", "folders", "get-iam-policy", request.resource.split("/")[1]]
    elif request.operation == "FOLDER_METADATA":
        args = ["resource-manager", "folders", "describe", request.resource.split("/")[1]]
    else:
        return None
    return (
        args
        + ["--project=" + request.project_id, "--format=json", "--quiet"]
        + (["--billing-project=" + quota] if quota else [])
    )


def classify_error(text: str, code: int = 0) -> str:
    text = text.lower()
    if (
        "serviceusage.services.use" in text
        or "quota project" in text
        or "user_project_denied" in text
    ):
        return "QUOTA_PROJECT_DENIED"
    if code == 404 or "not_found" in text or "not found" in text:
        return "MISSING"
    if "service_disabled" in text or "api has not been used" in text:
        return "API_DISABLED"
    if code in {401, 403} or "permission_denied" in text or "permission denied" in text:
        return "DENIED"
    return "API_ERROR"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DeltaError("REDIRECT_REFUSED")


class Transport:
    """Explicit execution only. OAuth token stays in RAM, never in logs or packages."""

    def __init__(self, gcloud: str = "gcloud", timeout: int = 60, max_pages: int = 20):
        self.gcloud = shutil.which(gcloud)
        if not self.gcloud:
            raise DeltaError("GCLOUD_NOT_AVAILABLE")
        self.timeout, self.max_pages = timeout, max_pages
        self.limiter = RateLimit(2.0)

    def process(self, args: list[str]) -> tuple[int, bytes, bytes]:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(
                [self.gcloud, *args], stdout=stdout, stderr=stderr, shell=False
            )
            start = time.monotonic()
            while process.poll() is None:
                if (
                    time.monotonic() - start > self.timeout
                    or stdout.tell() > LIMIT
                    or stderr.tell() > LIMIT
                ):
                    process.kill()
                    process.wait()
                    raise DeltaError("COMMAND_TIMEOUT_OR_BYTE_LIMIT")
                time.sleep(0.05)
            stdout.seek(0)
            stderr.seek(0)
            return process.returncode, stdout.read(LIMIT + 1), stderr.read(LIMIT + 1)

    def collect(self, request: Request, quota: str | None) -> tuple[object | None, str, bool]:
        args = command(request, quota)
        if args:
            code, raw, error = self.process(args)
            if code:
                return None, classify_error(error.decode("utf-8", errors="replace")), False
            if len(raw) > LIMIT:
                return None, "API_ERROR", False
            try:
                value = decode(raw)
            except (ValueError, RecursionError):
                return None, "API_ERROR", False
            return value, "COMPLETE", True
        if request.operation == "IAM_RECOMMENDATIONS":
            return None, "UNSUPPORTED", False
        # Existing Discovery Engine GET/list catalogue only, never documents/content.
        # Credential output is memory-only. Do not route it through temporary files.
        auth = subprocess.run(
            [self.gcloud, "auth", "print-access-token", "--quiet"],
            capture_output=True,
            timeout=self.timeout,
            check=False,
            shell=False,
        )
        raw = auth.stdout
        if auth.returncode or len(raw) > 8192:
            return None, "DENIED", False
        token = raw.decode().strip()
        if not re.fullmatch(r"[A-Za-z0-9._~-]{20,8192}", token):
            return None, "DENIED", False
        location = request.resource.split("/")[3]
        host = (
            "discoveryengine.googleapis.com"
            if location == "global"
            else location + "-discoveryengine.googleapis.com"
        )
        suffix, field = {
            "DISCOVERY_ENGINES": ("/engines", "engines"),
            "DISCOVERY_DATASTORES": ("/dataStores", "dataStores"),
            "DISCOVERY_RESOURCE": ("", ""),
        }[request.operation]
        base = "https://" + host + "/v1/" + request.resource + suffix
        records, page, total = [], "", 0
        for _ in range(self.max_pages):
            url = base + (
                "?" + urlencode({"pageSize": 100, **({"pageToken": page} if page else {})})
                if field
                else ""
            )
            headers = {"Authorization": "Bearer " + token}
            if quota:
                headers["X-Goog-User-Project"] = quota
            failed = None
            for attempt in range(3):
                self.limiter.wait("discoveryengine")
                try:
                    with build_opener(NoRedirect()).open(
                        HTTPRequest(url, headers=headers, method="GET"), timeout=self.timeout
                    ) as response:
                        content = response.read(LIMIT + 1)
                    data = decode(content)
                    if not isinstance(data, dict) or (
                        field and not isinstance(data.get(field, []), list)
                    ):
                        raise DeltaError("API_RESPONSE_OBJECT_REQUIRED")
                    failed = None
                    break
                except HTTPError as exc:
                    failed = classify_error(exc.read(65536).decode(errors="replace"), exc.code)
                    if exc.code not in {429, 500, 502, 503, 504}:
                        break
                    # Bounded quota/server retry; never enable a disabled service.
                    delay = min(
                        8.0,
                        max(
                            0.25 * 2**attempt,
                            float(exc.headers.get("Retry-After", 0))
                            if str(exc.headers.get("Retry-After", "")).isdigit()
                            else 0,
                        ),
                    )
                    time.sleep(delay)
                except (OSError, ValueError, DeltaError):
                    failed = "API_ERROR"
                    break
            if failed:
                return (records or None), "PARTIAL" if records else failed, False
            total += len(content)
            if total > LIMIT:
                return (records or None), "PARTIAL" if records else "API_ERROR", False
            records.extend(data.get(field, []) if field else [data])
            page = data.get("nextPageToken", "") if field else ""
            if not page:
                return records, "COMPLETE" if records else "EMPTY", True
        return (records or []), "PARTIAL", False


def _collect(
    plan: Plan,
    output: Path,
    *,
    execute: bool = False,
    transport=None,
    baseline: Manifest | None = None,
    origin: str = "tool-generated",
    matrix_sha256: str | None = None,
    scratch: Path,
) -> Manifest:
    if execute and (not plan.catalogue_reconciled or not plan.matrix_sha256):
        raise DeltaError("CATALOGUE_RECONCILIATION_REQUIRED")
    if execute and matrix_sha256 != plan.matrix_sha256:
        raise DeltaError("APPROVED_MATRIX_HASH_MISMATCH")
    if execute and transport is None:
        raise DeltaError("EXPLICIT_TRANSPORT_REQUIRED")
    if output.exists():
        raise DeltaError("NEW_OUTPUT_DIRECTORY_REQUIRED")
    output.mkdir(mode=0o700, parents=True)
    (output / "evidence").mkdir(mode=0o700)
    seen, completed, hashes, results = {}, {}, {}, []
    for r in baseline.results if baseline else []:
        if r.semantic_sha256:
            hashes[r.semantic_sha256] = r.request.request_id
        if r.state in {"COMPLETE", "EMPTY"}:
            completed[(r.request.project_id, r.request.operation, r.request.resource)] = (
                r.request.request_id
            )
    limiter = RateLimit(plan.requests_per_second_per_api)
    if isinstance(transport, Transport):
        transport.limiter = limiter

    byte_budget, budget_lock = [0], threading.Lock()

    def attempt(request):
        started = datetime.now(UTC)
        answer = (None, "API_ERROR", False)
        for number in range(3):
            limiter.wait(api_name(request.operation))
            try:
                answer = transport.collect(request, plan.quota_project)
            except (DeltaError, OSError, subprocess.TimeoutExpired):
                answer = (None, "API_ERROR", False)
            if answer[1] != "API_ERROR" or number == 2:
                break
            time.sleep(0.25 * 2**number)
        value, state, complete = answer
        temporary, redacted = None, 0
        if value is not None:
            value, redacted = clean(value)
            raw = json.dumps(
                value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            ).encode()
            with budget_lock:
                if len(raw) > LIMIT or byte_budget[0] + len(raw) > 256 * 1024 * 1024:
                    state, complete = "API_ERROR", False
                else:
                    byte_budget[0] += len(raw)
                    temporary = scratch / (sha(raw) + ".json")
                    temporary.write_bytes(raw)
            if redacted and temporary:
                state, complete = "PARTIAL", False
        return temporary, state, complete, started, datetime.now(UTC), redacted

    # One job, bounded workers; shared folders and resource requests have one future.
    answers = {}
    if execute:
        with ThreadPoolExecutor(max_workers=plan.concurrency) as pool:
            futures = {}
            for request in plan.requests:
                key = (request.project_id, request.operation, request.resource)
                wire = (request.operation, request.resource)
                if key not in completed and wire not in futures:
                    futures[wire] = pool.submit(attempt, request)
            answers = {wire: future.result() for wire, future in futures.items()}
    for request in plan.requests:
        start = finish = datetime.now(UTC)
        key = (request.project_id, request.operation, request.resource)
        duplicate = completed.get(key)
        wire_key = (request.operation, request.resource)
        value, state, complete, prior_redacted = None, "NOT_COLLECTED", False, 0
        if duplicate:
            state = "SKIPPED_ALREADY_COMPLETE"
        elif execute:
            temporary, state, complete, start, finish, prior_redacted = answers[wire_key]
            duplicate = seen.get(wire_key)
            seen.setdefault(wire_key, request.request_id)
            if temporary:
                value = load(temporary)
        filename, checksum, semantic_checksum, redacted, count = None, None, None, 0, 0
        if value is not None:
            value, redacted = clean(value)
            redacted += prior_redacted
            if redacted:
                state, complete = "PARTIAL", False
            raw = json.dumps(
                value, sort_keys=True, ensure_ascii=True, separators=(",", ":")
            ).encode()
            if len(raw) > LIMIT:
                raise DeltaError("COLLECTED_BYTE_LIMIT")
            checksum = sha(raw)
            semantic_checksum = sha(
                json.dumps(semantic(value), sort_keys=True, separators=(",", ":")).encode()
            )
            duplicate = duplicate or hashes.get(semantic_checksum)
            hashes.setdefault(semantic_checksum, request.request_id)
            filename = f"evidence/{checksum}.json"
            if not (output / filename).exists():
                (output / filename).write_bytes(raw)
            count = len(value) if isinstance(value, list) else 1
        results.append(
            Result(
                request=request,
                state=state,
                started_at=start,
                completed_at=finish,
                file=filename,
                sha256=checksum,
                semantic_sha256=semantic_checksum,
                record_count=count,
                duplicate_of=duplicate,
                pagination_complete=complete,
                redacted_fields=redacted,
                error_code=state
                if state
                in {
                    "DENIED",
                    "MISSING",
                    "API_ERROR",
                    "API_DISABLED",
                    "QUOTA_PROJECT_DENIED",
                    "UNSUPPORTED",
                }
                else None,
            )
        )
    manifest = Manifest(
        dataset_origin=origin,
        created_at=datetime.now(UTC),
        approval_sha256=sha(plan.model_dump_json().encode()),
        catalogue_reconciled=plan.catalogue_reconciled,
        executed=execute,
        quota_project=plan.quota_project,
        results=results,
    )
    (output / "manifest.json").write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    return manifest


def collect(
    plan: Plan,
    output: Path,
    *,
    execute: bool = False,
    transport=None,
    baseline: Manifest | None = None,
    origin: str = "tool-generated",
    matrix_sha256: str | None = None,
) -> Manifest:
    # Bounded worker results are sanitized and spooled; whole-estate JSON never accumulates
    # in RAM. Scratch is removed even if a malformed response prevents publication.
    with tempfile.TemporaryDirectory(prefix="clogcp-delta-") as directory:
        return _collect(
            plan,
            output,
            execute=execute,
            transport=transport,
            baseline=baseline,
            origin=origin,
            matrix_sha256=matrix_sha256,
            scratch=Path(directory),
        )
