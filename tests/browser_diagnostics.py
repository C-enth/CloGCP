"""Local synthetic browser diagnostics; never attach this to customer sessions."""

import io
import json
import zipfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree.ElementTree import fromstring


def word_text(value: bytes | str | Path) -> str:
    """Inspect a generated synthetic DOCX, including its native package contract."""
    payload = value if isinstance(value, bytes) else Path(value).read_bytes()
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert "[Content_Types].xml" in archive.namelist()
        return "\n".join(fromstring(archive.read("word/document.xml")).itertext())


@contextmanager
def capture_browser(context, output):
    output.mkdir(parents=True, exist_ok=True)
    events = []
    context.tracing.start(screenshots=True, snapshots=True, sources=True)

    def response_seen(response):
        path = urlsplit(response.url).path
        if not path.startswith("/api/") or path == "/api/session":
            return
        event = {"kind": "response", "path": path, "status": response.status}
        try:
            event["body"] = response.json()
        except Exception:
            event["body"] = "NON_JSON_OR_UNAVAILABLE"
        events.append(event)

    def page_seen(page):
        page.on("pageerror", lambda error: events.append({"kind": "pageerror", "text": str(error)}))
        page.on(
            "console",
            lambda message: events.append(
                {"kind": "console", "level": message.type, "text": message.text}
            ),
        )

    context.on("page", page_seen)
    context.on("response", response_seen)
    try:
        yield
    finally:
        for number, page in enumerate(context.pages):
            page.screenshot(path=str(output / f"page-{number}.png"), full_page=True)
        context.tracing.stop(path=str(output / "trace.zip"))
        (output / "events.private.json").write_text(json.dumps(events, indent=2), encoding="utf-8")
