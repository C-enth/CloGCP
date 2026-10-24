"""Streaming JSON validation with generic errors and no imported execution."""

import re
from pathlib import Path

import ijson

from offline_analyzer.contracts.errors import InputError as InputError

MAX_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
# Native AWS collectors write one file per API page; byte budgets remain the real bound.
MAX_PACKAGE_FILES = 20000
MAX_DEPTH = 40
MAX_EVENTS = 2_000_000
MAX_STRING = 65536
MAX_RECORDS = 100000
SECRET_KEYS = {
    "awsaccesskeyid",
    "awssecretaccesskey",
    "awssessiontoken",
    "secretaccesskey",
    "accesskeyid",
    "sessiontoken",
    "password",
    "privatekey",
    "secretstring",
    "secretbinary",
    "credentials",
    "masteruserpassword",
    "clientsecret",
    "accesstoken",
    "refreshtoken",
    "authorization",
    "apikey",
    "userdata",
    "keystring",
    "privatekeydata",
    "clientemailcredentials",
    "idtoken",
}
SECRET_VALUE = re.compile(
    r"AIza[0-9A-Za-z_-]{35}|(?:AKIA|ASIA)[A-Z0-9]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"
)


def inspect_json(path: Path, *, observer=None) -> dict:
    """Bound each file and check duplicate keys before any object construction.

    Root field/type information also prevents wrong-shape arrays becoming empty imports.
    """
    from offline_analyzer.provenance.execution import checkpoint

    checkpoint()
    if path.stat().st_size > MAX_BYTES:
        raise InputError(
            "INPUT_BYTE_LIMIT",
            limit={"name": "file_bytes", "allowed": MAX_BYTES, "observed": path.stat().st_size},
        )
    stack = []
    root = None
    fields = {}
    events = 0
    record_sizes = []
    try:
        with path.open("rb") as stream:
            if stream.read(3) != b"\xef\xbb\xbf":
                stream.seek(0)
            for prefix, event, value in ijson.parse(stream, use_float=True):
                events += 1
                if events % 4096 == 0:
                    checkpoint()
                if events > MAX_EVENTS:
                    raise InputError("INPUT_EVENT_LIMIT")
                approximate = len(value.encode("utf-8")) if isinstance(value, str) else 8
                for counter in record_sizes:
                    counter[1] += approximate
                    if counter[1] > 2 * 1024 * 1024:
                        raise InputError("RECORD_BYTE_LIMIT")
                if event in {"start_map", "start_array"} and prefix.endswith("item"):
                    record_sizes.append([len(stack) + 1, 0])
                if root is None:
                    root = event
                if event in {"start_map", "start_array"}:
                    stack.append(set() if event == "start_map" else None)
                    if len(stack) > MAX_DEPTH:
                        raise InputError("INPUT_DEPTH_LIMIT")
                elif event in {"end_map", "end_array"}:
                    record_sizes = [counter for counter in record_sizes if counter[0] != len(stack)]
                    stack.pop()
                elif event == "map_key":
                    if value in stack[-1]:
                        raise InputError("DUPLICATE_JSON_KEY")
                    stack[-1].add(value)
                    if len(stack[-1]) > 4096:
                        raise InputError("INPUT_KEY_LIMIT")
                    if re.sub(r"[^a-z]", "", value.lower()) in SECRET_KEYS:
                        raise InputError("CREDENTIAL_MATERIAL_REJECTED")
                if isinstance(value, str):
                    if len(value) > MAX_STRING:
                        raise InputError("INPUT_STRING_LIMIT")
                    if SECRET_VALUE.search(value):
                        raise InputError("CREDENTIAL_MATERIAL_REJECTED")
                if observer is not None:
                    observer(prefix, event, value)
                if (
                    prefix
                    and (
                        "." not in prefix
                        or prefix
                        in {
                            "Error.Code",
                            "ResponseMetadata.HTTPStatusCode",
                        }
                    )
                    and event != "map_key"
                ):
                    fields.setdefault(
                        prefix,
                        (
                            event,
                            value
                            if event not in {"start_array", "start_map", "end_array", "end_map"}
                            else None,
                        ),
                    )
    except (ijson.JSONError, OverflowError, UnicodeError) as exc:
        raise InputError("MALFORMED_JSON") from exc
    return {"root": root, "fields": fields}


def records(path: Path, prefix: str):
    from offline_analyzer.provenance.execution import checkpoint

    with path.open("rb") as stream:
        if stream.read(3) != b"\xef\xbb\xbf":
            stream.seek(0)
        for index, value in enumerate(ijson.items(stream, prefix, use_float=True)):
            checkpoint()
            if index >= MAX_RECORDS:
                raise InputError("RECORD_LIMIT")
            yield index, value
