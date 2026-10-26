#!/usr/bin/env python3
"""Shared helpers for the CloSec AWS pre-flight probe and batch collector (Python 3.9+).

Account lists, masked terminal output, a bounded worker pool and an atomic checkpoint file.
No AWS call is made here; nothing here reads or prints credentials.
"""

import csv
import io
import json
import pathlib
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

ACCOUNT = re.compile(r"^[0-9]{12}$")
GROUP = re.compile(r"^[A-Za-z0-9 _.&()-]{1,64}$")


def mask(account):
    """Terminal form of an account ID: last four digits only."""
    text = str(account or "")
    return ("*" * 8 + text[-4:]) if ACCOUNT.fullmatch(text) else "(invalid)"


def read_accounts(path):
    """Accounts from a CSV (header with `account_id`, optional `business_group` and `name`) or
    a text file (one 12-digit ID per line, optional `,business group`; `#` comments).

    Returns (accounts, problems). Leading zeros are preserved; duplicates are reported and
    only the first occurrence is kept; invalid lines are reported, never guessed."""
    text = pathlib.Path(path).read_text(encoding="utf-8-sig")
    lines = [line for line in text.splitlines() if line.split("#", 1)[0].strip()]
    problems, accounts, seen = [], [], set()
    rows = []
    if lines and "account_id" in lines[0].lower():
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        fields = {name.strip().lower(): name for name in reader.fieldnames or []}
        for number, row in enumerate(reader, start=2):
            rows.append(
                (
                    number,
                    (row.get(fields.get("account_id", ""), "") or "").strip(),
                    (row.get(fields.get("business_group", ""), "") or "").strip(),
                    (row.get(fields.get("name", ""), "") or "").strip(),
                )
            )
    else:
        for number, line in enumerate(text.splitlines(), start=1):
            item = line.split("#", 1)[0].strip()
            if not item:
                continue
            parts = [p.strip() for p in item.split(",")]
            rows.append((number, parts[0], parts[1] if len(parts) > 1 else "", ""))
    for number, account, group, name in rows:
        if not ACCOUNT.fullmatch(account):
            problems.append({"line": number, "problem": "INVALID_ACCOUNT_ID"})
            continue
        if group and not GROUP.fullmatch(group):
            problems.append({"line": number, "problem": "INVALID_BUSINESS_GROUP"})
            continue
        if account in seen:
            problems.append({"line": number, "problem": "DUPLICATE_ACCOUNT_ID", "account": account})
            continue
        seen.add(account)
        accounts.append(
            {"account_id": account, "business_group": group or None, "name": name or ""}
        )
    return accounts, problems


def write_json(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=1, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    temp.replace(path)


def write_csv(path, rows, fields):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


class Checkpoint:
    """Per-account state persisted after every account (atomic replace), so a restarted run
    skips accounts that already finished."""

    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.lock = threading.Lock()
        self.state = {"version": 1, "accounts": {}}
        if self.path.is_file():
            self.state = json.loads(self.path.read_text(encoding="utf-8"))

    def get(self, account):
        return self.state["accounts"].get(account)

    def put(self, account, row):
        with self.lock:
            self.state["accounts"][account] = row
            write_json(self.path, self.state)

    def rows(self):
        return dict(self.state["accounts"])


def run_pool(items, worker, concurrency, stop):
    """Run worker(item) with bounded concurrency; one failure never stops the others.
    `stop` (threading.Event) prevents new items from starting once set."""
    results = []

    def guarded(item):
        if stop.is_set():
            return item, None, "NOT_STARTED"
        try:
            return item, worker(item), None
        except Exception as exc:  # isolation: record and continue
            return item, None, f"{type(exc).__name__}: {str(exc)[:200]}"

    with ThreadPoolExecutor(max_workers=max(1, int(concurrency))) as pool:
        futures = [pool.submit(guarded, item) for item in items]
        try:
            for future in as_completed(futures):
                results.append(future.result())
        except KeyboardInterrupt:
            stop.set()
            for future in futures:
                future.cancel()
            raise
    return results
