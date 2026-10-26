"""Shared per-API pacing for bounded workers, including paginated requests."""

import threading
import time


class RateLimit:
    def __init__(self, rate: float):
        self.interval = 1.0 / rate
        self.lock = threading.Lock()
        self.next: dict[str, float] = {}

    def wait(self, api: str) -> None:
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next.get(api, now))
            self.next[api] = slot + self.interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)


def api_name(operation: str) -> str:
    return (
        "storage"
        if operation == "BUCKET_IAM"
        else ("discoveryengine" if operation.startswith("DISCOVERY_") else "resourcemanager")
    )
