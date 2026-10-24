"""Trusted adapter protocol; registration and source adapters are Phase 1."""

from collections.abc import Iterator
from pathlib import Path
from typing import Protocol

from offline_analyzer.contracts.models import Manifest, Observation


class EvidenceParser(Protocol):
    parser_id: str
    parser_version: str
    supported_formats: tuple[str, ...]

    def parse(self, root: Path, manifest: Manifest) -> Iterator[Observation]: ...
