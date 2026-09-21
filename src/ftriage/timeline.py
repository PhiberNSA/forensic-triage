"""MACB timeline built from file-system timestamps."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .scanner import FileRecord

# (letter, FileRecord attribute)
_FIELDS = (("M", "modified"), ("A", "accessed"), ("C", "changed"), ("B", "created"))


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: str  # ISO-8601, UTC
    macb: str  # e.g. "M.C." - which timestamps of the file have this value
    path: str
    size: int
    sha256: str | None


def build_timeline(records: Iterable[FileRecord]) -> list[TimelineEvent]:
    """One row per distinct ``(timestamp, file)``; equal timestamps are merged into one MACB
    string, like ``mactime`` does. Rows are sorted chronologically."""
    grouped: dict[tuple[str, str], tuple[FileRecord, set[str]]] = {}
    for record in records:
        if record.error:
            continue
        for letter, attribute in _FIELDS:
            timestamp = getattr(record, attribute)
            if timestamp:
                _, letters = grouped.setdefault((timestamp, record.path), (record, set()))
                letters.add(letter)

    events = []
    for (timestamp, path), (record, letters) in sorted(grouped.items()):
        macb = "".join(letter if letter in letters else "." for letter, _ in _FIELDS)
        events.append(
            TimelineEvent(timestamp, macb, path, record.size, record.hashes.get("sha256"))
        )
    return events
