"""Printable-string extraction and simple IOC (indicator of compromise) harvesting."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from .utils import open_readonly_mmap

DEFAULT_MIN_LENGTH = 6
ENCODINGS = ("ascii", "utf-16le")


@dataclass(frozen=True)
class FoundString:
    offset: int
    encoding: str  # "ascii" or "utf-16le"
    value: str


def extract_strings(
    buf: bytes, min_length: int = DEFAULT_MIN_LENGTH, encodings: Iterable[str] = ENCODINGS
) -> Iterator[FoundString]:
    """Yield printable strings, one pass per encoding (all ASCII first, then UTF-16LE)."""
    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    encodings = tuple(encodings)
    for encoding in encodings:
        if encoding not in ENCODINGS:
            raise ValueError(f"unsupported encoding {encoding!r} (supported: {ENCODINGS})")

    if "ascii" in encodings:
        pattern = re.compile(rb"[\x20-\x7e\t]{%d,}" % min_length)
        for match in pattern.finditer(buf):
            yield FoundString(match.start(), "ascii", match.group().decode("ascii"))
    if "utf-16le" in encodings:
        pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
        for match in pattern.finditer(buf):
            yield FoundString(match.start(), "utf-16le", match.group().decode("utf-16le"))


def iter_file_strings(
    path: str | os.PathLike,
    min_length: int = DEFAULT_MIN_LENGTH,
    encodings: Iterable[str] = ENCODINGS,
) -> Iterator[FoundString]:
    with open_readonly_mmap(path) as buf:
        yield from extract_strings(buf, min_length, encodings)


# --------------------------------------------------------------------------------------
# IOCs
# --------------------------------------------------------------------------------------
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"(?i)(?:https?|ftps?)://[^\s\"'<>`{}|\\^]+"),
    "ipv4": re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?!\d|\.\d)"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
    "registry_key": re.compile(
        r"(?i)HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)"
        r"(?:\\[^\\\s\"'<>|]+)+"
    ),
}


def extract_iocs(strings: Iterable[str]) -> dict[str, list[str]]:
    """Return ``{kind: sorted unique values}`` for every IOC kind that was found.

    The patterns are deliberately simple: expect false positives (for instance a version
    number such as ``1.2.3.4`` looks like an IPv4 address).
    """
    found: dict[str, set[str]] = {kind: set() for kind in IOC_PATTERNS}
    for text in strings:
        for kind, pattern in IOC_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                if kind == "url":
                    value = value.rstrip(".,;:!?)]}'\"")
                found[kind].add(value)
    return {kind: sorted(values) for kind, values in found.items() if values}


def defang(kind: str, value: str) -> str:
    """Make an indicator safe to paste into tickets and chats (hxxp, [.], [@])."""
    if kind == "url":
        value = re.sub(r"(?i)^(h)tt(ps?)://", r"\1xx\2://", value)
        value = re.sub(r"(?i)^f(t)p(s?)://", r"f\1p\2://", value)  # keeps ftp readable
        return value.replace(".", "[.]")
    if kind == "ipv4":
        return value.replace(".", "[.]")
    if kind == "email":
        return value.replace("@", "[@]").replace(".", "[.]")
    return value
