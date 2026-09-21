"""Small shared helpers."""

from __future__ import annotations

import contextlib
import mmap
import os
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def iso_utc_ns(ns: int | None) -> str | None:
    """POSIX timestamp in nanoseconds -> ISO-8601 UTC string (microsecond precision)."""
    if ns is None:
        return None
    try:
        moment = _EPOCH + timedelta(microseconds=ns // 1000)
        return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, ValueError):
        return None


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_size(num: float) -> str:
    """Human readable size (binary units)."""
    size = float(num)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


@contextlib.contextmanager
def open_readonly_mmap(path: str | os.PathLike) -> Iterator[bytes | mmap.mmap]:
    """Memory-map a file read-only. Empty files yield ``b""`` (mmap cannot map them)."""
    with open(path, "rb") as fh:
        if os.fstat(fh.fileno()).st_size == 0:
            yield b""
            return
        mapped = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            yield mapped
        finally:
            try:
                mapped.close()
            except BufferError:  # a consumer still holds a view; the GC will release it
                pass
