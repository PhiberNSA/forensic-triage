"""Scan a file or directory tree: hashes, type identification, entropy and timestamps."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .entropy import EntropyAccumulator
from .hashing import CHUNK_SIZE, DEFAULT_ALGORITHMS, new_hashers
from .signatures import HEAD_SIZE, detect_type, extension_matches, get_extension
from .utils import iso_utc_ns

DEFAULT_ENTROPY_THRESHOLD = 7.5
MIN_SIZE_FOR_ENTROPY_FLAG = 1024  # tiny files cannot reach a meaningful entropy
COMPRESSED_CATEGORIES = frozenset({"archive", "image", "media", "document"})

FLAG_EXT_MISMATCH = "EXT_MISMATCH"
FLAG_DISGUISED_EXEC = "DISGUISED_EXECUTABLE"
FLAG_HIGH_ENTROPY = "HIGH_ENTROPY"
FLAG_EMPTY = "EMPTY"


@dataclass
class FileRecord:
    path: str  # relative to the scan root, POSIX separators
    size: int
    modified: str | None = None  # M - content modified
    accessed: str | None = None  # A - last accessed
    changed: str | None = None  # C - metadata change (Unix) / creation (older Windows Python)
    created: str | None = None  # B - birth time, when the OS exposes it
    hashes: dict[str, str] = field(default_factory=dict)
    file_type: str | None = None
    category: str | None = None
    extension: str = ""
    entropy: float | None = None
    flags: list[str] = field(default_factory=list)
    error: str | None = None


def _stat_record(rel_path: str, st: os.stat_result) -> FileRecord:
    birth = getattr(st, "st_birthtime", None)
    return FileRecord(
        path=rel_path,
        size=st.st_size,
        modified=iso_utc_ns(st.st_mtime_ns),
        accessed=iso_utc_ns(st.st_atime_ns),
        changed=iso_utc_ns(st.st_ctime_ns),
        created=iso_utc_ns(int(birth * 1_000_000_000)) if birth else None,
    )


def _error_text(exc: OSError) -> str:
    return f"{type(exc).__name__}: {exc.strerror or exc}"


def analyze_file(
    record: FileRecord,
    full_path: str | os.PathLike,
    algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
) -> FileRecord:
    """Read the file once, filling hashes, detected type, entropy and flags."""
    hashers = new_hashers(algorithms)
    entropy = EntropyAccumulator()
    head = b""
    try:
        with open(full_path, "rb") as fh:
            while chunk := fh.read(CHUNK_SIZE):
                if not head:
                    head = chunk[:HEAD_SIZE]
                for hasher in hashers.values():
                    hasher.update(chunk)
                entropy.update(chunk)
    except OSError as exc:
        record.error = _error_text(exc)
        return record

    record.hashes = {name: hasher.hexdigest() for name, hasher in hashers.items()}
    record.entropy = round(entropy.value, 4)
    record.extension = get_extension(os.path.basename(full_path))

    signature = detect_type(head)
    if signature is not None:
        record.file_type = signature.name
        record.category = signature.category

    if record.size == 0:
        record.flags.append(FLAG_EMPTY)
    if signature is not None and not extension_matches(signature, record.extension):
        record.flags.append(FLAG_EXT_MISMATCH)
        if signature.category == "executable":
            record.flags.append(FLAG_DISGUISED_EXEC)
    if (
        record.entropy >= entropy_threshold
        and record.size >= MIN_SIZE_FOR_ENTROPY_FLAG
        and (signature is None or signature.category not in COMPRESSED_CATEGORIES)
    ):
        record.flags.append(FLAG_HIGH_ENTROPY)
    return record


def scan_path(
    root: str | os.PathLike,
    *,
    algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
    analyze: bool = True,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
) -> Iterator[FileRecord]:
    """Yield one :class:`FileRecord` per regular file below ``root`` (or for ``root`` itself).

    Symlinks and special files (devices, FIFOs, sockets) are skipped, so a scan can never
    block or leave the evidence tree. With ``analyze=False`` only ``stat`` data is collected
    (fast, does not read file contents - useful for timelines).
    """
    root_path = Path(root)
    algorithms = tuple(algorithms)

    if root_path.is_file():
        st = os.lstat(root_path)
        record = _stat_record(root_path.name, st)
        yield analyze_file(record, root_path, algorithms, entropy_threshold) if analyze else record
        return

    walk_errors: list[OSError] = []

    def flush_errors() -> Iterator[FileRecord]:
        while walk_errors:
            exc = walk_errors.pop(0)
            rel = os.path.relpath(exc.filename, root_path) if exc.filename else "."
            yield FileRecord(path=Path(rel).as_posix(), size=0, error=_error_text(exc))

    for dirpath, dirnames, filenames in os.walk(root_path, onerror=walk_errors.append):
        yield from flush_errors()
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath, name)
            rel = full.relative_to(root_path).as_posix()
            try:
                st = os.lstat(full)
            except OSError as exc:
                yield FileRecord(path=rel, size=0, error=_error_text(exc))
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            record = _stat_record(rel, st)
            yield analyze_file(record, full, algorithms, entropy_threshold) if analyze else record
    yield from flush_errors()
