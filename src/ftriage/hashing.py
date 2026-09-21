"""Streaming hash helpers (one pass over the data, several algorithms)."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable

SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")
DEFAULT_ALGORITHMS = ("md5", "sha1", "sha256")
CHUNK_SIZE = 1024 * 1024


def new_hashers(algorithms: Iterable[str]) -> dict:
    """Create hash objects. MD5/SHA-1 are used for evidence identification, not security."""
    hashers = {}
    for name in algorithms:
        name = name.strip().lower()
        if name not in SUPPORTED_ALGORITHMS:
            supported = ", ".join(SUPPORTED_ALGORITHMS)
            raise ValueError(f"unsupported hash algorithm {name!r} (supported: {supported})")
        hashers[name] = hashlib.new(name, usedforsecurity=False)
    return hashers


def hash_bytes(data: bytes, algorithms: Iterable[str] = DEFAULT_ALGORITHMS) -> dict[str, str]:
    hashers = new_hashers(algorithms)
    for hasher in hashers.values():
        hasher.update(data)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def hash_file(
    path: str | os.PathLike, algorithms: Iterable[str] = DEFAULT_ALGORITHMS
) -> dict[str, str]:
    hashers = new_hashers(algorithms)
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}
