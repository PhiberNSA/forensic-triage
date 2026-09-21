"""Shannon entropy - a quick indicator of compressed, encrypted or packed data."""

from __future__ import annotations

import math
from collections import Counter


class EntropyAccumulator:
    """Accumulates a byte histogram so entropy can be computed while streaming a file."""

    def __init__(self) -> None:
        self._counts = [0] * 256
        self._total = 0

    def update(self, data: bytes) -> None:
        if not data:
            return
        for value, count in Counter(data).items():
            self._counts[value] += count
        self._total += len(data)

    @property
    def total(self) -> int:
        return self._total

    @property
    def value(self) -> float:
        """Entropy in bits per byte: 0.0 (constant data) .. 8.0 (uniformly random)."""
        if self._total == 0:
            return 0.0
        total = self._total
        result = 0.0
        for count in self._counts:
            if count:
                p = count / total
                result -= p * math.log2(p)
        return result


def shannon_entropy(data: bytes) -> float:
    accumulator = EntropyAccumulator()
    accumulator.update(data)
    return accumulator.value
