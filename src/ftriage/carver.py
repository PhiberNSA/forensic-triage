"""Structure-aware file carving from raw disk images.

Classic carvers cut from a header to the *first* footer they find. That breaks on real files:
a JPEG with an EXIF thumbnail contains a complete JPEG (``FFD8 ... FFD9``) inside itself, and a
ZIP that stores another ZIP contains a second end-of-central-directory record.

Each format below therefore has an *end finder* that understands just enough of the file
structure to locate the true end:

* JPEG - walks the marker segments (skipping APPn payloads such as EXIF thumbnails) and the
  entropy-coded scan data until the EOI marker.
* PNG  - walks the chunk list until ``IEND``.
* GIF  - walks the block structure until the trailer byte.
* ZIP  - finds an end-of-central-directory record that is consistent with the archive start.
* PDF  - uses the last ``%%EOF`` before the next PDF header (handles linearised PDFs and
  incremental updates).

Carving assumes files are stored contiguously; fragmented files are out of scope.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

from .hashing import hash_bytes
from .utils import open_readonly_mmap

MIB = 1024 * 1024
DEFAULT_MAX_SIZE = 50 * MIB
DEFAULT_MIN_SIZE = 32

# (buffer, start_of_file, hard_limit) -> exclusive end offset, or None if the data is invalid.
# The buffer may be ``bytes`` or an ``mmap`` - only find/rfind/indexing/slicing are used.
EndFinder = Callable[[bytes, int, int], int | None]


# --------------------------------------------------------------------------------------
# End finders
# --------------------------------------------------------------------------------------
def _jpeg_skip_scan(buf: bytes, pos: int, limit: int) -> int | None:
    """Skip entropy-coded data; return the offset of the next real marker."""
    while True:
        pos = buf.find(b"\xff", pos, limit)
        if pos == -1 or pos + 1 >= limit:
            return None
        nxt = buf[pos + 1]
        if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:  # byte stuffing / restart markers
            pos += 2
        elif nxt == 0xFF:  # fill byte
            pos += 1
        else:
            return pos


def _jpeg_end(buf: bytes, start: int, limit: int) -> int | None:
    pos = start + 2  # after SOI
    seen_scan = False
    while pos + 2 <= limit:
        if buf[pos] != 0xFF:
            return None
        marker = buf[pos + 1]
        if marker == 0xFF:  # fill byte before a marker
            pos += 1
        elif marker == 0xD9:  # EOI
            return pos + 2 if seen_scan else None
        elif marker == 0x01 or 0xD0 <= marker <= 0xD8:  # markers without a length field
            pos += 2
        elif marker == 0x00:
            return None
        else:
            if pos + 4 > limit:
                return None
            length = (buf[pos + 2] << 8) | buf[pos + 3]
            if length < 2:
                return None
            pos += 2 + length
            if marker == 0xDA:  # SOS - compressed image data follows
                seen_scan = True
                pos = _jpeg_skip_scan(buf, pos, limit)
                if pos is None:
                    return None
    return None


def _png_end(buf: bytes, start: int, limit: int) -> int | None:
    if buf[start + 12 : start + 16] != b"IHDR":
        return None
    pos = start + 8
    while pos + 12 <= limit:
        length = int.from_bytes(buf[pos : pos + 4], "big")
        chunk_type = bytes(buf[pos + 4 : pos + 8])
        if not all(65 <= c <= 90 or 97 <= c <= 122 for c in chunk_type):
            return None
        end = pos + 12 + length  # length + type + data + CRC
        if end > limit:
            return None
        if chunk_type == b"IEND":
            return end
        pos = end
    return None


def _gif_skip_sub_blocks(buf: bytes, pos: int, limit: int) -> int | None:
    while pos < limit:
        size = buf[pos]
        pos += 1 + size
        if size == 0:
            return pos
    return None


def _gif_end(buf: bytes, start: int, limit: int) -> int | None:
    pos = start + 6
    if pos + 7 > limit:
        return None
    packed = buf[pos + 4]
    pos += 7  # logical screen descriptor
    if packed & 0x80:  # global colour table
        pos += 3 * (1 << ((packed & 0x07) + 1))
    while pos < limit:
        block = buf[pos]
        if block == 0x3B:  # trailer
            return pos + 1
        if block == 0x21:  # extension block
            pos = _gif_skip_sub_blocks(buf, pos + 2, limit)
        elif block == 0x2C:  # image descriptor
            if pos + 10 > limit:
                return None
            packed = buf[pos + 9]
            pos += 10
            if packed & 0x80:  # local colour table
                pos += 3 * (1 << ((packed & 0x07) + 1))
            pos = _gif_skip_sub_blocks(buf, pos + 1, limit)  # +1: LZW minimum code size
        else:
            return None
        if pos is None:
            return None
    return None


def _pdf_end(buf: bytes, start: int, limit: int) -> int | None:
    next_header = buf.find(b"%PDF-", start + 5, limit)
    bound = next_header if next_header != -1 else limit
    eof = buf.rfind(b"%%EOF", start, bound)
    if eof == -1:
        return None
    end = eof + 5
    if buf[end : end + 2] == b"\r\n":
        end += 2
    elif buf[end : end + 1] in (b"\n", b"\r"):
        end += 1
    return end


def _zip_end(buf: bytes, start: int, limit: int) -> int | None:
    pos = start + 4
    while True:
        eocd = buf.find(b"PK\x05\x06", pos, limit)
        if eocd == -1 or eocd + 22 > limit:
            return None
        cd_size = int.from_bytes(buf[eocd + 12 : eocd + 16], "little")
        cd_offset = int.from_bytes(buf[eocd + 16 : eocd + 20], "little")
        comment_len = int.from_bytes(buf[eocd + 20 : eocd + 22], "little")
        # The central directory must end exactly where this EOCD begins. This rejects the
        # EOCD of an archive nested (stored) inside the one being carved. 0xFFFFFFFF = ZIP64.
        consistent = cd_offset == 0xFFFFFFFF or start + cd_offset + cd_size == eocd
        if consistent and eocd + 22 + comment_len <= limit:
            return eocd + 22 + comment_len
        pos = eocd + 1


# --------------------------------------------------------------------------------------
# Carving
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class CarveSpec:
    key: str
    label: str
    extension: str
    headers: tuple[bytes, ...]
    find_end: EndFinder


CARVE_SPECS: dict[str, CarveSpec] = {
    spec.key: spec
    for spec in (
        CarveSpec("jpeg", "JPEG image", "jpg", (b"\xff\xd8\xff",), _jpeg_end),
        CarveSpec("png", "PNG image", "png", (b"\x89PNG\r\n\x1a\n",), _png_end),
        CarveSpec("gif", "GIF image", "gif", (b"GIF87a", b"GIF89a"), _gif_end),
        CarveSpec("pdf", "PDF document", "pdf", (b"%PDF-",), _pdf_end),
        CarveSpec("zip", "ZIP archive", "zip", (b"PK\x03\x04",), _zip_end),
    )
}


@dataclass
class CarvedFile:
    index: int
    type: str
    label: str
    offset: int
    size: int
    sha256: str
    filename: str

    def to_dict(self) -> dict:
        return asdict(self)


def select_specs(types: Iterable[str] | None) -> list[CarveSpec]:
    if not types:
        return list(CARVE_SPECS.values())
    specs = []
    for key in types:
        key = key.strip().lower()
        if key not in CARVE_SPECS:
            raise ValueError(f"unknown carve type {key!r} (available: {', '.join(CARVE_SPECS)})")
        specs.append(CARVE_SPECS[key])
    return specs


def find_carvable(
    buf: bytes,
    specs: Iterable[CarveSpec],
    max_size: int = DEFAULT_MAX_SIZE,
    min_size: int = DEFAULT_MIN_SIZE,
) -> Iterator[tuple[CarveSpec, int, int]]:
    """Yield ``(spec, start, end)`` for every file found in ``buf``, in offset order.

    All formats are scanned in a single pass and a hit that lies inside a file that was
    already carved is skipped, so an image embedded in a PDF (or a thumbnail inside a JPEG)
    is not reported a second time.
    """
    hits = []
    for spec in specs:
        for header in spec.headers:
            pos = buf.find(header)
            while pos != -1:
                hits.append((pos, spec))
                pos = buf.find(header, pos + 1)
    hits.sort(key=lambda hit: hit[0])

    cursor = 0
    for start, spec in hits:
        if start < cursor:
            continue
        limit = min(len(buf), start + max_size)
        end = spec.find_end(buf, start, limit)
        if end is None or end - start < min_size:
            continue
        yield spec, start, end
        cursor = end


def carve_image(
    image: str | os.PathLike,
    out_dir: str | os.PathLike,
    *,
    types: Iterable[str] | None = None,
    max_size: int = DEFAULT_MAX_SIZE,
    min_size: int = DEFAULT_MIN_SIZE,
) -> list[CarvedFile]:
    """Carve files out of ``image`` into ``out_dir``. The image is opened read-only."""
    specs = select_specs(types)
    out_path = Path(out_dir)
    carved: list[CarvedFile] = []
    with open_readonly_mmap(image) as buf:
        for spec, start, end in find_carvable(buf, specs, max_size, min_size):
            data = bytes(buf[start:end])
            index = len(carved) + 1
            filename = f"{index:05d}_{start:010x}.{spec.extension}"
            out_path.mkdir(parents=True, exist_ok=True)
            (out_path / filename).write_bytes(data)
            carved.append(
                CarvedFile(
                    index=index,
                    type=spec.key,
                    label=spec.label,
                    offset=start,
                    size=len(data),
                    sha256=hash_bytes(data, ("sha256",))["sha256"],
                    filename=filename,
                )
            )
    return carved
