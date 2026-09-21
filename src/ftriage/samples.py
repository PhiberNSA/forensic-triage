"""Synthetic sample data used by the test-suite and by `ftriage demo`.

Everything here is harmless: the "executable" files are inert stubs that only carry the
magic bytes of the real formats, and every indicator uses reserved documentation values
(RFC 5737 IP ranges, the `.example` / `.test` TLDs).
"""

from __future__ import annotations

import base64
import io
import os
import random
import struct
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

# A real, viewable 24x24 JPEG (702 bytes) generated once with Pillow.
_JPEG_B64 = (
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAA0JCgsKCA0LCgsODg0PEyAVExISEyccHhcgLikxMC4p"
    "LSwzOko+MzZGNywtQFdBRkxOUlNSMj5aYVpQYEpRUk//2wBDAQ4ODhMREyYVFSZPNS01T09PT09P"
    "T09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0//wAARCAAYABgDASIA"
    "AhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQA"
    "AAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3"
    "ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWm"
    "p6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEA"
    "AwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSEx"
    "BhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElK"
    "U1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3"
    "uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDj4bT2"
    "q9Dae1XobT2q/Dae1exUxJngsXsUYbT2ordhtPaiuKWJ1Pp6OL90SG09qvw2ntRRXHUnI/OMFUlo"
    "X4bT2ooorhlOVz6ejUlyn//Z"
)

_FAKE_THUMBNAIL = b"\xff\xd8\xff\xdb\x00\x04\x00\x00\xff\xd9"  # SOI ... EOI, like an EXIF thumbnail

# Smallest well-known valid GIF: 1x1 pixel, global colour table, one graphic-control block.
_GIF_HEX = (
    "47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b"
)

# Indicators planted in the demo files (all reserved / documentation values).
DEMO_URL = "http://update.evil.example/stage2.bin"
DEMO_IP = "203.0.113.42"
DEMO_EMAIL = "drop@evil.example"
DEMO_REGKEY = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater"


def make_png(width: int = 32, height: int = 32) -> bytes:
    """A valid, viewable RGB gradient PNG."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    rows = bytearray()
    for y in range(height):
        rows.append(0)  # filter type: none
        for x in range(width):
            rows += bytes((x * 255 // (width - 1), y * 255 // (height - 1), 160))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(rows)))
        + chunk(b"IEND", b"")
    )


def make_jpeg(exif_thumbnail: bool = True) -> bytes:
    """A real JPEG. With ``exif_thumbnail`` an APP1 segment holding an embedded (fake)
    thumbnail is inserted - the classic trap for header/footer carvers."""
    data = base64.b64decode(_JPEG_B64)
    if not exif_thumbnail:
        return data
    app0_end = 4 + int.from_bytes(data[4:6], "big")  # SOI + APP0 marker + APP0 payload
    payload = b"Exif\x00\x00" + _FAKE_THUMBNAIL
    app1 = b"\xff\xe1" + (len(payload) + 2).to_bytes(2, "big") + payload
    return data[:app0_end] + app1 + data[app0_end:]


def make_gif() -> bytes:
    return bytes.fromhex(_GIF_HEX)


def make_pdf(text: str = "ftriage demo document") -> bytes:
    """A minimal but valid one-page PDF with a correct cross-reference table."""
    stream = f"BT /F1 18 Tf 20 70 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref_offset = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref_offset,
    )
    return bytes(out)


def make_zip(nested: bool = True) -> bytes:
    """A ZIP archive; with ``nested`` it stores a second, complete ZIP inside itself."""
    stamp = (2026, 1, 1, 0, 0, 0)  # fixed timestamp -> reproducible bytes

    def build(members: list[tuple[str, bytes, int]]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, content, method in members:
                info = zipfile.ZipInfo(name, date_time=stamp)
                info.compress_type = method
                archive.writestr(info, content)
        return buffer.getvalue()

    members = [("notes.txt", b"ftriage demo archive\n" * 20, zipfile.ZIP_DEFLATED)]
    if nested:
        inner = build([("inner.txt", b"nested archive", zipfile.ZIP_STORED)])
        members.append(("inner.zip", inner, zipfile.ZIP_STORED))
    return build(members)


def make_random(size: int, seed: int = 0) -> bytes:
    return random.Random(seed).randbytes(size)


def make_pe_stub(with_indicators: bool = True) -> bytes:
    """INERT stub with valid MZ + PE signatures (not runnable), packed-looking random tail."""
    header = bytearray(0x200)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = (0x80).to_bytes(4, "little")  # e_lfanew
    header[0x80:0x84] = b"PE\x00\x00"
    header[0x84:0x86] = b"\x64\x86"  # machine: AMD64
    body = b""
    if with_indicators:
        body = (
            DEMO_URL.encode() + b"\x00"
            + DEMO_IP.encode() + b"\x00"
            + DEMO_EMAIL.encode() + b"\x00\x00\x00"  # padding: wide strings are 2-byte aligned
            + DEMO_REGKEY.encode("utf-16le") + b"\x00\x00"
        )  # fmt: skip
    return bytes(header) + body + make_random(16 * 1024, seed=7)


def make_elf_stub() -> bytes:
    """INERT stub: an ELF identification header followed by zeros."""
    return b"\x7fELF\x02\x01\x01\x00" + bytes(56)


def build_disk_image(
    blobs: list[bytes], seed: int = 1337, sector: int = 512
) -> tuple[bytes, list[int]]:
    """Embed ``blobs`` at sector-aligned offsets in random 'unallocated' noise.

    Returns the image and the offset of every blob."""
    rng = random.Random(seed)
    image = bytearray(rng.randbytes(sector * 8))
    offsets = []
    for blob in blobs:
        offsets.append(len(image))
        image += blob
        image += rng.randbytes((-len(image)) % sector + sector * rng.randint(2, 6))
    return bytes(image), offsets


_NOTES = (
    "Meeting notes - 2026-09-18\n"
    f"- Follow up with the vendor at contact@vendor.example\n"
    "- Staging server: 198.51.100.7 (do NOT expose)\n"
    "- Draft: https://reports.example.test/q3/summary\n"
)


def _epoch(*args: int) -> float:
    return datetime(*args, tzinfo=timezone.utc).timestamp()


def build_demo(dest: str | os.PathLike) -> dict:
    """Create ``dest/evidence`` (a small directory with suspicious files) and
    ``dest/disk.img`` (a raw image with deleted-looking files hidden in noise)."""
    dest = Path(dest)
    evidence = dest / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)

    # name -> (content, (year, month, day, hour, minute, second) used for atime/mtime)
    files = {
        "holiday.jpg": (make_pe_stub(), (2026, 9, 14, 3, 12, 40)),  # a PE disguised as a photo
        "cleanup.sh": (make_elf_stub(), (2026, 9, 14, 3, 15, 2)),  # an ELF disguised as a script
        "logo.png": (make_gif(), (2026, 8, 30, 9, 0, 0)),  # harmless mismatch
        "data.bin": (make_random(32 * 1024, seed=3), (2026, 9, 14, 3, 20, 11)),
        "photo.jpg": (make_jpeg(), (2026, 9, 1, 18, 45, 0)),
        "beach.png": (make_png(), (2026, 9, 1, 18, 46, 30)),
        "invoice.pdf": (make_pdf("Invoice 0042"), (2026, 9, 10, 8, 30, 0)),
        "archive.zip": (make_zip(), (2026, 9, 12, 14, 0, 0)),
        "notes.txt": (_NOTES.encode(), (2026, 9, 18, 16, 5, 0)),
    }
    for name, (content, moment) in files.items():
        path = evidence / name
        path.write_bytes(content)
        stamp = _epoch(*moment)
        os.utime(path, (stamp, stamp))

    embedded = [make_png(48, 48), make_jpeg(), make_gif(), make_pdf("Recovered"), make_zip()]
    image, offsets = build_disk_image(embedded)
    image_path = dest / "disk.img"
    image_path.write_bytes(image)
    return {
        "evidence": evidence,
        "image": image_path,
        "embedded_offsets": offsets,
        "embedded_sizes": [len(blob) for blob in embedded],
    }
