"""File-type identification by magic bytes ("file signatures")."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

HEAD_SIZE = 64 * 1024  # number of leading bytes inspected when identifying a file

PE_EXTENSIONS = "exe dll sys scr ocx cpl drv efi mui ax acm tlb"


@dataclass(frozen=True)
class Signature:
    """A known file format.

    ``magics`` holds alternative ``(offset, bytes)`` patterns - any one of them matching
    identifies the format. ``extensions`` are the extensions legitimately used by the format;
    an empty tuple means "do not check the extension" (e.g. plain text).
    """

    key: str
    name: str
    category: str
    extensions: tuple[str, ...]
    magics: tuple[tuple[int, bytes], ...]
    validator: Callable[[bytes], bool] | None = None

    def matches(self, head: bytes) -> bool:
        for offset, pattern in self.magics:
            if head[offset : offset + len(pattern)] == pattern:
                if self.validator is None or self.validator(head):
                    return True
        return False


def _is_pe(head: bytes) -> bool:
    """MZ header whose e_lfanew field points at a 'PE\\0\\0' signature."""
    if len(head) < 0x40:
        return False
    e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
    return 0 < e_lfanew <= len(head) - 4 and head[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"


def _is_bzip2(head: bytes) -> bool:
    return len(head) > 3 and 0x31 <= head[3] <= 0x39  # "BZh" + block size '1'..'9'


def _sig(
    key: str,
    name: str,
    category: str,
    extensions: str,
    *magics: bytes | tuple[int, bytes],
    validator: Callable[[bytes], bool] | None = None,
) -> Signature:
    parsed = tuple(m if isinstance(m, tuple) else (0, m) for m in magics)
    return Signature(key, name, category, tuple(extensions.split()), parsed, validator)


SIGNATURES: tuple[Signature, ...] = (
    # images
    _sig("jpeg", "JPEG image", "image", "jpg jpeg jpe jfif", b"\xff\xd8\xff"),
    _sig("png", "PNG image", "image", "png", b"\x89PNG\r\n\x1a\n"),
    _sig("gif", "GIF image", "image", "gif", b"GIF87a", b"GIF89a"),
    # documents
    _sig("pdf", "PDF document", "document", "pdf ai", b"%PDF-"),
    _sig("rtf", "RTF document", "document", "rtf", b"{\\rtf"),
    _sig(
        "ole",
        "OLE2 compound file (legacy Office / MSI)",
        "document",
        "doc dot xls xlt ppt pps pot msi msg msp mst vsd pub mpp db suo wps xlb",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    ),
    # archives
    _sig(
        "zip",
        "ZIP archive (or ZIP-based format)",
        "archive",
        "zip docx xlsx pptx odt ods odp jar war apk aar epub xpi vsix nupkg whl egg kmz cbz "
        "xps msix appx ipa crx 3mf",
        b"PK\x03\x04",
        b"PK\x05\x06",
    ),
    _sig("rar", "RAR archive", "archive", "rar", b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"),
    _sig("7z", "7-Zip archive", "archive", "7z", b"7z\xbc\xaf\x27\x1c"),
    _sig("gzip", "GZIP archive", "archive", "gz tgz svgz gzip", b"\x1f\x8b\x08"),
    _sig("bzip2", "BZIP2 archive", "archive", "bz2 tbz tbz2", b"BZh", validator=_is_bzip2),
    _sig("xz", "XZ archive", "archive", "xz txz lzma", b"\xfd7zXZ\x00"),
    _sig("zstd", "Zstandard archive", "archive", "zst zstd", b"\x28\xb5\x2f\xfd"),
    _sig("tar", "TAR archive", "archive", "tar", (257, b"ustar")),
    # executables (PE is checked before the looser DOS/MZ signature)
    _sig("pe", "PE executable (Windows)", "executable", PE_EXTENSIONS, b"MZ", validator=_is_pe),
    _sig("mz", "DOS/MZ executable", "executable", PE_EXTENSIONS + " com", b"MZ"),
    _sig(
        "elf",
        "ELF executable (Linux/Unix)",
        "executable",
        "elf so o ko bin out axf prx mod",
        b"\x7fELF",
    ),
    _sig(
        "macho",
        "Mach-O executable (macOS)",
        "executable",
        "dylib o bin macho kext bundle",
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
    ),
    # databases
    _sig(
        "sqlite",
        "SQLite database",
        "database",
        "db sqlite sqlite3 db3 sdb sqlitedb dat data store idx cache",
        b"SQLite format 3\x00",
    ),
    # Windows artefacts of forensic interest
    _sig(
        "lnk",
        "Windows shortcut (LNK)",
        "system",
        "lnk",
        b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F",
    ),
    _sig("regf", "Windows registry hive", "system", "dat hiv hive sav", b"regf"),
    _sig("evtx", "Windows event log (EVTX)", "log", "evtx", b"ElfFile\x00"),
    _sig("prefetch", "Windows Prefetch file", "system", "pf", (4, b"SCCA")),
    _sig("minidump", "Windows minidump", "system", "dmp mdmp hdmp", b"MDMP"),
    # network captures
    _sig(
        "pcap",
        "PCAP capture",
        "network",
        "pcap cap dmp",
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    ),
    _sig("pcapng", "PCAPNG capture", "network", "pcapng ntar", b"\x0a\x0d\x0d\x0a"),
    # media
    _sig("mp3", "MP3 audio (ID3)", "media", "mp3", b"ID3"),
    _sig(
        "isobmff",
        "ISO media (MP4/MOV/HEIC)",
        "media",
        "mp4 m4a m4v m4b mov qt 3gp 3g2 f4v heic heif avif cr3",
        (4, b"ftyp"),
    ),
    _sig("riff", "RIFF container (WAV/AVI/WEBP)", "media", "wav avi webp ani rmi", b"RIFF"),
)

TEXT = Signature("text", "Text", "text", (), ())

_NON_TEXT_DELETE = (
    bytes(range(0x20, 0x7F)) + b"\t\n\r\f\b\x1b" + bytes(range(0x80, 0x100))
)  # every byte that is acceptable inside a text file


def looks_like_text(head: bytes) -> bool:
    """Heuristic: BOM or (no NUL bytes and <= 5 % control characters)."""
    if not head:
        return False
    if head.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\x00" in head:
        return False
    suspicious = len(head.translate(None, _NON_TEXT_DELETE))
    return suspicious / len(head) <= 0.05


def detect_type(head: bytes) -> Signature | None:
    """Identify a file from its first bytes; returns ``None`` for unknown binary data."""
    for signature in SIGNATURES:
        if signature.matches(head):
            return signature
    if looks_like_text(head):
        return TEXT
    return None


def get_extension(filename: str) -> str:
    """Lower-case extension without the dot. Ignores dotfiles and trailing version numbers
    (``libc.so.6`` -> ``so``)."""
    parts = filename.lower().split(".")
    if len(parts) < 2 or (len(parts) == 2 and parts[0] == ""):
        return ""
    while parts[-1].isdigit() and len(parts) > 2:
        parts.pop()
    return parts[-1]


def extension_matches(signature: Signature, extension: str) -> bool:
    """True when the extension is plausible for the detected format (or cannot be judged)."""
    return not signature.extensions or not extension or extension in signature.extensions
