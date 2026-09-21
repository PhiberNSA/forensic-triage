"""Command-line interface: ``ftriage scan | carve | strings | timeline | demo``."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .carver import CARVE_SPECS, DEFAULT_MAX_SIZE, DEFAULT_MIN_SIZE, MIB, carve_image
from .hashing import DEFAULT_ALGORITHMS, hash_file
from .report import (
    ensure_dir,
    flagged,
    summarize,
    write_carve_report,
    write_csv,
    write_json,
    write_markdown,
    write_timeline_csv,
)
from .samples import build_demo
from .scanner import DEFAULT_ENTROPY_THRESHOLD, scan_path
from .strings_iocs import DEFAULT_MIN_LENGTH, defang, extract_iocs, iter_file_strings
from .timeline import build_timeline
from .utils import format_size, utc_now

SCAN_FORMATS = ("json", "csv", "md", "timeline")


def _csv_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _tool_meta() -> dict:
    return {"name": "ftriage", "version": __version__}


# --------------------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------------------
def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        raise ValueError(f"path does not exist: {target}")
    algorithms = _csv_list(args.algorithms) or list(DEFAULT_ALGORITHMS)
    formats = _csv_list(args.formats)
    for fmt in formats:
        if fmt not in SCAN_FORMATS:
            raise ValueError(f"unknown format {fmt!r} (choose from: {', '.join(SCAN_FORMATS)})")

    started = utc_now()
    clock = time.perf_counter()
    records = list(
        scan_path(target, algorithms=algorithms, entropy_threshold=args.entropy_threshold)
    )
    elapsed = time.perf_counter() - clock
    finished = utc_now()
    summary = summarize(records)

    print(f"ftriage {__version__} - scanned {target}")
    print(
        f"  {summary['files']} files, {format_size(summary['bytes'])} in {elapsed:.2f}s "
        f"({', '.join(algorithms)})"
    )
    if summary["by_category"]:
        print("\nBy category:")
        for category, count in summary["by_category"].items():
            print(f"  {category:<12} {count}")
    hits = flagged(records)
    print(f"\nFindings ({len(hits)}):" if hits else "\nFindings: none")
    for record in hits:
        print(
            f"  [{', '.join(record.flags)}]\n"
            f"      {record.path} - {record.file_type or 'unknown type'}, "
            f"entropy {record.entropy}"
        )
    if summary["errors"]:
        print(f"\n{summary['errors']} path(s) could not be read (see report).")

    if args.output:
        out_dir = ensure_dir(args.output)
        meta = {
            "tool": _tool_meta(),
            "scan": {
                "target": str(target.resolve()),
                "started_utc": started,
                "finished_utc": finished,
                "algorithms": algorithms,
                "entropy_threshold": args.entropy_threshold,
            },
        }
        written = []
        if "json" in formats:
            write_json(out_dir / "triage.json", meta, records)
            written.append("triage.json")
        if "csv" in formats:
            write_csv(out_dir / "triage.csv", records, algorithms)
            written.append("triage.csv")
        if "md" in formats:
            write_markdown(out_dir / "triage.md", meta, records)
            written.append("triage.md")
        if "timeline" in formats:
            write_timeline_csv(out_dir / "timeline.csv", build_timeline(records))
            written.append("timeline.csv")
        print(f"\nReports written to {out_dir}: {', '.join(written)}")
    return 0


# --------------------------------------------------------------------------------------
# timeline
# --------------------------------------------------------------------------------------
def cmd_timeline(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        raise ValueError(f"path does not exist: {target}")
    events = build_timeline(scan_path(target, analyze=False))
    if args.output:
        write_timeline_csv(args.output, events)
        print(f"{len(events)} timeline rows written to {args.output}")
    else:
        for event in events:
            print(f"{event.timestamp}  {event.macb}  {event.size:>10}  {event.path}")
    return 0


# --------------------------------------------------------------------------------------
# carve
# --------------------------------------------------------------------------------------
def cmd_carve(args: argparse.Namespace) -> int:
    image = Path(args.image)
    if not image.is_file():
        raise ValueError(f"image file not found: {image}")
    started = utc_now()
    carved = carve_image(
        image,
        args.output,
        types=_csv_list(args.types) or None,
        max_size=args.max_size * MIB,
        min_size=args.min_size,
    )
    meta = {
        "tool": _tool_meta(),
        "carve": {
            "image": str(image.resolve()),
            "image_size": image.stat().st_size,
            "started_utc": started,
            "finished_utc": utc_now(),
            "max_size": args.max_size * MIB,
            "min_size": args.min_size,
        },
    }
    if args.hash_image:
        meta["carve"]["image_sha256"] = hash_file(image, ("sha256",))["sha256"]

    print(f"ftriage {__version__} - carved {len(carved)} file(s) from {image}")
    if carved:
        print(f"\n  {'#':>3}  {'offset':<12} {'size':>10}  {'type':<5} {'sha256':<14} file")
        for item in carved:
            print(
                f"  {item.index:>3}  {item.offset:#012x} {format_size(item.size):>10}  "
                f"{item.type:<5} {item.sha256[:12]}..  {item.filename}"
            )
        write_carve_report(
            Path(args.output) / "carve_report.json", meta, [c.to_dict() for c in carved]
        )
        print(f"\nFiles and carve_report.json written to {args.output}")
    return 0


# --------------------------------------------------------------------------------------
# strings
# --------------------------------------------------------------------------------------
def cmd_strings(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        raise ValueError(f"file not found: {path}")
    encodings = ("ascii", "utf-16le") if args.encoding == "all" else (args.encoding,)
    found = iter_file_strings(path, args.min_length, encodings)

    if args.iocs:
        iocs = extract_iocs(item.value for item in found)
        if args.defang:
            iocs = {k: [defang(k, v) for v in vs] for k, vs in iocs.items()}
        if args.json:
            print(json.dumps({"file": str(path), "iocs": iocs}, indent=2))
        elif not iocs:
            print("No indicators found.")
        else:
            for kind, values in iocs.items():
                print(f"{kind} ({len(values)})")
                for value in values:
                    print(f"  {value}")
        return 0

    if args.json:
        rows = [{"offset": s.offset, "encoding": s.encoding, "value": s.value} for s in found]
        print(json.dumps({"file": str(path), "strings": rows}, indent=2))
    else:
        for item in found:
            print(f"{item.offset:#010x}  {item.encoding:<8}  {item.value}")
    return 0


# --------------------------------------------------------------------------------------
# demo
# --------------------------------------------------------------------------------------
def cmd_demo(args: argparse.Namespace) -> int:
    dest = Path(args.directory)
    if dest.exists() and any(dest.iterdir()) and not args.force:
        raise ValueError(f"{dest} is not empty (use --force to write into it anyway)")
    info = build_demo(dest)
    print(f"Synthetic demo data created in {dest}/")
    print(f"  {info['evidence']}/   9 files, some of them suspicious")
    print(f"  {info['image']}        raw image with 5 files hidden in random noise")
    print("\nTry:")
    print(f"  ftriage scan {info['evidence']} -o report")
    print(f"  ftriage carve {info['image']} -o carved")
    print(f"  ftriage strings {info['evidence'] / 'holiday.jpg'} --iocs --defang")
    print(f"  ftriage timeline {info['evidence']}")
    return 0


# --------------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ftriage",
        description="Digital forensics triage toolkit: hashing, file-type & entropy analysis, "
        "file carving, string/IOC extraction and MACB timelines. Read-only, no dependencies.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    scan = sub.add_parser("scan", help="hash, identify and score every file below a path")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument("-o", "--output", metavar="DIR", help="write reports into DIR")
    scan.add_argument(
        "--formats",
        default=",".join(SCAN_FORMATS),
        help="report formats when -o is used (default: %(default)s)",
    )
    scan.add_argument(
        "--algorithms",
        default=",".join(DEFAULT_ALGORITHMS),
        help="comma-separated hash algorithms: md5, sha1, sha256, sha512 (default: %(default)s)",
    )
    scan.add_argument(
        "--entropy-threshold",
        type=float,
        default=DEFAULT_ENTROPY_THRESHOLD,
        help="flag files at or above this entropy, 0-8 (default: %(default)s)",
    )
    scan.set_defaults(func=cmd_scan)

    timeline = sub.add_parser("timeline", help="MACB timeline from file-system timestamps")
    timeline.add_argument("path")
    timeline.add_argument("-o", "--output", metavar="FILE", help="write CSV instead of printing")
    timeline.set_defaults(func=cmd_timeline)

    carve = sub.add_parser("carve", help="recover files from a raw disk image")
    carve.add_argument("image", help="raw image (dd, .img, .raw ...) - opened read-only")
    carve.add_argument("-o", "--output", metavar="DIR", required=True, help="output directory")
    carve.add_argument(
        "--types",
        default="",
        help=f"comma-separated subset of: {', '.join(CARVE_SPECS)} (default: all)",
    )
    carve.add_argument(
        "--max-size",
        type=int,
        default=DEFAULT_MAX_SIZE // MIB,
        metavar="MIB",
        help="largest file to carve, in MiB (default: %(default)s)",
    )
    carve.add_argument(
        "--min-size",
        type=int,
        default=DEFAULT_MIN_SIZE,
        metavar="BYTES",
        help="smallest file to carve (default: %(default)s)",
    )
    carve.add_argument("--hash-image", action="store_true", help="record the image SHA-256")
    carve.set_defaults(func=cmd_carve)

    strings = sub.add_parser("strings", help="extract strings (ASCII + UTF-16LE) and IOCs")
    strings.add_argument("file")
    strings.add_argument("-n", "--min-length", type=int, default=DEFAULT_MIN_LENGTH)
    strings.add_argument(
        "--encoding", choices=("all", "ascii", "utf-16le"), default="all", help="(default: all)"
    )
    strings.add_argument("--iocs", action="store_true", help="only report URLs, IPs, e-mails, ...")
    strings.add_argument("--defang", action="store_true", help="defang indicators (hxxp, [.])")
    strings.add_argument("--json", action="store_true", help="JSON output")
    strings.set_defaults(func=cmd_strings)

    demo = sub.add_parser("demo", help="generate harmless synthetic sample data to play with")
    demo.add_argument("directory")
    demo.add_argument("--force", action="store_true", help="write into a non-empty directory")
    demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):  # file names may not be printable in the console
            stream.reconfigure(errors="backslashreplace")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:  # e.g. `ftriage strings x | head` - not an error
        try:  # stop Python from complaining again while flushing stdout at exit
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError, AttributeError):
            pass
        return 0
    except (OSError, ValueError) as exc:
        print(f"ftriage: error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nftriage: interrupted", file=sys.stderr)
        return 130
