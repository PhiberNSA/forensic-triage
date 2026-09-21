"""Report writers: JSON, CSV, Markdown and timeline CSV."""

from __future__ import annotations

import csv
import json
import os
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import asdict
from pathlib import Path

from .scanner import FileRecord
from .timeline import TimelineEvent
from .utils import format_size

MAX_INVENTORY_ROWS = 500


def summarize(records: Sequence[FileRecord]) -> dict:
    ok = [r for r in records if not r.error]
    return {
        "files": len(ok),
        "bytes": sum(r.size for r in ok),
        "errors": len(records) - len(ok),
        "by_category": dict(sorted(Counter(r.category or "unknown" for r in ok).items())),
        "by_type": dict(sorted(Counter(r.file_type or "unknown" for r in ok).items())),
        "flags": dict(sorted(Counter(f for r in ok for f in r.flags).items())),
    }


def flagged(records: Iterable[FileRecord]) -> list[FileRecord]:
    return [r for r in records if r.flags]


def _open_text(path: str | os.PathLike):
    # backslashreplace: file names can contain undecodable bytes (surrogate escapes)
    return open(path, "w", encoding="utf-8", errors="backslashreplace", newline="")


def write_json(path: str | os.PathLike, meta: dict, records: Sequence[FileRecord]) -> None:
    document = {
        **meta,
        "summary": summarize(records),
        "files": [asdict(r) for r in records],
    }
    with _open_text(path) as fh:
        json.dump(document, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def write_csv(
    path: str | os.PathLike, records: Sequence[FileRecord], algorithms: Sequence[str]
) -> None:
    columns = [
        "path", "size", "modified", "accessed", "changed", "created",
        *algorithms, "type", "category", "extension", "entropy", "flags", "error",
    ]  # fmt: skip
    with _open_text(path) as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(columns)
        for r in records:
            writer.writerow(
                [
                    r.path, r.size, r.modified, r.accessed, r.changed, r.created or "",
                    *(r.hashes.get(name, "") for name in algorithms),
                    r.file_type or "", r.category or "", r.extension,
                    "" if r.entropy is None else r.entropy,
                    ";".join(r.flags), r.error or "",
                ]
            )  # fmt: skip


def write_timeline_csv(path: str | os.PathLike, events: Iterable[TimelineEvent]) -> None:
    with _open_text(path) as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(["timestamp_utc", "macb", "size", "path", "sha256"])
        for e in events:
            writer.writerow([e.timestamp, e.macb, e.size, e.path, e.sha256 or ""])


def _md(text: object) -> str:
    return str(text).replace("|", "\\|").replace("`", "'").replace("\n", " ")


def write_markdown(path: str | os.PathLike, meta: dict, records: Sequence[FileRecord]) -> None:
    summary = summarize(records)
    scan = meta["scan"]
    lines = [
        "# Forensic Triage Report",
        "",
        f"- **Tool:** {meta['tool']['name']} {meta['tool']['version']}",
        f"- **Target:** `{_md(scan['target'])}`",
        f"- **Started (UTC):** {scan['started_utc']}",
        f"- **Finished (UTC):** {scan['finished_utc']}",
        f"- **Hash algorithms:** {', '.join(scan['algorithms'])}",
        f"- **Files analysed:** {summary['files']} ({format_size(summary['bytes'])})",
        f"- **Read errors:** {summary['errors']}",
        "",
        "## Summary",
        "",
        "| Category | Files |",
        "|---|---:|",
        *(f"| {_md(cat)} | {n} |" for cat, n in summary["by_category"].items()),
        "",
    ]

    hits = flagged(records)
    lines += ["## Findings", ""]
    if hits:
        lines += [
            "| Flags | Path | Detected type | Entropy | SHA-256 |",
            "|---|---|---|---:|---|",
        ]
        for r in hits:
            sha = r.hashes.get("sha256", "")
            lines.append(
                f"| {_md(', '.join(r.flags))} | `{_md(r.path)}` | {_md(r.file_type or 'unknown')} "
                f"| {r.entropy} | `{sha}` |"
            )
    else:
        lines.append("No findings.")

    errors = [r for r in records if r.error]
    if errors:
        lines += ["", "## Read errors", ""]
        lines += [f"- `{_md(r.path)}` - {_md(r.error)}" for r in errors]

    inventory = [r for r in records if not r.error]
    lines += ["", "## File inventory", ""]
    lines += ["| Path | Size | Type | Entropy | SHA-256 |", "|---|---:|---|---:|---|"]
    for r in inventory[:MAX_INVENTORY_ROWS]:
        lines.append(
            f"| `{_md(r.path)}` | {format_size(r.size)} | {_md(r.file_type or 'unknown')} "
            f"| {r.entropy} | `{r.hashes.get('sha256', '')}` |"
        )
    if len(inventory) > MAX_INVENTORY_ROWS:
        lines.append("")
        lines.append(
            f"_Inventory truncated to {MAX_INVENTORY_ROWS} rows - see the JSON/CSV report for "
            f"all {len(inventory)} files._"
        )

    with _open_text(path) as fh:
        fh.write("\n".join(lines) + "\n")


def write_carve_report(path: str | os.PathLike, meta: dict, files: Sequence[dict]) -> None:
    with _open_text(path) as fh:
        json.dump({**meta, "carved": list(files)}, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def ensure_dir(path: str | os.PathLike) -> Path:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory
