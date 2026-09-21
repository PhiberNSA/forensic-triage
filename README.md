# ftriage

**A zero-dependency digital forensics triage toolkit.** Hash, identify and score files, carve files out of raw disk images, harvest indicators of compromise and build MACB timelines. Read-only by design, pure Python standard library.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

## Why

When you receive a folder or a disk image, the first minutes decide where you look next. `ftriage` answers the first questions quickly, offline, and without installing anything except Python:

- What is in here, and does each file *look like* what it claims to be?
- Is anything packed, encrypted or disguised (an executable named `holiday.jpg`)?
- Are there files hiding in the raw image that the file system no longer lists?
- Which indicators (URLs, IPs, e-mails, registry keys) are embedded in these files?
- What happened, and in which order?

## Commands

| Command | What it does |
|---|---|
| `ftriage scan` | Hashes (MD5/SHA-1/SHA-256/SHA-512), identifies the true file type from its magic bytes, computes Shannon entropy and flags suspicious files. Writes JSON, CSV, Markdown and timeline reports. |
| `ftriage carve` | Recovers JPEG, PNG, GIF, PDF and ZIP files from a raw image using **structure-aware** carving. |
| `ftriage strings` | Extracts ASCII and UTF-16LE strings; with `--iocs` reports URLs, IPv4 addresses, e-mails and registry keys (optionally defanged). |
| `ftriage timeline` | Builds a chronological MACB timeline from file-system timestamps. |
| `ftriage demo` | Generates harmless synthetic sample data so you can try everything immediately. |

### Flags raised by `scan`

| Flag | Meaning |
|---|---|
| `EXT_MISMATCH` | The extension does not belong to the detected format (a GIF called `logo.png`). |
| `DISGUISED_EXECUTABLE` | PE / ELF / Mach-O content behind a non-executable extension. The one to look at first. |
| `HIGH_ENTROPY` | Entropy at or above the threshold (default 7.5 bits/byte) in a file that is *not* a normally compressed format, which points to packed or encrypted data. |
| `EMPTY` | Zero-byte file. |

## Install

```bash
git clone https://github.com/PhiberNSA/forensic-triage.git
cd forensic-triage
pip install .
```

No install? Run it straight from the checkout: `PYTHONPATH=src python -m ftriage --help`

## Quick start

```console
$ ftriage demo demo                      # creates demo/evidence/ and demo/disk.img
$ ftriage timeline demo/evidence
2026-08-30T09:00:00.000000Z  MA..          43  logo.png
2026-09-01T18:45:00.000000Z  MA..         722  photo.jpg
2026-09-01T18:46:30.000000Z  MA..        1796  beach.png
2026-09-10T08:30:00.000000Z  MA..         586  invoice.pdf
2026-09-12T14:00:00.000000Z  MA..         368  archive.zip
2026-09-14T03:12:40.000000Z  MA..       17111  holiday.jpg
2026-09-14T03:15:02.000000Z  MA..          64  cleanup.sh
2026-09-14T03:20:11.000000Z  MA..       32768  data.bin
2026-09-18T16:05:00.000000Z  MA..         177  notes.txt
```

```console
$ ftriage scan demo/evidence -o report
ftriage 0.1.0 - scanned demo/evidence
  9 files, 52.4 KiB in 0.00s (md5, sha1, sha256)

By category:
  archive      1
  document     1
  executable   2
  image        3
  text         1
  unknown      1

Findings (4):
  [EXT_MISMATCH, DISGUISED_EXECUTABLE]
      cleanup.sh - ELF executable (Linux/Unix), entropy 0.7738
  [HIGH_ENTROPY]
      data.bin - unknown type, entropy 7.9948
  [EXT_MISMATCH, DISGUISED_EXECUTABLE, HIGH_ENTROPY]
      holiday.jpg - PE executable (Windows), entropy 7.9142
  [EXT_MISMATCH]
      logo.png - GIF image, entropy 3.0315

Reports written to report: triage.json, triage.csv, triage.md, timeline.csv
```

```console
$ ftriage carve demo/disk.img -o carved
ftriage 0.1.0 - carved 5 file(s) from demo/disk.img

    #  offset             size  type  sha256         file
    1  0x0000001000    4.1 KiB  png   b4c161028b8c..  00001_0000001000.png
    2  0x0000002800      722 B  jpeg  2512c9617a84..  00002_0000002800.jpg
    3  0x0000003800       43 B  gif   693d949d8c3f..  00003_0000003800.gif
    4  0x0000004000      583 B  pdf   8b0c4a13c7fe..  00004_0000004000.pdf
    5  0x0000004c00      368 B  zip   b160737b4cf8..  00005_0000004c00.zip

Files and carve_report.json written to carved
```

```console
$ ftriage strings demo/evidence/holiday.jpg --iocs --defang
url (1)
  hxxp://update[.]evil[.]example/stage2[.]bin
ipv4 (1)
  203[.]0[.]113[.]42
email (1)
  drop[@]evil[.]example
registry_key (1)
  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater
```

All demo data is synthetic and inert: the "executables" are stubs that only carry the magic bytes, and every indicator uses reserved documentation values (RFC 5737 IP ranges, the `.example` / `.test` TLDs).

## How it works

**Identification.** About 30 formats are recognised by their magic bytes, including offset-based ones (Prefetch, TAR, MP4) and validated ones (a `PE` needs an `MZ` header whose `e_lfanew` really points at `PE\0\0`). The extension is only used to *compare* against the content, never to decide the type.

**Entropy.** Shannon entropy over the whole file, computed in the same single pass as the hashes. Formats that are compressed by nature (images, archives, media, PDFs) are exempt from `HIGH_ENTROPY`, otherwise every JPEG would be flagged.

**Carving.** Naive carvers cut from a header to the first footer, which breaks on real files. `ftriage` gives each format an *end finder* that walks the internal structure:

| Format | Classic trap | What `ftriage` does |
|---|---|---|
| JPEG | An EXIF thumbnail is a complete JPEG inside the file, so the first `FFD9` is the wrong end. | Walks marker segments (skipping APPn payloads) and the entropy-coded scan data until EOI. |
| PNG | Chunk data can contain anything. | Walks the chunk list, validating chunk types, until `IEND`. |
| GIF | The trailer byte `3B` also occurs in image data. | Walks extension and image blocks until the real trailer. |
| ZIP | A ZIP stored inside a ZIP has its own end-of-central-directory record. | Accepts only an EOCD whose central directory ends exactly where it begins. |
| PDF | Linearised PDFs and incremental updates contain several `%%EOF` markers. | Uses the last `%%EOF` before the next PDF header. |

All formats are scanned in one pass, and a hit that lies inside an already carved file is skipped, so a JPEG embedded in a PDF is not reported twice.

**Timeline.** One row per distinct timestamp and file. Timestamps that share a value are merged into a MACB string (`M` modified, `A` accessed, `C` metadata change, `B` birth), like `mactime` does. Everything is in UTC.

## Reports

`ftriage scan -o DIR` writes:

- `triage.json`: everything (tool version, target, timings, summary, one object per file)
- `triage.csv`: one row per file, easy to open in a spreadsheet or `pandas`
- `triage.md`: a human-readable report with summary, findings and inventory
- `timeline.csv`: the MACB timeline

Use `--formats json,md` to choose, `--algorithms sha256` to hash less, `--entropy-threshold 7.2` to be stricter.

## Forensic hygiene

- Work on a **copy**, a read-only mount or behind a write blocker. `ftriage` opens everything read-only and skips symlinks and special files, but the operating system may still update access times when files are read.
- `ftriage` captures a file's timestamps *before* it reads the file, so its own report is not affected by its own reads. A second scan of the same tree, however, may show changed access times.
- Write reports **outside** the evidence tree.
- Hash the image before and after (`ftriage carve --hash-image` records its SHA-256).
- `C` means metadata-change time on Unix but creation time on Windows (Python < 3.12 semantics). Interpret timelines with the OS in mind.

## Limitations

- Carving assumes files are stored **contiguously**; fragmented files are not reconstructed.
- Only JPEG, PNG, GIF, PDF and ZIP (which includes DOCX/XLSX/JAR/APK) are carved. Only the first 64 KiB of a file is used for identification.
- Entropy is a heuristic, not proof of encryption.
- The IOC patterns are intentionally simple and produce false positives (a version string such as `1.2.3.4` looks like an IPv4 address).
- UTF-16 string detection can absorb the last character of a directly preceding NUL-terminated ASCII string, as GNU `strings -el` does.
- Not a replacement for Autopsy, The Sleuth Kit, Volatility or plaso. It is a fast first look.

## Project layout

```
src/ftriage/
├── cli.py            argparse front-end (scan, carve, strings, timeline, demo)
├── scanner.py        directory walk, hashing, type detection, flags
├── signatures.py     magic-byte database and extension logic
├── carver.py         structure-aware end finders + single-pass carving
├── strings_iocs.py   string extraction, IOC regexes, defanging
├── entropy.py        streaming Shannon entropy
├── hashing.py        multi-algorithm streaming hashes
├── timeline.py       MACB timeline
├── report.py         JSON / CSV / Markdown writers
├── samples.py        synthetic, harmless sample data (tests + demo)
└── utils.py
tests/                unit tests (standard library only)
```

## Development

```bash
python -m unittest -v      # no test dependencies needed
```

CI runs the suite on Linux, Windows and macOS with Python 3.10-3.13 and smoke-tests the CLI.

## Roadmap

- [ ] PE / ELF header parser (sections, imports, per-section entropy)
- [ ] HTML report
- [ ] More carvers: SQLite, RAR, 7z, OLE2 (legacy Office)
- [ ] Known-good / known-bad hash lists (NSRL-style filtering)
- [ ] Parsers for Windows artefacts: Prefetch, LNK, EVTX
- [ ] Optional YARA rule matching during `scan`

Contributions and ideas are welcome, please open an issue.

## Legal

Only analyse data you are authorised to examine. This project is for defensive security, education and incident response.

## License

[MIT](LICENSE)
