import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from ftriage import __version__, samples
from ftriage.cli import main


def run(*argv):
    """Run the CLI, returning ``(exit_code, stdout, stderr)``."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in argv])
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.demo = self.tmp / "demo"
        code, _, _ = run("demo", self.demo)
        self.assertEqual(code, 0)

    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as raised:
            main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn(__version__, out.getvalue())

    def test_scan_writes_all_reports(self):
        report = self.tmp / "report"
        code, out, _ = run("scan", self.demo / "evidence", "-o", report)
        self.assertEqual(code, 0)
        self.assertIn("Findings (4)", out)
        self.assertEqual(
            sorted(p.name for p in report.iterdir()),
            ["timeline.csv", "triage.csv", "triage.json", "triage.md"],
        )

        document = json.loads((report / "triage.json").read_text(encoding="utf-8"))
        self.assertEqual(document["summary"]["files"], 9)
        flagged = {f["path"] for f in document["files"] if f["flags"]}
        self.assertEqual(flagged, {"holiday.jpg", "cleanup.sh", "data.bin", "logo.png"})

        with open(report / "triage.csv", newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 9)
        self.assertIn("sha256", rows[0])
        self.assertIn("## Findings", (report / "triage.md").read_text(encoding="utf-8"))

    def test_scan_formats_and_algorithms(self):
        report = self.tmp / "only-json"
        code, _, _ = run(
            "scan", self.demo / "evidence", "-o", report,
            "--formats", "json", "--algorithms", "sha256",
        )  # fmt: skip
        self.assertEqual(code, 0)
        self.assertEqual([p.name for p in report.iterdir()], ["triage.json"])
        document = json.loads((report / "triage.json").read_text(encoding="utf-8"))
        self.assertEqual(set(document["files"][0]["hashes"]), {"sha256"})

    def test_carve_recovers_the_five_hidden_files(self):
        out_dir = self.tmp / "carved"
        code, out, _ = run("carve", self.demo / "disk.img", "-o", out_dir, "--hash-image")
        self.assertEqual(code, 0)
        self.assertIn("carved 5 file(s)", out)
        report = json.loads((out_dir / "carve_report.json").read_text(encoding="utf-8"))
        types = [c["type"] for c in report["carved"]]
        self.assertEqual(types, ["png", "jpeg", "gif", "pdf", "zip"])
        self.assertEqual(len(report["carve"]["image_sha256"]), 64)
        expected = [
            samples.make_png(48, 48),
            samples.make_jpeg(),
            samples.make_gif(),
            samples.make_pdf("Recovered"),
            samples.make_zip(),
        ]
        for entry, original in zip(report["carved"], expected):
            self.assertEqual((out_dir / entry["filename"]).read_bytes(), original)

    def test_strings_iocs_json_and_defang(self):
        target = self.demo / "evidence" / "holiday.jpg"
        code, out, _ = run("strings", target, "--iocs", "--json", "--defang")
        self.assertEqual(code, 0)
        iocs = json.loads(out)["iocs"]
        self.assertEqual(iocs["url"], ["hxxp://update[.]evil[.]example/stage2[.]bin"])
        self.assertEqual(iocs["ipv4"], ["203[.]0[.]113[.]42"])

    def test_timeline_is_chronological_and_can_be_saved(self):
        code, out, _ = run("timeline", self.demo / "evidence")
        self.assertEqual(code, 0)
        stamps = [line.split()[0] for line in out.splitlines()]
        self.assertEqual(stamps, sorted(stamps))
        self.assertTrue(stamps[0].startswith("2026-08-30T09:00:00"))

        target = self.tmp / "timeline.csv"
        code, _, _ = run("timeline", self.demo / "evidence", "-o", target)
        self.assertEqual(code, 0)
        self.assertTrue(target.read_text(encoding="utf-8").startswith("timestamp_utc,macb,"))

    def test_errors_return_exit_code_1(self):
        self.assertEqual(run("scan", self.tmp / "missing")[0], 1)
        bad_type = run("carve", self.demo / "disk.img", "-o", self.tmp / "o", "--types", "exe")
        self.assertEqual(bad_type[0], 1)
        self.assertEqual(run("scan", self.demo, "--algorithms", "crc32")[0], 1)
        code, _, err = run("demo", self.demo)  # not empty any more
        self.assertEqual(code, 1)
        self.assertIn("not empty", err)


if __name__ == "__main__":
    unittest.main()
