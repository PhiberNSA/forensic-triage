import tempfile
import unittest
from pathlib import Path

from ftriage import samples
from ftriage.strings_iocs import defang, extract_iocs, extract_strings, iter_file_strings


class StringExtractionTests(unittest.TestCase):
    def test_ascii_and_utf16_with_offsets(self):
        data = b"\x01\x02hello world\x00\x03" + "wide text".encode("utf-16le") + b"\x00\x00"
        found = {(s.encoding, s.value): s.offset for s in extract_strings(data)}
        self.assertEqual(found[("ascii", "hello world")], 2)
        self.assertIn(("utf-16le", "wide text"), found)

    def test_min_length_and_encoding_selection(self):
        data = b"abc\x00abcdefgh\x00"
        self.assertEqual([s.value for s in extract_strings(data, min_length=4)], ["abcdefgh"])
        self.assertEqual(list(extract_strings(data, encodings=["utf-16le"])), [])
        with self.assertRaises(ValueError):
            list(extract_strings(data, min_length=0))

    def test_from_file_including_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp, "empty")
            empty.write_bytes(b"")
            self.assertEqual(list(iter_file_strings(empty)), [])
            stub = Path(tmp, "stub")
            stub.write_bytes(samples.make_pe_stub())
            values = {s.value for s in iter_file_strings(stub)}
            self.assertIn(samples.DEMO_URL, values)
            self.assertIn(samples.DEMO_REGKEY, values)  # UTF-16LE inside the file


class IocTests(unittest.TestCase):
    def test_extracts_each_indicator_kind(self):
        iocs = extract_iocs(
            [
                "download from https://evil.example/a.bin, then run",
                "beacon 203.0.113.42:8080 and mail bad.guy@evil.example.",
                r"persist via HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\x",
            ]
        )
        self.assertEqual(iocs["url"], ["https://evil.example/a.bin"])  # trailing comma removed
        self.assertEqual(iocs["ipv4"], ["203.0.113.42"])
        self.assertEqual(iocs["email"], ["bad.guy@evil.example"])
        self.assertEqual(len(iocs["registry_key"]), 1)

    def test_invalid_ips_and_version_strings_are_ignored(self):
        iocs = extract_iocs(["999.1.1.1", "1.2.3.4.5", "10.0.19041.1", "version 300.300.300.300"])
        self.assertNotIn("ipv4", iocs)

    def test_results_are_unique_and_sorted(self):
        iocs = extract_iocs(["9.9.9.9 1.1.1.1", "1.1.1.1"])
        self.assertEqual(iocs["ipv4"], ["1.1.1.1", "9.9.9.9"])

    def test_defang(self):
        self.assertEqual(defang("url", "http://a.example/x"), "hxxp://a[.]example/x")
        self.assertEqual(defang("url", "https://a.example"), "hxxps://a[.]example")
        self.assertEqual(defang("ipv4", "1.2.3.4"), "1[.]2[.]3[.]4")
        self.assertEqual(defang("email", "a@b.example"), "a[@]b[.]example")
        self.assertEqual(defang("registry_key", r"HKEY_USERS\x"), r"HKEY_USERS\x")


if __name__ == "__main__":
    unittest.main()
