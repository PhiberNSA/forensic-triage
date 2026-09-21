import os
import tempfile
import unittest
from pathlib import Path

from ftriage import samples
from ftriage.scanner import (
    FLAG_DISGUISED_EXEC,
    FLAG_EMPTY,
    FLAG_EXT_MISMATCH,
    FLAG_HIGH_ENTROPY,
    scan_path,
)


class ScannerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "sub").mkdir()
        files = {
            "photo.jpg": samples.make_jpeg(),
            "holiday.jpg": samples.make_pe_stub(),  # PE pretending to be a photo
            "blob.dat": samples.make_random(4096, seed=1),
            "empty.txt": b"",
            "notes.txt": b"nothing to see here\n",
            "sub/nested.png": samples.make_png(),
        }
        for name, content in files.items():
            (self.root / name).write_bytes(content)
        self.records = {r.path: r for r in scan_path(self.root)}

    def test_finds_every_regular_file_with_relative_posix_paths(self):
        self.assertEqual(
            set(self.records),
            {"photo.jpg", "holiday.jpg", "blob.dat", "empty.txt", "notes.txt", "sub/nested.png"},
        )

    def test_clean_files_have_no_flags(self):
        for name in ("photo.jpg", "notes.txt", "sub/nested.png"):
            self.assertEqual(self.records[name].flags, [], name)

    def test_executable_disguised_as_image_is_flagged(self):
        record = self.records["holiday.jpg"]
        self.assertEqual(record.file_type, "PE executable (Windows)")
        self.assertIn(FLAG_EXT_MISMATCH, record.flags)
        self.assertIn(FLAG_DISGUISED_EXEC, record.flags)
        self.assertIn(FLAG_HIGH_ENTROPY, record.flags)

    def test_random_unknown_data_is_high_entropy(self):
        record = self.records["blob.dat"]
        self.assertIsNone(record.file_type)
        self.assertGreater(record.entropy, 7.9)
        self.assertEqual(record.flags, [FLAG_HIGH_ENTROPY])

    def test_empty_file(self):
        record = self.records["empty.txt"]
        self.assertEqual(record.flags, [FLAG_EMPTY])
        self.assertEqual(record.hashes["md5"], "d41d8cd98f00b204e9800998ecf8427e")

    def test_hashes_sizes_and_timestamps(self):
        record = self.records["notes.txt"]
        self.assertEqual(set(record.hashes), {"md5", "sha1", "sha256"})
        self.assertEqual(record.size, len(b"nothing to see here\n"))
        self.assertTrue(record.modified.endswith("Z"))

    def test_compressed_formats_do_not_trigger_the_entropy_flag(self):
        self.assertNotIn(FLAG_HIGH_ENTROPY, self.records["sub/nested.png"].flags)

    def test_stat_only_mode_does_not_read_content(self):
        records = list(scan_path(self.root, analyze=False))
        self.assertEqual(len(records), 6)
        for record in records:
            self.assertEqual(record.hashes, {})
            self.assertIsNone(record.entropy)

    def test_scanning_a_single_file(self):
        records = list(scan_path(self.root / "notes.txt"))
        self.assertEqual([r.path for r in records], ["notes.txt"])

    def test_symlinks_are_skipped(self):
        try:
            os.symlink(self.root / "notes.txt", self.root / "link.txt")
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("symlinks not available")
        self.assertNotIn("link.txt", {r.path for r in scan_path(self.root)})

    @unittest.skipIf(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        "needs a non-root POSIX user to make a file unreadable",
    )
    def test_unreadable_file_is_reported_not_fatal(self):
        secret = self.root / "secret.bin"
        secret.write_bytes(b"x" * 10)
        secret.chmod(0)
        self.addCleanup(secret.chmod, 0o600)
        record = {r.path: r for r in scan_path(self.root)}["secret.bin"]
        self.assertIn("PermissionError", record.error)


if __name__ == "__main__":
    unittest.main()
