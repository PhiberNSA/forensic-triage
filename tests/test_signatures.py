import unittest

from ftriage import samples
from ftriage.signatures import (
    detect_type,
    extension_matches,
    get_extension,
    looks_like_text,
)


class DetectTypeTests(unittest.TestCase):
    def key(self, data: bytes):
        signature = detect_type(data)
        return signature.key if signature else None

    def test_common_formats(self):
        self.assertEqual(self.key(samples.make_png()), "png")
        self.assertEqual(self.key(samples.make_jpeg()), "jpeg")
        self.assertEqual(self.key(samples.make_gif()), "gif")
        self.assertEqual(self.key(samples.make_pdf()), "pdf")
        self.assertEqual(self.key(samples.make_zip()), "zip")
        self.assertEqual(self.key(samples.make_elf_stub()), "elf")

    def test_pe_is_distinguished_from_plain_mz(self):
        self.assertEqual(self.key(samples.make_pe_stub()), "pe")
        self.assertEqual(self.key(b"MZ" + bytes(200)), "mz")

    def test_signature_at_a_non_zero_offset(self):
        prefetch = b"\x17\x00\x00\x00SCCA" + bytes(100)
        self.assertEqual(self.key(prefetch), "prefetch")

    def test_bzip2_needs_a_valid_block_size(self):
        self.assertEqual(self.key(b"BZh9" + bytes(20)), "bzip2")
        self.assertNotEqual(self.key(b"BZhello world"), "bzip2")

    def test_text_and_unknown_binary(self):
        self.assertEqual(self.key(b"just some plain text\nwith two lines\n"), "text")
        self.assertIsNone(detect_type(bytes(range(256)) * 4))
        self.assertIsNone(detect_type(b""))

    def test_looks_like_text_rejects_nul_bytes(self):
        self.assertTrue(looks_like_text("café ünïcode\n".encode()))
        self.assertFalse(looks_like_text(b"abc\x00def"))


class ExtensionTests(unittest.TestCase):
    def test_get_extension(self):
        self.assertEqual(get_extension("Photo.JPG"), "jpg")
        self.assertEqual(get_extension("archive.tar.gz"), "gz")
        self.assertEqual(get_extension("libc.so.6"), "so")
        self.assertEqual(get_extension(".bashrc"), "")
        self.assertEqual(get_extension("Makefile"), "")

    def test_extension_matches(self):
        jpeg = detect_type(samples.make_jpeg())
        zip_ = detect_type(samples.make_zip())
        text = detect_type(b"hello world")
        self.assertTrue(extension_matches(jpeg, "jpg"))
        self.assertFalse(extension_matches(jpeg, "exe"))
        self.assertTrue(extension_matches(jpeg, ""))  # no extension -> cannot judge
        self.assertTrue(extension_matches(zip_, "docx"))  # Office files are ZIP containers
        self.assertTrue(extension_matches(text, "anything"))


if __name__ == "__main__":
    unittest.main()
