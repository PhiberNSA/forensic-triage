import hashlib
import tempfile
import unittest
from pathlib import Path

from ftriage import samples
from ftriage.carver import CARVE_SPECS, carve_image, find_carvable, select_specs


def carve_bytes(data: bytes, **kwargs):
    specs = select_specs(kwargs.pop("types", None))
    return [(spec.key, start, end) for spec, start, end in find_carvable(data, specs, **kwargs)]


class FindCarvableTests(unittest.TestCase):
    def test_recovers_every_format_at_the_exact_offsets(self):
        blobs = [
            samples.make_png(48, 48),
            samples.make_jpeg(),
            samples.make_gif(),
            samples.make_pdf(),
            samples.make_zip(),
        ]
        image, offsets = samples.build_disk_image(blobs)
        found = carve_bytes(image)
        self.assertEqual([f[0] for f in found], ["png", "jpeg", "gif", "pdf", "zip"])
        for (_, start, end), blob, offset in zip(found, blobs, offsets):
            self.assertEqual(start, offset)
            self.assertEqual(image[start:end], blob)

    def test_jpeg_with_embedded_thumbnail_is_not_cut_short(self):
        jpeg = samples.make_jpeg(exif_thumbnail=True)
        self.assertGreater(jpeg.count(b"\xff\xd9"), 1)  # the trap: more than one FFD9
        image, _ = samples.build_disk_image([jpeg])
        [(key, start, end)] = carve_bytes(image)
        self.assertEqual(image[start:end], jpeg)

    def test_zip_containing_a_zip_is_carved_as_one_file(self):
        archive = samples.make_zip(nested=True)
        self.assertGreater(archive.count(b"PK\x05\x06"), 1)  # inner + outer EOCD
        image, _ = samples.build_disk_image([archive])
        [(key, start, end)] = carve_bytes(image)
        self.assertEqual(image[start:end], archive)

    def test_pdf_with_incremental_update_extends_to_the_last_eof(self):
        pdf = samples.make_pdf() + b"3 0 obj\n<< >>\nendobj\nstartxref\n0\n%%EOF\n"
        image, _ = samples.build_disk_image([pdf, samples.make_pdf("second")])
        found = carve_bytes(image, types=["pdf"])
        self.assertEqual(len(found), 2)
        self.assertEqual(image[found[0][1] : found[0][2]], pdf)

    def test_file_embedded_in_another_is_not_reported_twice(self):
        pdf = b"%PDF-1.4\n% embedded picture follows\n" + samples.make_jpeg() + b"\n%%EOF\n"
        image, _ = samples.build_disk_image([pdf])
        self.assertEqual([f[0] for f in carve_bytes(image)], ["pdf"])

    def test_truncated_files_are_rejected(self):
        for blob in (samples.make_png()[:-20], samples.make_jpeg()[:-30], samples.make_gif()[:-5]):
            image, _ = samples.build_disk_image([blob])
            self.assertEqual(carve_bytes(image), [], blob[:4])

    def test_size_limits_and_type_filter(self):
        image, _ = samples.build_disk_image([samples.make_png(48, 48), samples.make_gif()])
        self.assertEqual([f[0] for f in carve_bytes(image, min_size=100)], ["png"])
        self.assertEqual([f[0] for f in carve_bytes(image, max_size=1000)], ["gif"])
        self.assertEqual([f[0] for f in carve_bytes(image, types=["gif"])], ["gif"])

    def test_noise_without_signatures_yields_nothing(self):
        self.assertEqual(carve_bytes(samples.make_random(200_000, seed=99)), [])

    def test_unknown_type_is_rejected(self):
        with self.assertRaises(ValueError):
            select_specs(["exe"])
        self.assertEqual({s.key for s in select_specs(None)}, set(CARVE_SPECS))


class CarveImageTests(unittest.TestCase):
    def test_writes_files_named_by_offset(self):
        blobs = [samples.make_png(), samples.make_pdf()]
        image, offsets = samples.build_disk_image(blobs)
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp, "disk.img")
            src.write_bytes(image)
            carved = carve_image(src, Path(tmp, "out"))
            self.assertEqual([c.type for c in carved], ["png", "pdf"])
            for item, blob, offset in zip(carved, blobs, offsets):
                self.assertEqual(item.offset, offset)
                self.assertEqual(item.size, len(blob))
                self.assertEqual(item.sha256, hashlib.sha256(blob).hexdigest())
                self.assertEqual(Path(tmp, "out", item.filename).read_bytes(), blob)
            self.assertEqual(carved[0].filename, f"00001_{offsets[0]:010x}.png")

    def test_empty_image_yields_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp, "empty.img")
            src.write_bytes(b"")
            self.assertEqual(carve_image(src, Path(tmp, "out")), [])
            self.assertFalse(Path(tmp, "out").exists())


if __name__ == "__main__":
    unittest.main()
