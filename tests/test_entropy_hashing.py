import hashlib
import tempfile
import unittest
from pathlib import Path

from ftriage.entropy import EntropyAccumulator, shannon_entropy
from ftriage.hashing import hash_bytes, hash_file


class EntropyTests(unittest.TestCase):
    def test_empty_and_constant_data_have_zero_entropy(self):
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertEqual(shannon_entropy(b"\x00" * 1000), 0.0)

    def test_two_equally_likely_symbols_give_one_bit(self):
        self.assertAlmostEqual(shannon_entropy(b"ab" * 500), 1.0)

    def test_uniform_bytes_give_eight_bits(self):
        self.assertAlmostEqual(shannon_entropy(bytes(range(256)) * 4), 8.0)

    def test_streaming_matches_one_shot(self):
        data = bytes(range(256)) * 3 + b"hello world" * 50
        accumulator = EntropyAccumulator()
        for i in range(0, len(data), 97):
            accumulator.update(data[i : i + 97])
        self.assertAlmostEqual(accumulator.value, shannon_entropy(data))
        self.assertEqual(accumulator.total, len(data))


class HashingTests(unittest.TestCase):
    def test_known_vectors_for_abc(self):
        digests = hash_bytes(b"abc")
        self.assertEqual(digests["md5"], "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(digests["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(
            digests["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_hash_file_matches_hashlib(self):
        data = b"forensics" * 300_000  # larger than one read chunk
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "big.bin")
            path.write_bytes(data)
            expected = hashlib.sha256(data).hexdigest()
            self.assertEqual(hash_file(path, ("sha256",))["sha256"], expected)

    def test_unsupported_algorithm_is_rejected(self):
        with self.assertRaises(ValueError):
            hash_bytes(b"x", ("crc32",))


if __name__ == "__main__":
    unittest.main()
