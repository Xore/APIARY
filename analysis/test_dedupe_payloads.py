import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("dedupe-payloads.py")
SPEC = importlib.util.spec_from_file_location("dedupe_payloads", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DedupePayloadsTest(unittest.TestCase):
    def test_duplicate_paths_share_an_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / "a.bin", root / "b.bin"
            first.write_bytes(b"same payload")
            second.write_bytes(b"same payload")
            result = MODULE.dedupe([root], root / "state.json")
            self.assertEqual(result["duplicates_linked"], 1)
            self.assertEqual(first.stat().st_ino, second.stat().st_ino)
            self.assertEqual(second.read_bytes(), b"same payload")


if __name__ == "__main__":
    unittest.main()
