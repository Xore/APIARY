import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("apply_personas.py")
SPEC = importlib.util.spec_from_file_location("apply_personas", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ApplyPersonasTest(unittest.TestCase):
    def test_apply_is_idempotent_and_records_state(self):
        stack = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = MODULE.apply(stack, root / "dionaea", root / "state")
            second = MODULE.apply(stack, root / "dionaea", root / "state")
            self.assertEqual(first["manifest_sha256"], second["manifest_sha256"])
            self.assertEqual(first["runtime_files"], second["runtime_files"])
            self.assertTrue((root / "dionaea/tftp/root/README.txt").is_file())
            self.assertTrue((root / "state/applied.json").is_file())


if __name__ == "__main__":
    unittest.main()
