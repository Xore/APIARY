#!/usr/bin/env python3
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("model_status_adapter", HERE / "model-status-adapter.py")
adapter = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(adapter)


class ModelStatusAdapterTests(unittest.TestCase):
    def status_file(self, value):
        root = Path(tempfile.mkdtemp())
        path = root / "status.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def test_sanitizes_fixed_schema(self):
        path = self.status_file({"schema_version": 1, "checked_at": "2026-08-01T00:00:00Z", "overall": "drift", "slots": {"ghidra": {"status": "drift", "codes": ["model_digest_changed"]}}, "runtime": {"status": "approved", "codes": []}, "host": {"status": "approved", "codes": []}, "advisory_only": True, "secret": "must not pass"})
        result = adapter.sanitize_status(path)
        self.assertEqual(result["overall"], "drift")
        self.assertNotIn("secret", result)

    def test_rejects_world_readable_source(self):
        if os.name != "posix":
            self.skipTest("POSIX permission bits are not available")
        path = self.status_file({"schema_version": 1, "overall": "approved", "slots": {}, "advisory_only": True})
        real_stat = path.stat()
        unsafe_stat = SimpleNamespace(st_mode=real_stat.st_mode | 0o044, st_size=real_stat.st_size, st_uid=real_stat.st_uid)
        with mock.patch.object(Path, "stat", return_value=unsafe_stat), self.assertRaises(ValueError):
            adapter.sanitize_status(path)

    def test_rejects_unknown_slots_and_codes(self):
        for value in [
            {"schema_version": 1, "overall": "approved", "slots": {"arbitrary": {"status": "approved", "codes": []}}, "advisory_only": True},
            {"schema_version": 1, "overall": "drift", "slots": {}, "codes": ["../../secret"], "advisory_only": True},
        ]:
            with self.assertRaises(ValueError):
                adapter.sanitize_status(self.status_file(value))


if __name__ == "__main__":
    unittest.main()
