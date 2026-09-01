"""#2252: copy_sample_to_vm(), execute_sample(), and collect_artifacts()
used to discard smbclient's returncode and WinRM's status_code/stdout
entirely -- a delivery failure (SMB hiccup, Start-Process erroring on a
missing file) looked identical to a real successful run to every caller.
These tests prove each now raises on failure and stays silent on success.
"""
import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

MODULE_PATH = Path(__file__).with_name("run_sample.py")
SPEC = importlib.util.spec_from_file_location("ghosts_run_sample", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _completed(returncode=0, stderr=b""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=b"", stderr=stderr)


class CopySampleToVmTests(unittest.TestCase):
    def test_success_returns_the_vm_path(self):
        with patch.object(MODULE.subprocess, "run", return_value=_completed(0)):
            result = MODULE.copy_sample_to_vm(Path("/tmp/sample.exe"), "a" * 64)
        self.assertEqual(result, f'C:\\Inbox\\{"a" * 16}.exe')

    def test_nonzero_returncode_raises(self):
        with patch.object(MODULE.subprocess, "run",
                           return_value=_completed(1, b"NT_STATUS_LOGON_FAILURE")):
            with self.assertRaisesRegex(RuntimeError, r"smbclient put failed.*NT_STATUS_LOGON_FAILURE"):
                MODULE.copy_sample_to_vm(Path("/tmp/sample.exe"), "a" * 64)


class ExecuteSampleTests(unittest.TestCase):
    def test_success_does_not_raise(self):
        with patch.object(MODULE, "winrm_run",
                           return_value={"status_code": 0, "stdout": "PID: 4242\n", "stderr": ""}):
            MODULE.execute_sample("C:\\Inbox\\aaaa.exe")  # must not raise

    def test_nonzero_status_code_raises(self):
        with patch.object(MODULE, "winrm_run",
                           return_value={"status_code": 1, "stdout": "", "stderr": "cannot find path"}):
            with self.assertRaisesRegex(RuntimeError, r"did not report a PID"):
                MODULE.execute_sample("C:\\Inbox\\aaaa.exe")

    def test_missing_pid_line_raises_even_with_a_zero_status_code(self):
        with patch.object(MODULE, "winrm_run",
                           return_value={"status_code": 0, "stdout": "unexpected output", "stderr": ""}):
            with self.assertRaisesRegex(RuntimeError, r"did not report a PID"):
                MODULE.execute_sample("C:\\Inbox\\aaaa.exe")


class CollectArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.hostname_patch = patch.object(MODULE, "get_guest_hostname", return_value="test-host")
        self.activity_patch = patch.object(MODULE, "fetch_ghosts_activity", return_value={"ok": True})
        self.hostname_patch.start()
        self.activity_patch.start()
        self.addCleanup(self.hostname_patch.stop)
        self.addCleanup(self.activity_patch.stop)

    def test_success_returns_activity_and_does_not_raise(self):
        with patch.object(MODULE.subprocess, "run", return_value=_completed(0)):
            with __import__("tempfile").TemporaryDirectory() as tmp:
                result = MODULE.collect_artifacts("a" * 64, Path(tmp))
        self.assertEqual(result, {"ok": True})

    def test_a_failed_get_raises_naming_the_file(self):
        calls = []

        def fake_run(args, **kwargs):
            calls.append(args)
            # First file (sysmon_before.evtx) fails; second must never run.
            return _completed(1, b"NT_STATUS_OBJECT_NAME_NOT_FOUND")

        with patch.object(MODULE.subprocess, "run", side_effect=fake_run):
            with __import__("tempfile").TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(RuntimeError, r"smbclient get sysmon_before\.evtx failed"):
                    MODULE.collect_artifacts("a" * 64, Path(tmp))
        self.assertEqual(len(calls), 1, "must stop at the first failed get, not continue to the second")


if __name__ == "__main__":
    unittest.main()
