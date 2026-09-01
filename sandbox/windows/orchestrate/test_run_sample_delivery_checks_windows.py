"""#2252: copy_sample_to_vm(), execute_sample(), and collect_artifacts()
used to discard smbclient's returncode and WinRM's status_code/stdout
entirely -- a delivery failure (SMB hiccup, Start-Process erroring on a
missing file) looked identical to a real successful run to every caller.
These tests prove each now raises on failure and stays silent on success,
mirroring sandbox/ghosts/orchestrate/test_run_sample_delivery_checks_ghosts.py
(the twin orchestrator).
"""
import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("run_sample.py")
SPEC = importlib.util.spec_from_file_location("windows_run_sample", MODULE_PATH)
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
    def test_success_does_not_raise(self):
        with patch.object(MODULE, "winrm_run", return_value={"status_code": 0, "stdout": "", "stderr": ""}), \
             patch.object(MODULE.subprocess, "run", return_value=_completed(0)):
            with __import__("tempfile").TemporaryDirectory() as tmp:
                MODULE.collect_artifacts("a" * 64, Path(tmp))  # must not raise

    def test_essential_file_failure_raises(self):
        """sysmon.evtx / powershell_scriptblock.evtx are hard-required --
        an SMB failure fetching either must abort the run, not just log."""
        with patch.object(MODULE, "winrm_run", return_value={"status_code": 0, "stdout": "", "stderr": ""}), \
             patch.object(MODULE.subprocess, "run",
                           return_value=_completed(1, b"NT_STATUS_OBJECT_NAME_NOT_FOUND")):
            with __import__("tempfile").TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(RuntimeError, r"smbclient get sysmon\.evtx failed"):
                    MODULE.collect_artifacts("a" * 64, Path(tmp))

    def test_best_effort_file_failure_is_logged_not_raised(self):
        """procmon.csv and friends stay best-effort, matching this file's
        own stop_procmon() philosophy: a missing optional artifact must
        never fail an otherwise-successful run."""
        calls = []

        def fake_run(args, **kwargs):
            calls.append(args)
            # The two essential gets (first two calls) succeed; everything
            # after (the best-effort loop) fails.
            if len(calls) <= 2:
                return _completed(0)
            return _completed(1, b"NT_STATUS_OBJECT_NAME_NOT_FOUND")

        with patch.object(MODULE, "winrm_run", return_value={"status_code": 0, "stdout": "", "stderr": ""}), \
             patch.object(MODULE.subprocess, "run", side_effect=fake_run), \
             patch.object(MODULE.log, "warning") as fake_warning:
            with __import__("tempfile").TemporaryDirectory() as tmp:
                MODULE.collect_artifacts("a" * 64, Path(tmp))  # must not raise
        self.assertTrue(fake_warning.called, "a failed best-effort get must still be logged, not silently discarded")


if __name__ == "__main__":
    unittest.main()
