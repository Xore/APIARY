"""#2775: the legacy WinRM path wrote no result document when it failed, and
a hardcoded 'completed' when it succeeded.

detonate_legacy_winrm() called post_process() -- the only thing that writes
the dashboard-facing windows-<job>.json -- as its last statement. Anything
that raised earlier (wait_for_winrm() timing out, #2252's delivery checks
inside copy_sample_to_vm()/execute_sample()/collect_artifacts()) aborted
before it ever ran, so a failed legacy run produced silence: no document, and
a sandbox job that simply never appeared. Separately, export_result.py derived
run_status only from 'watchdog_timeout', a value only detonate_inguest() ever
set, so a *successful* legacy run's document said 'completed' by accident
rather than by evidence -- indistinguishable from a document that says it
because nothing checked.

These drive detonate() end to end in legacy mode with every guest-touching
step mocked, and assert on the document that actually lands on disk:

1. the success path stamps 'completed' with an empty failure_reason;
2. a wait_for_winrm() failure still writes a document, marked 'failed' with
   the real exception text, and still re-raises;
3. a collect_artifacts() failure does the same, and artifacts are re-collected
   best-effort first;
4. the exception always propagates, so detonate()'s revert-to-golden still
   runs and the worker still sees the run as failed;
5. failure_reason is capped, and sha256/capture_name survive a failure.

Nothing here talks to a VM: WINDOWS_SANDBOX_LEGACY_WINRM=1 needs a live guest
by definition, which is exactly why this path rots unnoticed.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("run_sample.py")
# post_process() imports extract_iocs/generate_report/export_result by bare
# name at call time, the way run_sample.py itself is invoked (cwd on the
# path). Keep that import shape working so post_process runs for real here --
# the document it writes is the whole point of these tests.
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("windows_run_sample", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

# Every guest-touching step of the legacy sequence, in order. All are patched
# to no-ops; individual tests re-patch one of them to raise.
GUEST_STEPS = (
    "revert_to_golden", "wait_for_winrm", "start_fakenet", "start_procmon",
    "regshot_before", "autoruns_before", "execute_sample",
    "capture_memory_dump", "regshot_after", "autoruns_after", "stop_procmon",
    "collect_artifacts",
)


class LegacyWinrmResultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.results = root / "results"
        self.results.mkdir()
        self.sample = root / "sample.exe"
        self.sample.write_bytes(b"MZ not-really-a-pe")
        self.sha = MODULE.sha256_of(self.sample)
        self.addCleanup(self.tmp.cleanup)

    def run_detonation(self, **overrides):
        """detonate() in legacy mode with the guest mocked out. Returns the
        exception it raised (or None) -- the caller asserts on the document."""
        patches = [
            patch.object(MODULE, "LEGACY_WINRM_MODE", True),
            # post_process() writes into ARTIFACT_DIR, not results_dir.
            patch.object(MODULE, "ARTIFACT_DIR", self.results),
            patch.object(MODULE, "copy_sample_to_vm", return_value="C:\\Inbox\\x.exe"),
            patch.object(MODULE, "observe_with_early_stop", return_value=MODULE.OBS_SECS),
        ]
        patches += [patch.object(MODULE, name, **overrides.get(name, {}))
                    for name in GUEST_STEPS]
        raised = None
        with self._nested(patches):
            try:
                MODULE.detonate(self.sample, results_dir=self.results)
            except Exception as e:  # noqa: BLE001 -- the assertion is on the type
                raised = e
        return raised

    def _nested(self, patches):
        stack = __import__("contextlib").ExitStack()
        for p in patches:
            stack.enter_context(p)
        return stack

    def document(self):
        written = sorted(self.results.glob("windows-*.json"))
        self.assertEqual(len(written), 1,
                         f"exactly one result document expected, got {written}")
        return json.loads(written[0].read_text())

    def test_a_successful_run_stamps_completed(self):
        raised = self.run_detonation()
        self.assertIsNone(raised)
        doc = self.document()
        self.assertEqual(doc["run_status"], "completed")
        self.assertEqual(doc["failure_reason"], "")
        self.assertEqual(doc["sha256"], self.sha)
        self.assertEqual(doc["capture_name"], "sample.exe")

    def test_a_wait_for_winrm_failure_still_writes_a_failed_document(self):
        raised = self.run_detonation(wait_for_winrm={
            "side_effect": TimeoutError("WinRM never became reachable within 600s")})
        self.assertIsInstance(raised, TimeoutError)
        doc = self.document()
        self.assertEqual(doc["run_status"], "failed")
        self.assertIn("WinRM never became reachable", doc["failure_reason"])
        # The watchdog vocabulary is #490's alone; this failure must not
        # borrow it or the dashboard reports the wrong cause.
        self.assertEqual(doc["timeout_reason"], "")
        # sha256 is the dashboard's key -- a failure must not lose it.
        self.assertEqual(doc["sha256"], self.sha)
        self.assertEqual(doc["capture_name"], "sample.exe")

    def test_a_collect_artifacts_failure_still_writes_a_failed_document(self):
        raised = self.run_detonation(collect_artifacts={
            "side_effect": RuntimeError("#2252 delivery check: smbclient get returned 1")})
        self.assertIsInstance(raised, RuntimeError)
        doc = self.document()
        self.assertEqual(doc["run_status"], "failed")
        self.assertIn("smbclient get returned 1", doc["failure_reason"])

    def test_artifacts_are_collected_again_best_effort_after_a_failure(self):
        # detonate_inguest()'s "collect offline no matter what" behaviour: a
        # partial run's artifacts are still evidence. The retry raising again
        # must not swallow the original failure either.
        calls = []

        def failing(*args, **kwargs):
            calls.append(args)
            raise RuntimeError("smbclient get sysmon.evtx failed")

        raised = self.run_detonation(collect_artifacts={"side_effect": failing})
        self.assertIsInstance(raised, RuntimeError)
        self.assertEqual(len(calls), 2, "the failure path must retry collection once")
        self.assertEqual(self.document()["run_status"], "failed")

    def test_the_guest_is_still_reverted_after_a_failure(self):
        # detonate()'s finally-block revert is what keeps a guest that has run
        # untrusted code from surviving into the next sample. The new
        # try/except must not consume the exception that gets it there.
        with patch.object(MODULE, "LEGACY_WINRM_MODE", True), \
             patch.object(MODULE, "ARTIFACT_DIR", self.results), \
             patch.object(MODULE, "copy_sample_to_vm", return_value="C:\\Inbox\\x.exe"), \
             patch.object(MODULE, "observe_with_early_stop", return_value=MODULE.OBS_SECS), \
             patch.object(MODULE, "revert_to_golden") as revert, \
             patch.object(MODULE, "wait_for_winrm", side_effect=TimeoutError("boom")), \
             patch.multiple(MODULE, **{name: unittest.mock.DEFAULT for name in GUEST_STEPS
                                       if name not in ("revert_to_golden", "wait_for_winrm")}):
            with self.assertRaises(TimeoutError):
                MODULE.detonate(self.sample, results_dir=self.results)
        # Once at the start of the sequence, once in detonate()'s cleanup.
        self.assertEqual(revert.call_count, 2)

    def test_failure_reason_is_capped(self):
        raised = self.run_detonation(wait_for_winrm={
            "side_effect": RuntimeError("x" * 5000)})
        self.assertIsInstance(raised, RuntimeError)
        reason = self.document()["failure_reason"]
        self.assertEqual(len(reason), 512)

    def test_a_corrupt_metadata_json_does_not_lose_the_sha256(self):
        # _mark_legacy_winrm_status() reads metadata.json back before
        # stamping it. Starting from an empty dict on a read failure would
        # write a document with no sha256 -- the dashboard's key -- so the
        # out dir name (which IS the sha) seeds the replacement instead.
        out = self.results / self.sha
        out.mkdir(parents=True)
        (out / "metadata.json").write_text("{ this is not json")
        MODULE._mark_legacy_winrm_status(out, "legacy_winrm_failed", detail="corrupt")
        meta = json.loads((out / "metadata.json").read_text())
        self.assertEqual(meta["sha256"], self.sha)
        self.assertEqual(meta["run_status"], "legacy_winrm_failed")
        self.assertEqual(meta["run_status_detail"], "corrupt")


if __name__ == "__main__":
    unittest.main()
