#!/usr/bin/env python3
"""Exercise arcane-sync-drift-report.py's exit-code contract (#2858) with
fixture gitops-sync records -- no real Arcane API call, no git.

The case this file exists for is the degenerate one the original synthetic
verification never drove: a project that has *never* synced. Arcane returns
`lastSyncAt` present-and-null for it (#2853), and `.get("lastSyncAt", "")`
returns None rather than the default, which neither sorts against a str nor
survives `.replace()`. That crashed the report on exactly the fleet state it
was written to surface."""

from __future__ import annotations

import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "arcane-sync-drift-report.py"

_spec = importlib.util.spec_from_file_location("arcane_sync_drift_report", SCRIPT)
report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report)


def record(name: str, *, last_sync_at: str | None = "2026-09-04T00:00:00Z",
           status: str = "success", commit: str = "a" * 40) -> dict:
    return {
        "name": name,
        "lastSyncStatus": status,
        "lastSyncAt": last_sync_at,
        "lastSyncCommit": commit,
        "autoSync": False,
    }


class DriftReportExitCodeTest(unittest.TestCase):
    def run_main(self, recs: list[dict], *, argv: list[str] | None = None) -> tuple[int, str, str]:
        """Drive the shipped main() with fixture records. `git fetch`/`rev-list`
        are stubbed out so the fixtures decide the outcome, not the checkout."""
        orig_fetch, orig_behind, orig_argv = report.fetch_syncs, report.commits_behind, sys.argv
        orig_key = report.os.environ.get("ARCANE_API_KEY")
        orig_run = report.subprocess.run
        report.fetch_syncs = lambda api_key: recs
        report.commits_behind = lambda commit, repo_root, fetched: 0
        report.subprocess.run = lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "0", "stderr": ""})()
        report.os.environ["ARCANE_API_KEY"] = "fixture-key"
        sys.argv = ["arcane-sync-drift-report.py"] + (argv or [])
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = report.main()
        finally:
            report.fetch_syncs, report.commits_behind, sys.argv = orig_fetch, orig_behind, orig_argv
            report.subprocess.run = orig_run
            if orig_key is None:
                report.os.environ.pop("ARCANE_API_KEY", None)
            else:
                report.os.environ["ARCANE_API_KEY"] = orig_key
        return rc, out.getvalue(), err.getvalue()

    def test_healthy_fleet_exits_zero(self) -> None:
        rc, _, _ = self.run_main([record("honeypot-elk"), record("honeypot-keycloak")],
                                 argv=["--behind-days", "3650"])
        self.assertEqual(rc, 0)

    def test_never_synced_record_does_not_crash_and_fails_the_run(self) -> None:
        """#2853's shape: `lastSyncAt` present and null, alongside a healthy record.
        Before the fix this raised TypeError out of sorted()'s key, so the report
        never printed at all."""
        recs = [record("honeypot-elk"), record("never-synced-project", last_sync_at=None)]
        rc, out, err = self.run_main(recs, argv=["--behind-days", "3650"])
        self.assertEqual(rc, 1, "a record with no readable lastSyncAt must fail the run")
        self.assertIn("never-synced-project", out)
        self.assertIn("NO READABLE lastSyncAt", err)
        self.assertIn("never-synced-project", err)

    def test_absent_and_unparseable_last_sync_at_also_fail(self) -> None:
        for label, rec in (
            ("key absent", {"name": "no-key", "lastSyncStatus": "success",
                            "lastSyncCommit": "b" * 40, "autoSync": False}),
            ("unparseable", record("garbage-ts", last_sync_at="not-a-timestamp")),
        ):
            with self.subTest(label):
                rc, _, err = self.run_main([record("honeypot-elk"), rec],
                                           argv=["--behind-days", "3650"])
                self.assertEqual(rc, 1)
                self.assertIn("NO READABLE lastSyncAt", err)

    def test_structural_failure_is_exempt_but_still_printed(self) -> None:
        recs = [record("honeypot-elk"), record("honeypot-init", status="failed")]
        rc, out, err = self.run_main(recs, argv=["--behind-days", "3650"])
        self.assertEqual(rc, 0, "honeypot-init's permanent `failed` must not fail the run (#2854)")
        self.assertIn("EXEMPT", out)
        self.assertIn("honeypot-init", out)
        self.assertNotIn("FAILED:", err)

    def test_unexempt_failure_fails_the_run(self) -> None:
        recs = [record("honeypot-init", status="failed"), record("honeypot-elk", status="failed")]
        rc, _, err = self.run_main(recs, argv=["--behind-days", "3650"])
        self.assertEqual(rc, 1)
        self.assertIn("FAILED: honeypot-elk", err)

    def test_stale_record_fails_the_run(self) -> None:
        recs = [record("honeypot-elk", last_sync_at="2020-01-01T00:00:00Z")]
        rc, _, err = self.run_main(recs, argv=["--behind-days", "3"])
        self.assertEqual(rc, 1)
        self.assertIn("STALE", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
