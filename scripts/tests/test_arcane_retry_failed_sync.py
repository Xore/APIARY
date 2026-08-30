#!/usr/bin/env python3
"""Exercise arcane-retry-failed-sync.sh's decision logic (#2705) with
fixture gitops-sync data -- no real Arcane API call. Sources the script
(guarded so sourcing doesn't run main()) and overrides arcane_api()/curl()
with fixtures, the same way the shell functions would be swapped out for
a live install."""

from __future__ import annotations

import json
import shlex
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "arcane-retry-failed-sync.sh"


def run_case(*, syncs: list[dict], target: str, dry_run: int, curl_response: str = "") -> subprocess.CompletedProcess:
    """Source the script, stub arcane_api()/curl(), call process_target
    directly, and report its stdout plus exit code."""
    syncs_json = json.dumps({"data": syncs})
    bash_script = f"""
set -uo pipefail
export ARCANE_BEARER=fixture-bearer
source {shlex.quote(str(SCRIPT))}

arcane_api() {{
  cat <<'FIXTURE'
{syncs_json}
FIXTURE
}}

curl() {{
  printf '%s' {shlex.quote(curl_response)}
}}

ec=0
process_target {shlex.quote(target)} {dry_run} || ec=$?
echo "EXIT:$ec"
"""
    return subprocess.run(
        ["bash", "-c", bash_script],
        capture_output=True,
        text=True,
        timeout=10,
    )


class NeedsRedeployTest(unittest.TestCase):
    def _check(self, status: str, expected: bool) -> None:
        result = subprocess.run(
            ["bash", "-c", f"source {SCRIPT!s}; needs_redeploy {status!r}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode == 0, expected, result.stderr)

    def test_failed_needs_redeploy(self) -> None:
        self._check("failed", True)

    def test_success_does_not(self) -> None:
        self._check("success", False)

    def test_unknown_does_not(self) -> None:
        self._check("unknown", False)


class FindSyncTest(unittest.TestCase):
    SYNCS = json.dumps(
        {
            "data": [
                {"id": "1", "name": "ghidra", "lastSyncStatus": "failed", "projectId": "p1"},
                {"id": "2", "name": "ml-worker", "lastSyncStatus": "success", "projectId": "p2"},
            ]
        }
    )

    def test_matches_by_name(self) -> None:
        result = subprocess.run(
            ["bash", "-c", f"source {SCRIPT!s}; find_sync ml-worker {self.SYNCS!r}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        found = json.loads(result.stdout)
        self.assertEqual(found["id"], "2")

    def test_matches_by_id(self) -> None:
        result = subprocess.run(
            ["bash", "-c", f"source {SCRIPT!s}; find_sync 1 {self.SYNCS!r}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        found = json.loads(result.stdout)
        self.assertEqual(found["name"], "ghidra")

    def test_no_match_prints_nothing(self) -> None:
        result = subprocess.run(
            ["bash", "-c", f"source {SCRIPT!s}; find_sync nope {self.SYNCS!r}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.stdout.strip(), "")


class ProcessTargetTest(unittest.TestCase):
    def test_healthy_sync_is_a_noop_even_with_apply(self) -> None:
        result = run_case(
            syncs=[{"id": "1", "name": "ml-worker", "lastSyncStatus": "success", "projectId": "p1"}],
            target="ml-worker",
            dry_run=0,
        )
        self.assertIn("PASS  ml-worker: lastSyncStatus=success, no action needed", result.stdout)
        self.assertIn("EXIT:0", result.stdout)

    def test_failed_sync_dry_run_reports_would_redeploy_without_calling_curl(self) -> None:
        result = run_case(
            syncs=[{"id": "1", "name": "ghidra", "lastSyncStatus": "failed", "projectId": "p1"}],
            target="ghidra",
            dry_run=1,
        )
        self.assertIn("WOULD REDEPLOY  ghidra (project p1)", result.stdout)
        self.assertIn("EXIT:0", result.stdout)

    def test_failed_sync_apply_redeploys_and_passes_on_done_true(self) -> None:
        result = run_case(
            syncs=[{"id": "1", "name": "ghidra", "lastSyncStatus": "failed", "projectId": "p1"}],
            target="ghidra",
            dry_run=0,
            curl_response='{"done":true}',
        )
        self.assertIn("PASS  ghidra: redeploy completed", result.stdout)
        self.assertIn("EXIT:0", result.stdout)

    def test_failed_sync_apply_fails_without_done_true(self) -> None:
        result = run_case(
            syncs=[{"id": "1", "name": "ghidra", "lastSyncStatus": "failed", "projectId": "p1"}],
            target="ghidra",
            dry_run=0,
            curl_response='{"title":"Internal Server Error","status":500}',
        )
        self.assertIn("FAIL  ghidra: redeploy stream ended without a done:true frame", result.stdout)
        self.assertIn("EXIT:1", result.stdout)

    def test_unknown_target_fails(self) -> None:
        result = run_case(
            syncs=[{"id": "1", "name": "ghidra", "lastSyncStatus": "failed", "projectId": "p1"}],
            target="does-not-exist",
            dry_run=1,
        )
        self.assertIn("FAIL  does-not-exist: no matching gitops sync found", result.stdout)
        self.assertIn("EXIT:1", result.stdout)

    def test_failed_sync_without_project_id_fails(self) -> None:
        result = run_case(
            syncs=[{"id": "1", "name": "honeypot-wordpot", "lastSyncStatus": "failed"}],
            target="honeypot-wordpot",
            dry_run=1,
        )
        self.assertIn(
            "FAIL  honeypot-wordpot: lastSyncStatus=failed but sync has no projectId to redeploy",
            result.stdout,
        )
        self.assertIn("EXIT:1", result.stdout)


if __name__ == "__main__":
    unittest.main()
