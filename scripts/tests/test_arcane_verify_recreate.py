#!/usr/bin/env python3
"""Exercise arcane-verify-recreate.sh's evaluate_project() decision logic
(#2910) directly -- no real Arcane database, no docker daemon. Sources the
script (guarded so sourcing doesn't run main()) and calls the pure
comparison function with fixture timestamps, the same pattern
test_arcane_retry_failed_sync.py uses for its script."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "arcane-verify-recreate.sh"


def run_case(*, status: str, sync_at: str, containers: list[tuple[str, str]]) -> subprocess.CompletedProcess:
    container_args = " ".join(f'"{name}:{created}"' for name, created in containers)
    bash_script = f"""
set -uo pipefail
source {SCRIPT}
set +e
evaluate_project fixture-project {status!r} {sync_at!r} {container_args}
echo "EXIT:$?"
"""
    return subprocess.run(
        ["bash", "-c", bash_script],
        capture_output=True,
        text=True,
        timeout=10,
    )


class VerifyRecreateTest(unittest.TestCase):
    def test_container_created_before_successful_sync_fails(self) -> None:
        """#2910's exact shape: sync says success, container predates it."""
        result = run_case(
            status="success",
            sync_at="2026-09-03T10:22:08Z",
            containers=[("hp-sentrypeer", "2026-09-02T08:00:00Z")],
        )
        self.assertIn("FAIL", result.stdout)
        self.assertIn("not recreated since the last successful sync", result.stdout)
        # The message must carry the no-op-sync caveat, not just the verdict:
        # an unchanged project produces this exact shape legitimately, and
        # whoever reads the line is the one who has to tell them apart.
        self.assertIn("expected if the project's config was unchanged", result.stdout)
        self.assertIn("EXIT:1", result.stdout)

    def test_container_created_after_successful_sync_passes(self) -> None:
        result = run_case(
            status="success",
            sync_at="2026-09-03T10:22:08Z",
            containers=[("hp-sentrypeer", "2026-09-03T10:34:09Z")],
        )
        self.assertIn("PASS", result.stdout)
        self.assertIn("EXIT:0", result.stdout)

    def test_container_created_before_failed_sync_is_not_flagged(self) -> None:
        """A recorded failure never claimed a successful deploy, so an
        older container isn't evidence of anything wrong -- only a
        `success` record that didn't actually recreate is the defect."""
        result = run_case(
            status="failed",
            sync_at="2026-09-03T10:22:08Z",
            containers=[("hp-init-job", "2026-09-02T08:00:00Z")],
        )
        self.assertIn("PASS", result.stdout)
        self.assertIn("EXIT:0", result.stdout)

    def test_never_synced_project_is_informational_not_a_failure(self) -> None:
        result = run_case(status="null", sync_at="null", containers=[("hp-foo", "2026-09-02T08:00:00Z")])
        self.assertIn("INFO", result.stdout)
        self.assertIn("never synced", result.stdout)
        self.assertIn("EXIT:0", result.stdout)

    def test_no_containers_is_informational_not_a_failure(self) -> None:
        """#2853's shape: a project with a sync record but zero containers."""
        result = run_case(status="success", sync_at="2026-09-03T10:22:08Z", containers=[])
        self.assertIn("INFO", result.stdout)
        self.assertIn("no containers found", result.stdout)
        self.assertIn("EXIT:0", result.stdout)

    def test_multiple_containers_one_stale_fails_the_project(self) -> None:
        result = run_case(
            status="success",
            sync_at="2026-09-03T10:22:08Z",
            containers=[
                ("hp-a", "2026-09-03T10:34:09Z"),
                ("hp-b", "2026-09-02T08:00:00Z"),
            ],
        )
        self.assertIn("PASS  fixture-project/hp-a", result.stdout)
        self.assertIn("FAIL  fixture-project/hp-b", result.stdout)
        self.assertIn("EXIT:1", result.stdout)


if __name__ == "__main__":
    unittest.main()
