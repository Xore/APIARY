#!/usr/bin/env python3
"""Exercise vps/container-restart-watchdog.sh's escalation decision (#2907)
against a fake `docker` on PATH -- no real daemon, no real containers.

The behaviour under test: `docker start` cannot repair a container whose PID
namespace is bound to a container that has since been recreated, so the
watchdog escalates to `docker compose up -d --no-deps <service>` for exactly
that error and for nothing else."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vps" / "container-restart-watchdog.sh"

# The fake daemon always reports one exited container: hp-traefik-log-rotate,
# `unless-stopped`, exited an hour ago -- every precondition met, so only the
# `docker start` outcome decides what the watchdog does.
FAKE_DOCKER = r"""#!/usr/bin/env bash
# Records every invocation to $CALL_LOG and answers the handful of queries the
# watchdog makes.
printf '%s\n' "$*" >> "$CALL_LOG"
case "$1" in
  ps)
    echo deadbeefcafe
    ;;
  inspect)
    case "$*" in
      *RestartPolicy*)
        # name policy finished_at exit_code
        echo "/hp-traefik-log-rotate unless-stopped $FINISHED_AT 137"
        ;;
      *com.docker.compose.service*)      printf '%s\n' "$LABEL_SERVICE" ;;
      *project.working_dir*)             printf '%s\n' "$LABEL_WORKDIR" ;;
      *project.config_files*)            printf '%s\n' "$LABEL_CONFIG_FILES" ;;
      *) echo "" ;;
    esac
    ;;
  start)
    [ -n "$START_ERROR" ] || exit 0
    printf '%s\n' "$START_ERROR" >&2
    exit 1
    ;;
  compose)
    exit "${COMPOSE_EXIT:-0}"
    ;;
esac
exit 0
"""

NAMESPACE_ERROR = (
    "Error response from daemon: failed to join PID namespace: "
    "No such container: 4d5de108f3a67b46002f06d095494d6243e741a93007cc739e306130e6e6f132"
)


class WatchdogEscalationTest(unittest.TestCase):
    def run_watchdog(self, *, start_error: str = "", labels: dict[str, str] | None = None,
                     compose_exit: int = 0, compose_file_exists: bool = True) -> tuple[int, str, list[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            (bin_dir / "docker").write_text(FAKE_DOCKER, encoding="utf-8")
            (bin_dir / "docker").chmod(0o755)
            call_log = tmp_path / "calls"
            call_log.touch()

            workdir = tmp_path / "vps"
            workdir.mkdir()
            compose_file = workdir / "docker-compose.yml"
            if compose_file_exists:
                compose_file.write_text("services: {}\n", encoding="utf-8")

            defaults = {
                "com.docker.compose.service": "traefik-log-rotate",
                "com.docker.compose.project.working_dir": str(workdir),
                "com.docker.compose.project.config_files": str(compose_file),
            }
            defaults.update(labels or {})

            env = dict(os.environ)
            env.update(
                PATH=f"{bin_dir}:{env['PATH']}",
                CALL_LOG=str(call_log),
                START_ERROR=start_error,
                COMPOSE_EXIT=str(compose_exit),
                # an hour ago, well past GRACE_SECONDS
                FINISHED_AT=subprocess.run(
                    ["date", "-u", "-d", "1 hour ago", "-Iseconds"],
                    capture_output=True, text=True, check=True).stdout.strip(),
                LABEL_SERVICE=defaults["com.docker.compose.service"],
                LABEL_WORKDIR=defaults["com.docker.compose.project.working_dir"],
                LABEL_CONFIG_FILES=defaults["com.docker.compose.project.config_files"],
            )
            proc = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, env=env)
            calls = call_log.read_text(encoding="utf-8").splitlines()
        return proc.returncode, proc.stderr, calls

    @staticmethod
    def compose_calls(calls: list[str]) -> list[str]:
        return [c for c in calls if c.startswith("compose ")]

    def test_a_stale_namespace_binding_is_escalated_to_a_compose_recreate(self) -> None:
        code, stderr, calls = self.run_watchdog(start_error=NAMESPACE_ERROR)
        self.assertEqual(code, 0)
        recreates = self.compose_calls(calls)
        self.assertEqual(len(recreates), 1, f"expected exactly one compose recreate, got {recreates}")
        self.assertIn("up -d --no-deps traefik-log-rotate", recreates[0])
        self.assertIn("--project-directory", recreates[0])
        self.assertIn("recreated", stderr)
        self.assertNotIn("needs manual attention", stderr)

    def test_an_unrelated_start_failure_is_not_recreated(self) -> None:
        code, stderr, calls = self.run_watchdog(
            start_error="Error response from daemon: driver failed programming external connectivity")
        self.assertEqual(code, 0)
        self.assertEqual(self.compose_calls(calls), [], "only namespace failures may escalate")
        self.assertIn("needs manual attention", stderr)
        self.assertIn("driver failed programming external connectivity", stderr,
                      "the original daemon error must survive into the log")

    def test_a_successful_start_never_recreates(self) -> None:
        code, stderr, calls = self.run_watchdog()
        self.assertEqual(code, 0)
        self.assertEqual(self.compose_calls(calls), [])
        self.assertIn("restarted", stderr)

    def test_a_container_compose_did_not_create_is_not_recreated(self) -> None:
        code, stderr, calls = self.run_watchdog(
            start_error=NAMESPACE_ERROR,
            labels={"com.docker.compose.service": "", "com.docker.compose.project.config_files": ""})
        self.assertEqual(self.compose_calls(calls), [])
        self.assertIn("needs manual attention", stderr)

    def test_a_missing_compose_file_is_not_recreated(self) -> None:
        code, stderr, calls = self.run_watchdog(start_error=NAMESPACE_ERROR, compose_file_exists=False)
        self.assertEqual(self.compose_calls(calls), [])
        self.assertIn("needs manual attention", stderr)

    def test_a_failing_recreate_still_reports_manual_attention(self) -> None:
        code, stderr, calls = self.run_watchdog(start_error=NAMESPACE_ERROR, compose_exit=1)
        self.assertEqual(len(self.compose_calls(calls)), 1)
        self.assertIn("needs manual attention", stderr)
        self.assertNotIn("recreated --", stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
