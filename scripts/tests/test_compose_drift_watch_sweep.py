#!/usr/bin/env python3
"""Exercise compose-drift-watch.py's sweep() gate-1 fix (#3040) and
failing_streak_findings() (#3030) with faked subprocess output -- no docker
daemon, no live stacks root, no sudo helper.

#3023's root cause was two structural gates in sweep(): a single-service
project like llm-worker never has a "sibling" so the old blanket suppression
made its down-alarm unreachable, and project_dirs() only ever globbed for
compose.yml so llm-worker's docker-compose.captured-data-deploy.yml stack was
never even enumerated. This pins the gate fix directly: a single-service
project with its one container missing must alarm, while a project that has
actually been retired from the manifest and is fully down must stay quiet.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "compose-drift-watch.py"

_spec = importlib.util.spec_from_file_location("compose_drift_watch_sweep", SCRIPT)
cdw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cdw)


class _Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_compose_run(project_configs):
    """project_configs: {project_name: (services_restart_dict, containers_list)}"""

    def run(args, cwd=None, capture_output=True, text=True):
        name = Path(cwd).name
        services, containers = project_configs[name]
        if "config" in args:
            return _Result(0, json.dumps({
                "services": {svc: {"restart": r} for svc, r in services.items()}
            }))
        if "ps" in args:
            return _Result(0, "\n".join(json.dumps(c) for c in containers))
        raise AssertionError(args)

    return run


class SweepGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stacks_root = Path(self.tmp.name)

    def _mkproject(self, name: str) -> None:
        d = self.stacks_root / name
        d.mkdir()
        (d / "compose.yml").write_text("services: {}\n")

    def test_single_service_project_missing_container_alarms(self) -> None:
        self._mkproject("llm-worker")
        configs = {"llm-worker": ({"llm-worker": "unless-stopped"}, [])}
        with mock.patch.object(cdw.subprocess, "run", side_effect=_fake_compose_run(configs)):
            findings, unresolved = cdw.sweep(self.stacks_root, entries=[], retired=set())
        self.assertEqual(unresolved, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["project"], "llm-worker")
        self.assertEqual(findings[0]["service"], "llm-worker")
        self.assertEqual(findings[0]["siblings_running"], [])

    def test_fully_retired_project_down_stays_quiet(self) -> None:
        self._mkproject("wordpot")
        configs = {"wordpot": ({"wordpot": "unless-stopped"}, [])}
        with mock.patch.object(cdw.subprocess, "run", side_effect=_fake_compose_run(configs)):
            findings, unresolved = cdw.sweep(self.stacks_root, entries=[], retired={"wordpot"})
        self.assertEqual(findings, [])
        self.assertEqual(unresolved, [])

    def test_manifest_unreadable_suppresses_fully_down_project(self) -> None:
        # REVIEW-A/:502 -- retired=None (manifest unreadable this sweep)
        # must fall back to the pre-#3040 blanket-suppress behavior, not
        # the opposite: an empty `retired` set previously made this an
        # unconditional mass-alarm on every idle project every time the
        # manifest read merely failed.
        self._mkproject("wordpot")
        configs = {"wordpot": ({"wordpot": "unless-stopped"}, [])}
        with mock.patch.object(cdw.subprocess, "run", side_effect=_fake_compose_run(configs)):
            findings, _ = cdw.sweep(self.stacks_root, entries=[], retired=None)
        self.assertEqual(findings, [])

    def test_multi_service_project_with_one_sibling_up_still_alarms(self) -> None:
        # Pre-#3040 behaviour: blanket suppression whenever ANY sibling ran.
        # That was the wrong rule too -- a partially-down multi-service
        # project is still drift, sibling or not.
        self._mkproject("honeypot-elk")
        configs = {
            "honeypot-elk": (
                {"elasticsearch": "unless-stopped", "kibana": "unless-stopped"},
                [{"Service": "elasticsearch", "State": "running"}],
            )
        }
        with mock.patch.object(cdw.subprocess, "run", side_effect=_fake_compose_run(configs)):
            findings, _ = cdw.sweep(self.stacks_root, entries=[], retired=set())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["service"], "kibana")
        self.assertEqual(findings[0]["siblings_running"], ["elasticsearch"])


class ProjectDirsPermissionTest(unittest.TestCase):
    """REVIEW-A finding 1: project_dirs() used to crash the entire sweep
    with an unhandled PermissionError the moment it reached a 0700 root-
    owned stack dir (llm-worker, auth-events-worker, ml-worker) -- every
    fix below :133 was unreachable as a result. Simulates the same EACCES
    shape locally by chmod-ing a directory unreadable to its own owner
    (mode 0 denies traversal regardless of ownership, same as root-owned
    0700 denies a different user)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stacks_root = Path(self.tmp.name)

    def test_unreadable_dir_is_skipped_not_raised(self) -> None:
        readable = self.stacks_root / "honeypot-elk"
        readable.mkdir()
        (readable / "compose.yml").write_text("services: {}\n")

        locked = self.stacks_root / "llm-worker"
        locked.mkdir()
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o700)

        dirs = cdw.project_dirs(self.stacks_root)
        self.assertEqual([d.name for d in dirs], ["honeypot-elk"])


class GhidraDedupTest(unittest.TestCase):
    """REVIEW-A non-blocking: /var/dockge/stacks/ghidra/compose.yml is a
    symlink to docker-compose.ghidra.yml (confirmed live, same file) --
    project_dirs() finds it via the former, manifest_extra_targets() via
    the latter (the manifest's own dockerComposePath basename), so without
    a dedup it is swept and reported twice for one real project."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stacks_root = Path(self.tmp.name)

    def test_symlinked_compose_file_swept_once(self) -> None:
        d = self.stacks_root / "ghidra"
        d.mkdir()
        (d / "docker-compose.ghidra.yml").write_text("services: {}\n")
        (d / "compose.yml").symlink_to("docker-compose.ghidra.yml")

        entries = [{"syncName": "ghidra", "dockerComposePath": "sandbox/ghidra/docker-compose.ghidra.yml"}]
        configs = {"ghidra": ({"ghidra": "unless-stopped"}, [])}
        with mock.patch.object(cdw.subprocess, "run", side_effect=_fake_compose_run(configs)):
            findings, unresolved = cdw.sweep(self.stacks_root, entries=entries, retired=set())
        self.assertEqual(unresolved, [])
        self.assertEqual(len(findings), 1)


class ResourceLimitTest(unittest.TestCase):
    """#2972/#3028: a project's live cpus/memory limit silently drifting
    away from its repo-declared deploy.resources.limits (confirmed live to
    happen at exactly half the declared value) went uncaught until an
    unrelated PR's manual diff surfaced it. Pins resource_limit_findings()
    against faked `docker compose config`/`ps` and `docker inspect` output
    -- no live daemon needed."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stacks_root = Path(self.tmp.name)

    def _mkproject(self, name: str, cpus, memory) -> None:
        d = self.stacks_root / name
        d.mkdir()
        (d / "compose.yml").write_text("services: {}\n")
        self._limits = {"cpus": cpus, "memory": memory}

    def _fake_run(self, repo_cpus, repo_memory, containers, inspect_map):
        def run(args, cwd=None, capture_output=True, text=True):
            if args[0] == "docker" and args[1] == "compose":
                if "config" in args:
                    return _Result(0, json.dumps({
                        "services": {
                            "svc": {
                                "deploy": {"resources": {"limits": {
                                    "cpus": repo_cpus, "memory": repo_memory,
                                }}}
                            }
                        }
                    }))
                if "ps" in args:
                    return _Result(0, "\n".join(json.dumps(c) for c in containers))
            if args[0] == "docker" and args[1] == "inspect":
                return _Result(0, inspect_map[args[2]])
            raise AssertionError(args)

        return run

    def test_no_drift_when_live_matches_repo(self) -> None:
        self._mkproject("technitium", cpus=3, memory="2147483648")
        containers = [{"Service": "svc", "State": "running", "Name": "technitium-dns"}]
        inspect_map = {"technitium-dns": "3000000000 2147483648"}
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_run(3, "2147483648", containers, inspect_map)):
            findings = cdw.resource_limit_findings(self.stacks_root)
        self.assertEqual(findings, [])

    def test_memory_drifted_to_half_is_reported(self) -> None:
        self._mkproject("technitium", cpus=3, memory="2147483648")
        containers = [{"Service": "svc", "State": "running", "Name": "technitium-dns"}]
        inspect_map = {"technitium-dns": "3000000000 1073741824"}
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_run(3, "2147483648", containers, inspect_map)):
            findings = cdw.resource_limit_findings(self.stacks_root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["field"], "memory")
        self.assertEqual(findings[0]["repo"], 2147483648)
        self.assertEqual(findings[0]["live"], 1073741824)

    def test_cpu_drift_is_reported(self) -> None:
        self._mkproject("technitium", cpus=3, memory="2147483648")
        containers = [{"Service": "svc", "State": "running", "Name": "technitium-dns"}]
        inspect_map = {"technitium-dns": "1500000000 2147483648"}
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_run(3, "2147483648", containers, inspect_map)):
            findings = cdw.resource_limit_findings(self.stacks_root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["field"], "cpus")

    def test_non_running_container_is_ignored(self) -> None:
        self._mkproject("technitium", cpus=3, memory="2147483648")
        containers = [{"Service": "svc", "State": "exited", "Name": "technitium-dns"}]
        inspect_map = {"technitium-dns": "1500000000 1073741824"}
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_run(3, "2147483648", containers, inspect_map)):
            findings = cdw.resource_limit_findings(self.stacks_root)
        self.assertEqual(findings, [])

    def test_project_with_no_declared_limits_is_skipped(self) -> None:
        self._mkproject("plain", cpus=None, memory=None)
        containers = [{"Service": "svc", "State": "running", "Name": "plain"}]
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_run(None, None, containers, {})):
            findings = cdw.resource_limit_findings(self.stacks_root)
        self.assertEqual(findings, [])


class FailingStreakTest(unittest.TestCase):
    """#3030/REVIEW-A: a raw FailingStreak count resets to 0 the moment
    hp-autoheal restarts the container (this fleet's healthchecks near-
    universally use retries: 3), so a count threshold is unreachable.
    failing_streak_findings() now tracks first-seen-failing timestamps in a
    state file across sweeps and fires on elapsed duration instead --
    these tests simulate that by mocking time.time() across two calls
    sharing one state file, the way two scheduled sweeps 30 minutes apart
    would."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_file = Path(self.tmp.name) / "streak-state.json"

    @staticmethod
    def _fake_docker(containers: list[dict]):
        def run(args, capture_output=True, text=True):
            if args[:2] == ["docker", "ps"]:
                return _Result(0, "\n".join(c["Id"] for c in containers))
            if args[:2] == ["docker", "inspect"]:
                return _Result(0, json.dumps(containers))
            raise AssertionError(args)

        return run

    def test_first_sweep_never_fires_even_with_high_streak_count(self) -> None:
        # The whole point of #3030's fix: a bare FailingStreak of 6 on the
        # very first sweep that sees it must NOT alarm -- it has only been
        # failing since "now", by definition, until a later sweep confirms
        # it is still failing after the duration threshold.
        containers = [{
            "Id": "abc123",
            "Name": "/hp-llm-worker",
            "State": {"Health": {"FailingStreak": 6, "Status": "unhealthy"}},
        }]
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_docker(containers)), \
             mock.patch.object(cdw.time, "time", return_value=1_000_000.0):
            findings = cdw.failing_streak_findings(3600, state_file=self.state_file)
        self.assertEqual(findings, [])
        self.assertIn("hp-llm-worker", json.loads(self.state_file.read_text()))

    def test_fires_once_duration_threshold_elapses_across_sweeps(self) -> None:
        containers = [{
            "Id": "abc123",
            "Name": "/hp-llm-worker",
            "State": {"Health": {"FailingStreak": 3, "Status": "unhealthy"}},
        }]
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_docker(containers)), \
             mock.patch.object(cdw.time, "time", return_value=1_000_000.0):
            findings = cdw.failing_streak_findings(3600, state_file=self.state_file)
        self.assertEqual(findings, [])

        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_docker(containers)), \
             mock.patch.object(cdw.time, "time", return_value=1_000_000.0 + 3601):
            findings = cdw.failing_streak_findings(3600, state_file=self.state_file)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "hp-llm-worker")
        self.assertEqual(findings[0]["unhealthy_for_seconds"], 3601)

    def test_streak_clearing_resets_the_duration_clock(self) -> None:
        failing = [{
            "Id": "abc123",
            "Name": "/hp-llm-worker",
            "State": {"Health": {"FailingStreak": 3, "Status": "unhealthy"}},
        }]
        healthy = [{
            "Id": "abc123",
            "Name": "/hp-llm-worker",
            "State": {"Health": {"FailingStreak": 0, "Status": "healthy"}},
        }]
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_docker(failing)), \
             mock.patch.object(cdw.time, "time", return_value=1_000_000.0):
            cdw.failing_streak_findings(3600, state_file=self.state_file)
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_docker(healthy)), \
             mock.patch.object(cdw.time, "time", return_value=1_000_000.0 + 10):
            cdw.failing_streak_findings(3600, state_file=self.state_file)
        # Fails again well after the threshold, but only 5s after this
        # latest failure started -- must not fire on the stale first-seen.
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_docker(failing)), \
             mock.patch.object(cdw.time, "time", return_value=1_000_000.0 + 15):
            findings = cdw.failing_streak_findings(3600, state_file=self.state_file)
        self.assertEqual(findings, [])

    def test_container_without_healthcheck_is_ignored(self) -> None:
        containers = [{"Id": "abc123", "Name": "/no-healthcheck", "State": {}}]
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_docker(containers)):
            findings = cdw.failing_streak_findings(3600, state_file=self.state_file)
        self.assertEqual(findings, [])

    def test_no_running_containers_short_circuits(self) -> None:
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_docker([])):
            findings = cdw.failing_streak_findings(3600, state_file=self.state_file)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
