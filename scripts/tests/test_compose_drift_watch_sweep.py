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
        # #3129: llm-worker itself moved into EXPECTED_ABSENT_WHILE (see
        # below), so this general "single-service project alarms" pin now
        # uses a different real single-service manifest entry instead.
        self._mkproject("auth-events-worker")
        configs = {"auth-events-worker": ({"auth-events-worker": "unless-stopped"}, [])}
        with mock.patch.object(cdw.subprocess, "run", side_effect=_fake_compose_run(configs)):
            findings, unresolved = cdw.sweep(self.stacks_root, entries=[], retired=set())
        self.assertEqual(unresolved, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["project"], "auth-events-worker")
        self.assertEqual(findings[0]["service"], "auth-events-worker")
        self.assertEqual(findings[0]["siblings_running"], [])

    def test_expected_absent_project_stays_quiet(self) -> None:
        # #3129: llm-worker is still in the manifest (not retired) with a
        # persistent restart policy, but its one container has been
        # deliberately down since #3023. EXPECTED_ABSENT_WHILE must silence
        # exactly this named project without reopening #3040's blanket
        # "no sibling, don't alarm" rule for anything else.
        self._mkproject("llm-worker")
        configs = {"llm-worker": ({"llm-worker": "unless-stopped"}, [])}
        with mock.patch.object(cdw.subprocess, "run", side_effect=_fake_compose_run(configs)):
            findings, unresolved = cdw.sweep(self.stacks_root, entries=[], retired=set())
        self.assertEqual(findings, [])
        self.assertEqual(unresolved, [])

    def test_unlisted_single_service_project_still_alarms_next_to_expected_absent(self) -> None:
        # Control for the above: a different single-service project with the
        # same zero-container, no-sibling shape as llm-worker must still
        # alarm -- EXPECTED_ABSENT_WHILE only matches its one named key.
        self._mkproject("llm-worker")
        self._mkproject("ml-worker")
        configs = {
            "llm-worker": ({"llm-worker": "unless-stopped"}, []),
            "ml-worker": ({"ml-worker": "unless-stopped"}, []),
        }
        with mock.patch.object(cdw.subprocess, "run", side_effect=_fake_compose_run(configs)):
            findings, _ = cdw.sweep(self.stacks_root, entries=[], retired=set())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["project"], "ml-worker")

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


class ManifestCoverageTest(unittest.TestCase):
    """REVIEW-A blocking finding 1: manifest_extra_targets() used to skip
    every compose.yml-named entry on the theory project_dirs() already
    covered it -- true only for the unprivileged-readable minority. A dir
    that is both compose.yml-named and unreadable (0700 root:root, matching
    honeypot-elk/honeypot-keycloak live) fell through both functions and
    was never swept at all -- 31 of 38 manifest stacks, measured live."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stacks_root = Path(self.tmp.name)

    def test_unreadable_compose_yml_manifest_entry_reaches_privileged_fallback(self) -> None:
        # A readable sibling so project_dirs() has something to find --
        # its own "no compose.yml anywhere" gate is a separate, deliberate
        # loud-crash safety net, not part of what this test pins.
        # No declared services -- stays quiet on its own, exists purely so
        # project_dirs() has a readable match (its own deliberate "empty
        # fleet" safety gate is a separate concern from what this test pins).
        sibling = self.stacks_root / "technitium"
        sibling.mkdir()
        (sibling / "compose.yml").write_text("services: {}\n")

        locked = self.stacks_root / "honeypot-elk"
        locked.mkdir()
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o700)

        entries = [{"syncName": "honeypot-elk", "dockerComposePath": "arcane/home/honeypot-elk/compose.yml"}]

        def fake_run(args, cwd=None, capture_output=True, text=True):
            if cwd == locked:
                # 0700 root:root denies chdir before docker even runs --
                # same shape resolved_services()/actual_containers() catch.
                raise OSError("Permission denied")
            if cwd == sibling:
                if "config" in args:
                    return _Result(0, json.dumps({"services": {}}))
                if "ps" in args:
                    return _Result(0, "")
            if args[:2] == ["sudo", "-n"]:
                return _Result(0, json.dumps({
                    "services": {"elasticsearch": "unless-stopped"},
                    "containers": [],
                    "limits": {},
                }))
            raise AssertionError(args)

        with mock.patch.object(cdw.subprocess, "run", side_effect=fake_run):
            findings, unresolved = cdw.sweep(self.stacks_root, entries=entries, retired=set())
        self.assertEqual(unresolved, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["project"], "honeypot-elk")

    def test_readable_compose_yml_manifest_entry_not_double_reported(self) -> None:
        # Regression for the dedup this fix leans on: a project_dirs()-
        # readable stack whose manifest entry is ALSO compose.yml-named
        # must not be swept twice now that manifest_extra_targets() no
        # longer skips that basename.
        d = self.stacks_root / "honeypot-galah"
        d.mkdir()
        (d / "compose.yml").write_text("services: {}\n")

        entries = [{"syncName": "honeypot-galah", "dockerComposePath": "arcane/home/honeypot-galah/compose.yml"}]
        configs = {"honeypot-galah": ({"galah": "unless-stopped"}, [])}
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


class ResourceLimitPrivilegedFallbackTest(unittest.TestCase):
    """REVIEW-A blocking finding 2/#3028: resource_limit_findings() had no
    privileged fallback at all, so it could never fire against any
    .env-locked or 0700 root-owned stack -- measured live as "projects with
    declared limits: 0". Now routes through project_limits()/
    project_state(), same as sweep() does for restart-policy drift."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stacks_root = Path(self.tmp.name)

    def test_env_locked_project_resolves_limits_through_privileged_helper(self) -> None:
        # project_dirs() refuses to treat a stacks root with zero readable
        # matches as a healthy fleet (its own deliberate safety gate) -- give
        # it one ordinary readable sibling, same as a real fleet would have.
        sibling = self.stacks_root / "honeypot-galah"
        sibling.mkdir()
        (sibling / "compose.yml").write_text("services: {}\n")

        locked = self.stacks_root / "technitium"
        locked.mkdir()
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o700)

        entries = [{"syncName": "technitium", "dockerComposePath": "sandbox/technitium/compose.yml"}]

        def fake_run(args, cwd=None, capture_output=True, text=True):
            if cwd == locked:
                raise OSError("Permission denied")
            if cwd == sibling:
                if "config" in args:
                    return _Result(0, json.dumps({"services": {}}))
                if "ps" in args:
                    return _Result(0, "")
            if args[:2] == ["sudo", "-n"]:
                return _Result(0, json.dumps({
                    "services": {"technitium-dns": "unless-stopped"},
                    "containers": [{"Service": "technitium-dns", "State": "running", "Name": "technitium-dns"}],
                    "limits": {"technitium-dns": {"cpus": 3, "memory": "2147483648"}},
                }))
            if args[:2] == ["docker", "inspect"]:
                return _Result(0, "1500000000 2147483648")
            raise AssertionError(args)

        with mock.patch.object(cdw.subprocess, "run", side_effect=fake_run):
            findings = cdw.resource_limit_findings(self.stacks_root, entries=entries)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["field"], "cpus")
        self.assertEqual(findings[0]["project"], "technitium")

    def test_env_locked_project_with_no_drift_stays_quiet(self) -> None:
        sibling = self.stacks_root / "honeypot-galah"
        sibling.mkdir()
        (sibling / "compose.yml").write_text("services: {}\n")

        locked = self.stacks_root / "technitium"
        locked.mkdir()
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o700)

        entries = [{"syncName": "technitium", "dockerComposePath": "sandbox/technitium/compose.yml"}]

        def fake_run(args, cwd=None, capture_output=True, text=True):
            if cwd == locked:
                raise OSError("Permission denied")
            if cwd == sibling:
                if "config" in args:
                    return _Result(0, json.dumps({"services": {}}))
                if "ps" in args:
                    return _Result(0, "")
            if args[:2] == ["sudo", "-n"]:
                return _Result(0, json.dumps({
                    "services": {"technitium-dns": "unless-stopped"},
                    "containers": [{"Service": "technitium-dns", "State": "running", "Name": "technitium-dns"}],
                    "limits": {"technitium-dns": {"cpus": 3, "memory": "2147483648"}},
                }))
            if args[:2] == ["docker", "inspect"]:
                return _Result(0, "3000000000 2147483648")
            raise AssertionError(args)

        with mock.patch.object(cdw.subprocess, "run", side_effect=fake_run):
            findings = cdw.resource_limit_findings(self.stacks_root, entries=entries)
        self.assertEqual(findings, [])


class LimitsSchemaSkewTest(unittest.TestCase):
    """REVIEW-A blocking finding 3/#3028: the deployed privileged helper
    predates the "limits" field, so `data.get("limits")` returned None and
    was silently treated identically to a resolved-but-empty `{}` --
    "no limits declared" and "helper doesn't know about limits" looked the
    same. A missing key must warn loudly instead of reading as clean."""

    def setUp(self) -> None:
        cdw._warned_limits_schema_skew = False

    def test_missing_limits_key_warns_once_and_treats_as_empty(self) -> None:
        old_helper_output = json.dumps({
            "services": {"svc": "unless-stopped"},
            "containers": [{"Service": "svc", "State": "running", "Name": "svc"}],
        })
        with mock.patch.object(
            cdw.subprocess, "run", return_value=_Result(0, old_helper_output)
        ), mock.patch.object(cdw.sys, "stderr") as fake_stderr:
            result = cdw.privileged_project_state(Path("/some/project"))
            result2 = cdw.privileged_project_state(Path("/some/project"))
        self.assertIsNotNone(result)
        _, _, limits = result
        self.assertEqual(limits, {})
        _, _, limits2 = result2
        self.assertEqual(limits2, {})
        warnings = [c for c in fake_stderr.write.call_args_list if "limits" in c.args[0]]
        # print() calls .write() once for the message and once for the
        # newline -- assert the warning fired exactly once across both
        # privileged_project_state() calls, not once per call.
        self.assertEqual(sum(1 for c in warnings if "no 'limits' field" in c.args[0]), 1)

    def test_present_empty_limits_dict_does_not_warn(self) -> None:
        resolved_output = json.dumps({
            "services": {"svc": "unless-stopped"},
            "containers": [{"Service": "svc", "State": "running", "Name": "svc"}],
            "limits": {},
        })
        with mock.patch.object(
            cdw.subprocess, "run", return_value=_Result(0, resolved_output)
        ), mock.patch.object(cdw.sys, "stderr") as fake_stderr:
            result = cdw.privileged_project_state(Path("/some/project"))
        self.assertIsNotNone(result)
        _, _, limits = result
        self.assertEqual(limits, {})
        warnings = [c for c in fake_stderr.write.call_args_list if "no 'limits' field" in c.args[0]]
        self.assertEqual(warnings, [])


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

    def test_state_file_is_written_group_writable(self) -> None:
        # REVIEW-A blocking finding 3/#3030: a runner user's default umask
        # (022) leaves write_text()'s file at 0644 -- unwritable by the
        # other three github-ci-runner-{2,3,4} accounts sharing the group,
        # confirmed live as the actual root cause of the state never
        # updating. _save_streak_state() must chmod every write explicitly.
        containers = [{
            "Id": "abc123",
            "Name": "/hp-llm-worker",
            "State": {"Health": {"FailingStreak": 6, "Status": "unhealthy"}},
        }]
        with mock.patch.object(cdw.subprocess, "run", side_effect=self._fake_docker(containers)), \
             mock.patch.object(cdw.time, "time", return_value=1_000_000.0):
            cdw.failing_streak_findings(3600, state_file=self.state_file)
        mode = self.state_file.stat().st_mode & 0o777
        self.assertEqual(mode, 0o664)


if __name__ == "__main__":
    unittest.main()
