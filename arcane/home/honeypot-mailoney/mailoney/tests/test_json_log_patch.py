#!/usr/bin/env python3
"""Test mailoney/json_log_patch.py (#1422), including #2197's UTC contract.

The patch is a build-time exact-text rewrite of vendored core.py, so two
things are asserted here rather than trusted:

- what the patch *injects* -- its injected helper block is exec'd directly
  against a TZ=Europe/Berlin process, because that zone is pinned in
  compose.yml and was load-bearing in #2197: a bare strftime() rendered
  Berlin wall clock wearing a Z suffix, ip-enrichment-worker parsed those
  stamps as RFC3339 UTC for the portbridge join (sensors.rs), and the DST
  offset leaked straight into time-since-dial attribution -- the same
  ambiguity window #1917 had just shrunk;
- what the patch *matches* -- the OLD constants must still appear in
  upstream core.py as written, or the image build dies several layers
  below this file. Assembling the fixture from the patch's own OLD texts
  means there is no second copy to drift (same reasoning as
  test_xff_trust_patch.py's fixture).

Upstream relative imports (db/config/mail_storage) are stripped before
exec'ing the injected header -- they need the vendored package tree,
which is unavailable outside the image build, and none of the tested
helpers reference them.

Usage: mailoney/tests/test_json_log_patch.py
"""
import base64
import importlib.util
import json
import os
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from time import gmtime, strftime, tzset

HERE = Path(__file__).resolve().parent
PATCH = HERE.parent / "json_log_patch.py"
STAMP_FORMAT = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"


def load_patch(target=None):
    """Load the real patch module, optionally pointing TARGET at a fixture."""
    source = PATCH.read_text()
    if target is not None:
        source = source.replace(
            'Path("/build/mailoney/core.py")', f"Path({str(target)!r})"
        )
    spec = importlib.util.spec_from_loader(PATCH.stem, loader=None)
    module = importlib.util.module_from_spec(spec)
    exec(compile(source, str(PATCH), "exec"), module.__dict__)
    return module


def exec_injected_header(module):
    """Run the patch's own replacement header as patched core.py would."""
    source = "\n".join(
        line for line in module.IMPORTS_NEW.splitlines()
        if not line.startswith("from .")
    )
    ns = {}
    exec(compile(source, "<patched core.py header>", "exec"), ns)
    return ns


def emit_as_patched(ns, log_path, **overrides):
    """Invoke the injected _emit_json_event once, return the record dict."""
    saved = os.environ.get("MAILONEY_JSON_LOG")
    os.environ["MAILONEY_JSON_LOG"] = str(log_path)
    try:
        ns["_emit_json_event"](
            "login", ("192.0.2.10", 50321), "172.23.0.5", 25, "mx.example",
            username="user@example.org", password="hunter2",
        )
    finally:
        if saved is None:
            del os.environ["MAILONEY_JSON_LOG"]
        else:
            os.environ["MAILONEY_JSON_LOG"] = saved
    line = Path(log_path).read_text().splitlines()[0]
    return json.loads(line)


class BerlinPinnedTimestamp(unittest.TestCase):
    """The #2197 regression: stamps claim Z, so they must BE UTC."""

    def setUp(self):
        self.module = load_patch()
        self.ns = exec_injected_header(self.module)

    @staticmethod
    def pin_berlin():
        old = os.environ.pop("TZ", None)

        def restore():
            if old is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old
            tzset()

        os.environ["TZ"] = "Europe/Berlin"
        tzset()
        return restore

    def test_emit_under_berlin_tz_is_true_utc(self):
        restore = self.pin_berlin()
        try:
            with tempfile.TemporaryDirectory() as d:
                record = emit_as_patched(self.ns, Path(d) / "out.jsonl")
        finally:
            restore()
        self.assertRegex(record["timestamp"], STAMP_FORMAT)
        got = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
        skew = abs((datetime.now(timezone.utc) - got).total_seconds())
        # Whole-second truncation contributes up to 1.0s on its own; the
        # defect this guards against is >=3599s (#2197), so 2.0s keeps the
        # regression caught while not flaking at second boundaries.
        self.assertLessEqual(skew, 2.0, f"{record['timestamp']} is not true UTC")

    def test_emit_event_shape_matches_enrichline_contract(self):
        # The whole reason the sink exists: enrichLine() consumes flat
        # top-level src_ip/src_port plus the fleet's "sensor" literal.
        with tempfile.TemporaryDirectory() as d:
            record = emit_as_patched(self.ns, Path(d) / "out.jsonl")
        self.assertEqual(record["sensor"], "mailoney")
        self.assertEqual(record["event"], "login")
        self.assertEqual(record["src_ip"], "192.0.2.10")
        self.assertEqual(record["src_port"], 50321)
        self.assertEqual(record["dst_ip"], "172.23.0.5")
        self.assertEqual(record["dst_port"], 25)
        self.assertEqual(record["username"], "user@example.org")

    def test_the_old_localtime_expression_actually_drifts_here(self):
        # Negative control for the TZ machinery above: if the test host
        # could not resolve Europe/Berlin (glibc falls back to UTC), the
        # first test would pass vacuously while the very bug it exists to
        # catch stayed live in production. Force that case visible instead.
        restore = self.pin_berlin()
        try:
            # The strftime below reproduces the OLD bare-localtime call ON
            # PURPOSE -- it must localize, or every UTC assertion in this
            # suite is vacuous -- hence the inline waiver for
            # scripts/check-timestamp-utc.py.
            old_behavior = datetime.strptime(
                strftime("%Y-%m-%dT%H:%M:%SZ"), "%Y-%m-%dT%H:%M:%SZ"  # utc-verified: deliberate localtime repro, negative control
            ).replace(tzinfo=timezone.utc)
        finally:
            restore()
        skew = abs((datetime.now(timezone.utc) - old_behavior).total_seconds())
        self.assertGreaterEqual(skew, 1800, "TZ=Europe/Berlin did not localize; "
                                             "this suite's UTC proof is vacuous")


class PatchApplication(unittest.TestCase):
    """Exact-match discipline: every region replaces, second run no-ops."""

    def setUp(self):
        self.module = load_patch()
        m = self.module
        # No third copy of upstream text: the fixture IS the patch's own
        # match targets, so any edit to either side breaks here first.
        fixture = "\n\n".join(
            [m.IMPORTS_OLD, m.RECEIVE_OLD, m.AUTH_OLD, m.ENVELOPE_OLD, m.BODY_OLD]
        )
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.target = Path(self.dir.name) / "core.py"
        self.target.write_text(fixture)

    def patch(self):
        target_before = self.target.read_text()
        mod = load_patch(target=self.target)
        mod.main()
        self.assertIn(mod.MARKER, self.target.read_text())
        # Marker presence short-circuits main() on later runs, so reload to
        # exercise idempotency-by-marker honestly.
        if target_before == self.target.read_text():
            load_patch(target=self.target).main()
        return self.target.read_text()

    def test_all_five_regions_replaced_exactly_once(self):
        result = self.patch()
        m = self.module
        for new in (m.RECEIVE_NEW, m.AUTH_NEW, m.ENVELOPE_NEW, m.BODY_NEW):
            self.assertEqual(result.count(new), 1)
        # IMPORTS and AUTH were fully rewritten or restructured -- none of
        # their OLD text survives contiguously.
        for old in (m.IMPORTS_OLD, m.RECEIVE_OLD, m.AUTH_OLD):
            self.assertNotIn(old, result)
        # ENVELOPE and BODY are extensions in place: NEW legitimately
        # contains OLD, so absence cannot be asserted -- exactly-one
        # occurrence of each injected call is what pins them instead.
        self.assertEqual(result.count('"envelope", addr'), 1)
        self.assertEqual(result.count('"mail-body", addr'), 1)
        # No stray double-patch artifacts anywhere.
        self.assertEqual(result.count(m.MARKER), 1)

    def test_the_injected_stamp_carries_gmtime(self):
        result = self.patch()
        self.assertIn("from time import gmtime, strftime", result)
        self.assertIn('strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())', result)
        for lineno, line in enumerate(result.splitlines(), start=1):
            if "%SZ" in line and "strftime" in line:
                self.assertIn("gmtime", line, f"patched core.py:{lineno}")

    def test_no_bare_z_suffixed_strftime_survives_in_output(self):
        # Mirrors scripts/check-timestamp-utc.py at unit scope, so the
        # class cannot creep back in through a later tweak of this patch.
        result = self.patch()
        for lineno, line in enumerate(result.splitlines(), start=1):
            if re.search(r"\bstrftime\s*\(", line) and "%SZ" in line:
                self.assertTrue(re.search(r"\bgmtime\b|timezone\.utc|\butcnow\b", line),
                                f"core.py:{lineno}: {line.strip()}")

    def test_upstream_db_session_log_stays_untouched(self):
        # Scope discipline: mailoney's own SQLAlchemy session records keep
        # their naive local stamps -- only the additive JSON sink feeds
        # cross-sensor consumers, and only ITS stamp carried a Z claim.
        result = self.patch()
        needle = '"timestamp": strftime("%Y-%m-%d %H:%M:%S")'
        self.assertEqual(result.count(needle), 1, needle)

    def test_idempotent_second_run_changes_nothing(self):
        first = self.patch()
        load_patch(target=self.target).main()
        self.assertEqual(first, self.target.read_text())

    def test_refuses_on_unexpected_upstream_text(self):
        # A drifted vendored core.py must fail the image build loudly at
        # the patch step, not silently ship half the sink (#1908's lesson).
        self.target.write_text(
            self.target.read_text().replace(
                "log_credential(session_record.id, auth_string)",
                "log_credential(session_record.id, cred_string)",
                1,
            )
        )
        mod = load_patch(target=self.target)
        with self.assertRaises(SystemExit):
            mod.main()


class AuthPlainDecode(unittest.TestCase):
    """Injected into every capture path; the base64 alphabet quirk lives."""

    def setUp(self):
        self.module = load_patch()
        # The helper lives inside the injected header text, not as a
        # module attribute -- exec it exactly as patched core.py would.
        self.decode_auth_plain = exec_injected_header(self.module)["_decode_auth_plain"]

    def decode(self, raw: bytes) -> tuple[str, str]:
        b64 = base64.b64encode(raw).decode()
        return self.decode_auth_plain(b64)

    def test_splits_authzid_authcid_password(self):
        self.assertEqual(
            self.decode(b"\x00user@example.org\x00SecRet42"),
            ("user@example.org", "SecRet42"),
        )

    def test_tolerates_missing_padding(self):
        # AUTH PLAIN client supplies unpadded base64 routinely; the padding
        # repair (-len%4) must hold or captures die inside the try/except.
        payload = base64.b64encode(b"\x00ab\x00cd").decode().rstrip("=")
        self.assertEqual(self.decode_auth_plain(payload), ("ab", "cd"))

    def test_garbage_returns_empty_pair_not_raise(self):
        self.assertEqual(self.decode_auth_plain("!!!!"), ("", ""))


if __name__ == "__main__":
    unittest.main()
