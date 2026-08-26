#!/usr/bin/env python3
"""#1984: the triage report's only output surface for hostile bytes is
print_table, and it must emit attacker-supplied control characters inertly.

analyze.py's inputs are SSH usernames/passwords/commands, HTTP paths,
user-agents and multipot commands -- Cowrie records whatever bytes a client
sends, so an ESC sequence in any counted field used to print raw and drive
the analyst's terminal emulator. These tests prove no C0/C1 byte survives
to stdout, that payloads stay visible as evidence (<0xNN> spellings), that
clean values render byte-identically, and that counts -- the only column
an operator eyeballs numerically -- keep their formatting.

TestHygieneBatch1985 covers #1985: malformed lines are reported instead of
silently dropped, print_table carries no dead parameters, generic events
count toward the total with or without an IP, foreign category-bearing
events stay out of the http tables, and multipot's VNC auth attempts show
up in the login-failed figure.

Stdlib only, like analyze.py itself: runs plain `python3 test_analyze.py`.
"""

import contextlib
import inspect
import io
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyze  # noqa: E402

ALL_CONTROLS = [chr(c) for c in list(range(0x20)) + [0x7F] + list(range(0x80, 0xA0))]


def exhaust_with_stderr(it):
    """Drain an iter_events generator with stderr captured.

    The skip summary prints when iteration ends -- exhausting here is what
    fires it, so this is both the drive mechanism and the assertion source.
    """
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        items = list(it)
    return items, buf.getvalue()


def render(counter):
    """Run print_table over counter and return everything it printed."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        analyze.print_table("t", Counter(counter), top=100)
    return buf.getvalue()


class TestSanitisation(unittest.TestCase):
    def test_osc_title_rewrite_is_inert_and_visible(self):
        out = render({"console": 1, "\x1b]0;pwned\x07": 3})
        self.assertNotIn("\x1b", out)
        # Evidence stays readable on screen, just spelled out.
        self.assertIn("<0x1b>", out)
        self.assertIn("]0;pwned", out)

    def test_real_attack_sequences_never_reach_stdout(self):
        payloads = [
            "\x1b]0;pwned\x07",                 # OSC title rewrite
            "\x1b[H\x1b[2J",                    # cursor home + screen erase
            "\x1b[6n",                          # device status query
            "\x1b]52;c;YWJj\x07",               # OSC 52 clipboard overwrite
            "pass\x0dwd\x0aexit success",       # CR/LF table-row forgery
            "\x9b2J",                           # eight-bit C1 CSI
        ]
        out = render({p: i + 1 for i, p in enumerate(payloads)})
        # The only raw newlines allowed are print_table's own row breaks --
        # any inside a value show up as <0x0a> instead.
        scan = out.replace("\n", "")
        for ch in ALL_CONTROLS:
            self.assertNotIn(ch, scan, f"raw control character {ch!r} leaked")
        for marker in ("]0;pwned", "[2J", "]52;c;YWJj", "pass", "wd"):
            self.assertIn(marker, out)

    def test_every_c0_del_and_c1_byte_is_rendered(self):
        sanitized = analyze._sanitize("".join(ALL_CONTROLS))
        for c in ALL_CONTROLS:
            self.assertNotIn(c, sanitized)
            self.assertIn(f"<0x{ord(c):02x}>", sanitized,
                          f"{ord(c):02x} not rendered visibly")

    def test_clean_values_are_byte_identical(self):
        values = {"root / toor": 12, "/admin.php?cmd=1": 7, "SSH-2.0-libssh_0.8.0": 3}
        out = render(values)
        for v, n in values.items():
            self.assertIn(f"  {n:>6}  {v}\n", out)

    def test_counts_keep_column_formatting(self):
        self.assertIn("       5  x\n", render({"x": 5}))


class TestEndToEnd(unittest.TestCase):
    def test_hostile_cowrie_event_flows_through_stats_and_table(self):
        st = analyze.Stats()
        st.add_cowrie({
            "eventid": "cowrie.login.failed",
            "src_ip": "203.0.113.7",
            "username": "\x1b[31;1mroot",
            "password": "\x1b]52;c;base64payload\x07",
        })
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            analyze.print_table("Top usernames", st.usernames, top=10)
            analyze.print_table("Top passwords", st.passwords, top=10)
        out = buf.getvalue().replace("\n", "")
        self.assertNotIn("\x1b", out)
        self.assertIn("<0x1b>[31;1mroot", out)
        self.assertIn("<0x1b>]52;c;base64payload<0x07>", out)

    def test_json_export_still_carries_raw_values(self):
        st = analyze.Stats()
        st.add_http({
            "sensor": "http-honeypot",
            "src_ip": "203.0.113.7",
            "path": "/\x1b[2Jprobe",
            "category": "scan",
        })
        self.assertEqual(st.http_paths.most_common(1)[0][0], "/\x1b[2Jprobe")


class TestHygieneBatch1985(unittest.TestCase):
    """#1985: silent malformed-line skips, dead code, total undercount,
    category catch-all, and the missing VNC login counter."""

    def test_unparsable_lines_reported_per_file_on_stderr(self):
        with tempfile.TemporaryDirectory() as d:
            good = Path(d, "cowrie.json")
            bad = Path(d, "truncated.json")
            clean = Path(d, "clean.json")
            good.write_text(
                '{"eventid": "cowrie.login.failed"}\n'
                '{"eventid": "cowrie.login.success"}\n', encoding="utf-8")
            bad.write_text(
                '{"eventid": "cowrie.command.input", "input": "id"}\n'
                '{"eventid": "cowrie.comm\n'          # rotation mid-write
                'not json at all\n'
                '\n'                                   # blank: not a skip
                '{"eventid": "x"}\n', encoding="utf-8")
            clean.write_text('{"sensor": "multipot"}\n', encoding="utf-8")

            events, err = exhaust_with_stderr(analyze.iter_events([d]))

            self.assertEqual(len(events), 5)  # everything except the 2 bad lines
            self.assertIn("! skipped 2 unparsable line(s) in " + str(bad), err)
            for name in (str(good), str(clean)):
                self.assertNotIn(name, err)

    def test_zero_skips_print_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "a.json").write_text('{"ok": true}\n', encoding="utf-8")
            _events, err = exhaust_with_stderr(analyze.iter_events([d]))
            self.assertEqual(err, "")

    def test_print_table_has_no_dead_parameters(self):
        # The cols=("count", "value") parameter and the computed-then-unused
        # width were dead since the table's first revision (#1985).
        params = list(inspect.signature(analyze.print_table).parameters)
        self.assertEqual(params, ["title", "counter", "top"])

    def test_generic_event_without_ip_counts_toward_total(self):
        st = analyze.Stats()
        st.add_generic({"sensor": "dionaea", "connection": {"protocol": "smb"}})
        self.assertEqual(st.total, 1)
        self.assertEqual(st.other_sensors["dionaea"], 1)
        self.assertEqual(len(st.src_ips), 0)

    def test_foreign_sensor_with_category_lands_in_generic(self):
        e = {"sensor": "third-party-sensor", "category": "scan",
             "src_ip": "203.0.113.9"}
        # Same dispatch order main() uses.
        if analyze.is_cowrie(e):
            analyze.Stats().add_cowrie(e)
        elif analyze.is_multipot(e):
            pass
        elif analyze.is_http(e):
            self.fail("category-bearing foreign event claimed by is_http")
        else:
            st = analyze.Stats()
            st.add_generic(e)
            self.assertEqual(st.src_ips["203.0.113.9"], 1)
            self.assertEqual(st.other_sensors["third-party-sensor"], 1)
            self.assertEqual(st.http_paths, Counter())

    def test_legacy_unstamped_http_records_still_route_to_http(self):
        # The fallback survives, keyed on real HTTP fields rather than a
        # bare category (#1985).
        self.assertTrue(analyze.is_http({"path": "/admin"}))
        self.assertTrue(analyze.is_http({"user_agent": "curl/8"}))
        self.assertFalse(analyze.is_http({"category": "scan"}))
        self.assertTrue(analyze.is_http({"sensor": "http-honeypot",
                                         "category": "probe"}))

    def test_vnc_auth_attempt_counts_as_failed_login(self):
        st = analyze.Stats()
        st.add_multipot({"sensor": "multipot", "event": "auth_attempt",
                         "proto": "vnc", "src_ip": "203.0.113.5",
                         "username": "admin", "password": ""})
        self.assertEqual(st.login_failed, 1)
        self.assertEqual(st.total, 1)
        self.assertEqual(st.creds["admin / "], 1)
        self.assertEqual(st.protos["vnc"], 1)
        # Plain logins keep counting as before.
        st.add_multipot({"sensor": "multipot", "event": "login",
                         "proto": "ssh", "src_ip": "203.0.113.5",
                         "username": "root", "password": "toor"})
        self.assertEqual(st.login_failed, 2)


if __name__ == "__main__":
    unittest.main()
