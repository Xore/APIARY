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

Stdlib only, like analyze.py itself: runs plain `python3 test_analyze.py`.
"""

import contextlib
import io
import sys
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyze  # noqa: E402

ALL_CONTROLS = [chr(c) for c in list(range(0x20)) + [0x7F] + list(range(0x80, 0xA0))]


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


if __name__ == "__main__":
    unittest.main()
