#!/usr/bin/env python3
"""Filter GNU `strings` output for punctuation-only fragments (#530).

`strings -a` is exactly as permissive as dashboard/payload_analysis.go's own
byte-range string scan -- any run of printable bytes counts, no character-
class filtering -- so both emit the identical class of noise: pure
separator/punctuation runs (``//////``, ``--------``) as their own
"strings", and real strings glued to quote/backslash/slash padding at the
boundary. This applies the same rule dashboard/payload_analysis.go's
cleanExtractedString does, so the two independently-run extractors (dashboard
static analysis, this sandbox script) stay in sync instead of silently
diverging: trim boundary noise from both ends of each line -- never the
middle, where it is real content, e.g. a quoted argument or a Windows path
-- then drop anything left with no letter or digit anywhere in it.

Reads lines on stdin, writes the cleaned, non-empty ones to stdout.
"""
import sys

NOISE = "'\"`\\/|"
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def clean(line: str) -> str:
    """Trim boundary noise and reject punctuation-only content.

    Returns the cleaned string, or "" if nothing worth keeping remains --
    either the line was blank/all-noise, or what's left after trimming has
    no letter or digit anywhere in it.
    """
    s = line.rstrip("\n").strip(NOISE).strip()
    if not s or not any(c in ALNUM for c in s):
        return ""
    return s


def main() -> None:
    for raw in sys.stdin:
        s = clean(raw)
        if s:
            print(s)


if __name__ == "__main__":
    main()
