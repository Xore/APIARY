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
import os
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
    # guest-runner.sh always pipes this through `| head -n 4000` -- head
    # exiting once it has its 4000 lines closes our stdout out from under us,
    # and Python's default SIGPIPE handling turns that into an unhandled
    # BrokenPipeError traceback (confirmed live, #498's smoke test run:
    # landed in runner_log even though strings-ascii.txt/strings-utf16le.txt
    # were both written correctly -- head already had everything it needed).
    # Standard fix per Python's own devguide: swallow the error, redirect
    # stdout to /dev/null so the interpreter's own shutdown-time flush
    # doesn't raise a second one, then exit non-zero.
    try:
        for raw in sys.stdin:
            s = clean(raw)
            if s:
                print(s)
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)


if __name__ == "__main__":
    main()
