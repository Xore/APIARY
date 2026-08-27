#!/usr/bin/env python3
"""Drop `&optional` where HASSH pairs it with `&default` (#1821).

Zeek deprecated declaring a record field with both attributes, and its own
NEWS says when that stops being a warning:

    Using ``&default`` and ``&optional`` together on a record field has been
    deprecated as it would only result in ``&default`` behavior. This will
    become an error starting with Zeek 8.1.

HASSH does it on fourteen live fields. On Zeek 8.1 the script fails to
load, which does not degrade quietly: either the image build fails, or
Zeek comes up with no SSH fingerprinting at all and every hassh value is
empty. That second shape is the dangerous one, because it is exactly what
a checksum-offload problem looked like in #1742 -- a second, unrelated
cause producing an identical symptom, which is why #1821 wanted this
written down before anyone bumps Zeek.

## Why `&optional` is the one that goes

#1821 proposed dropping `&default`. That is the wrong half, and Zeek's own
wording is the reason: the combination "would only result in `&default`
behavior". So today every one of these fields is always present, carrying
"" when nothing set it. Drop `&default` and they become genuinely
optional -- absent from the log rather than empty -- which changes what
ships to Elasticsearch and what every downstream reader sees.

Dropping `&optional` keeps the observable behaviour identical. That is the
point: this patch exists to survive an upgrade, not to redesign a log.

## Why the package is patched here rather than fixed upstream

It cannot be fixed upstream. salesforce/hassh is archived -- its final
commit, 56fa496 on 2025-05-01, is titled "This repo is ARCHIVED". There is
nobody to send this to, and the code will not change again.

That also makes the pin in the Containerfile exact rather than aspirational:
`--version 56fa496af4495ce890ea790a0152215520fc3b7a` is the last state the
package will ever have.

Same shape as this repo's other build-time patches (hellpot/router_patch.py,
mailoney/json_log_patch.py): exact-match replacement, a marker for
idempotency, applied at image build.
"""
import re
import sys
from pathlib import Path

MARKER = "# honeypot-stack: &optional dropped for Zeek 8.1 (#1821)"

# zkg installs the package here; the clone and scratch copies are not what
# Zeek loads, so they are deliberately left alone.
TARGET = Path("/usr/local/zeek/share/zeek/site/packages/hassh/hassh.zeek")

# Only where the two appear together, and only in that order -- the file
# also has plenty of legitimate `&optional`-alone fields (the SSH::Info
# record at the bottom) which must not be touched.
PAIR = re.compile(r"&optional\s+(&default=)")

# What upstream has today. If this ever stops matching, the package changed
# under us and the patch should fail loudly rather than silently do nothing.
EXPECTED_LIVE_PAIRS = 14


def main():
    if not TARGET.exists():
        raise SystemExit(f"hassh_optional_patch.py: {TARGET} not found")

    text = TARGET.read_text()
    if MARKER in text:
        return  # already patched

    # Count only live declarations; two of the pairs upstream sit on
    # commented-out lines and are patched harmlessly along with the rest.
    live = sum(
        1
        for line in text.splitlines()
        if PAIR.search(line) and not line.lstrip().startswith("#")
    )
    if live != EXPECTED_LIVE_PAIRS:
        raise SystemExit(
            "hassh_optional_patch.py: expected %d live '&optional &default' fields, found %d "
            "-- the package changed, re-check before shipping" % (EXPECTED_LIVE_PAIRS, live)
        )

    patched = PAIR.sub(r"\1", text)
    if patched == text:
        raise SystemExit("hassh_optional_patch.py: nothing replaced")

    # Nothing that was `&optional` alone may have been touched.
    before_alone = len(re.findall(r"&optional(?!\s+&default)", text))
    after_alone = len(re.findall(r"&optional(?!\s+&default)", patched))
    if before_alone != after_alone:
        raise SystemExit(
            "hassh_optional_patch.py: an &optional-only field was modified "
            "(%d -> %d) -- refusing" % (before_alone, after_alone)
        )

    TARGET.write_text(f"{MARKER}\n{patched}")
    print(f"hassh_optional_patch.py: dropped &optional from {live} fields", file=sys.stderr)


if __name__ == "__main__":
    main()
