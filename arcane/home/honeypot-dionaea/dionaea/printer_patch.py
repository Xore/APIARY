#!/usr/bin/env python3
"""Quiet printer.py's routine internet-noise warning to match its own
established log-level convention (#339).

process_pjl_line() in printer.py logs every *recognized* PJL command at
DEBUG (`logger.debug("input matches command '%s'", command)`, and the same
for ECHO/FSDIRLIST/FSQUERY), but the one path for an *unrecognized* line
logs at WARNING:

    logger.warning("unable to find command for '%s'", str(line))

Port 9100 (this service's port) is scanned constantly by generic HTTP/RDP
probers that have nothing to do with PJL -- confirmed live on the homeserver
(#339): 59 of these in 2000 log lines, the "commands" actually being plain
HTTP request lines (`GET / HTTP/1.1`, `Host: ...`, `User-Agent: ...`) and
what looks like an RDP X.224 Connection Request TPDU. That is exactly the
kind of routine, expected-to-be-common input this function's own author
already logs at DEBUG everywhere else -- WARNING here was the outlier, not
a deliberate signal to page or scroll `docker logs` on, and it drowned out
real PJL-protocol activity in the noise. This does not touch behavior: the
"?" reply and dionaea's own connection-level event recording (which does
not depend on this log call at all) are unchanged.
"""
from pathlib import Path

MARKER = "honeypot-stack: quiet the non-PJL warning to match this file's own DEBUG convention (#339)"
TARGET = Path("/opt/dionaea/lib/dionaea/python/dionaea/printer.py")

ANCHOR = (
    "        logger.warning(\"unable to find command for '%s'\", str(line))\n"
    "        self.reply(\"?\")\n"
)

REPLACEMENT = (
    f"        # --- {MARKER} ---\n"
    "        logger.debug(\"unable to find command for '%s'\", str(line))\n"
    "        self.reply(\"?\")\n"
)

text = TARGET.read_text()
if MARKER in text:
    print(f"printer_patch: {TARGET} already patched, skipping")
else:
    if text.count(ANCHOR) != 1:
        raise SystemExit("printer_patch: expected exactly one occurrence of the unable-to-find-command anchor, refusing to patch blind")
    text = text.replace(ANCHOR, REPLACEMENT, 1)
    TARGET.write_text(text)
    print(f"printer_patch: quieted the non-PJL warning in {TARGET}")
