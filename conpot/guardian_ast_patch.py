#!/usr/bin/env python3
"""Two independent patches to Conpot's guardian_ast handler.

guardian_ast_server.py's handle() runs a persistent `while True` loop over
one connection, expecting a next command after each response -- unlike this
image's other protocol handlers, which answer one request and close.

## Patch 1: quiet expected connection-reset noise (#333)

Any peer that disconnects abruptly after its last command (this repo's own
healthcheck.py's probe_guardian_ast() was one such peer, see #333 and the
fix in that file) makes the handler's next `sock.recv(4096)` raise
ConnectionResetError or BrokenPipeError, caught today only by the loop's
generic `except Exception as e: logger.exception(...)` -- an ERROR-level
log with a full traceback for something that is completely ordinary session
teardown, firing on this repo's own healthcheck.py every ~60s in addition to
however often a real client behaves the same way.

This patch adds a narrower except clause before the generic one: log a
plain one-line disconnect message (matching the existing
"GuardianAST client disconnected" message's own info level) instead of a
traceback, and break the loop immediately -- there is nothing left to read
on a reset socket, so retrying (the existing code's behavior: falls through
to the next loop iteration and calls sock.recv() again) only produces a
second, identical exception before the loop's other exit paths finally
catch up, which is exactly the double-traceback-per-cycle pattern observed
live.

## Patch 2: fix a busy-loop DoS (#617, same class as #111)

Independent of patch 1, and of a different bug class: each command is
accumulated like this:

    request = sock.recv(4096)
    if not request:
        break
    while not (b"\\n" in request or b"00" in request):
        request += sock.recv(4096)   # <-- no EOF check

If a peer sends a partial command (no terminating "\\n" or "00") and then
closes the connection, sock.recv(4096) returns b"" (EOF) forever after --
an empty return is not truthy and isn't checked for here, so `request`
never changes and the loop spins calling recv(4096) at full CPU with no
blocking and no yield to gevent's scheduler. guardian_ast_patch.py already
existed for patch 1 above (#333) but never touched this separate
accumulation loop.
"""
from pathlib import Path

TARGET = Path(
    "/usr/lib/python3.11/site-packages/conpot/protocols/guardian_ast/guardian_ast_server.py"
)

MARKER_RESET = "honeypot-stack: guardian_ast ConnectionReset patch"
MARKER_DOS = "honeypot-stack: guardian_ast recv(4096) EOF patch"

text = TARGET.read_text()
changed = False

if MARKER_RESET in text:
    print(f"guardian_ast_patch: {TARGET} connection-reset patch already applied, skipping")
else:
    anchor = (
        "            except Exception as e:\n"
        '                logger.exception(("Unknown Error: {}".format(str(e))))\n'
    )
    if text.count(anchor) != 1:
        raise SystemExit(
            "guardian_ast_patch: expected exactly one occurrence of the generic except clause"
        )

    replacement = (
        "            # --- {marker} (conpot/guardian_ast_patch.py) ---\n"
        "            # See #333: an abrupt disconnect after the session's last\n"
        "            # command (this image's own healthcheck.py is one such\n"
        "            # peer) is ordinary teardown, not an error -- logged at the\n"
        "            # same info level as the disconnect message below, no\n"
        "            # traceback, and the loop stops immediately since there is\n"
        "            # nothing left to read on a reset socket.\n"
        "            except (ConnectionResetError, BrokenPipeError):\n"
        '                logger.info(\n'
        '                    "GuardianAST connection reset %s:%d. (%s)",\n'
        "                    addr[0],\n"
        "                    addr[1],\n"
        "                    session.id,\n"
        "                )\n"
        "                break\n"
        "            # --- end {marker} ---\n"
        "{anchor}"
    ).format(marker=MARKER_RESET, anchor=anchor)

    text = text.replace(anchor, replacement, 1)
    changed = True
    print(f"guardian_ast_patch: quieted ConnectionResetError/BrokenPipeError in {TARGET}")

if MARKER_DOS in text:
    print(f"guardian_ast_patch: {TARGET} recv(4096) EOF patch already applied, skipping")
else:
    old = (
        "                while not (b\"\\n\" in request or b\"00\" in request):\n"
        "                    request += sock.recv(4096)"
    )
    if text.count(old) != 1:
        raise SystemExit(
            "guardian_ast_patch: expected exactly one occurrence of the recv(4096) accumulation loop"
        )
    new = (
        "                # --- {marker} ---\n"
        "                # See #617 (same class as #111): a peer that sends a\n"
        "                # partial command (no terminating \\n or 00) and then\n"
        "                # closes makes recv(4096) return b\"\" (EOF) forever.\n"
        "                # That is a normal return value, not an exception, and\n"
        "                # `request` never changes, so the loop spun at 100% CPU\n"
        "                # with no blocking and no yield.\n"
        "                while not (b\"\\n\" in request or b\"00\" in request):\n"
        "                    new_data = sock.recv(4096)\n"
        "                    if not new_data:\n"
        "                        break\n"
        "                    request += new_data\n"
        "                # --- end {marker} ---"
    ).format(marker=MARKER_DOS)
    text = text.replace(old, new, 1)
    changed = True
    print(f"guardian_ast_patch: fixed the recv(4096) EOF spin in {TARGET}")

if changed:
    TARGET.write_text(text)
