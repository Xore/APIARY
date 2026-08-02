#!/usr/bin/env python3
"""Quiet expected connection-reset noise in Conpot's guardian_ast handler.

guardian_ast_server.py's handle() runs a persistent `while True` loop over
one connection, expecting a next command after each response -- unlike this
image's other protocol handlers, which answer one request and close. Any
peer that disconnects abruptly after its last command (this repo's own
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
"""
from pathlib import Path

MARKER = "honeypot-stack: guardian_ast ConnectionReset patch"
TARGET = Path(
    "/usr/lib/python3.11/site-packages/conpot/protocols/guardian_ast/guardian_ast_server.py"
)

text = TARGET.read_text()
if MARKER in text:
    print(f"guardian_ast_patch: {TARGET} already patched, skipping")
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
    ).format(marker=MARKER, anchor=anchor)

    text = text.replace(anchor, replacement, 1)
    TARGET.write_text(text)
    print(f"guardian_ast_patch: quieted ConnectionResetError/BrokenPipeError in {TARGET}")
