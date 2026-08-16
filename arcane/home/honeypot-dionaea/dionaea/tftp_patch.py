#!/usr/bin/env python3
"""Fix dionaea's TFTP handler dropping attack telemetry on malformed RRQs.

handle_io_in() in tftp.py has:

    if recvpkt.mode != 'octet':
        self.senderror(TftpErrors.IllegalTftpOp)
        logger.warn("Unsupported mode: %s" % recvpkt.mode)
        self.close()

    if self.state.state == 'rrq':
        ...
        else:
            self.senderror(TftpErrors.FileNotFound)

The first `if` is not followed by `return`, so a single RRQ with both a
non-octet mode (e.g. netascii) and a nonexistent filename falls through into
the second `if` and calls senderror() again on the connection self.close()
already tore down. senderror() reads self.remote.host/self.remote.port --
a Cython-bound property that raises ReferenceError once the underlying C
connection is gone, losing the attack record (no JSON event, no SQLite row)
for that connection.

Confirmed live on the homeserver (#114): dionaea hit this from real traffic,
and the sibling insecure-path branch a few lines below already follows its
own close() with `return len(data)` -- this patch makes the mode-mismatch
branch do the same, matching the file's own established convention instead
of introducing a different style (e.g. elif).
"""
from pathlib import Path

MARKER = "honeypot-stack: tftp mode-mismatch fall-through patch (#114)"
TARGET = Path("/opt/dionaea/lib/dionaea/python/dionaea/tftp.py")

ANCHOR = (
    "            if recvpkt.mode != 'octet':\n"
    "                self.senderror(TftpErrors.IllegalTftpOp)\n"
    "                #raise TftpException(\"Unsupported mode: %s\" % recvpkt.mode)\n"
    "                logger.warn(\"Unsupported mode: %s\" % recvpkt.mode)\n"
    "                self.close()\n"
    "\n"
    "\n"
    "            if self.state.state == 'rrq':\n"
)

REPLACEMENT = (
    "            if recvpkt.mode != 'octet':\n"
    "                self.senderror(TftpErrors.IllegalTftpOp)\n"
    "                #raise TftpException(\"Unsupported mode: %s\" % recvpkt.mode)\n"
    "                logger.warn(\"Unsupported mode: %s\" % recvpkt.mode)\n"
    "                self.close()\n"
    f"                return len(data)  # --- {MARKER} ---\n"
    "\n"
    "            if self.state.state == 'rrq':\n"
)

text = TARGET.read_text()
if MARKER in text:
    print(f"tftp_patch: {TARGET} already patched, skipping")
else:
    if text.count(ANCHOR) != 1:
        raise SystemExit("tftp_patch: expected exactly one occurrence of the mode-mismatch anchor, refusing to patch blind")
    text = text.replace(ANCHOR, REPLACEMENT, 1)
    TARGET.write_text(text)
    print(f"tftp_patch: added return-after-close in {TARGET}")
