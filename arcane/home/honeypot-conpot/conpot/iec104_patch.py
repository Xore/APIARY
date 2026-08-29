#!/usr/bin/env python3
"""Fix a busy-loop DoS in Conpot's IEC104 handler.

Same bug class as #111 (modbus_patch.py/s7comm_patch.py), found by auditing
every protocol handler this repo ships as a persona for the same pattern
(#617). IEC104_server.py accumulates the 2-byte APCI start into `request`
like this:

    request = sock.recv(6)
    if not request:
        ... break
    while request and len(request) < 2:
        new_byte = sock.recv(1)
        request += new_byte          # <-- no `if not new_byte: break`

If a peer sends exactly 1 byte and then closes the connection, sock.recv(1)
returns b"" (EOF) forever after -- an empty return is not an exception, so
nothing here catches it, and the loop spins calling recv(1) at full CPU
with no blocking and no yield to gevent's scheduler. Notably, the *next*
accumulation loop a few lines down (for the length-prefixed body) already
has the correct EOF check; only this earlier 2-byte header loop is missing
it.

This patch adds the same missing EOF check, matching the pattern the
already-correct loop right below it (and modbus_patch.py before it) both
use.
"""
from pathlib import Path

MARKER = "honeypot-stack: IEC104 recv(1) EOF patch"
TARGET = Path(
    "/usr/lib/python3.12/site-packages/conpot/protocols/IEC104/IEC104_server.py"
)

OLD = """                        while request and len(request) < 2:
                            new_byte = sock.recv(1)
                            request += new_byte"""

NEW = """                        # --- {marker} ---
                        # See #617 (same class as #111): a peer that sends
                        # a single byte and then closes makes recv(1)
                        # return b"" (EOF) forever. That is a normal
                        # return value, not an exception, so the loop
                        # spun at 100% CPU with no blocking and no yield.
                        while request and len(request) < 2:
                            new_byte = sock.recv(1)
                            if not new_byte:
                                break
                            request += new_byte
                        # --- end {marker} ---""".format(marker=MARKER)

text = TARGET.read_text()
if MARKER in text:
    print(f"iec104_patch: {TARGET} already patched, skipping")
else:
    if text.count(OLD) != 1:
        raise SystemExit("iec104_patch: expected exactly one occurrence of the recv(1) accumulation loop")
    text = text.replace(OLD, NEW, 1)
    TARGET.write_text(text)
    print(f"iec104_patch: fixed the recv(1) EOF spin in {TARGET}")
