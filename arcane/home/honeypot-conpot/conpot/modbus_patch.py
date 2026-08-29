#!/usr/bin/env python3
"""Fix a busy-loop DoS in Conpot's Modbus handler.

Confirmed live as the actual trigger for #111 (py-spy caught the process
frozen here, strace showed a tight recv(1) spin with zero yields, and
docker's own healthcheck confirmed the container was unreachable for
several minutes) -- this is the real root cause; the s7comm MSG_WAITALL fix
in s7comm_patch.py addresses a separate, real bug in a different handler,
not this one.

modbus_server.py accumulates a frame past the 7-byte MBAP header like this:

    _, _, length = struct.unpack(">HHH", request[:6])
    while len(request) < (length + 6):
        try:
            new_byte = sock.recv(1)
            request += new_byte
        except Exception:
            break

`length` comes straight from the attacker's own header (up to 65535). If the
peer sends a header promising more bytes than it delivers and then closes
the connection, sock.recv(1) returns b"" (EOF) forever -- and an empty
return is not an exception, so `except Exception` never fires. The loop
spins calling recv(1) at full CPU with no blocking and no yield to gevent's
scheduler, which is why it starves every other connection on the container,
not just the attacker's own.

This patch adds the missing EOF check: same pattern already used at the top
of the outer loop (`if not request: ... break`), just applied to the
accumulation loop too.
"""
from pathlib import Path

MARKER = "honeypot-stack: modbus recv(1) EOF patch"
TARGET = Path(
    "/usr/lib/python3.12/site-packages/conpot/protocols/modbus/modbus_server.py"
)

OLD = '''                _, _, length = struct.unpack(">HHH", request[:6])
                while len(request) < (length + 6):
                    try:
                        new_byte = sock.recv(1)
                        request += new_byte
                    except Exception:
                        break'''

NEW = '''                _, _, length = struct.unpack(">HHH", request[:6])
                # --- {marker} ---
                # See #111: a peer that promises `length` bytes, sends
                # fewer, and closes makes recv(1) return b"" (EOF) forever.
                # That is a normal return value, not an exception, so the
                # bare except below never caught it and the loop spun at
                # 100% CPU with no blocking and no yield.
                while len(request) < (length + 6):
                    try:
                        new_byte = sock.recv(1)
                    except Exception:
                        break
                    if not new_byte:
                        break
                    request += new_byte
                # --- end {marker} ---'''.format(marker=MARKER)

text = TARGET.read_text()
if MARKER in text:
    print(f"modbus_patch: {TARGET} already patched, skipping")
else:
    if text.count(OLD) != 1:
        raise SystemExit("modbus_patch: expected exactly one occurrence of the recv(1) accumulation loop")
    text = text.replace(OLD, NEW, 1)
    TARGET.write_text(text)
    print(f"modbus_patch: fixed the recv(1) EOF spin in {TARGET}")
