#!/usr/bin/env python3
"""Fix a busy-loop DoS in Conpot's s7comm handler.

s7_server.py reads each frame with `sock.recv(n, socket.MSG_WAITALL)`.
gevent's monkey-patched socket does not handle MSG_WAITALL cooperatively: a
peer that opens a connection and never completes the requested byte count
(trickled writes, or simply stopping mid-frame) can spin the greenlet's
retry loop at 100% CPU instead of blocking on the socket, wedging the whole
single-threaded reactor -- the listen socket stays open and accepting, but
nothing is ever serviced or logged again.

Confirmed as the live trigger for #111: the COTP-fuzzing client documented
there fuzzed the COTP TPDU-type byte across ~40 near-simultaneous
connections, settled on one value, and has re-hit conpot with
malformed/incomplete frames roughly hourly since -- including reconnecting
in the same minute conpot was manually restarted, i.e. polling for the hang
to return.

This patch replaces both MSG_WAITALL reads with a manual accumulate-until-n
loop using plain sock.recv(), which gevent already handles correctly via
its normal cooperative wait -- the existing `sock.settimeout(self.timeout)`
at the top of handle() still bounds a peer that goes silent, raising
socket.timeout into the handler's existing except clause instead of
spinning.
"""
from pathlib import Path

MARKER = "honeypot-stack: s7comm MSG_WAITALL patch"
TARGET = Path(
    "/usr/lib/python3.12/site-packages/conpot/protocols/s7comm/s7_server.py"
)

HELPER = '''

# --- {marker} (conpot/s7comm_patch.py) ---
# See #111: MSG_WAITALL is not gevent-safe and can busy-loop the reactor at
# 100% CPU on a connection that never completes its requested byte count.
def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf
# --- end {marker} ---
'''.format(marker=MARKER)

text = TARGET.read_text()
if MARKER in text:
    print(f"s7comm_patch: {TARGET} already patched, skipping")
else:
    anchor = (
        'def cleanse_byte_string(packet):\n'
        '    new_packet = packet.decode("latin-1").replace("b", "")\n'
        '    return new_packet.encode("latin-1")\n'
    )
    if anchor not in text:
        raise SystemExit("s7comm_patch: anchor function not found, refusing to patch blind")
    text = text.replace(anchor, anchor + HELPER, 1)

    old_first = "data = sock.recv(4, socket.MSG_WAITALL)"
    old_second = "data += sock.recv(length - 4, socket.MSG_WAITALL)"
    if text.count(old_first) != 1 or text.count(old_second) != 1:
        raise SystemExit("s7comm_patch: expected exactly one occurrence of each MSG_WAITALL call")
    text = text.replace(old_first, "data = _recv_exact(sock, 4)", 1)
    text = text.replace(old_second, "data += _recv_exact(sock, length - 4)", 1)

    TARGET.write_text(text)
    print(f"s7comm_patch: replaced MSG_WAITALL reads in {TARGET}")
