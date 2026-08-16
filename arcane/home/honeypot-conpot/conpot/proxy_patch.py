#!/usr/bin/env python3
"""Append a HAProxy PROXY-protocol v1 shim to the installed Conpot package.

Conpot has no PROXY-protocol support, so behind portbridge (VPS -> WireGuard)
every session would be logged from the tunnel peer 10.8.0.1. This patch wraps
gevent's StreamServer.do_read at accept time: when CONPOT_PROXY_PROTOCOL=1 is
set, each TCP connection is first peeked for a "PROXY TCP4/TCP6 <src> <dst>
<sport> <dport>" header (emitted by portbridge ":pp" rules); if present it is
consumed and the parsed (ip, port) replaces the address handed to Conpot's
protocol handlers. Connections without the header pass through untouched, so
local probes and healthchecks keep working. UDP listeners (SNMP/BACnet/IPMI)
are unaffected.
"""
from pathlib import Path

MARKER = "CONPOT_PROXY_PROTOCOL"
INIT = Path("/usr/lib/python3.11/site-packages/conpot/__init__.py")

SNIPPET = '''

# --- honeypot-stack: PROXY protocol v1 shim (conpot/proxy_patch.py) ---
# Active only with CONPOT_PROXY_PROTOCOL=1 in the container environment.
import os as _proxy_os

if _proxy_os.environ.get("CONPOT_PROXY_PROTOCOL", "0") == "1":
    import socket as _proxy_socket
    from gevent.server import StreamServer as _ProxyStreamServer

    def _conpot_proxy_peer(sock, address):
        peek = sock.recv(5, _proxy_socket.MSG_PEEK)
        if peek != b"PROXY":
            return address
        data = b""
        while not data.endswith(b"\\r\\n") and len(data) < 108:
            chunk = sock.recv(1)
            if not chunk:
                return address
            data += chunk
        f = data.split()
        # PROXY TCP4/TCP6 <src> <dst> <sport> <dport>
        if len(f) >= 6 and f[1] in (b"TCP4", b"TCP6"):
            try:
                return (f[2].decode("ascii"), int(f[4]))
            except ValueError:
                pass
        return address

    # Patch at accept time: StreamServer.do_read returns the (sock, address)
    # pair that do_handle then hands to the protocol handler. Consuming the
    # PROXY header here and rewriting the address is transparent to every
    # conpot protocol (s7comm, modbus, IEC104, guardian_ast, kamstrup, enip).
    # Safe against double-import: a second pass simply finds no header.
    _conpot_orig_do_read = _ProxyStreamServer.do_read

    def _conpot_proxy_do_read(self):
        args = _conpot_orig_do_read(self)
        if not args:
            return args
        sock, address = args
        try:
            address = _conpot_proxy_peer(sock, address)
        except Exception:
            pass
        return sock, address

    _ProxyStreamServer.do_read = _conpot_proxy_do_read
# --- end honeypot-stack PROXY shim ---
'''

text = INIT.read_text()
if MARKER in text:
    print(f"proxy_patch: {INIT} already patched, skipping")
else:
    INIT.write_text(text + SNIPPET)
    print(f"proxy_patch: appended PROXY v1 shim to {INIT}")
