#!/usr/bin/env python3
"""Append a HAProxy PROXY-protocol v1 shim to the installed Conpot package.

Conpot has no PROXY-protocol support, so behind portbridge (VPS -> WireGuard)
every session would be logged from the tunnel peer 10.8.0.1. This patch wraps
gevent's StreamServer.do_handle: when CONPOT_PROXY_PROTOCOL=1 is set, each TCP
connection is peeked -- inside its own per-connection greenlet, before the
protocol handler runs -- for a "PROXY TCP4/TCP6 <src> <dst> <sport> <dport>"
header (emitted by portbridge ":pp" rules); if present it is consumed and the
parsed (ip, port) replaces the address handed to Conpot's protocol handlers.
Connections without the header pass through untouched (bounded by
CONPOT_PROXY_PEEK_TIMEOUT, default 1.0s), so local probes and healthchecks
keep working. UDP listeners (SNMP/BACnet/IPMI) are unaffected.

#2883: this used to patch do_read (accept time, gevent's Hub context) instead
of do_handle (per-connection greenlet context, spawned by do_handle before the
protocol handler runs). do_read cannot block to wait for a header that hasn't
arrived yet -- a blocking call from Hub context raises BlockingSwitchOutError
immediately (#2321 already established and refuted the theory that this
parks the listener) -- so a header portbridge writes as a separate write
across the WireGuard tunnel and that simply hasn't landed yet by accept time
was silently treated as absent, misattributing the session to the tunnel peer
10.8.0.1. How much of the traffic that hits is load-dependent, not a constant:
a 30-day daily breakdown of conpot NEW_CONNECTION events puts the tunnel-peer
share at ~25-53% on scanning-burst days (the ~35% the issue headlines comes
from such a window) and ~0% on quiet days -- which is itself the signature of
a race, and means any before/after comparison has to be taken under
comparable load to mean anything. Moving the peek
into do_handle's spawned greenlet is not a timeout bolted onto the same
Hub-context peek (that would treat a slow-but-genuine header as absent, which
is worse, per #2321's own conclusion) -- it runs somewhere blocking is
actually legal, so it can wait out real network jitter without blocking
accept for any other connection.
"""
from pathlib import Path

MARKER = "CONPOT_PROXY_PROTOCOL"
INIT = Path("/usr/lib/python3.12/site-packages/conpot/__init__.py")

SNIPPET = '''

# --- honeypot-stack: PROXY protocol v1 shim (conpot/proxy_patch.py) ---
# Active only with CONPOT_PROXY_PROTOCOL=1 in the container environment.
import os as _proxy_os

if _proxy_os.environ.get("CONPOT_PROXY_PROTOCOL", "0") == "1":
    import socket as _proxy_socket
    import gevent as _proxy_gevent
    from gevent.server import StreamServer as _ProxyStreamServer

    try:
        # Private gevent symbol, imported at conpot startup: if a base-image
        # bump renames or drops it, an unguarded import fails the whole
        # process, not just this shim. The fallback is gevent's own body for
        # it (25.9.1) minus the SystemError/KeyboardInterrupt bookkeeping the
        # real one does for the server's error handler.
        from gevent.baseserver import (
            _handle_and_close_when_done as _proxy_handle_and_close_when_done,
        )
    except ImportError:
        def _proxy_handle_and_close_when_done(handle, close, args):
            try:
                return handle(*args)
            finally:
                close(*args)

    # #2883: bounded wait for the header to arrive over the tunnel -- 1.0s is
    # comfortably past the ~0.3s delay measured live between portbridge's
    # dial and its (separate) header write landing on conpot's side.
    _PROXY_PEEK_TIMEOUT = float(_proxy_os.environ.get("CONPOT_PROXY_PEEK_TIMEOUT", "1.0"))

    def _conpot_proxy_peer(sock, address):
        try:
            with _proxy_gevent.Timeout(_PROXY_PEEK_TIMEOUT, False):
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
        except Exception:
            pass
        return address

    # Patch do_handle rather than do_read (see module docstring, #2883):
    # do_handle still runs in the Hub's accept-loop context, but all it does
    # is decide how to spawn the greenlet that will run the protocol
    # handler -- wrapping the function that gets spawned is what actually
    # moves the peek into greenlet context, where blocking briefly is legal.
    # Reimplements gevent.baseserver.BaseServer.do_handle's own body
    # (confirmed against the pinned gevent 25.9.1 source) rather than
    # delegating to it, because there is no seam in the original to inject a
    # wrapped handle function without doing so. Safe against double-import:
    # a second pass simply peeks again and finds no header the second time.
    def _conpot_proxy_do_handle(self, *args):
        spawn = self._spawn
        orig_handle = self._handle
        close = self.do_close

        def _proxy_wrapped_handle(sock, address):
            try:
                address = _conpot_proxy_peer(sock, address)
            except Exception:
                pass
            return orig_handle(sock, address)

        try:
            if spawn is None:
                _proxy_handle_and_close_when_done(_proxy_wrapped_handle, close, args)
            else:
                spawn(_proxy_handle_and_close_when_done, _proxy_wrapped_handle, close, args)
        except:  # noqa: E722 -- bare, exactly as gevent's own do_handle: a
            # BaseException out of spawn() (GreenletExit at shutdown, or a
            # gevent.Timeout, which is not an Exception) must still close the
            # socket rather than leak it.
            close(*args)
            raise

    _ProxyStreamServer.do_handle = _conpot_proxy_do_handle
# --- end honeypot-stack PROXY shim ---
'''

def apply_patch(target: Path) -> str:
    """Idempotently append the shim to target; returns a one-line status
    message. Factored out (and now importable without side effects, unlike
    before #2883) so tests/test_proxy_patch.py can exercise this module
    without touching a real conpot install."""
    text = target.read_text()
    if MARKER in text:
        return f"proxy_patch: {target} already patched, skipping"
    target.write_text(text + SNIPPET)
    return f"proxy_patch: appended PROXY v1 shim to {target}"


if __name__ == "__main__":
    print(apply_patch(INIT))
