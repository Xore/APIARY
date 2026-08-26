#!/usr/bin/env python3
"""Protocol-level liveness probe for cowrie's Twisted reactor.

A TCP connect (Docker's built-in "is the port open" notion of healthy) is
not enough: a single-threaded Twisted reactor can wedge exactly the way
conpot's gevent loop did in #111 -- busy-spinning, its listen socket still
completing handshakes via the kernel backlog while never servicing a byte.
This probe performs a minimal SSH version-string exchange against
127.0.0.1:2222 and requires the server's own "SSH-..." banner back within
a short timeout, which only a reactor that is actually scheduling can
produce. Same doctrine as honeypot-conpot/conpot/healthcheck.py (#111);
cowrie is checked here strictly at protocol level too, not merely "port
answers".

Banner-only by design: no auth, no exec channel (the heavier variant
sketched in #2107), because the wedge class this guards against dies
before key exchange even begins -- a reactor that cannot write its
version string cannot service a shell either. Both listen endpoints
(2222 ssh, 2223 telnet) are served by the same reactor, so exercising
one exercises the loop both depend on.

Cost: one loopback connection and a few hundred bytes per run. Cowrie
logs each probe as a session.connect/session.closed pair sourced from
127.0.0.1, and the ingest enrichment auto-marks those honeypot.internal_probe
(ip_enrichment/sensors.rs marks every loopback-src_ip event generically --
the same path that flags conpot's and dionaea's healthcheck traffic),
which every dashboard consumer then excludes (#1677 doctrine). So the
only visible footprint is raw document counts: ~2880 tiny sessions/day
at the deployed 30s interval against tens of millions indexed. Measured
live before adopting -- see #2107.

Usage: healthcheck-probe.py [port]   (default 2222)
"""
import socket
import sys

TIMEOUT = 4.0  # below the compose healthcheck's own 5s kill window

CLIENT_BANNER = b"SSH-2.0-cowrie-healthcheck-probe\r\n"


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2222
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            # Sent unconditionally: a server that speaks first ignores it,
            # one that waits for the client's version gets it.
            s.sendall(CLIENT_BANNER)
            data = b""
            while b"\n" not in data and len(data) < 256:
                chunk = s.recv(256 - len(data))
                if not chunk:
                    break
                data += chunk
    except OSError as exc:
        print(f"probe: no timely response on :{port}: {exc}", file=sys.stderr)
        return 1
    if not data.startswith(b"SSH-"):
        print(f"probe: unexpected response on :{port}: {data[:64]!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
