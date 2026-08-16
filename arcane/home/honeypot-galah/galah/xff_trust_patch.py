#!/usr/bin/env python3
"""Trust X-Forwarded-For from the tunnel peer only (#1511).

commonFields() (internal/logger/logger.go) resolves srcIP purely from
r.RemoteAddr via net.SplitHostPort -- correct and sufficient for galah's
existing raw-port/portbridge-only deployment (docker-compose.galah.yml),
where RemoteAddr already carries the real attacker address. #1511 adds a
Traefik-routed subdomain alongside that raw port so galah is reachable
through Cloudflare too (a raw non-standard port isn't on Cloudflare's
proxied-port allowlist -- see #1511/#1512's own issue text). Once any
request can arrive via Traefik -> socat, RemoteAddr becomes the WireGuard
tunnel peer for that path, not the attacker, exactly the gap http-honeypot's
own clientIP() (http-honeypot/main.go) already solved for its own Traefik
route.

Same trust rule, ported: X-Forwarded-For is consulted *only* when RemoteAddr
is exactly the tunnel peer (10.8.0.1) -- everywhere else (the raw-port path)
it stays fully attacker-controlled and must be ignored. Take the *last* XFF
hop, not the first: Cloudflare appends the real client IP to whatever XFF a
client already sent rather than replacing it, and socat forwards bytes
verbatim with no header rewriting, so the leftmost hop is spoofable
(`curl -H "X-Forwarded-For: 1.2.3.4" ...`) while the rightmost is the one
Cloudflare itself appended.

Same shape as hellpot/router_patch.py: exact-match string replacement with
a marker for idempotency, applied at Docker build time.
"""
from pathlib import Path

MARKER = "honeypot-stack: trust XFF from the tunnel peer only (#1511)"
TARGET = Path("/build/internal/logger/logger.go")

OLD = """	srcIP, srcPort, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		srcIP = r.RemoteAddr
		srcPort = ""
	}"""

NEW = """	srcIP, srcPort, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		srcIP = r.RemoteAddr
		srcPort = ""
	}
	// MARKER_PLACEHOLDER
	// Traefik-routed requests show the WireGuard tunnel peer as RemoteAddr;
	// only from that exact peer is X-Forwarded-For trusted, and only its
	// last hop (Cloudflare's own append, not a client-spoofable prefix).
	const tunnelPeerIP = "10.8.0.1"
	if srcIP == tunnelPeerIP {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			hops := strings.Split(xff, ",")
			srcIP = strings.TrimSpace(hops[len(hops)-1])
			srcPort = ""
		}
	}""".replace("MARKER_PLACEHOLDER", MARKER)


def main():
    text = TARGET.read_text()
    if MARKER in text:
        return  # already patched
    count = text.count(OLD)
    if count != 1:
        raise SystemExit(
            "xff_trust_patch.py: expected exactly 1 match for commonFields()'s "
            "srcIP resolution, found {}".format(count)
        )
    TARGET.write_text(text.replace(OLD, NEW, 1))


if __name__ == "__main__":
    main()
