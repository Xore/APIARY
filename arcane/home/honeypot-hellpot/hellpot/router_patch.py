#!/usr/bin/env python3
"""Remove HellPot's client-spoofable X-Real-IP trust (#1419).

getRealRemote() in internal/http/router.go returns config.HeaderName's
(X-Real-IP by default) raw value with zero validation of which hop set it
-- confirmed live by sending a direct request carrying its own
"X-Real-IP: 203.0.113.9" header against an unpatched build: REMOTE_ADDR in
HellPot's own log was exactly that attacker-supplied value. Nothing
upstream of HellPot in this stack's request path (Traefik, socat) rewrites
or strips a client-supplied X-Real-IP the way http-honeypot/main.go's own
clientIP() deliberately only trusts X-Forwarded-For from the WireGuard
tunnel peer and takes the last hop -- so left as-is, HellPot would log a
fully attacker-controlled value as REMOTE_ADDR.

The real fix is deployment, not code: this stack runs HellPot raw-port/
portbridge-only (no Traefik hostname, see arcane/home/honeypot-hellpot/compose.yml),
resolving the true attacker IP the same trusted way as every other
non-PROXY-protocol sensor here -- ip-enrichment-worker's via_port join
against portbridge's own connection log (hellpot.go). That join is keyed
by source port, which upstream's ctx.RemoteIP().String() throws away
(fasthttp's RemoteIP() strips the port; RemoteAddr() keeps "ip:port").
This patch drops the header entirely and switches to RemoteAddr() so
REMOTE_ADDR always carries a joinable port, from a value only ever
determined by the actual TCP connection, never by request content.

Same shape as dionaea/log_rotation_patch.py: exact-match string
replacement with a marker for idempotency, applied at Docker build time.
"""
from pathlib import Path

MARKER = "honeypot-stack: drop spoofable X-Real-IP trust, keep the port (#1419)"
TARGET = Path("/build/internal/http/router.go")

OLD = '''func getRealRemote(ctx *fasthttp.RequestCtx) string {
	xrealip := string(ctx.Request.Header.Peek(config.HeaderName))
	if len(xrealip) > 0 {
		return xrealip
	}
	return ctx.RemoteIP().String()
}'''

NEW = '''func getRealRemote(ctx *fasthttp.RequestCtx) string {
	// --- MARKER_PLACEHOLDER ---
	return ctx.RemoteAddr().String()
}'''.replace("MARKER_PLACEHOLDER", MARKER)


def main():
    text = TARGET.read_text()
    if MARKER in text:
        return  # already patched
    count = text.count(OLD)
    if count != 1:
        raise SystemExit(
            "router_patch.py: expected exactly 1 match for getRealRemote(), found {}".format(count)
        )
    TARGET.write_text(text.replace(OLD, NEW, 1))


if __name__ == "__main__":
    main()
