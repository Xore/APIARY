#!/usr/bin/env python3
"""Trust X-Forwarded-For from the tunnel peer only (#1876).

router_patch.py (#1419) made getRealRemote() return ctx.RemoteAddr()
verbatim, dropping upstream's unvalidated X-Real-IP trust. That was right
and its stated reasoning was that HellPot runs "raw-port/portbridge-only
(no Traefik hostname)", so RemoteAddr is either the attacker directly or
the tunnel peer with a port the ip-enrichment-worker's via_port join can
resolve against portbridge's connection log.

That statement stopped being true. #1509 added a Traefik route for HellPot
-- the bare/www/static hosts -- reaching it through socat rather than
portbridge:

    honeypot-hellpot:
      loadBalancer:
        servers:
          - url: "http://socat-hp-hellpot:8084"

portbridge never sees those connections, so it writes no record for them,
so the via_port join has nothing to match and misses permanently. The two
changes were never reconciled, and the result is measurable: 192 hellpot
events a day logging the tunnel peer as REMOTE_ADDR with no way to recover
the client. Every other sensor is attributed; these are most of what is
left.

socat does not strip headers -- it is a byte pipe and forwards the request
verbatim -- so Traefik's X-Forwarded-For arrives intact. The address was
never destroyed; nothing was reading it.

Same trust rule as galah's xff_trust_patch.py (#1511), which solved exactly
this situation for exactly this reason:

  * X-Forwarded-For is consulted *only* when RemoteAddr is the tunnel peer.
    On the raw-port path RemoteAddr is the attacker and the header is fully
    attacker-controlled, so trusting it there would reintroduce precisely
    the spoofing #1419 removed -- confirmed live at the time by sending a
    request carrying its own header and seeing it logged.

  * The *last* hop is taken, not the first. Cloudflare appends the real
    client to whatever XFF the client already sent rather than replacing
    it, so the leftmost hop is spoofable and the rightmost is the one
    Cloudflare itself wrote.

The port is preserved where XFF is not used, because the via_port join on
the portbridge path depends on it -- that is the whole reason #1419 chose
RemoteAddr() over RemoteIP(). When XFF does resolve the client, the port is
portbridge-irrelevant and carries no meaning, so it is dropped rather than
reported as if it were the attacker's.

Same shape as router_patch.py and galah's: exact-match string replacement
with a marker for idempotency, applied at Docker build time.
"""
from pathlib import Path

MARKER = "honeypot-stack: trust XFF from the tunnel peer only (#1876)"
ROUTER_MARKER = "honeypot-stack: drop spoofable X-Real-IP trust, keep the port (#1419)"
TARGET = Path("/build/internal/http/router.go")

# router_patch.py runs first and leaves exactly this.
OLD = '''func getRealRemote(ctx *fasthttp.RequestCtx) string {
	// --- ROUTER_MARKER ---
	return ctx.RemoteAddr().String()
}'''.replace("ROUTER_MARKER", ROUTER_MARKER)

NEW = '''func getRealRemote(ctx *fasthttp.RequestCtx) string {
	// --- ROUTER_MARKER ---
	// --- MARKER_PLACEHOLDER ---
	addr := ctx.RemoteAddr().String()
	const tunnelPeerIP = "10.8.0.1"
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != tunnelPeerIP {
		return addr
	}
	xff := string(ctx.Request.Header.Peek("X-Forwarded-For"))
	if xff == "" {
		return addr
	}
	hops := strings.Split(xff, ",")
	client := strings.TrimSpace(hops[len(hops)-1])
	if client == "" {
		return addr
	}
	return client
}'''.replace("ROUTER_MARKER", ROUTER_MARKER).replace("MARKER_PLACEHOLDER", MARKER)


def ensure_imports(text: str) -> str:
    """`net` and `strings` are needed by the block above.

    Added only when absent: upstream may already import either, and a
    duplicate import is a compile error rather than a no-op.
    """
    for pkg in ("net", "strings"):
        if f'\n\t"{pkg}"\n' in text:
            continue
        marker = "import (\n"
        index = text.index(marker) + len(marker)
        text = text[:index] + f'\t"{pkg}"\n' + text[index:]
    return text


def main():
    text = TARGET.read_text()
    if MARKER in text:
        return  # already patched
    count = text.count(OLD)
    if count != 1:
        raise SystemExit(
            "xff_trust_patch.py: expected exactly 1 match for router_patch.py's "
            "getRealRemote(), found {} -- run router_patch.py first".format(count)
        )
    text = text.replace(OLD, NEW, 1)
    TARGET.write_text(ensure_imports(text))


if __name__ == "__main__":
    main()
