#!/usr/bin/env python3
"""Log the forwarded header as a fact; let the worker decide (#1876).

The first version of this patch resolved X-Forwarded-For inside
getRealRemote(), trusting it whenever RemoteAddr was the tunnel peer --
the rule galah's xff_trust_patch.py used under #1511. The reasoning that
called that rule "safe for galah" did not survive contact with the
deployment, and #1891 disproved it live:

  * galah's raw port is a plain portbridge relay (tcp:8889:10.8.0.2:8888,
    no `:pp`), so RemoteAddr is the tunnel peer on *both* of galah's
    paths -- not the attacker, as this docstring once claimed. An
    attacker-supplied `X-Forwarded-For: 198.51.100.77` was logged
    verbatim as srcIP, which is exactly what #1891 is.

  * Galah's sensor-side rule was therefore removed outright (#1891):
    upstream is left alone, commonFields() keeps logging RemoteAddr plus
    every request header, and ip-enrichment-worker's enrich_galah_line
    adjudicates. Only this stack got the split-port variant below
    (#1908), because HellPot's portbridge path leans on the via_port
    join -- enrichHellpotLine resolving on the port of a tunnel-peer
    RemoteAddr -- which a bare header log cannot serve. So here too
    RemoteAddr is the tunnel peer on *both* paths, the condition cannot
    tell them apart, and trusting the header on the portbridge path lets
    an attacker set their own source by sending one. That is precisely
    the spoofing #1419 removed.

No header can tell the paths apart, because anything Traefik adds an
attacker can also send. What separates them is something outside the
request: whether portbridge relayed the connection. Only the enrichment
worker knows that, because only it holds portbridge's connection log.

That answer was left incomplete, and #1908 finishes it. Asking portbridge
works when it says yes on the raw path -- but its map is keyed by port
alone and holds six hours of them, so on the *proxied* path an entry
matching socat's ephemeral source port is a coincidence rather than an
answer, and under this traffic a likely one. Taking it swaps in an
unrelated attacker's address, silently, since a wrong address looks
exactly like a right one.

So the two paths stop sharing a door. HellPot binds one port
(config.HTTPPort), which is why they did; this patch adds a second
listener on HELLPOT_PROXIED_PORT that only socat-hp-hellpot can reach --
same server, same routes, same logging -- and records the port each
request arrived on. "Which way in" is then a fact in the log line, and the
worker uses portbridge's record on the raw path and the forwarded chain on
the proxied one, without either having to guess.

So this patch stops deciding. REMOTE_ADDR keeps the true TCP peer and its
port -- unchanged from router_patch.py, so the via_port join still works --
and the raw header is recorded alongside it as XFF. The worker then runs
both joins and adjudicates:

  * via_port resolves            -> portbridge relayed it; that is ground
                                    truth, derived from the connection
                                    rather than from its content.
  * via_port misses, XFF present -> Traefik path; the header is the only
                                    evidence and portbridge never saw it.
  * both, and they disagree      -> surfaced with a warning rather than
                                    silently resolved. On the portbridge
                                    path that disagreement *is* a spoof
                                    attempt, which is worth seeing.

Recording the header rather than acting on it also means a spoofed value
is preserved as evidence instead of being either believed or discarded.

Same shape as router_patch.py and dionaea/log_rotation_patch.py:
exact-match string replacement with a marker for idempotency, applied at
Docker build time. Runs after router_patch.py, which owns getRealRemote().
"""
from pathlib import Path

MARKER = "honeypot-stack: record the forwarded header, adjudicate in the worker (#1876)"
MARKER_SECOND_DOOR = "honeypot-stack: Traefik-only second listener (#1908) :second-door"
TARGET = Path("/build/internal/http/router.go")

# The listener only the Traefik-side bridge can reach. compose.yml's
# published port, the socat target in vps/docker-compose.yml, and
# HELLPOT_PROXIED_PORT in the enrichment worker repeat this value across
# stacks and languages nothing here can import into, so their agreement is
# asserted by tests/test_xff_trust_patch.py (ProxiedPortAgreement, #2192)
# rather than left to this comment to remember.
HELLPOT_PROXIED_PORT = "8090"

OLD = '''	slog := log.With().
		Str("USERAGENT", string(ctx.UserAgent())).
		Str("REMOTE_ADDR", remoteAddr).
		Interface("URL", string(ctx.RequestURI())).Logger()'''

NEW = '''	// --- MARKER_PLACEHOLDER ---
	slog := log.With().
		Str("USERAGENT", string(ctx.UserAgent())).
		Str("REMOTE_ADDR", remoteAddr).
		Str("XFF", string(ctx.Request.Header.Peek("X-Forwarded-For"))).
		Str("DST_PORT", localPort(ctx)).
		Interface("URL", string(ctx.RequestURI())).Logger()'''.replace(
    "MARKER_PLACEHOLDER", MARKER
)

# localPort is a declaration, so it goes at file scope rather than inside
# the handler whose log line uses it.
HELPER_OLD = '''func hellPot(ctx *fasthttp.RequestCtx) {'''
HELPER_NEW = '''// localPort reports which of HellPot\'s listeners took this request, which
// is how the enrichment worker tells a Cloudflare-proxied request from one
// sent straight at the raw port. See this file\'s patch docstring.
func localPort(ctx *fasthttp.RequestCtx) string {
	addr := ctx.LocalAddr()
	if addr == nil {
		return ""
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return strconv.Itoa(tcp.Port)
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return port
}

func hellPot(ctx *fasthttp.RequestCtx) {'''

# The handler's file already imports fasthttp; net and strconv it does not.
# Anchored on the surrounding lines rather than the block opener, so the two
# additions land in gofmt's sorted order instead of at the top.
IMPORT_OLD = '''	"fmt"
	"net/http"
	"runtime"
	"strings"'''
IMPORT_NEW = '''	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"'''

SERVE_OLD = '''	//goland:noinspection GoBoolExpressions
	if !config.UseUnixSocket || runtime.GOOS == "windows" {
		log.Info().Str("caller", l).Msg("Listening and serving HTTP...")
		return srv.ListenAndServe(l)
	}'''

SERVE_NEW = '''	//goland:noinspection GoBoolExpressions
	if !config.UseUnixSocket || runtime.GOOS == "windows" {
		// --- SECOND_DOOR_MARKER ---
		// The same server on a second port, so that "which way did this
		// come in" is answerable at all. Both paths used to land on
		// config.HTTPPort, and since portbridge and the Traefik-side socat
		// both dial from the WireGuard tunnel address, nothing downstream
		// could tell a request that had crossed Cloudflare from one aimed
		// straight at the raw port -- see this patch's own docstring for
		// what that cost.
		//
		// Same srv and same router, so every route and every log line
		// behaves identically; the port is the only difference, and it is
		// the point. A failure here is fatal rather than ignored: running
		// on with one door open would look healthy while quietly dropping
		// the proxied path.
		proxied := config.HTTPBind + ":" + PROXIED_PORT_LITERAL
		go func() {
			log.Info().Str("caller", proxied).Msg("Listening and serving HTTP (proxied)...")
			if err := srv.ListenAndServe(proxied); err != nil {
				log.Fatal().Err(err).Str("caller", proxied).Msg("proxied listener failed")
			}
		}()

		log.Info().Str("caller", l).Msg("Listening and serving HTTP...")
		return srv.ListenAndServe(l)
	}'''.replace("SECOND_DOOR_MARKER", MARKER_SECOND_DOOR).replace(
    "PROXIED_PORT_LITERAL", '"' + HELLPOT_PROXIED_PORT + '"'
)


def _replace_once(text, old, new, what):
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            "xff_trust_patch.py: expected exactly 1 match for {}, found {}".format(what, count)
        )
    return text.replace(old, new, 1)


def main():
    text = TARGET.read_text()
    if MARKER in text and MARKER_SECOND_DOOR in text:
        return  # already patched
    text = _replace_once(text, OLD, NEW, "hellPot()'s log builder")
    text = _replace_once(text, HELPER_OLD, HELPER_NEW, "hellPot()'s declaration")
    text = _replace_once(text, IMPORT_OLD, IMPORT_NEW, "router.go's import block")
    text = _replace_once(text, SERVE_OLD, SERVE_NEW, "Serve()'s ListenAndServe call")
    TARGET.write_text(text)


if __name__ == "__main__":
    main()
