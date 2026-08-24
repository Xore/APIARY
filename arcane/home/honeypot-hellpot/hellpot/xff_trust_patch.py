#!/usr/bin/env python3
"""Log the forwarded header as a fact; let the worker decide (#1876).

The first version of this patch resolved X-Forwarded-For inside
getRealRemote(), trusting it whenever RemoteAddr was the tunnel peer --
the rule galah's xff_trust_patch.py uses (#1511). That rule is safe for
galah and unsafe here, and the difference is the deployment:

  * galah's raw port is source-preserving, so on that path RemoteAddr is
    the attacker. "RemoteAddr is the tunnel peer" therefore means "this
    came through Traefik", and trusting the header follows.

  * HellPot's portbridge path is *not* source-preserving -- that is the
    entire reason enrichHellpotLine joins on the port of a tunnel-peer
    RemoteAddr. So here RemoteAddr is the tunnel peer on *both* paths, the
    condition cannot tell them apart, and trusting the header on the
    portbridge path lets an attacker set their own source by sending one.
    That is precisely the spoofing #1419 removed.

There is no header HellPot can check to distinguish the paths, because
anything Traefik adds an attacker can also send. What does distinguish
them is something HellPot cannot see: whether portbridge relayed the
connection. Only the enrichment worker knows that, because only it holds
portbridge's connection log.

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
TARGET = Path("/build/internal/http/router.go")

OLD = '''	slog := log.With().
		Str("USERAGENT", string(ctx.UserAgent())).
		Str("REMOTE_ADDR", remoteAddr).
		Interface("URL", string(ctx.RequestURI())).Logger()'''

NEW = '''	// --- MARKER_PLACEHOLDER ---
	slog := log.With().
		Str("USERAGENT", string(ctx.UserAgent())).
		Str("REMOTE_ADDR", remoteAddr).
		Str("XFF", string(ctx.Request.Header.Peek("X-Forwarded-For"))).
		Interface("URL", string(ctx.RequestURI())).Logger()'''.replace(
    "MARKER_PLACEHOLDER", MARKER
)


def main():
    text = TARGET.read_text()
    if MARKER in text:
        return  # already patched
    count = text.count(OLD)
    if count != 1:
        raise SystemExit(
            "xff_trust_patch.py: expected exactly 1 match for hellPot()'s log "
            "builder, found {}".format(count)
        )
    TARGET.write_text(text.replace(OLD, NEW, 1))


if __name__ == "__main__":
    main()
