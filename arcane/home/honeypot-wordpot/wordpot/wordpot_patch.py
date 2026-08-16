#!/usr/bin/env python
"""Make wordpot's log output JSON and joinable via source port (#1421),
and trust X-Forwarded-For from the WireGuard tunnel peer only (#1512).

Three gaps, all closed here, config-only vendoring otherwise (no new
detection logic -- every plugin/route this patch touches keeps doing
exactly what it already does):

1. logger.py's FileHandler formatter emits
   `'%(asctime)s - %(message)s'` plain text (confirmed directly, not
   assumed -- this is the exact gap #1421 was filed to close). Swapped
   for a JSON envelope: {"time": ..., "level": ..., "message": ...}.
   `message` is whatever wordpot itself already formatted (e.g. "1.2.3.4
   tried to login with username admin and password hunter2") --
   ip-enrichment-worker/wordpot.go regexes that fixed, known set of
   wordpot's own log sentence templates (confirmed live, see that file's
   doc comment), the same "known templates, deterministic extraction"
   approach as reading any other structured field.

2. Every one of wordpot's own log call sites captures only
   `request.remote_addr` (an IP, no port) as `origin` -- confirmed
   directly across views.py and 4 of 5 plugins. Without a port,
   ip-enrichment-worker's via_port join (keyed by source port against
   portbridge's own connection log, the same trusted mechanism every
   other raw-port sensor here uses -- see hellpot/router_patch.py for
   why this exact gap mattered there too) has nothing to join on: the
   real attacker IP could never be resolved, silently, for every single
   event. Rather than patch each of those ~6 scattered call sites
   individually (higher risk of drift breaking an exact-match patch),
   one small WSGI middleware in __init__.py rewrites
   environ['REMOTE_ADDR'] to "ip:port" before Flask ever sees the
   request, so every existing `request.remote_addr` call site picks up
   the port for free with zero changes to views.py or any plugin.
   Confirmed safe: `to_json_log()`'s own `source_ip`/`source_port`
   fields are never read anywhere in this vendored tree (only ever
   published over hpfeeds, which stays disabled by this stack's
   wordpot.conf -- see docker-compose.wordpot.yml), so widening what
   remote_addr contains has no other observer to break.

3. #1512 adds a Traefik-routed subdomain alongside wordpot's existing raw
   portbridge port (Cloudflare doesn't proxy non-standard ports outside its
   own fixed allowlist -- see #1511/#1512's own issue text). A request
   arriving that way shows the WireGuard tunnel peer as REMOTE_ADDR, not the
   attacker -- via_port join (fix 2 above) only resolves the real IP for
   the raw-port path, since Traefik terminates and re-originates the
   backend connection with its own ephemeral source port. Extended the same
   middleware to trust X-Forwarded-For, but *only* when REMOTE_ADDR is
   exactly the tunnel peer, and only its *last* hop: Cloudflare appends the
   real client IP to any XFF a client already sent rather than replacing
   it, and socat forwards bytes verbatim with no header rewriting, so the
   leftmost hop is spoofable (`curl -H "X-Forwarded-For: 1.2.3.4" ...`)
   while the rightmost is the one Cloudflare itself appended -- same rule
   http-honeypot/main.go's own clientIP() and galah's xff_trust_patch.py
   already use for the identical gap.

Same shape as dionaea/log_rotation_patch.py/hellpot/router_patch.py:
exact-match string replacement with a marker for idempotency, applied at
Docker build time.
"""
from pathlib import Path

MARKER_LOGGER = "honeypot-stack: JSON logging (#1421) :logger"
MARKER_MIDDLEWARE_DEF = "honeypot-stack: port-preserving remote_addr + tunnel-peer XFF trust (#1421/#1512) :middleware-def"
MARKER_MIDDLEWARE_WRAP = "honeypot-stack: port-preserving remote_addr (#1421) :middleware-wrap"

LOGGER_TARGET = Path("/opt/wordpot/wordpot/logger.py")
LOGGER_OLD = "    formatter = logging.Formatter('%(asctime)s - %(message)s')"
LOGGER_NEW = """    # --- {marker} ---
    class _JsonFormatter(logging.Formatter):
        def format(self, record):
            import json
            return json.dumps({{
                'time': self.formatTime(record, '%Y-%m-%dT%H:%M:%S'),
                'level': record.levelname,
                'message': record.getMessage(),
            }})
    formatter = _JsonFormatter()""".format(marker=MARKER_LOGGER)

INIT_TARGET = Path("/opt/wordpot/wordpot/__init__.py")
INIT_OLD = "app = Flask('wordpot')"
INIT_NEW = '''app = Flask('wordpot')

# --- {marker} ---
_TUNNEL_PEER_IP = '10.8.0.1'


class _PreservePortMiddleware(object):
    """Rewrite REMOTE_ADDR to "ip:port" so every existing
    request.remote_addr call site in this vendored tree picks up the
    source port for free (#1421); trust X-Forwarded-For's last hop when
    REMOTE_ADDR is exactly the WireGuard tunnel peer, for the Traefik-routed
    path where via_port join can't resolve the real attacker (#1512) --
    see wordpot_patch.py's own doc comment for both."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        addr = environ.get('REMOTE_ADDR')
        if addr == _TUNNEL_PEER_IP:
            xff = environ.get('HTTP_X_FORWARDED_FOR')
            if xff:
                environ['REMOTE_ADDR'] = xff.split(',')[-1].strip()
                return self.wsgi_app(environ, start_response)
        port = environ.get('REMOTE_PORT')
        if port and addr and ':' not in addr:
            environ['REMOTE_ADDR'] = '%s:%s' % (addr, port)
        return self.wsgi_app(environ, start_response)'''.format(marker=MARKER_MIDDLEWARE_DEF)
INIT_WRAP_OLD = "pm = PluginsManager()"
INIT_WRAP_NEW = "# --- {marker} ---\napp.wsgi_app = _PreservePortMiddleware(app.wsgi_app)\n\npm = PluginsManager()".format(
    marker=MARKER_MIDDLEWARE_WRAP
)


def _apply(target, old, new, marker):
    text = target.read_text()
    if marker in text:
        return
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            "wordpot_patch.py: expected exactly 1 match for {} in {}, found {}".format(
                repr(old[:40]), target, count
            )
        )
    target.write_text(text.replace(old, new, 1))


def main():
    _apply(LOGGER_TARGET, LOGGER_OLD, LOGGER_NEW, MARKER_LOGGER)
    _apply(INIT_TARGET, INIT_OLD, INIT_NEW, MARKER_MIDDLEWARE_DEF)
    _apply(INIT_TARGET, INIT_WRAP_OLD, INIT_WRAP_NEW, MARKER_MIDDLEWARE_WRAP)


if __name__ == "__main__":
    main()
