#!/usr/bin/env python
"""Make wordpot's log output JSON, joinable via source port (#1421), and
honest about which way in a request came (#1908).

Five gaps, all closed here, config-only vendoring otherwise (no new
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
   wordpot.conf -- see arcane/home/honeypot-wordpot/compose.yml), so widening what
   remote_addr contains has no other observer to break.

3. #1512 added a Traefik-routed subdomain alongside wordpot's existing raw
   portbridge port (Cloudflare doesn't proxy non-standard ports outside its
   own fixed allowlist -- see #1511/#1512's own issue text). A request
   arriving that way shows the WireGuard tunnel peer as REMOTE_ADDR, not
   the attacker, and the via_port join in fix 2 can't help: Traefik
   terminates and re-originates the connection with its own ephemeral
   source port, which portbridge never saw.

   #1512 answered that in this middleware, by trusting X-Forwarded-For's
   last hop whenever REMOTE_ADDR was the tunnel peer. Both halves were
   wrong, and #1908 replaces them:

   - The condition can't tell the two paths apart. wordpot's raw port is
     portbridge rule `tcp:8082:10.8.0.2:8081`, with no `:pp`, so portbridge
     relays it and REMOTE_ADDR is the tunnel peer *there too* -- on every
     single request. Verified against the running stack, not argued: a
     request to the raw port carrying `X-Forwarded-For: 198.51.100.77` was
     logged as "198.51.100.77 probed for the login page". Anyone could file
     their traffic under any address they liked. Same defect as #1883 and
     #1891, and the third sensor to inherit this same rule by copying.

   - The last hop isn't the client. Cloudflare does append the real client
     to whatever the client sent -- but Traefik then appends the peer *it*
     saw, which is a Cloudflare edge node, so the chain ends one hop past
     the answer.

   There was a third consequence nobody noticed. Resolving XFF here also
   dropped the port, leaving a bare "1.2.3.4 probed ..." message; the
   worker's parser requires an "ip:port" prefix, so every proxied wordpot
   event was discarded as if it were a startup line.

   So the sensor stops deciding, and instead records what it saw. The
   middleware only ever widens REMOTE_ADDR (fix 2), the formatter writes
   the request's own fields alongside the sentence (fix 4), and the
   enrichment worker adjudicates -- it holds portbridge's connection log,
   which is the only evidence that separates the two paths.

4. Which door a request arrived at is now a fact in the log line rather
   than an inference, because the two doors are genuinely separate: fix 5
   opens a second listener that only the Traefik-side bridge can reach.
   The JSON envelope carries src_ip/src_port/dst_port, plus the forwarding
   headers verbatim for the worker to adjudicate -- never resolved here.
   The `message` sentence is left exactly as wordpot wrote it, so the
   existing parser and every downstream reader keep working unchanged.

5. wordpot binds one port (`app.run`), which is why both paths shared one.
   A second werkzeug server on WORDPOT_PROXIED_PORT runs in a daemon
   thread against the same app -- same handlers, same logging, no
   behavioural fork. It is published only on the WireGuard address with no
   portbridge rule pointing at it, so socat-hp-wordpot is its only possible
   caller and "arrived on that port" means "came through Cloudflare".

Same shape as dionaea/log_rotation_patch.py/hellpot/router_patch.py:
exact-match string replacement with a marker for idempotency, applied at
Docker build time.
"""
from pathlib import Path

MARKER_LOGGER = "honeypot-stack: JSON logging (#1421) :logger"
MARKER_MIDDLEWARE_DEF = "honeypot-stack: port-preserving remote_addr (#1421/#1908) :middleware-def"
MARKER_MIDDLEWARE_WRAP = "honeypot-stack: port-preserving remote_addr (#1421) :middleware-wrap"
MARKER_SECOND_DOOR = "honeypot-stack: Traefik-only second listener (#1908) :second-door"

# The listener only the Traefik-side bridge can reach. Kept in step with
# compose.yml's published port, the socat target in vps/docker-compose.yml,
# and WORDPOT_PROXIED_PORT in the enrichment worker.
WORDPOT_PROXIED_PORT = 8090

LOGGER_TARGET = Path("/opt/wordpot/wordpot/logger.py")
LOGGER_OLD = "    formatter = logging.Formatter('%(asctime)s - %(message)s')"
LOGGER_NEW = """    # --- {marker} ---
    class _JsonFormatter(logging.Formatter):
        def format(self, record):
            import json
            entry = {{
                'time': self.formatTime(record, '%Y-%m-%dT%H:%M:%S'),
                'level': record.levelname,
                'message': record.getMessage(),
            }}
            # #1908: the sentence is what wordpot chose to say; these are
            # what the request actually was. Recorded, never resolved --
            # deciding which of them identifies the attacker needs
            # portbridge's connection log, which lives in the worker.
            #
            # Anything raised in here would otherwise take the log line
            # with it, so a failure degrades to the plain envelope: the
            # sentence still carries the address, as it always did.
            try:
                from flask import has_request_context, request
                if has_request_context():
                    env = request.environ
                    addr = env.get('REMOTE_ADDR') or ''
                    # The middleware widened this to "ip:port"; an IPv6
                    # address it left alone has colons of its own.
                    if addr.count(':') == 1:
                        ip, _, port = addr.partition(':')
                    else:
                        ip, port = addr, env.get('REMOTE_PORT') or ''
                    if ip:
                        entry['src_ip'] = ip
                    if port:
                        entry['src_port'] = port
                    if env.get('SERVER_PORT'):
                        entry['dst_port'] = str(env['SERVER_PORT'])
                    for key, field in (
                        ('HTTP_X_FORWARDED_FOR', 'xff'),
                        ('HTTP_CF_CONNECTING_IP', 'cf_connecting_ip'),
                    ):
                        if env.get(key):
                            entry[field] = env[key]
            except Exception:
                pass
            return json.dumps(entry)
    formatter = _JsonFormatter()""".format(marker=MARKER_LOGGER)

INIT_TARGET = Path("/opt/wordpot/wordpot/__init__.py")
INIT_OLD = "app = Flask('wordpot')"
INIT_NEW = '''app = Flask('wordpot')

# --- {marker} ---


class _PreservePortMiddleware(object):
    """Rewrite REMOTE_ADDR to "ip:port" so every existing
    request.remote_addr call site in this vendored tree picks up the source
    port for free (#1421).

    That is the whole job. It used to also resolve X-Forwarded-For when
    REMOTE_ADDR was the tunnel peer (#1512), which on the raw port is every
    request -- so sending the header was enough to choose your own source
    address, and doing so dropped the port that the join needs. #1908
    removed it; see wordpot_patch.py's own doc comment."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        addr = environ.get('REMOTE_ADDR')
        port = environ.get('REMOTE_PORT')
        if port and addr and ':' not in addr:
            environ['REMOTE_ADDR'] = '%s:%s' % (addr, port)
        return self.wsgi_app(environ, start_response)'''.format(marker=MARKER_MIDDLEWARE_DEF)
INIT_WRAP_OLD = "pm = PluginsManager()"
INIT_WRAP_NEW = "# --- {marker} ---\napp.wsgi_app = _PreservePortMiddleware(app.wsgi_app)\n\npm = PluginsManager()".format(
    marker=MARKER_MIDDLEWARE_WRAP
)


MAIN_TARGET = Path("/opt/wordpot/wordpot.py")
MAIN_OLD = "    app.run(debug=app.debug, host=app.config['HOST'], port=int(app.config['PORT']))"
MAIN_NEW = """    # --- {marker} ---
    # The same app on a second port, so that "which way did this come in"
    # is answerable at all. Both paths used to land on app.config['PORT'],
    # and since portbridge and the Traefik-side socat both dial from the
    # WireGuard tunnel address, nothing downstream could tell a request
    # that had crossed Cloudflare from one aimed straight at the raw port.
    # Everything built on top of that was a guess -- see this file's own
    # doc comment for what the guesses cost.
    #
    # Same app object, so every route, plugin and log call behaves
    # identically; the port is the only difference, and it is the point.
    # A daemon thread, so this dies with the process rather than holding
    # shutdown open.
    import threading
    from werkzeug.serving import make_server

    _proxied = make_server(app.config['HOST'], {proxied_port}, app, threaded=True)
    _proxied_thread = threading.Thread(target=_proxied.serve_forever)
    _proxied_thread.daemon = True
    _proxied_thread.start()
    LOGGER.info('Honeypot proxied listener started on %s:%s', app.config['HOST'], {proxied_port})

    app.run(debug=app.debug, host=app.config['HOST'], port=int(app.config['PORT']))""".format(
    marker=MARKER_SECOND_DOOR, proxied_port=WORDPOT_PROXIED_PORT
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
    _apply(MAIN_TARGET, MAIN_OLD, MAIN_NEW, MARKER_SECOND_DOOR)


if __name__ == "__main__":
    main()
