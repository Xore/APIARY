# APIARY-owned proxy-scheme shim for the vendored Rev·Deck build. Never
# patch webui/ itself -- that's biniamf/ai-reverse-engineering's own tree,
# cloned by hand into ./revdeck/ai-reverse-engineering
# (docker-compose.ghidra.yml's own comment), not tracked in this repo, and
# liable to be silently reset by a future re-clone. This file lives outside
# that tree and is bind-mounted in read-only at container start instead.
#
# The bug: webui/app.py's own same-origin guard (_reject_cross_origin)
# rejects every state-changing route with 403 "cross-origin request is not
# allowed" whenever the browser's Origin header doesn't match
# request.host_url. request.host_url is built by Werkzeug from the raw
# connection gunicorn accepted, and this build configures zero proxy trust
# anywhere (no ProxyFix, no X-Forwarded-* handling at all -- confirmed by
# grepping the built image). Traefik terminates TLS at the public edge
# (vps/traefik/dynamic.yml's honeypot-revdeck router, entrypoint
# `websecure`) and relays plain HTTP from there through oauth2-proxy and a
# raw socat TCP bridge (vps/docker-compose.yml's socat-hp-revdeck) to this
# container, so request.host_url comes out "http://rev.<domain>/" while the
# browser's own Origin is "https://rev.<domain>" -- scheme-only mismatch.
# Confirmed live 2026-08-11 against the deployed container's own request
# log (POST /upload -> 403) before this fix existed.
#
# x_proto=1: Traefik is the only hop in this chain that actually derives
# X-Forwarded-Proto from anything real (the entrypoint TLS terminates on);
# oauth2-proxy and socat both relay it through unchanged rather than
# re-deriving or appending their own value, so there is exactly one
# trustworthy value to read here, not one per network hop.
# x_host=1: Host is already passed through byte-for-byte end to end
# (passHostHeader: true on the same Traefik router), so this is a no-op in
# practice today -- kept for correctness if that ever stops being true.
from werkzeug.middleware.proxy_fix import ProxyFix

from wsgi import app

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)


# Preset-prompts composer button: same "never patch webui/ itself" reasoning
# as the ProxyFix wrapping above. preset_prompts.js (this directory,
# bind-mounted read-only into webui/static/js/ alongside the vendored
# composer.js/app.js -- see docker-compose.ghidra.yml's revdeck service)
# does the actual DOM work; this hook's only job is getting a <script> tag
# for it onto every HTML page, since the vendored index.html template can't
# be edited to reference it directly.
#
# CSP-safe without a nonce: app.py's own Content-Security-Policy header sets
# script-src to same-origin only (no 'unsafe-inline', no nonce requirement
# for a same-origin src URL) -- confirmed by reading that header's own
# construction. A same-origin <script src> tag needs nothing special here.
#
# Registered after create_app() already added its own after_request hooks
# inside app.py (this decorator runs at import time, after that factory
# function returns), so Flask's LIFO after_request order runs this one
# FIRST, before app.py's own CSP/security-header hooks -- irrelevant here
# since this only rewrites the HTML body, never touches headers.
@app.after_request
def _inject_preset_prompts_script(response):
    if response.content_type and response.content_type.startswith("text/html"):
        body = response.get_data(as_text=True)
        if "</body>" in body:
            response.set_data(
                body.replace(
                    "</body>",
                    '<script defer src="/static/js/preset_prompts.js"></script></body>',
                    1,
                )
            )
    return response
