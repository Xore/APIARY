#!/usr/bin/env python3
"""Build-time patch for the vendored elasticpot checkout (#1423).

elasticpot.py unconditionally calls get_public_ip() at startup -- an
outbound HTTPS request to https://ident.me (configurable, but the call
itself is not gated by the report_public_ip setting, only whether the
result later gets used in a logged event). Confirmed live: this repo's
sensors run without general outbound internet access
(docs/persona-design.md's per-honeypot outbound policy), and an
unreachable ident.me makes get_public_ip() raise, which is never caught,
crashing the whole process before it starts listening at all.

The fetched value is only ever used as decorative content in a few faked
Elasticsearch `_nodes` API fields (core/protocol.py) and optionally as
event['dst_ip'] -- nothing here needs the honeypot's *real* internet-
facing IP specifically, since this container has no meaningful public IP
of its own anyway (it sits behind HP_BIND=10.8.0.2 and WireGuard/NAT).
Swapping in get_local_ip() (already vendored in core/tools.py, a local
socket call with a hardcoded 127.0.0.1 fallback, no network egress)
keeps every downstream field populated with a same-shaped value and
removes the external dependency entirely.
"""
import sys

TARGET = "elasticpot.py"
MARKER = "# no_egress_patch: get_local_ip"

IMPORT_OLD = "from core.tools import mkdir, import_plugins, stop_plugins, get_public_ip"
IMPORT_NEW = "from core.tools import mkdir, import_plugins, stop_plugins, get_local_ip  " + MARKER

CALL_OLD = "    cfg_options['public_ip'] = get_public_ip(cfg_options['public_ip_url'])"
CALL_NEW = "    cfg_options['public_ip'] = get_local_ip().encode('utf-8')  " + MARKER

with open(TARGET) as f:
    src = f.read()

if MARKER in src:
    sys.exit(0)  # already patched, idempotent

if src.count(IMPORT_OLD) != 1:
    sys.exit(f"no_egress_patch: expected exactly one match for the import line in {TARGET}, found {src.count(IMPORT_OLD)}")
if src.count(CALL_OLD) != 1:
    sys.exit(f"no_egress_patch: expected exactly one match for the get_public_ip call in {TARGET}, found {src.count(CALL_OLD)}")

src = src.replace(IMPORT_OLD, IMPORT_NEW, 1)
src = src.replace(CALL_OLD, CALL_NEW, 1)

with open(TARGET, "w") as f:
    f.write(src)
