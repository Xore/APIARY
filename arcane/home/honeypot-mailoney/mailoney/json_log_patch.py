#!/usr/bin/env python3
"""Add per-event JSON-line logging to Mailoney, unmodified otherwise (#1422).

Mailoney persists each SMTP session's event list to a SQLAlchemy database
only (SQLite by default, mailoney/db.py's update_session_data()) --
confirmed by reading mailoney/core.py directly, not assumed from the
README. Every other sensor in this stack writes one JSON line per event
to a bind-mounted file for ip-enrichment-worker/Filebeat; Mailoney has no
equivalent.

Rather than dump the whole session as one line at the end (which would
need a bespoke nested-event enrich function, like beelzebub.go's), this
emits one flat JSON line per meaningful event -- login/envelope/mail-body
-- at the same three points core.py already logs them, mirroring
multipot's own now-retired SMTP handler's inline emit-per-event style
(multipot/protocols.go's handleSMTP, removed in this same change since
Mailoney now owns port 25). Flat "src_ip"/"src_port"/"sensor" fields mean
this needs no bespoke ip-enrichment-worker enrich function either --
reuses enrichLine() directly, the same pattern elasticpot/honeypot.cfg's
own sensor_name override established (#1423). The existing DB write
(update_session_data) is untouched -- this only adds a second, additive
sink.

Also fixes a real, confirmed-live credential-capture bug while here: core.py
lowercases the *entire* request line (including the AUTH PLAIN base64
payload) before extracting it -- since the base64 alphabet is
case-sensitive, this silently corrupts any captured username/password
containing an uppercase letter (confirmed by sending a real AUTH PLAIN
request with a mixed-case credential against the patched build and
observing decode failure before this fix, success after). The receive-line
patch below keeps a case-preserved copy specifically for this extraction;
every other command match still uses the lowercased line as before.

Since #2196 the injected sink also self-rotates (MAILONEY_JSON_MAX_BYTES,
default 64MiB, 0 disables): rename-aside as mailoney.json.<utcstamp>[.N],
digit-leading suffix per the #120 pruner contract that
analysis/log-maintenance.sh's glob family matches.

Same shape as dionaea/log_rotation_patch.py and hellpot/router_patch.py:
exact-match string replacement with a marker for idempotency, applied at
Docker build time.
"""
from pathlib import Path

MARKER = "honeypot-stack: JSON-line event log sink (#1422)"
TARGET = Path("/build/mailoney/core.py")

IMPORTS_OLD = '''import re
import socket
import threading
import logging
import json
import sys
import uuid
import argparse
from time import strftime
from typing import Optional, Tuple, Dict, Any, List

from .db import create_session, update_session_data, log_credential, init_db
from .config import get_settings, configure_logging
from .mail_storage import store_mail_body

logger = logging.getLogger(__name__)'''

IMPORTS_NEW = '''import re
import socket
import threading
import logging
import json
import os
import base64
import binascii
import sys
import uuid
import argparse
from time import gmtime, strftime
from typing import Optional, Tuple, Dict, Any, List

from .db import create_session, update_session_data, log_credential, init_db
from .config import get_settings, configure_logging
from .mail_storage import store_mail_body

logger = logging.getLogger(__name__)

# --- MARKER_PLACEHOLDER ---
def _rotate_json_log(path):
    """Rename mailoney.json aside as <path>.<utcstamp>[.N] (#120, #2196).

    Same rotation contract as dionaea/log_rotation_patch.py's FileHandler
    and multipot/http-honeypot's logger.rotate(): generations get a
    digit-leading suffix so analysis/log-maintenance.sh's pruner family
    ('mailoney.json.[0-9]*', -mmin json_retention_min) deletes them once
    aged out. This sink opens per event instead of holding one fd (as
    dionaea's does), so "close/rename/reopen" collapses to rename-aside;
    the next event's open(path, "a") recreates the live file. A same-
    second collision appends .2/.3 like dionaea -- without it a rapid
    second rotate silently replaces the first generation and loses it.
    Two handlers racing one rename is possible under core.py's threading;
    the loser's OSError is swallowed, which is the same tolerance every
    other rotating writer here already accepts.
    """
    stamp = strftime("%Y%m%d-%H%M%S", gmtime())
    target = path + "." + stamp
    if os.path.exists(target):
        n = 2
        while os.path.exists(target + "." + str(n)):
            n += 1
        target = target + "." + str(n)
    try:
        os.rename(path, target)
    except OSError:
        pass


def _emit_json_event(event, addr, dest_ip, dest_port, server_name, **fields):
    """Append one flat JSON line, matching enrichLine's expected shape
    (top-level "src_ip" string + "src_port" number) and this repo's
    "sensor" literal convention (elasticpot/honeypot.cfg's own
    sensor_name override established the same pattern for #1423)."""
    path = os.environ.get("MAILONEY_JSON_LOG", "/var/log/honeypot/mailoney.json")
    # Same "0 means unbounded" env-knob contract as DIONAEA_LOG_MAX_BYTES
    # and the Go writers' LOG_MAX_BYTES. Port 25 is continuously probed and
    # every connection emits at least an envelope event, so an unbounded
    # flat append filled the bind mount on the live host (#120, #2196) --
    # which takes out neighbors sharing /logs, not just this sensor.
    try:
        max_bytes = int(os.environ.get("MAILONEY_JSON_MAX_BYTES", "67108864"))
    except ValueError:
        max_bytes = 67108864  # a hostile/garbage env must not kill SMTP sessions
    record = {
        # Explicit-UTC stamp: strftime renders process-local wall clock, and
        # this container pins TZ=Europe/Berlin (compose.yml), so a bare
        # "%Y-%m-%dT%H:%M:%SZ" emits Berlin time wearing a Z -- off by the
        # DST offset (2h summer / 1h winter) while claiming UTC. The
        # ip-enrichment-worker parses exactly this field as RFC3339 UTC for
        # its portbridge join (sensors.rs), so that skew directly widened
        # the time-since-dial window and re-created the wrong-attribution
        # ambiguity #1917 shrank. gmtime() is the deliberate UTC source;
        # do not "derive" it from the TZ env var, which is set to Berlin
        # here on purpose (#2197).
        "timestamp": strftime("%Y-%m-%dT%H:%M:%SZ", gmtime()),
        "sensor": "mailoney",
        "event": event,
        "src_ip": addr[0],
        "src_port": addr[1],
        "dst_ip": dest_ip,
        "dst_port": dest_port,
        "server_name": server_name,
    }
    record.update(fields)
    try:
        if max_bytes > 0:
            # Probe is isolated: a not-yet-existing live file (first event
            # after boot or a previous rotation) must read as "nothing to
            # rotate", not fall into the write-failure path below.
            try:
                needs_rotate = os.path.getsize(path) >= max_bytes
            except OSError:
                needs_rotate = False
            if needs_rotate:
                _rotate_json_log(path)
        with open(path, "a") as f:
            f.write(json.dumps(record) + "\\n")
    except OSError as e:
        logger.error(f"Failed to write JSON event log: {e}")


def _decode_auth_plain(b64_value):
    """AUTH PLAIN is base64(authzid NUL authcid NUL password) per RFC 4616.
    core.py's own request parsing already .lower()s every input line
    before this ever runs, so username/password here are always
    lowercased -- a real upstream limitation (confirmed live), not
    something this patch can recover, since the original case is gone by
    the time this string exists."""
    try:
        decoded = base64.b64decode(b64_value + "=" * (-len(b64_value) % 4))
        parts = decoded.split(b"\\x00")
        if len(parts) == 3:
            return parts[1].decode("utf-8", "replace"), parts[2].decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        pass
    return "", ""'''.replace("MARKER_PLACEHOLDER", MARKER)

RECEIVE_OLD = ("                    request = client_socket.recv(4096).decode().strip().lower()\n"
               "                    if not request:\n")

RECEIVE_NEW = ("                    request_raw = client_socket.recv(4096).decode().strip()\n"
               "                    request = request_raw.lower()\n"
               "                    if not request:\n")

AUTH_OLD = ("                    elif request.startswith('auth plain'):\n"
            "                        # Extract auth string\n"
            "                        parts = request.split()\n"
            "                        if len(parts) >= 3:\n"
            "                            auth_string = parts[2]\n"
            "                            log_credential(session_record.id, auth_string)\n"
            '                            logger.info(f"Captured credential: {auth_string}")\n'
            "                            \n"
            '                        response = "235 2.7.0 Authentication failed\\n"')

AUTH_NEW = '''                    elif request.startswith('auth plain'):
                        # Extract auth string. request_raw (case-preserved, see the
                        # receive-line patch above) not request -- confirmed live:
                        # request is .lower()'d before this runs, which silently
                        # corrupts any captured credential containing an uppercase
                        # letter (the base64 alphabet is case-sensitive).
                        parts = request_raw.split()
                        if len(parts) >= 3:
                            auth_string = parts[2]
                            log_credential(session_record.id, auth_string)
                            logger.info(f"Captured credential: {auth_string}")
                            _username, _password = _decode_auth_plain(auth_string)
                            _emit_json_event(
                                "login", addr, self.bind_ip, self.bind_port, self.server_name,
                                session_id=session_uuid, username=_username, password=_password,
                            )

                        response = "235 2.7.0 Authentication failed\\n"'''

ENVELOPE_OLD = '''                    elif request.startswith(('mail from:', 'rcpt to:')):
                        response = "250 2.1.0 OK\\n"
                        client_socket.send(response.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                        error_count = 0'''

ENVELOPE_NEW = '''                    elif request.startswith(('mail from:', 'rcpt to:')):
                        response = "250 2.1.0 OK\\n"
                        client_socket.send(response.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                        _emit_json_event(
                            "envelope", addr, self.bind_ip, self.bind_port, self.server_name,
                            session_id=session_uuid, command=request,
                        )
                        error_count = 0'''

BODY_OLD = '''                        # If self.mail_dir is unset, only metadata (size,
                        # truncated) is retained. Operators opt in to body
                        # retention by setting MAIL_DIR.
                        session_log.append(body_entry)'''

BODY_NEW = '''                        # If self.mail_dir is unset, only metadata (size,
                        # truncated) is retained. Operators opt in to body
                        # retention by setting MAIL_DIR.
                        session_log.append(body_entry)
                        _emit_json_event(
                            "mail-body", addr, self.bind_ip, self.bind_port, self.server_name,
                            session_id=session_uuid,
                            size=body_entry.get("size"),
                            truncated=body_entry.get("truncated"),
                            body_path=body_entry.get("body_path"),
                            body_preview=body[:512].decode("utf-8", "replace"),
                        )'''


def _apply(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"json_log_patch.py: expected exactly 1 match for {label}, found {count}")
    return text.replace(old, new, 1)


def main():
    text = TARGET.read_text()
    if MARKER in text:
        return  # already patched
    text = _apply(text, IMPORTS_OLD, IMPORTS_NEW, "imports/logger block")
    text = _apply(text, RECEIVE_OLD, RECEIVE_NEW, "raw request receive")
    text = _apply(text, AUTH_OLD, AUTH_NEW, "AUTH PLAIN credential capture")
    text = _apply(text, ENVELOPE_OLD, ENVELOPE_NEW, "MAIL FROM/RCPT TO envelope")
    text = _apply(text, BODY_OLD, BODY_NEW, "DATA body capture")
    TARGET.write_text(text)


if __name__ == "__main__":
    main()
