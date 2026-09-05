"""#2978: a Go listen address in a port field must not kill the worker.

beelzebub's `Init service` records carry honeypot.port as the address it
bound (":8880", ":389"), and the honeypot ingest pipeline copied
honeypot.port straight into destination.port. destination.port maps as
`integer`, so Elasticsearch never indexed those values -- but the string
survived in `_source`, which is what this worker reads. `int(":8880")` in
_get_port() then raised out of retrain() -- which, unlike the live scoring
path (#171), has no per-event guard -- before the worker ever reached its
polling loop: 366 crashes in two hours, nothing scored for five hours, from
fifteen bad documents in a 20 000-event training window.

":8880" is a known representation of a port, not junk, so it is parsed.
Anything genuinely uninterpretable still raises, which is #171's deliberate
contract (see TestUnhandledEventErrorsCrashTheBatch in test_worker_audit.py):
the caller quarantines the event as reviewable rather than scoring it on a
value nobody can defend.

arcane/home/honeypot-init/analysis/elasticsearch-setup.sh now normalises the
value at ingest as well, but documents already indexed keep the old shape
forever, so the read side has to hold on its own.

Run: python3 -m pytest ml-worker/tests/test_malformed_field_guards.py -v
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models.isolation_forest import (  # noqa: E402
    _get_port, _get_src_port, _parse_port,
)
from models.session_features import compute_batch_session_features  # noqa: E402


@pytest.mark.parametrize("value,expected", [
    (8880, 8880),
    (0, 0),
    ("8880", 8880),
    (":8880", 8880),            # the beelzebub case
    (":389", 389),
    ("0.0.0.0:389", 389),
    ("[::]:8880", 8880),        # rsplit, so the IPv6 host cannot swallow it
    (" :8880 ", 8880),
])
def test_parse_port_understands_listen_addresses(value, expected):
    assert _parse_port(value) == expected


@pytest.mark.parametrize("value", ["not-a-port", "", ":", "80/tcp", "8080:extra"])
def test_parse_port_still_raises_on_genuine_junk(value):
    """#171: the readers stay strict so the caller can quarantine the event
    instead of silently scoring it on an invented value."""
    with pytest.raises(ValueError):
        _parse_port(value)


def test_get_port_survives_a_listen_address():
    """The exact document shape that took the worker down, as indexed."""
    doc = {
        "honeypot": {"msg": "Init service: Wordpress 6.0", "port": ":8880"},
        "destination": {"port": ":8880"},
        "source": {},
        "event": {},
    }
    assert _get_port(doc) == 8880


def test_get_port_still_raises_on_a_malformed_value():
    with pytest.raises(ValueError):
        _get_port({"destination": {"port": "not-a-port"}, "source": {}})


def test_get_src_port_understands_listen_addresses_too():
    assert _get_src_port({"source": {"port": ":51234"}, "destination": {}}) == 51234


def test_plain_numeric_ports_are_unchanged():
    doc = {"source": {"ip": "198.51.100.77", "port": 51234}, "destination": {"port": 22}}
    assert _get_port(doc) == 22
    assert _get_src_port(doc) == 51234


def test_retrain_batch_features_survive_a_listen_address_document():
    """The regression itself: compute_batch_session_features() is what
    retrain() calls, and it walks the whole training window through
    _get_port(). One beelzebub Init-service row raised and killed the
    process on every retrain cycle."""
    good = {
        "@timestamp": "2026-09-04T07:22:30.000Z",
        "source": {"ip": "198.51.100.77", "port": 51234},
        "destination": {"port": 22},
        "honeypot": {"eventid": "cowrie.login.failed", "session": "s1"},
    }
    beelzebub_init = {
        "@timestamp": "2026-09-04T07:22:34.510Z",
        "source": {},
        "destination": {"port": ":8880"},
        "honeypot": {"msg": "Init service: Wordpress 6.0", "port": ":8880"},
    }
    features = compute_batch_session_features([good, beelzebub_init, good])
    assert len(features) == 3
    assert all(f is not None for f in features)
    assert all({"cmd_count", "failed_logins_1h", "unique_ports_1h"} <= set(f) for f in features)
