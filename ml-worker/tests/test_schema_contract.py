"""
Feature-schema contract (#62 task 32): proves, against real-shaped fixtures
for all 5 source types (fixtures.py), exactly which fields extract_features()
currently reads correctly, reads wrong, or can't reach at all. This is the
baseline #33's extract_features() rewrite must fix -- each assertion here
documents one specific gap, not a general "it's broken" statement.

The Dionaea/Cowrie/Conpot ECS-promotion gaps this file documents are ingest
pipeline issues, not ml-worker bugs -- filed separately as #132.

Run: python3 -m pytest ml-worker/tests/test_schema_contract.py -v
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models.isolation_forest import IsoForestModel  # noqa: E402
import fixtures  # noqa: E402


@pytest.fixture
def model():
    return IsoForestModel(model_dir="/tmp/does-not-matter")


class TestAllFiveSourcesYieldOnlyDefaultedFeatures:
    """extract_features() reads a flat top-level schema; every one of these
    5 real-shaped sources nests its data instead, so every single source
    currently produces the all-defaults feature vector regardless of what
    the underlying event actually contains."""

    @pytest.mark.parametrize("doc", fixtures.ALL_REAL_DOCUMENTS, ids=lambda d: d["_id"])
    def test_no_real_source_populates_the_ip_field(self, model, doc):
        src = doc["_source"]
        features = model.extract_features(src).flatten()
        # is_known_scanner (index 12) depends on the ip lookup finding
        # something; every source's real IP is unreachable via
        # src.get("src_ip") or src.get("id.orig_h"), so it's always 0 even
        # for fixtures whose source.ip / honeypot.src_ip is a real address.
        assert features[12] == 0.0

    @pytest.mark.parametrize("doc", fixtures.ALL_REAL_DOCUMENTS, ids=lambda d: d["_id"])
    def test_no_real_source_populates_the_port_field(self, model, doc):
        src = doc["_source"]
        features = model.extract_features(src).flatten()
        assert features[2] == 0.0, "port always defaults to 0/65535.0=0.0 despite every fixture carrying a real port 2-3 levels deep"


class TestPerSourceFieldLocations:
    """Where the real data actually lives for each source, and which of it
    the geoip-honeypot ingest pipeline (analysis/elasticsearch-setup.sh)
    promotes to ECS fields -- extract_features() should eventually read from
    here, preferring the promoted ECS fields since they're the one place a
    schema is consistent across all 5 sources."""

    def test_cowrie_ip_and_port_are_ecs_promoted(self):
        src = fixtures.COWRIE_LOGIN_FAILED["_source"]
        assert src["source"]["ip"] == src["honeypot"]["src_ip"]
        assert src["destination"]["port"] == src["honeypot"]["dst_port"]

    def test_cowrie_protocol_field_name_mismatch_blocks_ecs_promotion(self):
        # Cowrie's own field is "protocol", but the ingest pipeline only
        # promotes network.protocol from h.proto -- so it's never set here,
        # even though the raw value is right there under honeypot.protocol.
        src = fixtures.COWRIE_LOGIN_FAILED["_source"]
        assert src["honeypot"]["protocol"] == "ssh"
        assert "network" not in src or "protocol" not in src.get("network", {})

    def test_dionaea_connection_event_has_no_event_sensor(self):
        # Gap #2: dionaea.json (the flat connection log) has neither a
        # `sensor` nor an `eventid` field, and the pipeline's event.sensor
        # logic has no further fallback for it -- a query on
        # event.sensor:dionaea will never match this real, common event.
        src = fixtures.DIONAEA_CONNECTION_ACCEPT["_source"]
        assert src["event"].get("sensor") is None
        assert src["source"]["ip"] == src["honeypot"]["src_ip"], "ip IS promoted correctly, just not filterable by sensor"

    def test_dionaea_incident_stream_has_sensor_but_no_parsed_fields(self):
        # The other dionaea stream (dionaea_incident.json) gets sensor=dionaea
        # via a static filebeat field, but its payload is an opaque JSON
        # string inside honeypot.message -- there is no honeypot.src_ip here
        # at all, structured or otherwise.
        src = fixtures.DIONAEA_INCIDENT_RAW["_source"]
        assert src["event"]["sensor"] == "dionaea"
        assert "src_ip" not in src["honeypot"]
        assert isinstance(src["honeypot"]["message"], str)

    def test_conpot_has_no_sensor_or_proto_field_in_the_event_itself(self):
        # event.sensor="conpot-s7-1200" here comes from the log file path
        # (elasticsearch-setup.sh's log.file.path branch), not from any key
        # conpot's own json_log.py ever writes. data_type carries the
        # protocol info the pipeline's h.proto branch never sees.
        src = fixtures.CONPOT_MODBUS_REQUEST["_source"]
        assert "sensor" not in src["honeypot"]
        assert "proto" not in src["honeypot"]
        assert src["honeypot"]["data_type"] == "modbus"
        assert src["event"]["sensor"] == "conpot-s7-1200"

    def test_http_honeypot_is_the_one_source_extract_features_could_read_directly(self):
        # http-honeypot writes proto-compatible field names (sensor, src_ip,
        # username, password all present, flat, at honeypot.* depth 1) --
        # still one level too deep for the current top-level-only reads, but
        # the ECS promotion here is complete: ip, user.name, url.path.
        src = fixtures.HTTP_HONEYPOT_LOGIN_ATTEMPT["_source"]
        assert src["source"]["ip"] == src["honeypot"]["src_ip"]
        assert src["user"]["name"] == src["honeypot"]["username"]
        assert src["url"]["path"] == src["honeypot"]["path"]

    def test_suricata_network_events_use_a_different_index_and_top_key(self):
        # Not honeypot-v2-* at all -- suricata-v2-<event_type>-*, with the
        # raw record nested under suricata.eve.*, not honeypot.*.
        doc = fixtures.SURICATA_ALERT
        assert doc["_index"].startswith("suricata-v2-")
        src = doc["_source"]
        assert "honeypot" not in src
        assert src["suricata"]["eve"]["event_type"] == "alert"
        assert src["source"]["ip"] == src["suricata"]["eve"]["src_ip"]


class TestMalformedEventsDoNotCrashFeatureExtraction:
    def test_event_with_no_timestamp_at_all_does_not_raise(self, model):
        src = fixtures.MALFORMED_MISSING_TIMESTAMP["_source"]
        features = model.extract_features(src)
        assert features.shape == (1, 15)
