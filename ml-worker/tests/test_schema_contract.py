"""
Feature-schema contract (#62 tasks 32/33): proves, against real-shaped
fixtures for all 5 source types (fixtures.py), exactly which fields
extract_features() reads correctly, reads wrong, or can't reach at all.
Task 33 fixed the per-sensor field reads (models/isolation_forest.py's
_get_ip/_get_port/_get_transport_proto/_get_username/_get_password/
_get_duration) -- this file now proves the FIXED behavior per source, plus
the handful of gaps that remain genuinely unfixable from extract_features()
alone (either an ingest-pipeline gap -- #132 -- or a field no real sensor
emits at all, e.g. Conpot's transport or HTTP-honeypot's own port).

Run: python3 -m pytest ml-worker/tests/test_schema_contract.py -v
"""
import ipaddress
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import models.isolation_forest as iso_mod  # noqa: E402
from models.isolation_forest import IsoForestModel, _get_ip, _get_port, _get_transport_proto  # noqa: E402
import fixtures  # noqa: E402


@pytest.fixture
def model():
    return IsoForestModel(model_dir="/tmp/does-not-matter")


class TestIpAndPortNowCorrectlyResolvedPerSource:
    """Every source whose real document actually carries an IP/port
    (everything except the opaque dionaea-incident payload) now resolves it
    -- checked directly via _get_ip()/_get_port() rather than through
    is_known_scanner()/normalised-port, so the assertion can't accidentally
    pass just because a synthetic fixture IP isn't scanner-listed."""

    @pytest.mark.parametrize("doc", [
        fixtures.COWRIE_LOGIN_FAILED, fixtures.COWRIE_COMMAND_INPUT,
        fixtures.DIONAEA_CONNECTION_ACCEPT, fixtures.CONPOT_MODBUS_REQUEST,
        fixtures.HTTP_HONEYPOT_LOGIN_ATTEMPT, fixtures.SURICATA_ALERT,
    ], ids=lambda d: d["_id"])
    def test_ip_resolves_to_the_real_address(self, doc):
        src = doc["_source"]
        assert _get_ip(src) == src["source"]["ip"]

    @pytest.mark.parametrize("doc,expected_port", [
        (fixtures.COWRIE_LOGIN_FAILED, 22),
        (fixtures.COWRIE_COMMAND_INPUT, 22),
        (fixtures.DIONAEA_CONNECTION_ACCEPT, 445),
        (fixtures.CONPOT_MODBUS_REQUEST, 502),
        (fixtures.SURICATA_ALERT, 22),
    ], ids=lambda x: x if isinstance(x, int) else x["_id"])
    def test_port_resolves_to_the_real_value(self, doc, expected_port):
        assert _get_port(doc["_source"]) == expected_port

    def test_http_honeypot_port_stays_unset_because_none_is_ever_logged(self):
        # Not a bug: main.go's own event struct has no port field at all --
        # the honeypot always listens on the same implicit web port, so it's
        # never worth logging per-event. Nothing for extract_features() to
        # read here, honestly reflected as 0 rather than guessed.
        assert _get_port(fixtures.HTTP_HONEYPOT_LOGIN_ATTEMPT["_source"]) == 0

    def test_dionaea_incident_ip_and_port_stay_unset_because_payload_is_opaque(self):
        # honeypot.message is a raw JSON string (log_incident.py's actual
        # shape); there is no structured src_ip/dst_port here to read at all.
        src = fixtures.DIONAEA_INCIDENT_RAW["_source"]
        assert _get_ip(src) == ""
        assert _get_port(src) == 0


class TestTransportProtocolPerSource:
    """proto_enc (index 3) encodes transport layer (tcp/udp/icmp), not
    application protocol -- multipot's own `proto` field is application-layer
    ("vnc"/"redis"/"mysql"/...; confirmed by reading protocols.go directly),
    so _get_transport_proto() must not read it as-is."""

    def test_cowrie_infers_tcp_structurally_ssh_and_telnet_are_tcp_only(self):
        assert _get_transport_proto(fixtures.COWRIE_LOGIN_FAILED["_source"]) == "tcp"

    def test_http_honeypot_infers_tcp_structurally(self):
        assert _get_transport_proto(fixtures.HTTP_HONEYPOT_LOGIN_ATTEMPT["_source"]) == "tcp"

    def test_dionaea_reads_the_actual_transport_field_not_the_app_layer_one(self):
        src = fixtures.DIONAEA_CONNECTION_ACCEPT["_source"]
        assert src["honeypot"]["connection"]["protocol"] == "smbd"  # app-layer, must NOT be returned
        assert _get_transport_proto(src) == "tcp"                   # connection.transport, the real field

    def test_conpot_has_no_honest_transport_inference_available(self):
        # data_type ("modbus") is application-layer; Conpot's personas span
        # both TCP (Modbus/S7comm/HTTP) and UDP (SNMP) with nothing in the
        # event itself distinguishing which -- left unset rather than guessed.
        assert _get_transport_proto(fixtures.CONPOT_MODBUS_REQUEST["_source"]) is None

    def test_suricata_reads_the_ecs_promoted_transport_field(self):
        assert _get_transport_proto(fixtures.SURICATA_ALERT["_source"]) == "tcp"


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


class TestNetflowReflectedDirectionResolvesToTheRealRemoteParty:
    """#174: Suricata netflow logs both directions of a flow as separate
    records, so ECS source/destination reflect literal packet direction,
    not attacker/victim. Confirmed live against real production netflow
    docs: for the "reflected" record, source.ip is the honeypot's own
    public IP. ML_HOME_NET (parsed once into the module-level HOME_NET
    list) is how _get_ip()/_get_port() tell the two apart -- monkeypatched
    directly here since it's read at import time, not per-call."""

    # RFC 5737 documentation ranges, same convention vps/.env.example's own
    # SURICATA_HOME_NET example uses -- not this deployment's real address.
    HOME_IP = "203.0.113.10"
    ATTACKER_IP = "198.51.100.23"

    def _forward_doc(self):
        # Attacker -> us: the normal case, no swap needed.
        return {
            "source": {"ip": self.ATTACKER_IP, "port": 63000},
            "destination": {"ip": self.HOME_IP, "port": 445},
            "suricata": {"eve": {"event_type": "netflow"}},
        }

    def _reflected_doc(self):
        # Us -> attacker: same flow, other direction. Naive source/
        # destination reading would misattribute this to ourselves.
        return {
            "source": {"ip": self.HOME_IP, "port": 445},
            "destination": {"ip": self.ATTACKER_IP, "port": 63000},
            "suricata": {"eve": {"event_type": "netflow"}},
        }

    def test_without_home_net_configured_reflected_direction_is_trusted_as_is(self):
        # Documents the pre-fix/unconfigured behaviour: no ML_HOME_NET
        # means no way to know which side is "us", so the naive (wrong for
        # this one direction) reading is what callers get -- a safe no-op
        # default, not a crash or a guess.
        assert _get_ip(self._reflected_doc()) == self.HOME_IP
        assert _get_port(self._reflected_doc()) == 63000

    def test_forward_direction_unaffected_by_home_net(self, monkeypatch):
        monkeypatch.setattr(iso_mod, "HOME_NET", [ipaddress.ip_network(f"{self.HOME_IP}/32")])
        assert _get_ip(self._forward_doc()) == self.ATTACKER_IP
        assert _get_port(self._forward_doc()) == 445

    def test_reflected_direction_resolves_to_the_attacker_not_ourselves(self, monkeypatch):
        monkeypatch.setattr(iso_mod, "HOME_NET", [ipaddress.ip_network(f"{self.HOME_IP}/32")])
        assert _get_ip(self._reflected_doc()) == self.ATTACKER_IP
        # The port actually touched on OUR side is what matters for
        # unique_ports_1h -- that's source.port here (445), not
        # destination.port (63000, the attacker's own ephemeral port).
        assert _get_port(self._reflected_doc()) == 445

    def test_neither_side_matching_home_net_is_unaffected(self, monkeypatch):
        # Two external parties (shouldn't normally happen, but must not
        # misfire) -- no swap since source.ip isn't ours.
        monkeypatch.setattr(iso_mod, "HOME_NET", [ipaddress.ip_network("10.0.0.0/8")])
        assert _get_ip(self._forward_doc()) == self.ATTACKER_IP
        assert _get_port(self._forward_doc()) == 445
