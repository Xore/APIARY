#!/bin/sh
set -eu

es_url="${ELASTICSEARCH_URL:-http://elasticsearch:9200}"

until curl -fsS "$es_url/_cluster/health" >/dev/null; do
  sleep 2
done

curl -fsS -X PUT "$es_url/_snapshot/honeypot-fs" \
  -H 'Content-Type: application/json' \
  --data-binary '{"type":"fs","settings":{"location":"/snapshots","compress":true}}' >/dev/null

# Bounded retention prevents a noisy internet-wide scan or IDS signature from
# filling the homeserver disk. Daily Filebeat names already provide rollover;
# ILM handles deletion of the old daily indices/backing indices.
for spec in honeypot-30d:30d suricata-7d:7d dead-letter-60d:60d; do
  name=${spec%%:*}
  age=${spec#*:}
  curl -fsS -X PUT "$es_url/_ilm/policy/$name" \
    -H 'Content-Type: application/json' \
    --data-binary "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{}},\"delete\":{\"min_age\":\"$age\",\"actions\":{\"delete\":{}}}}}}" >/dev/null
done

# Geo enrichment is best-effort. Listener/startup events legitimately contain
# an empty source IP and must still be indexed rather than rejected.
curl -fsS -X PUT "$es_url/_ingest/pipeline/geoip-honeypot" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "description": "Geo + ASN enrichment for Suricata and honeypot events (local GeoLite2 files)",
  "processors": [
    {
      "script": {
        "lang": "painless",
        "ignore_failure": true,
        "source": "if (ctx.event == null) ctx.event = new HashMap(); if (ctx.source == null) ctx.source = new HashMap(); if (ctx.destination == null) ctx.destination = new HashMap(); if (ctx.network == null) ctx.network = new HashMap(); if (ctx.honeypot != null) { def h = ctx.honeypot; if (h.sensor != null) ctx.event.sensor = h.sensor; else if (h.eventid != null && h.eventid.toString().startsWith('cowrie.')) ctx.event.sensor = 'cowrie'; if (h.src_ip != null && h.src_ip != '') ctx.source.ip = h.src_ip; if (h.dst_ip != null && h.dst_ip != '') ctx.destination.ip = h.dst_ip; if (h.dst_port != null) ctx.destination.port = h.dst_port; else if (h.port != null) ctx.destination.port = h.port; if (h.proto != null) ctx.network.protocol = h.proto; if (h.username != null) { if (ctx.user == null) ctx.user = new HashMap(); ctx.user.name = h.username; } if (h.command != null || h.input != null) { if (ctx.process == null) ctx.process = new HashMap(); ctx.process.command_line = h.command != null ? h.command : h.input; } if (h.path != null) { if (ctx.url == null) ctx.url = new HashMap(); ctx.url.path = h.path; } if (h.shasum != null) { if (ctx.file == null) ctx.file = new HashMap(); if (ctx.file.hash == null) ctx.file.hash = new HashMap(); ctx.file.hash.sha256 = h.shasum; } if (h.category != null) ctx.event.category = h.category; } if (ctx.log != null && ctx.log.file != null && ctx.log.file.path != null) { String p = ctx.log.file.path; if (ctx.event.sensor == null && p.contains('/conpot')) { int a = p.indexOf('/conpot') + 1; int b = p.indexOf('/', a); ctx.event.sensor = b > a ? p.substring(a,b) : 'conpot'; } if (ctx.event.sensor != null && ctx.event.sensor.toString().startsWith('conpot')) { if (ctx.ot == null) ctx.ot = new HashMap(); ctx.ot.persona = ctx.event.sensor; } } if (ctx.suricata != null && ctx.suricata.eve != null) { def s = ctx.suricata.eve; ctx.event.sensor = 'suricata'; if (s.event_type != null) ctx.event.category = s.event_type; if (s.src_ip != null) ctx.source.ip = s.src_ip; if (s.dest_ip != null) ctx.destination.ip = s.dest_ip; if (s.dest_port != null) ctx.destination.port = s.dest_port; if (s.proto != null) ctx.network.transport = s.proto.toString().toLowerCase(); }"
      }
    },
    {
      "geoip": {
        "field": "suricata.eve.src_ip",
        "target_field": "source.geo",
        "database_file": "GeoLite2-City.mmdb",
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "suricata.eve.src_ip",
        "target_field": "source.as",
        "database_file": "GeoLite2-ASN.mmdb",
        "properties": ["asn", "organization_name"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "suricata.eve.dest_ip",
        "target_field": "destination.geo",
        "database_file": "GeoLite2-City.mmdb",
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "honeypot.src_ip",
        "target_field": "source.geo",
        "database_file": "GeoLite2-City.mmdb",
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "honeypot.src_ip",
        "target_field": "source.as",
        "database_file": "GeoLite2-ASN.mmdb",
        "properties": ["asn", "organization_name"],
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "script": {
        "lang": "painless",
        "ignore_failure": true,
        "source": "if (ctx.source != null && ctx.source.as != null && ctx.source.as.organization_name != null) { String o = ctx.source.as.organization_name.toLowerCase(); String t = 'network'; if (o.contains('censys') || o.contains('shadowserver') || o.contains('binaryedge') || o.contains('securitytrails') || o.contains('shodan')) t = 'scanner'; else if (o.contains('amazon') || o.contains('google cloud') || o.contains('microsoft') || o.contains('azure') || o.contains('digitalocean') || o.contains('oracle cloud') || o.contains('linode') || o.contains('vultr') || o.contains('cloudflare')) t = 'cloud'; else if (o.contains('hosting') || o.contains('server') || o.contains('datacenter') || o.contains('hetzner') || o.contains('ovh') || o.contains('leaseweb')) t = 'hosting'; ctx.source.as.type = t; }"
      }
    }
  ]
}
JSON

echo

# Sensor formats are intentionally heterogeneous. Mapping the complete source
# object as `flattened` keeps every key/value searchable without allowing one
# sensor's value type to reject another sensor's event.
curl -fsS -X PUT "$es_url/_index_template/honeypot-events-v2" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["honeypot-v2-*"],
  "priority": 500,
  "data_stream": {},
  "template": {
    "settings": {
      "index.default_pipeline": "geoip-honeypot",
      "index.lifecycle.name": "honeypot-30d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 2000,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "honeypot": { "type": "flattened" },
        "sensor": { "type": "keyword" },
        "event_format": { "type": "keyword" },
        "logset": { "type": "keyword" },
        "event": { "properties": { "sensor": { "type": "keyword" }, "category": { "type": "keyword" }, "kind": { "type": "keyword" } } },
        "source": { "properties": {
          "ip": { "type": "ip", "ignore_malformed": true },
          "geo": { "properties": { "location": { "type": "geo_point" }, "country_iso_code": { "type": "keyword" }, "city_name": { "type": "keyword" } } },
          "as": { "properties": { "asn": { "type": "long" }, "organization_name": { "type": "keyword" }, "type": { "type": "keyword" } } }
        } },
        "destination": { "properties": { "ip": { "type": "ip", "ignore_malformed": true }, "port": { "type": "integer", "ignore_malformed": true } } },
        "network": { "properties": { "transport": { "type": "keyword" }, "protocol": { "type": "keyword" } } },
        "user": { "properties": { "name": { "type": "keyword" } } },
        "process": { "properties": { "command_line": { "type": "wildcard" } } },
        "url": { "properties": { "path": { "type": "wildcard" } } },
        "file": { "properties": { "hash": { "properties": { "sha256": { "type": "keyword" } } } } },
        "ot": { "properties": { "persona": { "type": "keyword" }, "protocol": { "type": "keyword" } } }
      }
    }
  }
}
JSON

# Suricata's protocol-specific daily indices can be high volume. Keep their
# mappings permissive but bounded, and retain seven days of raw IDS telemetry.
curl -fsS -X PUT "$es_url/_index_template/suricata-events" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["suricata-*"],
  "priority": 400,
  "template": {
    "settings": {
      "index.default_pipeline": "geoip-honeypot",
      "index.lifecycle.name": "suricata-7d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 5000,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "10s"
    },
    "mappings": { "properties": {
      "event": { "properties": { "sensor": { "type": "keyword" }, "category": { "type": "keyword" } } },
      "source": { "properties": {
        "ip": { "type": "ip", "ignore_malformed": true },
        "geo": { "properties": { "location": { "type": "geo_point" }, "country_iso_code": { "type": "keyword" }, "city_name": { "type": "keyword" } } },
        "as": { "properties": { "asn": { "type": "long" }, "organization_name": { "type": "keyword" }, "type": { "type": "keyword" } } }
      } },
      "destination": { "properties": {
        "ip": { "type": "ip", "ignore_malformed": true },
        "port": { "type": "integer", "ignore_malformed": true },
        "geo": { "properties": { "location": { "type": "geo_point" }, "country_iso_code": { "type": "keyword" }, "city_name": { "type": "keyword" } } }
      } },
      "network": { "properties": { "transport": { "type": "keyword" }, "protocol": { "type": "keyword" } } }
    } }
  }
}
JSON

# #166: destination.geo.location was previously left to dynamic mapping here
# (unlike source.geo.location just above), so it came in as a plain
# {lat,lon} float object instead of geo_point on every live suricata-*
# index -- destination-side geo queries/map visualizations silently
# couldn't use it. A separate, untracked template ('suricata-field-limit',
# lower priority, never applied) had the correct destination.geo.location
# mapping and nothing else useful; folded that fix in here instead of
# keeping two templates for one setting. Existing indices keep their old
# dynamic mapping until suricata-7d ILM rolls them off; only new indices
# pick this up.

curl -fsS -X PUT "$es_url/_index_template/honeypot-dead-letter" \
  -H 'Content-Type: application/json' \
  --data-binary '{"index_patterns":["dead-letter-honeypot*"],"priority":450,"template":{"settings":{"index.lifecycle.name":"dead-letter-60d","index.number_of_replicas":0}}}' >/dev/null

# Adopt indices created before this policy was introduced. A missing wildcard
# is harmless on a fresh installation.
curl -fsS -X PUT "$es_url/suricata-*/_settings?allow_no_indices=true" \
  -H 'Content-Type: application/json' \
  -d '{"index.lifecycle.name":"suricata-7d"}' >/dev/null || true
curl -fsS -X PUT "$es_url/.ds-honeypot-v2-*/_settings?allow_no_indices=true&expand_wildcards=all" \
  -H 'Content-Type: application/json' \
  -d '{"index.lifecycle.name":"honeypot-30d"}' >/dev/null || true

# This is intentionally a single-node analysis cluster. Replica shards cannot
# be allocated here and only make cluster health yellow; primaries retain data.
curl -fsS -X PUT "$es_url/_all/_settings?expand_wildcards=all" \
  -H 'Content-Type: application/json' \
  -d '{"index.number_of_replicas":0}' >/dev/null || true

echo
echo "elasticsearch-setup: GeoIP, retention policies, and event templates installed"
