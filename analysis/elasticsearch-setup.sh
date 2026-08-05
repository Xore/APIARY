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
# filling the homeserver disk. Daily Filebeat names already provide rollover
# for suricata/portbridge/dead-letter/analysis-results (a fresh, plain
# date-named index each day -- see analysis/filebeat.yml's output.elasticsearch
# indices routing); ILM only has to delete the old ones once they age out.
# honeypot-30d is deliberately NOT in this loop -- see the #585 block below
# for why it needs a real rollover action instead of this delete-only shape.
#
# #261: every retention window in this stack (these ILM policies, the
# on-disk JSON retention in log-maintenance.sh/suricata-log-maintenance.sh/
# portbridge-log-maintenance.sh, and BISTREAMS_RETENTION_DAYS in
# dedupe-payloads.py) derives its default from this one operator-facing
# knob, T-Pot-style, instead of each hardcoding its own number. Ratios below
# match this stack's previous independent defaults (7d/30d, 60d/30d,
# 180d/30d) so a plain default deploy behaves exactly as before; an operator
# who sets HONEYPOT_RETENTION_DAYS scales every window at once.
#
# Policy *names* stay fixed (suricata-7d etc.) even though the actual
# min_age they enforce is now dynamic -- they are stable ILM policy
# identifiers referenced by index templates elsewhere in this file, not a
# literal claim about the configured duration.
retention_days="${HONEYPOT_RETENTION_DAYS:-30}"
suricata_days=$(( retention_days * 7 / 30 ))
[ "$suricata_days" -ge 1 ] || suricata_days=1
for spec in "suricata-7d:${suricata_days}d" \
            "dead-letter-60d:$(( retention_days * 2 ))d" "portbridge-30d:${retention_days}d" \
            "analysis-results-180d:$(( retention_days * 6 ))d"; do
  name=${spec%%:*}
  age=${spec#*:}
  curl -fsS -X PUT "$es_url/_ilm/policy/$name" \
    -H 'Content-Type: application/json' \
    --data-binary "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{}},\"delete\":{\"min_age\":\"$age\",\"actions\":{\"delete\":{}}}}}}" >/dev/null
done

# #585: honeypot-30d is the one policy attached to a real ILM-managed data
# stream (honeypot-events-v2's own template below, "data_stream": {}) rather
# than a plain Filebeat date-named index -- confirmed live against a real
# Elasticsearch instance that without an explicit rollover action in the hot
# phase, ILM will not (structurally cannot) delete a data stream's write
# index, since a write index can only be removed after it has rolled over.
# With hot.actions empty (this policy's shape before this fix), the delete
# phase gets permanently stuck at "wait-for-shard-history-leases" and the
# single backing index grows unbounded forever -- the 30-day retention this
# policy is supposed to enforce did nothing at all. Daily rollover matches
# suricata-7d/portbridge-30d's own per-day cadence above (they get a new
# index each day from Filebeat's date-named pattern instead); 25gb is a
# secondary safety trigger so an unusually heavy single day still rolls
# rather than growing one shard past a healthy size.
curl -fsS -X PUT "$es_url/_ilm/policy/honeypot-30d" \
  -H 'Content-Type: application/json' \
  --data-binary '{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"1d","max_primary_shard_size":"25gb"}}},"delete":{"min_age":"30d","actions":{"delete":{}}}}}}' >/dev/null

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
        "source": "if (ctx.event == null) ctx.event = new HashMap(); if (ctx.source == null) ctx.source = new HashMap(); if (ctx.destination == null) ctx.destination = new HashMap(); if (ctx.network == null) ctx.network = new HashMap(); if (ctx.honeypot != null) { def h = ctx.honeypot; if (h.sensor != null) ctx.event.sensor = h.sensor; else if (h.eventid != null && h.eventid.toString().startsWith('cowrie.')) ctx.event.sensor = 'cowrie'; if (h.src_ip != null && h.src_ip != '') ctx.source.ip = h.src_ip; if (h.dst_ip != null && h.dst_ip != '') ctx.destination.ip = h.dst_ip; if (h.dst_port != null) ctx.destination.port = h.dst_port; else if (h.port != null) ctx.destination.port = h.port; if (h.proto != null) ctx.network.protocol = h.proto; else if (h.protocol != null) ctx.network.protocol = h.protocol; else if (h.data_type != null) ctx.network.protocol = h.data_type; if (h.username != null) { if (ctx.user == null) ctx.user = new HashMap(); ctx.user.name = h.username; } if (h.command != null || h.input != null) { if (ctx.process == null) ctx.process = new HashMap(); ctx.process.command_line = h.command != null ? h.command : h.input; } if (h.path != null) { if (ctx.url == null) ctx.url = new HashMap(); ctx.url.path = h.path; } else if (h.url != null) { if (ctx.url == null) ctx.url = new HashMap(); ctx.url.path = h.url; } if (h.shasum != null) { if (ctx.file == null) ctx.file = new HashMap(); if (ctx.file.hash == null) ctx.file.hash = new HashMap(); ctx.file.hash.sha256 = h.shasum; } if (h.category != null) ctx.event.category = h.category; } if (ctx.log != null && ctx.log.file != null && ctx.log.file.path != null) { String p = ctx.log.file.path; if (ctx.event.sensor == null && p.contains('/conpot')) { int a = p.indexOf('/conpot') + 1; int b = p.indexOf('/', a); if (b > a) { ctx.event.sensor = p.substring(a, b); } else { String base = p.substring(a); ctx.event.sensor = base.endsWith('.json') ? base.substring(0, base.length() - 5) : base; } } if (ctx.event.sensor == null && p.contains('/dionaea')) { ctx.event.sensor = 'dionaea'; } if (ctx.event.sensor != null && ctx.event.sensor.toString().startsWith('conpot')) { if (ctx.ot == null) ctx.ot = new HashMap(); ctx.ot.persona = ctx.event.sensor; } } if (ctx.suricata != null && ctx.suricata.eve != null) { def s = ctx.suricata.eve; ctx.event.sensor = 'suricata'; if (s.event_type != null) ctx.event.category = s.event_type; if (s.src_ip != null) ctx.source.ip = s.src_ip; if (s.dest_ip != null) ctx.destination.ip = s.dest_ip; if (s.dest_port != null) ctx.destination.port = s.dest_port; if (s.proto != null) ctx.network.transport = s.proto.toString().toLowerCase(); } if (ctx.portbridge != null) { def pb = ctx.portbridge; ctx.event.sensor = 'portbridge'; ctx.event.category = pb.event != null ? pb.event.toString() : 'connect'; if (pb.src_ip != null && pb.src_ip != '') ctx.source.ip = pb.src_ip; if (pb.port != null) ctx.destination.port = pb.port; if (pb.proto != null) ctx.network.transport = pb.proto; }"
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
      "geoip": {
        "field": "portbridge.src_ip",
        "target_field": "source.geo",
        "database_file": "GeoLite2-City.mmdb",
        "ignore_missing": true,
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "portbridge.src_ip",
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
        "description": "#354: dionaea's captured-payload hash only exists inside dionaea_incident.json's raw message text -- that input is deliberately kept unparsed by filebeat (different incident origins reuse the same data keys with incompatible value types, and dynamically expanding them caused Elasticsearch mapping rejections; see filebeat.yml's dionaea-incidents-raw-v1 comment). Rather than parsing the whole heterogeneous document, this pulls out only a hash-shaped value by plain string scanning (no Painless regex, which is disabled by default) -- sha256/sha256hash preferred (64 hex chars), md5hash/md5 as the fallback dionaea actually emits today (32 hex chars). A trailing closing-quote check guards against matching a decoy substring or a truncated value.",
        "source": "if (ctx.message != null) { String msg = ctx.message; String key = null; int hashLen = 0; boolean isMd5 = false; if (msg.indexOf('\"sha256\"') >= 0) { key = '\"sha256\"'; hashLen = 64; } else if (msg.indexOf('\"sha256hash\"') >= 0) { key = '\"sha256hash\"'; hashLen = 64; } else if (msg.indexOf('\"md5hash\"') >= 0) { key = '\"md5hash\"'; hashLen = 32; isMd5 = true; } else if (msg.indexOf('\"md5\"') >= 0) { key = '\"md5\"'; hashLen = 32; isMd5 = true; } if (key != null) { int i = msg.indexOf(key) + key.length(); while (i < msg.length() && (msg.charAt(i) == (char)' ' || msg.charAt(i) == (char)':')) { i++; } if (i < msg.length() && msg.charAt(i) == (char)'\"') { i++; if (i + hashLen <= msg.length()) { String candidate = msg.substring(i, i + hashLen); boolean valid = true; for (int j = 0; j < candidate.length(); j++) { char c = candidate.charAt(j); if (!((c >= (char)'0' && c <= (char)'9') || (c >= (char)'a' && c <= (char)'f') || (c >= (char)'A' && c <= (char)'F'))) { valid = false; break; } } if (valid && i + hashLen < msg.length() && msg.charAt(i + hashLen) == (char)'\"') { if (ctx.file == null) ctx.file = new HashMap(); if (ctx.file.hash == null) ctx.file.hash = new HashMap(); if (isMd5) { ctx.file.hash.md5 = candidate.toLowerCase(); } else { ctx.file.hash.sha256 = candidate.toLowerCase(); } } } } } }"
      }
    },
    {
      "script": {
        "lang": "painless",
        "ignore_failure": true,
        "source": "if (ctx.source != null && ctx.source.as != null && ctx.source.as.organization_name != null) { String o = ctx.source.as.organization_name.toLowerCase(); String t = 'network'; if (o.contains('censys') || o.contains('shadowserver') || o.contains('binaryedge') || o.contains('securitytrails') || o.contains('shodan')) t = 'scanner'; else if (o.contains('amazon') || o.contains('google cloud') || o.contains('microsoft') || o.contains('azure') || o.contains('digitalocean') || o.contains('oracle cloud') || o.contains('linode') || o.contains('vultr') || o.contains('cloudflare')) t = 'cloud'; else if (o.contains('hosting') || o.contains('server') || o.contains('datacenter') || o.contains('hetzner') || o.contains('ovh') || o.contains('leaseweb')) t = 'hosting'; ctx.source.as.type = t; }"
      }
    },
    {
      "script": {
        "lang": "painless",
        "ignore_failure": true,
        "description": "#238/#416: flags JNDI/Log4Shell injection attempts across every sensor's captured free-text fields (concatenates every string value under honeypot.*, so this covers path/body/user_agent/headers/command/etc. uniformly without hardcoding field names per sensor -- automatically covers future sensors too). Deobfuscates Log4j lookup-based evasion first (nested lookup tricks like lower:j + ndi splitting the word jndi across sub-expressions, which a naive substring check for the literal jndi prefix would miss) -- ported from Log4Pot's deobfuscator.py (detection only, not its payloader.py, which actively downloads the attacker's LDAP/RMI callback payload; that outbound fetch is a distinct, larger decision out of scope here). depth is a hard recursion cap (25) and blob length is capped at 8192 chars -- both defend against a crafted pathological input causing runaway recursion/allocation on the ingest node, which the original Python implementation does not bound.",
        "source": "String deobfuscate(String expr, int depth) { if (depth > 25) { return expr; } if (expr.startsWith('${')) { int posEnd = expr.indexOf('}'); if (posEnd == -1) { return expr; } int posLookup = expr.indexOf('${', 2); if (posLookup != -1 && posLookup < posEnd) { return deobfuscate(expr.substring(0, posLookup) + deobfuscate(expr.substring(posLookup, posEnd + 1), depth + 1) + deobfuscate(expr.substring(posEnd + 1), depth + 1), depth + 1); } int posColon = expr.indexOf(':'); if (posColon == -1) { return expr; } String lookupType = expr.substring(2, posColon).toLowerCase(); int posValue = -1; int posValueRaw = expr.indexOf(':-'); if (posValueRaw != -1) { posValue = posValueRaw + 2; } if (lookupType.equals('jndi')) { return '${jndi' + expr.substring(6); } if (lookupType.equals('lower')) { return expr.substring(posColon + 1, posEnd).toLowerCase() + deobfuscate(expr.substring(posEnd + 1), depth + 1); } if (lookupType.equals('upper')) { return expr.substring(posColon + 1, posEnd).toUpperCase() + deobfuscate(expr.substring(posEnd + 1), depth + 1); } if (posValue != -1 && posValue < posEnd) { return expr.substring(posValue, posEnd) + deobfuscate(expr.substring(posEnd + 1), depth + 1); } return expr.substring(posColon + 1, posEnd) + deobfuscate(expr.substring(posEnd + 1), depth + 1); } int posExpr = expr.indexOf('${'); if (posExpr == -1) { return expr; } return expr.substring(0, posExpr) + deobfuscate(expr.substring(posExpr), depth + 1); } if (ctx.honeypot != null) { StringBuilder sb = new StringBuilder(); for (def v : ctx.honeypot.values()) { if (v instanceof String) { sb.append((String) v).append(' '); } } String blob = sb.toString(); if (blob.length() > 0 && blob.length() < 8192 && blob.indexOf('${') >= 0) { String result = deobfuscate(blob, 0); if (result.toLowerCase().indexOf('${jndi:') >= 0) { if (ctx.event == null) { ctx.event = new HashMap(); } ctx.event.log4shell = true; } } }"
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
        "file": { "properties": { "hash": { "properties": { "sha256": { "type": "keyword" }, "md5": { "type": "keyword" } } } } },
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

# #354: portbridge tunnel-connection records (real attacker IP, honeypot
# port, p0f OS guess), shipped to ES for the first time -- previously
# local-disk-only (dashboard/classify.go's buildViaMap). The geoip-honeypot
# pipeline's normalization script promotes portbridge.src_ip into the same
# source.ip / event.sensor ECS envelope honeypot-v2-* and suricata-* use, so
# a single query across honeypot-v2-*,suricata-*,portbridge-v2-* for one
# source.ip returns every correlated record for that IP in one pass -- no
# per-index-family join needed. Plain daily indices like suricata-events
# (not a data stream like honeypot-events-v2): portbridge's volume doesn't
# need rollover, and this keeps the simpler index-per-day model.
curl -fsS -X PUT "$es_url/_index_template/portbridge-events" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["portbridge-v2-*"],
  "priority": 470,
  "template": {
    "settings": {
      "index.default_pipeline": "geoip-honeypot",
      "index.lifecycle.name": "portbridge-30d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 200,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "portbridge": { "type": "flattened" },
        "event": { "properties": { "sensor": { "type": "keyword" }, "category": { "type": "keyword" } } },
        "source": { "properties": {
          "ip": { "type": "ip", "ignore_malformed": true },
          "geo": { "properties": { "location": { "type": "geo_point" }, "country_iso_code": { "type": "keyword" }, "city_name": { "type": "keyword" } } },
          "as": { "properties": { "asn": { "type": "long" }, "organization_name": { "type": "keyword" }, "type": { "type": "keyword" } } }
        } },
        "destination": { "properties": { "port": { "type": "integer", "ignore_malformed": true } } },
        "network": { "properties": { "transport": { "type": "keyword" } } }
      }
    }
  }
}
JSON

# #565: dionaea's log_incident ihandler (dionaea_incident.json) -- every
# exploit/download/credential/lifecycle incident dionaea's core emits,
# across every enabled service (SMB/SIP/UPnP/TFTP/etc). Confirmed directly
# against upstream dionaea/lib/dionaea/python/dionaea/log_incident.py's
# handle_incident(): every record is exactly {timestamp, name, origin,
# data} -- the first three consistent across every incident, `data` not
# (different origins reuse the same keys with incompatible value types,
# the reason analysis/filebeat.yml previously left this whole stream as an
# opaque `message` string). Same flattened-for-heterogeneous-keys approach
# honeypot-events-v2's own `honeypot` field already uses, so `data` becomes
# queryable/aggregatable (data.url:*, data.shasum, ...) without a mapping
# explosion. Own index (not folded into honeypot-v2-*): a different record
# shape entirely (top-level origin/data, not the honeypot.* envelope every
# other sensor writes), and dashboard/classify.go's own dionaea-incident
# handler (~line 427) reads this file directly off disk, unaffected either
# way -- this is purely an additive ES-only path. Plain daily indices, not
# a data stream, same reasoning as portbridge-events above.
curl -fsS -X PUT "$es_url/_index_template/dionaea-incidents" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "index_patterns": ["dionaea-incidents-v1-*"],
  "priority": 465,
  "template": {
    "settings": {
      "index.lifecycle.name": "honeypot-30d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 200,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "timestamp": { "type": "date" },
        "name": { "type": "keyword" },
        "origin": { "type": "keyword" },
        "data": { "type": "flattened" }
      }
    }
  }
}
JSON

# #378: Ghidra/sandbox/GitHub-analysis/workbench-run results, ingested by
# analysis/es-results-importer/importer.py (previously local-disk-only JSON
# files, per the issue's gap analysis). Each result document is heterogeneous
# and fairly deep (Ghidra alone has functions/capa/floss/lief/revdeck
# sub-objects), so -- same call as honeypot-events-v2's `honeypot` field --
# the full result is mapped `flattened` under a source-namespaced field
# rather than hand-mapping every nested key, and only the handful of fields
# actually needed for filtering/sorting/cross-index correlation are promoted
# to real types. file.hash.sha256 uses the same ECS field
# honeypot-events-v2 already populates from Dionaea's shasum, so a single
# query across honeypot-v2-*,ghidra-analysis-v1,sandbox-analysis-v1,
# github-analysis-v1 for one hash returns the raw capture event and every
# analysis result for that sample in one pass. 180d retention (not 30d like
# raw events): a completed analysis report is the valuable, expensive-to-
# regenerate artifact, not high-volume raw telemetry. Plain single indices,
# not data streams -- importer overwrites by deterministic _id (sha256, job
# id, or run id) rather than appending, so there is nothing to roll over.
#
# ignore_above on the flattened field: found live (2026-08-02) importing real
# sandbox results -- flattened stores each leaf value as a Lucene keyword
# term, and sandbox.stdout/runner_log routinely carry multi-KB dmesg/boot
# output past Lucene's 32766-byte term limit, which fails the *entire*
# document, not just that one leaf, unlike honeypot-events-v2's `honeypot`
# field (short per-sensor values only, never hit this). ignore_above makes
# ES skip indexing (not storing) an overlong leaf instead -- still present
# and returned in _source/the document view, just not term-searchable.
for spec in \
  "ghidra-analysis-v1:ghidra" \
  "sandbox-analysis-v1:sandbox" \
  "github-analysis-v1:github_analysis" \
  "workbench-runs-v1:workbench"
do
  index_name=${spec%%:*}
  ns=${spec#*:}
  curl -fsS -X PUT "$es_url/_index_template/${index_name%-v1}" \
    -H 'Content-Type: application/json' \
    --data-binary "$(cat <<JSON
{
  "index_patterns": ["${index_name}"],
  "priority": 460,
  "template": {
    "settings": {
      "index.lifecycle.name": "analysis-results-180d",
      "index.number_of_replicas": 0,
      "index.mapping.total_fields.limit": 500,
      "index.mapping.ignore_malformed": true,
      "index.refresh_interval": "30s"
    },
    "mappings": {
      "properties": {
        "${ns}": { "type": "flattened", "ignore_above": 32000 },
        "@timestamp": { "type": "date" },
        "event": { "properties": { "category": { "type": "keyword" } } },
        "file": { "properties": { "hash": { "properties": { "sha256": { "type": "keyword" } } } } },
        "exit_status": { "type": "keyword" },
        "risk_level": { "type": "keyword" },
        "risk_score": { "type": "integer", "ignore_malformed": true },
        "family": { "type": "keyword" },
        "platform": { "type": "keyword" }
      }
    }
  }
}
JSON
)" >/dev/null
done

# #494: dashboard-owned operational alert-rule state (campaign detection,
# stale sensor feeds, activity spikes, ES pipeline health, OT command
# detection, YARA hits, sandbox failures -- ack/cooldown bookkeeping, not
# sensor telemetry). Written directly by the dashboard itself via
# doc-level PUT (dashboard/elastic.go's docGet/docIndex), not through the
# Python importer's flattened-namespace pattern the analysis-results
# indices above use -- the whole small, low-cardinality record is mapped at
# the top level. No ILM policy: this is bookkeeping an operator's
# acknowledgment should not silently expire out from under them, and the
# record count is bounded by how many distinct alert keys the stack
# produces (dozens, not millions), not by event volume.
curl -fsS -X PUT "$es_url/_index_template/dashboard-alert-state" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-alert-state-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "1s"
    },
    "mappings": {
      "properties": {
        "Key": { "type": "keyword" },
        "Message": { "type": "text" },
        "Link": { "type": "keyword" },
        "FirstSeen": { "type": "date" },
        "LastSeen": { "type": "date" },
        "LastNotified": { "type": "date" },
        "Count": { "type": "integer" },
        "Acknowledged": { "type": "boolean" }
      }
    }
  }
}' >/dev/null

# Static-analysis cache (payload_analysis.go's staticAnalysisFor): the pure-
# function-of-bytes half of a payload's analysis (hashes, entropy, extracted
# strings/IOCs, static risk score) -- content-hash keyed and immutable once
# written (the same bytes always produce the same analysis), unlike
# dashboard-alert-state-v1's mutable ack/cooldown records above, so this
# needs no seq_no/if_match update path, only get-or-create. Bounded by
# docIndexMaxBytes (2MB, dashboard/elastic.go) at write time -- this holds a
# capped preview/string-extraction summary, never raw payload bytes.
curl -fsS -X PUT "$es_url/_index_template/dashboard-static-analysis" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-static-analysis-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "30s",
      "index.mapping.total_fields.limit": 200
    },
    "mappings": {
      "properties": {
        "Fingerprint": { "type": "keyword" },
        "Analysis": {
          "properties": {
            "SHA256": { "type": "keyword" },
            "MD5": { "type": "keyword" },
            "SHA1": { "type": "keyword" },
            "MIME": { "type": "keyword" },
            "ScriptType": { "type": "keyword" },
            "StaticRiskLevel": { "type": "keyword" },
            "StaticRiskScore": { "type": "integer" },
            "EntropyValue": { "type": "float" },
            "PackedLikely": { "type": "boolean" },
            "Truncated": { "type": "boolean" }
          }
        }
      }
    }
  }
}' >/dev/null

# Payload inventory (#483, payloads_data.go's scanPayloads/indexPayloadInventory):
# Elasticsearch is now the sole source /payloads reads from -- no local
# disk-scan fallback (see payloadInventoryIndex's own comment in
# payloads_data.go). Documents are the same capturedFile shape scanPayloads
# has always built, keyed by hash; Preview is a hex-dump of a capped 512-byte
# head, never raw payload bytes, backstopped by docIndexMaxBytes at write
# time. Every dashboard instance's own periodic disk scan indexes into this
# same index, so mount-path differences between instances don't affect what
# any instance serves.
curl -fsS -X PUT "$es_url/_index_template/dashboard-payload-inventory" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-payload-inventory-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "30s",
      "index.mapping.total_fields.limit": 200
    },
    "mappings": {
      "properties": {
        "Hash": { "type": "keyword" },
        "Size": { "type": "long" },
        "Mtime": { "type": "keyword" },
        "MIME": { "type": "keyword" },
        "Kind": { "type": "keyword" },
        "KindCode": { "type": "keyword" },
        "Platform": { "type": "keyword" },
        "Dynamic": { "type": "boolean" },
        "Sources": { "type": "keyword" },
        "Copies": { "type": "integer" },
        "PreviewTruncated": { "type": "boolean" }
      }
    }
  }
}' >/dev/null

# Generated PDF reports (#475, reports_es.go): metadata plus the base64-
# encoded PDF bytes itself, so any dashboard instance can serve a
# previously generated report regardless of which instance produced it --
# unlike the payload/static-analysis indices above, this one legitimately
# stores a real binary artifact (a dashboard-generated document, not raw
# captured malware), hence the larger per-document size expectation
# (docIndexSized's own generatedReportMaxBytes cap, not the blanket 2MB
# docIndexMaxBytes bookkeeping-record guard). No ILM: retention is enforced
# by application-level pruning (reportStore.maxGenerated) instead of age,
# since an operator may want to keep an old report much longer than a fixed
# window suggests.
curl -fsS -X PUT "$es_url/_index_template/dashboard-generated-reports" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-generated-reports-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "1s",
      "index.mapping.total_fields.limit": 50
    },
    "mappings": {
      "properties": {
        "id": { "type": "keyword" },
        "definition_id": { "type": "keyword" },
        "name": { "type": "text" },
        "template": { "type": "keyword" },
        "theme": { "type": "keyword" },
        "title": { "type": "text" },
        "size_bytes": { "type": "long" },
        "created_at": { "type": "date" },
        "origin": { "type": "keyword" },
        "pdf_base64": { "type": "binary" }
      }
    }
  }
}' >/dev/null

# Payload Workbench runs (#405 follow-up, workbench_es.go): the run's own
# document ID IS its idempotency key (workbenchIdempotency's deterministic
# hash of payload+recipe+analyzer selection, prefixed "run_"), so a duplicate
# submission is detected by an ES op_type=create 409 rather than a directory
# scan -- correct across multiple dashboard instances, unlike the single-
# process mutex this replaced. Mutable after creation (children transition
# queued -> running -> completed as async analyzers report back), so updates
# go through docGet/docIndex with if_seq_no/if_primary_term CAS, not create-
# only. No ILM: retention is enforced by workbenchMaxRuns at submission time,
# not by age.
curl -fsS -X PUT "$es_url/_index_template/dashboard-workbench-runs" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-workbench-runs-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "1s",
      "index.mapping.total_fields.limit": 200
    },
    "mappings": {
      "properties": {
        "schema_version": { "type": "integer" },
        "id": { "type": "keyword" },
        "payload_sha256": { "type": "keyword" },
        "payload_kind": { "type": "keyword" },
        "owner": { "type": "keyword" },
        "recipe_id": { "type": "keyword" },
        "recipe_revision": { "type": "integer" },
        "recipe_name": { "type": "keyword" },
        "idempotency_key": { "type": "keyword" },
        "state": { "type": "keyword" },
        "created_at": { "type": "date" },
        "updated_at": { "type": "date" },
        "children": {
          "properties": {
            "analyzer_id": { "type": "keyword" },
            "display_name": { "type": "keyword" },
            "state": { "type": "keyword" },
            "reason": { "type": "text" },
            "summary": { "type": "text" },
            "result_url": { "type": "keyword" },
            "created_at": { "type": "date" },
            "updated_at": { "type": "date" },
            "deadline": { "type": "date" },
            "queue_deadline": { "type": "date" },
            "attempts": { "type": "integer" },
            "retryable": { "type": "boolean" },
            "cancelable": { "type": "boolean" },
            "detonates": { "type": "boolean" },
            "gpu_consuming": { "type": "boolean" },
            "local_only": { "type": "boolean" },
            "stale": { "type": "boolean" }
          }
        }
      }
    }
  }
}' >/dev/null

# Payload Workbench recipes (#405 follow-up, workbench_es.go): each revision
# is its own immutable ES document keyed "<id>:<revision>" and written with
# op_type=create, so a genuine race on the same revision number conflicts
# instead of silently overwriting -- revisions are append-only, never
# mutated in place. No ILM: an operator's saved recipe should not silently
# expire.
curl -fsS -X PUT "$es_url/_index_template/dashboard-workbench-recipes" \
  -H 'Content-Type: application/json' \
  --data-binary '{
  "index_patterns": ["dashboard-workbench-recipes-v1"],
  "priority": 460,
  "template": {
    "settings": {
      "index.number_of_replicas": 0,
      "index.refresh_interval": "1s",
      "index.mapping.total_fields.limit": 200
    },
    "mappings": {
      "properties": {
        "schema_version": { "type": "integer" },
        "id": { "type": "keyword" },
        "revision": { "type": "integer" },
        "name": { "type": "keyword" },
        "description": { "type": "text" },
        "owner": { "type": "keyword" },
        "scope": { "type": "keyword" },
        "created_at": { "type": "date" },
        "analyzers": {
          "properties": {
            "analyzer_id": { "type": "keyword" },
            "options": {
              "properties": {
                "timeout_seconds": { "type": "integer" },
                "max_queue_age_seconds": { "type": "integer" },
                "retry_limit": { "type": "integer" }
              }
            }
          }
        }
      }
    }
  }
}' >/dev/null

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
