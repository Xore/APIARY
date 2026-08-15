package main

import (
	"encoding/json"
	"strconv"
)

// enrichBeelzebubLine handles beelzebub.json, which has no field in common
// with enrichLine's src_ip/src_port shape. Two gaps, both closed here
// instead of by patching config, since beelzebub is run unmodified,
// config-only (beelzebub/configurations/):
//
//  1. Every logrus line beelzebub's own standardOutStrategy writes
//     (internal/builder/director.go) nests the actual tracer.Event under a
//     top-level "event" key, alongside its own "level"/"msg"/"status" --
//     confirmed by actually running the pinned binary and inspecting real
//     output, not by reading tracer.go's struct definition in isolation
//     (which is what the first draft of this file did, and got wrong: it
//     assumed SourceIp/SourcePort/Protocol/etc. were top-level keys, which
//     silently break every line's IP resolution). event.SourceIp/
//     event.SourcePort are the tunnel peer address (both strings,
//     PascalCase, no json tags -- upstream's own Go field names verbatim).
//  2. Nothing in the line names this repo's sensors at all -- upstream
//     doesn't know about that convention.
//
// Three things happen on every line, independent of each other:
//  1. event.SourceIp is rewritten to the real attacker IP when it's
//     currently the tunnel peer and event.SourcePort resolves against vm
//     (same join as enrichLine, just reaching one level deeper).
//  2. A flat top-level src_ip/src_port pair mirroring the (possibly
//     just-rewritten) event.SourceIp/SourcePort is added -- geoip-honeypot's
//     ingest pipeline (analysis/elasticsearch-setup.sh) only ever promotes
//     h.src_ip at honeypot.* top level, never something nested three levels
//     deep, so without this every beelzebub event would keep the tunnel
//     peer as source.ip in Elasticsearch even after a successful join.
//  3. sensor/protocol/username/command/path are added as flat top-level
//     lowercase fields dashboard/classify.go's beelzebub block and the
//     geoip pipeline both read, mirrored from event.Protocol/User/Command/
//     RequestURI -- RequestURI is empty for every non-HTTP protocol, which
//     is fine, path is simply omitted then (falls through classify.go's
//     default case).
//
// No destination-port field: beelzebub's Event carries no listen-port of
// its own (confirmed directly against tracer.go -- Protocol is the only
// per-service identifier it logs), so unlike every hand-written sensor in
// this repo, a beelzebub event's dst_port cannot be recovered from the log
// line alone. Documented gap, not silently papered over -- closing it
// needs a small upstream-facing patch (an extra field on Event), the same
// vendor-and-extend precedent as dionaea/log_rotation_patch.py, not
// something ip-enrichment-worker can fix from outside the process.
func enrichBeelzebubLine(line []byte, vm viaMap, tftpVM viaMap, persona string) (out []byte, resolved bool) {
	var e map[string]any
	if err := json.Unmarshal(line, &e); err != nil {
		return line, true // unparseable: nothing to retry, pass through as-is
	}
	ev, ok := e["event"].(map[string]any)
	if !ok {
		return line, true // not a standardOutStrategy "New Event" line (e.g. a startup/error log) -- nothing to enrich
	}

	changed := false

	if s, ok := ev["Protocol"].(string); ok && s != "" {
		if e["sensor"] != "beelzebub" {
			e["sensor"] = "beelzebub"
			changed = true
		}
		if e["protocol"] != s {
			e["protocol"] = s
			changed = true
		}
	}
	for srcKey, dstKey := range map[string]string{"User": "username", "Command": "command", "RequestURI": "path"} {
		if v, ok := ev[srcKey].(string); ok && v != "" && e[dstKey] != v {
			e[dstKey] = v
			changed = true
		}
	}

	ip, _ := ev["SourceIp"].(string)
	if ip != tunnelPeerIP {
		if ip != "" && e["src_ip"] != ip {
			e["src_ip"] = ip
			changed = true
		}
		return marshalIfChanged(line, e, changed), true // already correct (or genuinely unknown) -- not ours to touch further
	}

	portStr, _ := ev["SourcePort"].(string)
	port, err := strconv.Atoi(portStr)
	if err != nil || port == 0 {
		if e["src_ip"] != ip {
			e["src_ip"] = ip
			changed = true
		}
		return marshalIfChanged(line, e, changed), true // no src_port to join on -- nothing further to try
	}

	real, ok := vm[port]
	if !ok {
		if e["src_ip"] != ip {
			e["src_ip"] = ip
			changed = true
		}
		return marshalIfChanged(line, e, changed), false // via_port miss -- caller retries later
	}

	ev["SourceIp"] = real
	e["event"] = ev
	e["src_ip"] = real
	e["src_port"] = port
	return marshalIfChanged(line, e, true), true
}
