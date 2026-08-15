package main

import (
	"encoding/json"
	"strconv"
)

// enrichGalahLine handles galah's event_log.json. Two gaps, both closed
// here instead of by patching config, since galah is run unmodified,
// config-only (galah/config.yaml):
//
//  1. Every "successfulResponse" line galah's own commonFields()
//     (internal/logger/logger.go) writes has flat srcIP/srcPort fields
//     already -- confirmed by actually running the pinned commit end to
//     end against a fake Ollama backend and inspecting real output, not
//     assumed from the struct definitions alone. Unlike beelzebub/hellpot
//     this needs no unwrapping, just the usual sensor-tagging and
//     via_port join this repo's convention expects (h.src_ip, matching
//     analysis/elasticsearch-setup.sh's ingest pipeline).
//  2. srcHost/tags in that same line are galah's OWN enrichment
//     (internal/logger/logger.go's commonFields calls
//     l.EnrichCache.Process(srcIP) before this worker ever sees the
//     line) -- run against whatever srcIP was AT LOG TIME, which is the
//     tunnel peer address, not the real attacker IP, until this function
//     resolves it below. Confirmed live: a local request from 127.0.0.1
//     produced srcHost:"localhost" -- a real, but meaningless, reverse
//     lookup on the wrong address. Deliberately left untouched (not
//     deleted, not trusted) -- dashboard/classify.go's galah block does
//     not read srcHost/tags for this reason.
//
// httpRequest.bodySha256 is promoted to a flat body_sha256 field (the
// #1420 issue's own "cross-reference against payload-inventory" ask) --
// promoted, not joined: analysis/elasticsearch-setup.sh's ingest pipeline
// has no galah-aware hash-promotion rule (its only shasum->file.hash.sha256
// mapping is cowrie-eventid-gated), so this is queryable in Elasticsearch
// today but wiring an automatic join against the payload-inventory index
// is a natural, separately-scoped follow-up, not done here.
//
// No destination-port field: like beelzebub/hellpot, galah logs no
// listen-port of its own on the event line (confirmed against
// internal/logger/logger.go -- "port" here is the string server address,
// e.g. "18889", already just the port, so it IS available -- unlike
// beelzebub/hellpot this one actually has it, promoted as dst_port below).
func enrichGalahLine(line []byte, vm viaMap, tftpVM viaMap, persona string) (out []byte, resolved bool) {
	var e map[string]any
	if err := json.Unmarshal(line, &e); err != nil {
		return line, true // unparseable: nothing to retry, pass through as-is
	}
	if e["msg"] != "successfulResponse" {
		return line, true // not a per-request event line (e.g. a startup log) -- nothing to enrich
	}

	changed := false
	if e["sensor"] != "galah" {
		e["sensor"] = "galah"
		changed = true
	}
	if e["protocol"] != "HTTP" {
		e["protocol"] = "HTTP"
		changed = true
	}
	if dst, ok := e["port"].(string); ok && dst != "" && e["dst_port"] != dst {
		e["dst_port"] = dst
		changed = true
	}
	if hr, ok := e["httpRequest"].(map[string]any); ok {
		if req, ok := hr["request"].(string); ok && req != "" && e["path"] != req {
			e["path"] = req
			changed = true
		}
		if ua, ok := hr["userAgent"].(string); ok && ua != "" && e["user_agent"] != ua {
			e["user_agent"] = ua
			changed = true
		}
		if sha, ok := hr["bodySha256"].(string); ok && sha != "" && e["body_sha256"] != sha {
			e["body_sha256"] = sha
			changed = true
		}
	}

	ip, _ := e["srcIP"].(string)
	if ip != tunnelPeerIP {
		if ip != "" && e["src_ip"] != ip {
			e["src_ip"] = ip
			changed = true
		}
		return marshalIfChanged(line, e, changed), true // already correct (or genuinely unknown) -- not ours to touch further
	}

	portStr, _ := e["srcPort"].(string)
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

	e["srcIP"] = real
	e["src_ip"] = real
	e["src_port"] = port
	return marshalIfChanged(line, e, true), true
}
