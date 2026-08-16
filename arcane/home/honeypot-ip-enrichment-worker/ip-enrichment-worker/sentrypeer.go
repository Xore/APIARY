package main

import (
	"encoding/json"
	"net"
	"strconv"
)

// enrichSentrypeerLine handles sentrypeer.json. SentryPeer isn't PROXY-
// protocol wrapped (SIP is a raw UDP/TCP protocol with no such mechanism,
// and confirmed directly against the vendored source -- no proxyproto
// import anywhere), so like beelzebub/hellpot it only ever sees the tunnel
// peer address in its own raw log. Its own "source_ip" field is a single
// "ip:port" string (confirmed by actually running the patched binary and
// sending it a real SIP REGISTER, not assumed from source alone), same
// shape as hellpot's REMOTE_ADDR -- needs its own parse, not enrichLine's
// separate src_ip/src_port fields.
//
// Two things happen on every line, independent of each other:
//  1. The host half of source_ip is rewritten to the real attacker IP when
//     it's currently the tunnel peer and the port half resolves against vm
//     (same join as hellpot.go, against a differently-named combined field).
//  2. sensor/src_ip/src_port/sip_method/user_agent are added as flat
//     top-level fields dashboard/classify.go's sentrypeer block and the
//     geoip pipeline both read, mirrored from sip_method/sip_user_agent --
//     geoip-honeypot's ingest pipeline (analysis/elasticsearch-setup.sh)
//     only ever promotes h.src_ip at honeypot.* top level, so without this
//     every sentrypeer event would keep the tunnel peer as source.ip in
//     Elasticsearch even after a successful join.
//
// No destination-port field: SentryPeer's own JSON logs "destination_ip"
// as a fixed "0.0.0.0:5060" bind-address string, not the real per-request
// listen port (confirmed live), so a sentrypeer event's dst_port can't be
// recovered from the log line the way most sensors' can.
func enrichSentrypeerLine(line []byte, vm viaMap, tftpVM viaMap, persona string) (out []byte, resolved bool) {
	var e map[string]any
	if err := json.Unmarshal(line, &e); err != nil {
		return line, true // unparseable: nothing to retry, pass through as-is
	}
	sourceAddr, ok := e["source_ip"].(string)
	if !ok || sourceAddr == "" {
		return line, true // not a per-request event line -- nothing to enrich
	}

	changed := false
	if e["sensor"] != "sentrypeer" {
		e["sensor"] = "sentrypeer"
		changed = true
	}
	if e["protocol"] != "SIP" {
		e["protocol"] = "SIP"
		changed = true
	}
	// sip_method is already a flat, top-level field in SentryPeer's own
	// JSON output (confirmed live) -- nothing to rename there, unlike
	// hellpot's uppercase USERAGENT/URL. Only user_agent needs mirroring,
	// for the cross-sensor "user_agent" convention dashboard/classify.go's
	// per-sensor blocks read (e.g. its hellpot block, same field name).
	if ua, ok := e["sip_user_agent"].(string); ok && ua != "" && e["user_agent"] != ua {
		e["user_agent"] = ua
		changed = true
	}

	ip, portStr, err := net.SplitHostPort(sourceAddr)
	if err != nil {
		return marshalIfChanged(line, e, changed), true // malformed source_ip: nothing further to try
	}

	if ip != tunnelPeerIP {
		if e["src_ip"] != ip {
			e["src_ip"] = ip
			changed = true
		}
		return marshalIfChanged(line, e, changed), true // already correct (or genuinely unknown) -- not ours to touch further
	}

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

	e["source_ip"] = net.JoinHostPort(real, portStr)
	e["src_ip"] = real
	e["src_port"] = port
	return marshalIfChanged(line, e, true), true
}
