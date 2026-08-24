package main

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
)

// enrichHellpotLine handles hellpot.json. Two gaps, both closed here
// instead of by patching config further, since upstream's own JSON output
// (hellpot/router_patch.py's patched getRealRemote(), see that file's doc
// comment) is otherwise used unmodified:
//
//  1. REMOTE_ADDR is a single "ip:port" string (fasthttp's RemoteAddr(),
//     confirmed by actually running the patched binary and inspecting
//     real output), not the separate src_ip/src_port fields enrichLine
//     expects -- needs its own parse, not a shared one.
//  2. Nothing in the line names this repo's sensors at all -- upstream
//     doesn't know about that convention.
//
// Two things happen on every line, independent of each other:
//  1. The host half of REMOTE_ADDR is rewritten to the real attacker IP
//     when it's currently the tunnel peer and the port half resolves
//     against vm (same join as enrichLine, just against a combined field
//     instead of two separate ones).
//  2. sensor/src_ip/src_port/path/user_agent are added as flat top-level
//     fields dashboard/classify.go's hellpot block and the geoip pipeline
//     both read, mirrored from REMOTE_ADDR/URL/USERAGENT -- geoip-honeypot's
//     ingest pipeline (analysis/elasticsearch-setup.sh) only ever promotes
//     h.src_ip at honeypot.* top level, so without this every hellpot
//     event would keep the tunnel peer as source.ip in Elasticsearch even
//     after a successful join.
//
// No destination-port field: hellpot logs no listen-port of its own
// (confirmed directly against internal/http/router.go -- REMOTE_ADDR/URL/
// USERAGENT are the only per-request fields it logs), so like beelzebub's
// event a hellpot event's dst_port cannot be recovered from the log line
// alone. Every hellpot event is HTTP by definition (it's a single-protocol
// tarpit), so "protocol" is a constant here rather than something read off
// the line.
func enrichHellpotLine(line []byte, vm viaMap, tftpVM viaMap, persona string) (out []byte, resolved bool) {
	var e map[string]any
	if err := json.Unmarshal(line, &e); err != nil {
		return line, true // unparseable: nothing to retry, pass through as-is
	}
	remoteAddr, ok := e["REMOTE_ADDR"].(string)
	if !ok || remoteAddr == "" {
		return line, true // not a per-request "NEW"/"FINISH"/"END_ON_ERR" line (e.g. a startup log) -- nothing to enrich
	}

	changed := false
	if e["sensor"] != "hellpot" {
		e["sensor"] = "hellpot"
		changed = true
	}
	if e["protocol"] != "HTTP" {
		e["protocol"] = "HTTP"
		changed = true
	}
	if url, ok := e["URL"].(string); ok && url != "" && e["path"] != url {
		e["path"] = url
		changed = true
	}
	if ua, ok := e["USERAGENT"].(string); ok && ua != "" && e["user_agent"] != ua {
		e["user_agent"] = ua
		changed = true
	}

	ip, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return marshalIfChanged(line, e, changed), true // malformed REMOTE_ADDR: nothing further to try
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

	// #1876: two joins, adjudicated here rather than trusted in the sensor.
	//
	// HellPot is reachable two ways and cannot tell them apart: the
	// portbridge path and the Traefik path both present the tunnel peer as
	// RemoteAddr. Only this worker can distinguish them, because only it
	// holds portbridge's connection log -- so the sensor records the
	// forwarded header as a fact (hellpot/xff_trust_patch.py) and the
	// decision is made against that log.
	//
	// via_port is derived from the connection portbridge actually made.
	// XFF is content, and on the portbridge path it is attacker-authored.
	// So where both speak, the connection wins.
	real, viaOK := vm[port]
	forwarded := lastForwardedHop(e)

	switch {
	case viaOK && forwarded != "" && forwarded != real:
		// Both resolved and they disagree. On the portbridge path that is
		// an attacker setting their own X-Forwarded-For, which is worth
		// seeing rather than silently discarding -- so both addresses are
		// kept, the connection-derived one is the source, and the claim is
		// preserved next to it under a flag the dashboard can badge.
		e["REMOTE_ADDR"] = net.JoinHostPort(real, portStr)
		e["src_ip"] = real
		e["src_port"] = port
		e["src_ip_claimed"] = forwarded
		e["src_ip_conflict"] = true
		return marshalIfChanged(line, e, true), true

	case viaOK:
		// portbridge relayed it, so the address comes from the connection.
		// Any header present agrees, or there is none.
		e["REMOTE_ADDR"] = net.JoinHostPort(real, portStr)
		e["src_ip"] = real
		e["src_port"] = port
		return marshalIfChanged(line, e, true), true

	case forwarded != "":
		// portbridge never saw this connection -- the Traefik path, where
		// the header is the only evidence there is. The port belongs to
		// the relay rather than the client, so it is not reported as if it
		// were theirs.
		e["REMOTE_ADDR"] = forwarded
		e["src_ip"] = forwarded
		delete(e, "src_port")
		return marshalIfChanged(line, e, true), true
	}

	if e["src_ip"] != ip {
		e["src_ip"] = ip
		changed = true
	}
	return marshalIfChanged(line, e, changed), false // neither join resolved -- caller retries later
}

// lastForwardedHop reads the X-Forwarded-For value the sensor recorded and
// returns the hop that was appended last.
//
// The last hop, not the first: Cloudflare appends the real client to
// whatever the client already sent rather than replacing it, so the
// leftmost entry is attacker-controlled and the rightmost is the one
// Cloudflare itself wrote. An attacker sending "1.2.3.4" on a path
// Cloudflare fronts ends up left of the truth, not in place of it.
func lastForwardedHop(e map[string]any) string {
	raw, _ := e["XFF"].(string)
	if raw == "" {
		return ""
	}
	hops := strings.Split(raw, ",")
	last := strings.TrimSpace(hops[len(hops)-1])
	if net.ParseIP(last) == nil {
		return "" // not an address: nothing usable was forwarded
	}
	return last
}
