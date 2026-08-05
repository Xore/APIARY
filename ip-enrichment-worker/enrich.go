package main

import "encoding/json"

// tunnelPeerIP is the WireGuard peer address cowrie/dionaea/conpot/
// dns-honeypot/cisco-asa-honeypot's IKE side all see for every connection
// that isn't PROXY-protocol wrapped -- portbridge dials them from its own
// tunnel-side address, not the real attacker's. Matches dashboard/util.go's
// own constant of the same name exactly; kept in sync by hand since these
// are separate Go modules with no shared package.
const tunnelPeerIP = "10.8.0.1"

// extractSrcPort mirrors dashboard/classify.go's eventSrcPort for exactly
// the shapes the five affected sensors actually emit (confirmed live
// against production ES documents, not just source-reading, for cowrie,
// dionaea, conpot, dns-honeypot -- all top-level "src_port"): a top-level
// "src_port" first, dionaea's older nested connection.remote_port shape as
// a defensive fallback (the dtagdevsec image currently deployed uses the
// top-level form, but classify.go itself still carries this fallback for a
// reason -- kept here for the same reason, not because it's been observed
// live).
func extractSrcPort(e map[string]any) int {
	if p, ok := e["src_port"].(float64); ok && p != 0 {
		return int(p)
	}
	if conn, ok := e["connection"].(map[string]any); ok {
		if p, ok := conn["remote_port"].(float64); ok {
			return int(p)
		}
	}
	return 0
}

// conpotPortRemap corrects "dst_port" for the two Siemens S7 personas whose
// host-published Modbus/S7comm ports differ from the container-internal
// port conpot itself binds and logs -- see docker-compose.conpot.yml's own
// "${HP_BIND:-10.8.0.2}:1502:502" / ":1102:102" (and :2502/:2102 for
// s7-1500) style remaps. Conpot has no visibility into the Docker NAT
// remap, so its own log always carries the container-internal port; #745
// found this collapses all three Siemens personas (the base conpot
// service, which really is published on 502/102, plus these two) into the
// same destination.port once ECS-mapped, making three deliberately
// "separately fingerprintable" PLCs (docker-compose.conpot.yml's own words)
// indistinguishable by port.
var conpotPortRemap = map[string]map[float64]float64{
	"conpot-s7-1200": {502: 1502, 102: 1102},
	"conpot-s7-1500": {502: 2502, 102: 2102},
}

// fixConpotDestPort rewrites e["dst_port"] in place per conpotPortRemap when
// persona is one of the remapped S7 personas and dst_port is still the
// container-internal value. Returns whether it changed anything.
func fixConpotDestPort(e map[string]any, persona string) bool {
	remap, ok := conpotPortRemap[persona]
	if !ok {
		return false
	}
	p, ok := e["dst_port"].(float64)
	if !ok {
		return false
	}
	real, ok := remap[p]
	if !ok {
		return false
	}
	e["dst_port"] = real
	return true
}

// enrichLine rewrites line's "src_ip" field to the real attacker IP when it
// currently reads the tunnel peer address (joined against portbridge's
// via_port map) or is one of dionaea's TFTP events relayed through
// tftp-relay (#747, joined against tftpVM instead -- see
// isTftpRelayRecord). Also corrects "dst_port" for the s7-1200/s7-1500
// conpot personas per fixConpotDestPort above. Returns the original bytes
// unchanged (never mutates, never drops) whenever nothing applies: line
// isn't valid JSON, doesn't match either src_ip trigger, has no recoverable
// src_port, or the join misses. A src_ip miss is the caller's signal to
// retry later, not a permanent answer -- see pending.go; a dst_port fix
// never affects that decision, since it's independent of both src_ip joins.
func enrichLine(line []byte, vm viaMap, tftpVM viaMap, persona string) (out []byte, resolved bool) {
	var e map[string]any
	if err := json.Unmarshal(line, &e); err != nil {
		return line, true // unparseable: nothing to retry, pass through as-is
	}
	portFixed := fixConpotDestPort(e, persona)

	ip, _ := e["src_ip"].(string)
	lookup := vm
	switch {
	case ip == tunnelPeerIP:
		lookup = vm
	case isTftpRelayRecord(e, persona):
		lookup = tftpVM
	default:
		return marshalIfChanged(line, e, portFixed), true // already correct (or genuinely unknown) -- not ours to touch further
	}
	port := extractSrcPort(e)
	if port == 0 {
		return marshalIfChanged(line, e, portFixed), true // no src_port to join on -- nothing further to try
	}
	real, ok := lookup[port]
	if !ok {
		// Still returns the dst_port fix (if any) even though src_ip isn't
		// resolved yet: pendingQueue.drain calls enrichLine again on every
		// retry (cheap, re-derives fresh from the original stored line each
		// time -- see pending.go) and writes *this* return value once the
		// line either resolves or times out, so the port fix must not be
		// silently dropped on a miss.
		return marshalIfChanged(line, e, portFixed), false
	}
	e["src_ip"] = real
	return marshalIfChanged(line, e, true), true
}

// rewriteDionaeaConnections recursively walks v (typically a
// dionaea_incident.json record's "data" field) looking for every embedded
// connection-shape object -- any map carrying both "remote_ip" and
// "remote_port" -- and rewrites remote_ip in place wherever it's
// currently the tunnel peer and the port resolves against vm. Confirmed
// live against every incident origin currently observed on the
// homeserver (smb.exploit, connection.tcp.accept/udp.connect/free/link,
// download.complete*, smb.dcerpc.request/bind, sip.command, ftp.command/
// login, mssql/mysql/mqtt/pptp): every one nests this exact {remote_ip,
// remote_port, ...} shape somewhere in data, under a key that varies by
// origin ("connection" for most, but "child"+"parent" -- two separate
// connection objects in one record -- for dionaea.connection.link).
// Matching on the shape itself rather than a fixed key name handles all
// of these, including any future origin, without per-origin cases.
//
// Returns how many objects were rewritten, and whether every tunnel-peer
// object encountered either got rewritten or had no port to join on
// (nothing further to try) -- allResolved=false means at least one
// tunnel-peer object's port simply isn't in vm yet, the same "retry
// later" signal enrichLine's port-miss case gives.
func rewriteDionaeaConnections(v any, vm viaMap) (changed int, allResolved bool) {
	allResolved = true
	switch node := v.(type) {
	case map[string]any:
		if ip, ok := node["remote_ip"].(string); ok && ip == tunnelPeerIP {
			if portF, ok := node["remote_port"].(float64); ok {
				if real, ok := vm[int(portF)]; ok {
					node["remote_ip"] = real
					changed++
				} else {
					allResolved = false
				}
			}
		}
		for _, child := range node {
			c, r := rewriteDionaeaConnections(child, vm)
			changed += c
			allResolved = allResolved && r
		}
	case []any:
		for _, child := range node {
			c, r := rewriteDionaeaConnections(child, vm)
			changed += c
			allResolved = allResolved && r
		}
	}
	return
}

// enrichDionaeaIncidentLine is dionaea_incident.json's own enrichLine:
// unlike the five flat-log sensors, an incident record carries no
// top-level src_ip at all -- the real signal is buried in "data" (see
// rewriteDionaeaConnections). tftpVM/persona are accepted only to match
// enrichFunc's shared signature (see pending.go) and are unused here --
// no TFTP-relay incident origin has been observed to need that join.
func enrichDionaeaIncidentLine(line []byte, vm viaMap, _ viaMap, _ string) (out []byte, resolved bool) {
	var e map[string]any
	if err := json.Unmarshal(line, &e); err != nil {
		return line, true // unparseable: nothing to retry, pass through as-is
	}
	changed, allResolved := rewriteDionaeaConnections(e["data"], vm)
	if changed == 0 {
		return line, allResolved
	}
	rewritten, err := json.Marshal(e)
	if err != nil {
		return line, allResolved // shouldn't happen; fall back to the original line
	}
	return rewritten, allResolved
}

// marshalIfChanged returns line unchanged when nothing was modified
// (preserving the original bytes exactly, including key order/formatting),
// or e re-marshalled when it was.
func marshalIfChanged(line []byte, e map[string]any, changed bool) []byte {
	if !changed {
		return line
	}
	rewritten, err := json.Marshal(e)
	if err != nil {
		return line // shouldn't happen; fall back to the original line
	}
	return rewritten
}
