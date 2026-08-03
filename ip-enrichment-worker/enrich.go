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

// enrichLine rewrites line's "src_ip" field to the real attacker IP when it
// currently reads the tunnel peer address and a matching portbridge via_port
// entry is found. Returns the original bytes unchanged (never mutates,
// never drops) whenever nothing applies: line isn't valid JSON, doesn't
// carry the tunnel peer IP, has no recoverable src_port, or the join
// misses. A miss is the caller's signal to retry later, not a permanent
// answer -- see pending.go.
func enrichLine(line []byte, vm viaMap) (out []byte, resolved bool) {
	var e map[string]any
	if err := json.Unmarshal(line, &e); err != nil {
		return line, true // unparseable: nothing to retry, pass through as-is
	}
	ip, _ := e["src_ip"].(string)
	if ip != tunnelPeerIP {
		return line, true // already correct (or genuinely unknown) -- not ours to touch
	}
	port := extractSrcPort(e)
	if port == 0 {
		return line, true // no src_port to join on -- nothing further to try
	}
	real, ok := vm[port]
	if !ok {
		return line, false // may resolve once a later portbridge entry lands
	}
	e["src_ip"] = real
	rewritten, err := json.Marshal(e)
	if err != nil {
		return line, true // shouldn't happen; fall back to the original line
	}
	return rewritten, true
}
