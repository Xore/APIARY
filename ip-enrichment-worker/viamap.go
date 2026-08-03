package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
)

// viaMap indexes portbridge's connection log by via_port (the tunnel-side
// ephemeral port portbridge dialed the honeypot from), which equals the
// src_port a non-PROXY-wrapped sensor observes for that same connection.
// Ported from dashboard/classify.go's buildViaMap/viaLookup -- same source
// files, same two-generation read window, same "newest match wins"
// resolution -- but without the listen-port sanity check viaLookup also
// does: via_port is a high-entropy ephemeral port per connection, and this
// worker never sees the honeypot's own listen port in a form worth
// duplicating conpot's persona-specific port-remapping table for. That
// check exists there as defense-in-depth, not the primary correctness
// mechanism.
type viaMap map[int]string

// buildViaMap reads portbridge.json.1 (if present, the previous 8 MiB
// rotation generation -- see vps/docker-compose.yml's portbridge-log-rotate
// sidecar) then portbridge.json (the live file), oldest first, so a later
// entry for the same via_port overwrites an earlier one -- "newest wins"
// falls out of plain map-assignment order rather than needing an explicit
// timestamp comparison.
func buildViaMap(portbridgeDir string) viaMap {
	m := viaMap{}
	for _, name := range []string{"portbridge.json.1", "portbridge.json"} {
		readPortbridgeLines(filepath.Join(portbridgeDir, name), m)
	}
	return m
}

func readPortbridgeLines(path string, m viaMap) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var e map[string]any
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if s, _ := e["sensor"].(string); s != "portbridge" {
			continue
		}
		ip, _ := e["src_ip"].(string)
		if ip == "" {
			continue
		}
		vp, ok := e["via_port"].(float64)
		if !ok || vp == 0 {
			continue
		}
		m[int(vp)] = ip
	}
}
