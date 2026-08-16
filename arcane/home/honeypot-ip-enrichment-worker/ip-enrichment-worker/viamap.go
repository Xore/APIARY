package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
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
		parsePortbridgeLine(sc.Bytes(), m)
	}
}

func parsePortbridgeLine(line []byte, m viaMap) {
	var e map[string]any
	if json.Unmarshal(line, &e) != nil {
		return
	}
	if s, _ := e["sensor"].(string); s != "portbridge" {
		return
	}
	ip, _ := e["src_ip"].(string)
	if ip == "" {
		return
	}
	vp, ok := e["via_port"].(float64)
	if !ok || vp == 0 {
		return
	}
	m[int(vp)] = ip
}

// viaMapBuilder maintains the via_port -> src_ip map incrementally across
// refresh() calls instead of re-reading and re-parsing both portbridge
// generations (up to ~10 MiB combined) from scratch every REFRESH_INTERVAL
// forever -- see #1206: under this worker's 0.5-CPU container limit, that
// full-file-every-2s cost compounded with the live file's size across a
// container's uptime, throttling the process (observed: >95% of CFS
// scheduling periods throttled) badly enough to push the highest-volume
// sensor's (cowrie) join attempts outside their PENDING_TIMEOUT window
// almost entirely after ~2 days up, while every other sensor -- far lower
// event volume, so far less sensitive to the same scheduling jitter --
// kept resolving normally. A fresh restart cleared it instantly, which is
// what pointed at accumulating per-tick cost rather than a logic bug.
//
// portbridge.json.1 (the previous, now-static generation) is only
// re-parsed when it actually changes (a rotation happened) rather than
// every tick, detected via mtime+size. portbridge.json (the live,
// still-growing file) is tailed for new bytes only, the same offset-based
// approach tail.go's readNewLines already uses for every sensor log --
// including its "file now shorter than offset" rotation handling, which
// here doubles as the signal that a rotation moved live content into
// portbridge.json.1, letting the next call's .1 mtime/size check pick up
// whatever we hadn't caught up to yet before the rename.
//
// via_port's key space is a port number (0-65535), so the accumulated map
// is inherently bounded regardless of log volume or uptime -- unlike the
// old two-generation read window, entries here are never explicitly
// evicted, only overwritten by a newer entry for the same port. Given
// real-world port reuse volume this is expected to be at least as fresh in
// practice, not staler.
//
// refresh returns an independent copy each call -- the builder's own map
// is never handed out directly -- so the caller can safely publish it via
// atomic.Pointer.Store without a concurrent reader ever observing an
// in-progress mutation.
type viaMapBuilder struct {
	portbridgeDir string
	m             viaMap
	liveOffset    int64
	genModTime    time.Time
	genSize       int64
}

func newViaMapBuilder(portbridgeDir string) *viaMapBuilder {
	b := &viaMapBuilder{portbridgeDir: portbridgeDir, m: viaMap{}}
	b.refresh()
	return b
}

func (b *viaMapBuilder) refresh() viaMap {
	genPath := filepath.Join(b.portbridgeDir, "portbridge.json.1")
	if fi, err := os.Stat(genPath); err == nil {
		if !fi.ModTime().Equal(b.genModTime) || fi.Size() != b.genSize {
			readPortbridgeLines(genPath, b.m)
			b.genModTime, b.genSize = fi.ModTime(), fi.Size()
		}
	}

	livePath := filepath.Join(b.portbridgeDir, "portbridge.json")
	if lines, newOffset, err := readNewLines(livePath, b.liveOffset); err == nil {
		for _, line := range lines {
			parsePortbridgeLine(line, b.m)
		}
		b.liveOffset = newOffset
	}

	snapshot := make(viaMap, len(b.m))
	for k, v := range b.m {
		snapshot[k] = v
	}
	return snapshot
}
