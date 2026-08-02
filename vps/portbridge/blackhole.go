// blackhole.go — drop connections from known mass scanners before they ever
// reach a honeypot listener, while leaving Suricata (which sniffs the public
// interface independently of anything portbridge does with an accepted
// connection) fully able to see and log the same traffic. #268.
//
// T-Pot's own blackhole.sh (docker/tpotinit/dist/bin/blackhole.sh) does this
// with a kernel null-route (`ip route add blackhole $ip`) sourced from
// stamparm/maltrail's mass_scanner.txt. portbridge already does per-connection
// work (PROXY-header injection, p0f queries) before a connection reaches its
// target, so the natural integration point is here rather than a second,
// separate mechanism at the OS routing table — refusing to dial upstream for
// a blackholed source achieves the same "no honeypot listener sees it"
// outcome T-Pot's null-route does, without needing NET_ADMIN or host routing
// table access from a container that otherwise needs neither.
//
// BLACKHOLE_LIST names a local file, one IPv4 address per line (comments and
// trailing "# host.example.com"-style annotations are ignored — the same
// mass_scanner.txt format T-Pot consumes). Empty/unset disables the feature
// entirely, same "empty path = off" convention CONN_LOG already uses. The
// file is expected to be kept fresh by an external process (this repo's
// vps/portbridge-blackhole-refresh.sh, gated behind the docker-compose
// "blackhole" profile so it is opt-in per deployment, not a silent default)
// — portbridge itself only reads it, on a timer, and never fetches anything
// over the network.
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const blackholeReloadInterval = 15 * time.Minute

// blackhole holds the current blocklist behind an atomic pointer so the
// per-connection hot path (blocked) never takes a lock against the
// background reload goroutine.
type blackhole struct {
	path    string
	ips     atomic.Pointer[map[string]struct{}]
	modTime time.Time
}

// newBlackhole starts a blackhole watcher. path == "" returns a non-nil
// blackhole whose blocked() always reports false, so call sites never need a
// nil check — same pattern connLogger's callers already rely on for CONN_LOG.
func newBlackhole(path string) *blackhole {
	b := &blackhole{path: path}
	empty := map[string]struct{}{}
	b.ips.Store(&empty)
	if path == "" {
		return b
	}
	b.reload()
	go func() {
		for range time.Tick(blackholeReloadInterval) {
			b.reload()
		}
	}()
	return b
}

// reload re-reads the blocklist file if its mtime changed since the last
// read. A missing file (the refresh sidecar hasn't run yet, or the
// "blackhole" compose profile isn't active) is not an error: it just means
// blocked() reports false until the file shows up, exactly like an unset
// BLACKHOLE_LIST.
func (b *blackhole) reload() {
	st, err := os.Stat(b.path)
	if err != nil {
		return
	}
	if !st.ModTime().After(b.modTime) {
		return
	}
	f, err := os.Open(b.path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: blackhole list %s: %v\n", b.path, err)
		return
	}
	defer f.Close()

	set := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// mass_scanner.txt lines are "<ip> # host.example.com"; the address is
		// always the first field. net.ParseIP rejects anything that slipped
		// through malformed rather than silently blackholing a garbage entry.
		ip := strings.Fields(line)[0]
		if net.ParseIP(ip) != nil {
			set[ip] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: blackhole list %s: read error: %v\n", b.path, err)
		return
	}

	b.ips.Store(&set)
	b.modTime = st.ModTime()
	fmt.Fprintf(os.Stderr, "portbridge: blackhole list reloaded, %d addresses (%s)\n", len(set), b.path)
}

// blocked reports whether ip (a bare address, no port — callers already have
// this from net.SplitHostPort/splitHostPort) is a known mass scanner.
func (b *blackhole) blocked(ip string) bool {
	set := b.ips.Load()
	if set == nil {
		return false
	}
	_, ok := (*set)[ip]
	return ok
}
