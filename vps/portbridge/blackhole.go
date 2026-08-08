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
//
// BLACKHOLE_MANUAL_LIST (#914) names a second, independently-refreshed file
// in the same format, holding operator-triggered blocks from the dashboard
// (see docs/dashboard-manual-ip-block-design.md) — kept fresh by
// vps/portbridge-manual-blackhole-refresh.sh, a separate sidecar from the
// maltrail one above. The two lists are deliberately two files, not one:
// each is independently owned and independently refreshed (maltrail on a
// ~24h cadence from GitHub, manual blocks on demand from the dashboard), so
// neither refresh can ever silently wipe the other's entries by overwriting
// a shared file.
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

// blackholeSource tracks one on-disk list's own mtime, independently of any
// other source sharing the same blackhole.
type blackholeSource struct {
	path    string
	modTime time.Time
	ips     map[string]struct{}
}

// blackhole holds the current union of every configured list's addresses
// behind an atomic pointer so the per-connection hot path (blocked) never
// takes a lock against the background reload goroutine.
type blackhole struct {
	sources []*blackholeSource
	ips     atomic.Pointer[map[string]struct{}]
}

// newBlackhole starts a blackhole watcher over one or more list files (empty
// path strings are skipped). No configured paths at all returns a non-nil
// blackhole whose blocked() always reports false, so call sites never need a
// nil check — same pattern connLogger's callers already rely on for CONN_LOG.
func newBlackhole(paths ...string) *blackhole {
	b := &blackhole{}
	empty := map[string]struct{}{}
	b.ips.Store(&empty)
	for _, p := range paths {
		if p == "" {
			continue
		}
		b.sources = append(b.sources, &blackholeSource{path: p})
	}
	if len(b.sources) == 0 {
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

// reload re-reads every source file whose mtime changed since the last read,
// then republishes the union. A missing file (the refresh sidecar for that
// particular source hasn't run yet, or its compose profile isn't active) is
// not an error for that source: it just contributes nothing to the union
// until the file shows up, exactly like an unset path.
func (b *blackhole) reload() {
	changed := false
	for _, src := range b.sources {
		if src.readOne() {
			changed = true
		}
	}
	if !changed {
		return
	}
	union := map[string]struct{}{}
	for _, src := range b.sources {
		for ip := range src.ips {
			union[ip] = struct{}{}
		}
	}
	b.ips.Store(&union)
	fmt.Fprintf(os.Stderr, "portbridge: blackhole reloaded, %d addresses across %d source(s)\n", len(union), len(b.sources))
}

// readOne re-reads src's own file if its mtime moved, reporting whether it
// changed anything.
func (src *blackholeSource) readOne() bool {
	st, err := os.Stat(src.path)
	if err != nil {
		return false
	}
	if !st.ModTime().After(src.modTime) {
		return false
	}
	f, err := os.Open(src.path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portbridge: blackhole list %s: %v\n", src.path, err)
		return false
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
		fmt.Fprintf(os.Stderr, "portbridge: blackhole list %s: read error: %v\n", src.path, err)
		return false
	}

	src.ips = set
	src.modTime = st.ModTime()
	return true
}

// blocked reports whether ip (a bare address, no port — callers already have
// this from net.SplitHostPort/splitHostPort) is a known mass scanner or a
// manually-blocked address, across every configured source.
func (b *blackhole) blocked(ip string) bool {
	set := b.ips.Load()
	if set == nil {
		return false
	}
	_, ok := (*set)[ip]
	return ok
}
