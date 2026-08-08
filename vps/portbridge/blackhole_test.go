package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestBlackholeEmptyPathNeverBlocks(t *testing.T) {
	b := newBlackhole("")
	if b == nil {
		t.Fatal("newBlackhole(\"\") returned nil; callers rely on a non-nil value")
	}
	if b.blocked("1.2.3.4") {
		t.Error("blocked() reported true with no list configured")
	}
}

func TestBlackholeMissingFileNeverBlocks(t *testing.T) {
	// The refresh sidecar (vps/portbridge-blackhole-refresh.sh) hasn't run yet,
	// or the "blackhole" compose profile isn't active -- this must behave like
	// disabled, not like an error.
	b := newBlackhole(filepath.Join(t.TempDir(), "does-not-exist.txt"))
	if b.blocked("1.2.3.4") {
		t.Error("blocked() reported true against a nonexistent list file")
	}
}

func TestBlackholeParsesMassScannerFormat(t *testing.T) {
	// Real mass_scanner.txt shape: a comment header, blank lines, and
	// "<ip> # host.example.com" data lines.
	content := "# Copyright header\n" +
		"# more header\n" +
		"\n" +
		"129.82.138.12 # pinger1a.netsec.colostate.edu\n" +
		"67.21.36.100 # researchscanner100.eecs.berkeley.edu\n" +
		"not-an-ip # malformed line should be skipped\n"
	path := filepath.Join(t.TempDir(), "mass_scanner.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	b := newBlackhole(path)
	for _, ip := range []string{"129.82.138.12", "67.21.36.100"} {
		if !b.blocked(ip) {
			t.Errorf("blocked(%q) = false, want true", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "not-an-ip"} {
		if b.blocked(ip) {
			t.Errorf("blocked(%q) = true, want false", ip)
		}
	}
}

func TestBlackholeReloadPicksUpChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mass_scanner.txt")
	if err := os.WriteFile(path, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := newBlackhole(path)
	if !b.blocked("1.1.1.1") {
		t.Fatal("blocked(1.1.1.1) = false after initial load")
	}
	if b.blocked("2.2.2.2") {
		t.Fatal("blocked(2.2.2.2) = true before it was ever added")
	}

	// os.Stat's ModTime resolution on some filesystems is coarser than a Go
	// timer tick; sleep past it so reload() sees a real mtime change rather
	// than racing it.
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(path, []byte("2.2.2.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b.reload()
	if b.blocked("1.1.1.1") {
		t.Error("blocked(1.1.1.1) = true after reload replaced the list")
	}
	if !b.blocked("2.2.2.2") {
		t.Error("blocked(2.2.2.2) = false after reload should have picked it up")
	}
}

// #914: the maltrail feed and the manual-block list are two independent
// files unioned together, specifically so a refresh of one can never wipe
// entries from the other -- exercised here by refreshing only one of the
// two sources and confirming the other's entries survive untouched.
func TestBlackholeUnionsTwoIndependentSources(t *testing.T) {
	maltrailPath := filepath.Join(t.TempDir(), "mass_scanner.txt")
	manualPath := filepath.Join(t.TempDir(), "manual.txt")
	if err := os.WriteFile(maltrailPath, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manualPath, []byte("2.2.2.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	b := newBlackhole(maltrailPath, manualPath)
	for _, ip := range []string{"1.1.1.1", "2.2.2.2"} {
		if !b.blocked(ip) {
			t.Errorf("blocked(%q) = false, want true (union of both sources)", ip)
		}
	}

	// Refreshing the maltrail feed alone (a wholesale-replace, same as the
	// real refresh sidecar's atomic rename) must not lose the manual
	// source's own entry.
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(maltrailPath, []byte("3.3.3.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b.reload()
	if b.blocked("1.1.1.1") {
		t.Error("blocked(1.1.1.1) = true after the maltrail feed dropped it -- stale union entry")
	}
	if !b.blocked("3.3.3.3") {
		t.Error("blocked(3.3.3.3) = false after the maltrail feed refresh should have picked it up")
	}
	if !b.blocked("2.2.2.2") {
		t.Fatal("blocked(2.2.2.2) = false after an unrelated maltrail refresh -- manual source was wiped")
	}
}

func TestBlackholeVariadicSkipsEmptyPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manual.txt")
	if err := os.WriteFile(path, []byte("9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// BLACKHOLE_LIST unset (empty string) alongside a configured
	// BLACKHOLE_MANUAL_LIST -- the empty path must be skipped, not treated
	// as a real (always-missing) source.
	b := newBlackhole("", path)
	if !b.blocked("9.9.9.9") {
		t.Error("blocked(9.9.9.9) = false with an empty first path and a real second path")
	}
}

// TestServeTCPDropsBlackholedSourceBeforeUpstream is the actual point of
// #268: a blackholed source must never reach the honeypot listener. Since
// tests dial from 127.0.0.1, the blackhole list here names 127.0.0.1 itself
// so the client IP genuinely matches an entry, exercising the real code path
// serveTCP takes rather than a mocked one.
func TestServeTCPDropsBlackholedSourceBeforeUpstream(t *testing.T) {
	reached := make(chan struct{}, 1)
	honeypot, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer honeypot.Close()
	go func() {
		c, err := honeypot.Accept()
		if err == nil {
			reached <- struct{}{}
			c.Close()
		}
	}()

	listPath := filepath.Join(t.TempDir(), "mass_scanner.txt")
	if err := os.WriteFile(listPath, []byte("127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bh := newBlackhole(listPath)

	port := freeTCPPort(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	r := rule{proto: "tcp", listenPort: strconv.Itoa(port), target: honeypot.Addr().String()}
	go serveTCP("127.0.0.1", r, nil, bh)

	// serveTCP binds asynchronously (same reasoning as the existing UDP test's
	// own comment on serveUDP): retry the dial until the listener is up.
	var c net.Conn
	for i := 0; i < 50; i++ {
		c, err = net.Dial("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()

	select {
	case <-reached:
		t.Fatal("blackholed source's connection reached the upstream honeypot listener")
	case <-time.After(300 * time.Millisecond):
		// Expected: portbridge closed the connection without dialing target.
	}
}

// freeTCPPort returns a port number nothing is bound to, mirroring
// freeUDPPort in main_test.go for the same reason: serveTCP takes the port
// as part of its rule and never reports back what it bound.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
