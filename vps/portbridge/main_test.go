package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// UDP is the one transport portbridge cannot PROXY-wrap: there is no header to
// prepend to a datagram, and conpot's shim is TCP-only. The conn log's via_port
// is therefore the only thing that can attribute a UDP probe to a real source,
// and it is worth nothing unless it equals the port the honeypot actually sees
// the datagram arrive from. That equality is what this asserts. See issue #75.
func TestUDPConnLogViaPortIsTheSourcePortTheHoneypotSees(t *testing.T) {
	honeypot, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer honeypot.Close()

	observed := make(chan int, 1)
	go func() {
		buf := make([]byte, 512)
		if _, from, err := honeypot.ReadFromUDP(buf); err == nil {
			observed <- from.Port
		}
	}()

	logPath := filepath.Join(t.TempDir(), "portbridge.json")
	r := rule{
		proto:      "udp",
		listenPort: strconv.Itoa(freeUDPPort(t)),
		target:     honeypot.LocalAddr().String(),
	}
	cl := newConnLogger(logPath)
	// serveUDP never returns, so the log file stays open for the rest of the
	// run; close it before the temp dir is torn down.
	t.Cleanup(func() { cl.f.Close() })
	go serveUDP("127.0.0.1", r, cl, newBlackhole(""))

	// serveUDP binds asynchronously, so keep sending until it forwards one.
	// Every datagram comes from the same client socket, so they all belong to
	// one session and produce exactly one log line. The socket is deliberately
	// unconnected: a connected UDP socket on Linux surfaces the ICMP
	// port-unreachable from a datagram sent before serveUDP bound as an error
	// on the *next* write, which has nothing to do with what is being tested.
	bridge, err := net.ResolveUDPAddr("udp4", net.JoinHostPort("127.0.0.1", r.listenPort))
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var srcPort int
	deadline := time.After(10 * time.Second)
	for srcPort == 0 {
		if _, err := client.WriteToUDP([]byte("probe"), bridge); err != nil {
			t.Fatal(err)
		}
		select {
		case srcPort = <-observed:
		case <-deadline:
			t.Fatal("the honeypot never received a forwarded datagram")
		case <-time.After(25 * time.Millisecond):
		}
	}

	rec := lastConnLogRecord(t, logPath)
	if got := int(rec["via_port"].(float64)); got != srcPort {
		t.Fatalf("via_port=%d, the honeypot saw src port %d — the join would miss", got, srcPort)
	}
	if got := rec["proto"]; got != "udp" {
		t.Fatalf("proto=%v, want udp", got)
	}
	if got := int(rec["port"].(float64)); strconv.Itoa(got) != r.listenPort {
		t.Fatalf("port=%d, want the listen port %s the dashboard sanity-checks the join against", got, r.listenPort)
	}
	if got := rec["src_ip"]; got != "127.0.0.1" {
		t.Fatalf("src_ip=%v, want the real client address", got)
	}
}

// TestServeUDPBindsWildcardAlongsideExistingLoopbackListener is a regression
// test for a real production failure (#238, #415 deploy): a wildcard
// 0.0.0.0 bind conflicts with an existing more-specific bind on the same
// port unless SO_REUSEADDR is set, even though nothing shows up bound to
// 0.0.0.0 itself. Hit this live on the VPS -- systemd-resolved's stub
// resolver already holds 127.0.0.53:53 and 127.0.0.54:53, and portbridge's
// LISTEN_IP=0.0.0.0 rule for the new dns-honeypot (53/udp) failed with
// EADDRINUSE despite `ss`/`lsof` showing no wildcard listener on that port
// at all. Confirmed directly (a standalone bind reproduced it, and setting
// SO_REUSEADDR resolved it) before fixing serveUDP's listener to set it.
func TestServeUDPBindsWildcardAlongsideExistingLoopbackListener(t *testing.T) {
	port := freeUDPPort(t)

	// A plain net.ListenUDP here (no SO_REUSEADDR) reproduces a *stricter*
	// case than systemd-resolved's real socket and still fails even with
	// the fix below -- confirmed directly on the VPS that systemd-resolved's
	// own stub-listener socket must itself carry SO_REUSEADDR (or
	// SO_REUSEPORT), since a wildcard SO_REUSEADDR bind against a bare
	// Python socket with no such option set still returns EADDRINUSE. This
	// reuseAddrListenUDP helper matches the real, working condition.
	//
	// Bound to 127.0.0.2, not 127.0.0.1: the bind-conflict check is
	// port-wide regardless of which specific address the competitor uses
	// (matching production, where systemd-resolved's 127.0.0.53/54 collide
	// with a 0.0.0.0 bind on the same port), but Linux's *packet delivery*
	// prefers the most specific matching socket. Using the same address as
	// the client's destination below would make this fake "systemd-resolved"
	// silently steal every test datagram instead of portbridge's wildcard
	// socket ever seeing it -- which is not what's being tested here, and
	// is also not what happens for real attacker traffic against the VPS's
	// public IP, which has no specific competitor at all.
	loopbackHolder, err := reuseAddrListenUDP("127.0.0.2", port)
	if err != nil {
		t.Fatal(err)
	}
	defer loopbackHolder.Close()

	honeypot, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer honeypot.Close()

	observed := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 512)
		if _, _, err := honeypot.ReadFromUDP(buf); err == nil {
			observed <- struct{}{}
		}
	}()

	r := rule{proto: "udp", listenPort: strconv.Itoa(port), target: honeypot.LocalAddr().String()}
	go serveUDP("0.0.0.0", r, newConnLogger(""), newBlackhole(""))

	bridge, err := net.ResolveUDPAddr("udp4", net.JoinHostPort("127.0.0.1", r.listenPort))
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	deadline := time.After(10 * time.Second)
	for {
		if _, err := client.WriteToUDP([]byte("probe"), bridge); err != nil {
			t.Fatal(err)
		}
		select {
		case <-observed:
			return // wildcard bind succeeded and forwarded despite the loopback-bound competitor
		case <-deadline:
			t.Fatal("serveUDP never forwarded a datagram — wildcard bind alongside an existing loopback listener must have failed")
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// reuseAddrListenUDP binds ip:port with SO_REUSEADDR set, the way
// systemd-managed sockets (e.g. systemd-resolved's real stub listener) do.
func reuseAddrListenUDP(ip string, port int) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var setErr error
		if err := c.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return setErr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// freeUDPPort returns a port number nothing is bound to. serveUDP takes the
// port as part of its rule and never reports back what it bound, so the test
// has to pick one it can also dial.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// #120: portbridge.json has no external rotation (it's shipped to the home
// stack over a read-only sshfs mount, so nothing there can rotate it either),
// so the logger has to bound its own size the way Suricata's rotate-interval
// bounds eve.json -- close, rename aside, reopen fresh at the same path.
// This asserts the rename actually happens, the original path keeps
// receiving new lines afterward, and no line is lost across the rotation.
func TestConnLoggerRotatesAtMaxBytesWithoutLosingLines(t *testing.T) {
	t.Setenv("LOG_MAX_BYTES", "1")
	logPath := filepath.Join(t.TempDir(), "portbridge.json")
	cl := newConnLogger(logPath)
	t.Cleanup(func() { cl.f.Close() })

	r := rule{proto: "tcp", listenPort: "22", target: "10.8.0.2:19022"}
	src := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 40000}
	cl.log(r, src, nil)
	cl.log(r, src, nil)

	dir := filepath.Dir(logPath)
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var rotated, current int
	for _, f := range files {
		switch {
		case f.Name() == "portbridge.json":
			current++
		case strings.HasPrefix(f.Name(), "portbridge.json."):
			rotated++
		}
	}
	if rotated != 1 {
		t.Fatalf("want exactly 1 rotated file after 2 writes with LOG_MAX_BYTES=1, got %d (files: %v)", rotated, files)
	}
	if current != 1 {
		t.Fatalf("want the original path still present and receiving writes, got %d", current)
	}

	// Every line across both files must still be a valid, complete record --
	// rotation must never truncate or split one mid-write.
	total := 0
	for _, f := range files {
		if f.Name() != "portbridge.json" && !strings.HasPrefix(f.Name(), "portbridge.json.") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("corrupt line across rotation: %v (%q)", err, line)
			}
			total++
		}
	}
	if total != 2 {
		t.Fatalf("want both log lines to survive across the rotation, got %d", total)
	}
}

func lastConnLogRecord(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("want exactly one line for one client session, got %d: %q", len(lines), string(data))
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}
