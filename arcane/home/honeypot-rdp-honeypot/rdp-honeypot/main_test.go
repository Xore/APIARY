package main

import (
	"encoding/base64"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestExtractUsernameFindsMstshashCookie(t *testing.T) {
	data := []byte("Cookie: mstshash=jdoe\r\n\x01\x00\x08\x00")
	if got := extractUsername(data); got != "jdoe" {
		t.Fatalf("username = %q, want jdoe", got)
	}
}

func TestExtractUsernameEmptyWhenAbsent(t *testing.T) {
	data := []byte("\x03\x00\x00\x2b\x25\xe0\x00\x00\x00\x00\x00")
	if got := extractUsername(data); got != "" {
		t.Fatalf("username = %q, want empty", got)
	}
}

func TestExtractUsernameOnlyMatchesAllowedCharacters(t *testing.T) {
	// A real client's cookie username is alnum/-/_/@ only, matching
	// upstream's own regex character class.
	data := []byte("mstshash=user-name_1@corp")
	if got := extractUsername(data); got != "user-name_1@corp" {
		t.Fatalf("username = %q", got)
	}
}

func TestExtractNegotiationProtocolsDecodesRequestedBitmask(t *testing.T) {
	// type=0x01 (TYPE_RDP_NEG_REQ), flags=0x00, length=8 (LE), protocols
	// bitmask 0x00000003 (TLS | CredSSP) -- the whole 8-byte structure
	// MS-RDPBCGR fixes as the tail of the X.224 Connection Request.
	data := append([]byte("Cookie: mstshash=jdoe\r\n"), 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00)
	got, ok := extractNegotiationProtocols(data)
	if !ok {
		t.Fatal("expected RDP_NEG_REQ to be recognized")
	}
	if got != "TLS+CredSSP" {
		t.Fatalf("protocols = %q, want TLS+CredSSP", got)
	}
}

func TestExtractNegotiationProtocolsZeroMeansPlainRDP(t *testing.T) {
	data := append([]byte("Cookie: mstshash=jdoe\r\n"), 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00)
	got, ok := extractNegotiationProtocols(data)
	if !ok || got != "RDP" {
		t.Fatalf("protocols = %q ok=%v, want RDP true", got, ok)
	}
}

func TestExtractNegotiationProtocolsAbsentWhenNoNegReq(t *testing.T) {
	// A bare cookie with no trailing RDP_NEG_REQ structure at all.
	data := []byte("Cookie: mstshash=jdoe\r\n")
	if _, ok := extractNegotiationProtocols(data); ok {
		t.Fatal("expected no negotiation protocols to be recognized without a trailing RDP_NEG_REQ")
	}
}

func TestServeLogsConnectionAndSendsNegFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	log := newLogger("")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		serve(c, log, 3389)
	}()

	client, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	payload := []byte("Cookie: mstshash=attacker01\r\n\x01\x00\x08\x00")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != negFailure {
		t.Fatalf("response = %q, want %q", got, negFailure)
	}
}

func TestServeLoggedEventCapturesUsernameAndBase64Data(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Use a real file-backed logger so the emitted JSON can be inspected --
	// newLogger("") only writes to stdout.
	logPath := t.TempDir() + "/rdp.json"
	log := newLogger(logPath)

	done := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		serve(c, log, 3389)
		close(done)
	}()

	client, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("Cookie: mstshash=attacker01\r\n")
	client.Write(payload)
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	client.Read(buf)
	client.Close()
	<-done

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	data := string(raw)
	if !strings.Contains(data, `"username":"attacker01"`) {
		t.Fatalf("log missing username: %s", data)
	}
	wantData := base64.StdEncoding.EncodeToString(payload)
	if !strings.Contains(data, wantData) {
		t.Fatalf("log missing base64 data %q: %s", wantData, data)
	}
	if !strings.Contains(data, `"proto":"rdp"`) {
		t.Fatalf("log missing proto=rdp: %s", data)
	}
}

func TestServeIgnoresEmptyReadWithoutLogging(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	log := newLogger("")
	done := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		serve(c, log, 3389)
		close(done)
	}()

	client, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.Close() // close immediately without sending anything

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after client closed without sending data")
	}
}

// TestSpawnServeDoesNotBlockOnSilentPeer covers #2099: the PROXY-header
// decode must run inside the spawned goroutine, never in the accept loop.
// spawnServe's previous equivalent -- `go serve(decodeProxy(c, proxy), ...)`
// -- looks like the safe shape but is not: a go statement's arguments are
// evaluated synchronously on the calling goroutine, so the 5s-bounded
// decode ran before serve ever started and one silent connection stalled
// admission of every other connection. The test calls spawnServe directly
// with a peer that never sends a header; the call itself must return long
// before that deadline would expire if the decode were synchronous.
func TestSpawnServeDoesNotBlockOnSilentPeer(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	// Deliberately send nothing from the client side.

	done := make(chan struct{}, 1)
	go func() {
		spawnServe(server, true, newLogger(""), 3389, func() {})
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("spawnServe blocked on a silent peer -- the decode ran outside its goroutine")
	}
}

// TestNextAcceptBackoffDoublesAndCaps covers #2328: repeated Accept()
// errors must back off instead of retrying unconditionally (which spins a
// CPU core at 100% under persistent fd exhaustion), and the backoff must
// not grow unbounded. Ported from endlessh-honeypot/main_test.go.
func TestNextAcceptBackoffDoublesAndCaps(t *testing.T) {
	d := time.Duration(0)
	d = nextAcceptBackoff(d)
	if d != 5*time.Millisecond {
		t.Fatalf("first backoff = %s, want 5ms", d)
	}
	d = nextAcceptBackoff(d)
	if d != 10*time.Millisecond {
		t.Fatalf("second backoff = %s, want 10ms", d)
	}
	for i := 0; i < 20; i++ {
		d = nextAcceptBackoff(d)
	}
	if d != maxAcceptBackoff {
		t.Fatalf("backoff after many failures = %s, want it capped at %s", d, maxAcceptBackoff)
	}
}

// TestSpawnServeReleasesSemaphoreOnCompletion covers #2328: the MAX_CLIENTS
// semaphore slot must be released when the connection handler actually
// finishes, not when spawnServe returns (spawnServe returns immediately,
// per TestSpawnServeDoesNotBlockOnSilentPeer above).
func TestSpawnServeReleasesSemaphoreOnCompletion(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	released := make(chan struct{}, 1)
	spawnServe(server, false, newLogger(""), 3389, func() { released <- struct{}{} })

	select {
	case <-released:
		t.Fatal("release fired before the connection handler ran -- semaphore slot freed too early")
	case <-time.After(50 * time.Millisecond):
	}

	// handleConn's serve() reads with a 10s deadline and returns once the
	// peer sends nothing more and closes -- closing the client conn ends
	// the read and lets serve() (and therefore release) proceed.
	client.Close()

	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("release never fired after the connection closed")
	}
}
