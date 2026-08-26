package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPipeTCPClosesIdleConnection verifies that a forwarded connection with
// no data flowing in either direction is closed once it exceeds the idle
// timeout, instead of being held open (and its goroutines/fds pinned)
// forever.
func TestPipeTCPClosesIdleConnection(t *testing.T) {
	// Upstream "target" that accepts and then goes silent, like a
	// legitimate service that just hasn't sent anything yet.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstreamLn.Close()
	go func() {
		c, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(2 * time.Second)
	}()

	// Front listener that stands in for the honeypot's public accept
	// loop, so we can obtain a real net.Conn pair to hand to pipeTCP.
	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen front: %v", err)
	}
	defer frontLn.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := frontLn.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	attacker, err := net.Dial("tcp", frontLn.Addr().String())
	if err != nil {
		t.Fatalf("dial front: %v", err)
	}
	defer attacker.Close()

	var serverSide net.Conn
	select {
	case serverSide = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for front accept")
	}

	done := make(chan struct{})
	go func() {
		pipeTCP(serverSide, upstreamLn.Addr().String(), 100*time.Millisecond)
		close(done)
	}()

	// The attacker sends nothing and reads nothing. Once the idle
	// timeout trips, pipeTCP must close its side, which the attacker
	// observes as EOF.
	attacker.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = attacker.Read(buf)
	if err == nil {
		t.Fatal("expected idle connection to be closed, got no error")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeTCP did not return after idle timeout")
	}
}

// failListener fails every Accept with the injected error until Close is
// called, after which it reports net.ErrClosed so acceptLoop can exit.
type failListener struct {
	err    error
	closed chan struct{}
}

func newFailListener(err error) *failListener {
	return &failListener{err: err, closed: make(chan struct{})}
}

func (f *failListener) Accept() (net.Conn, error) {
	select {
	case <-f.closed:
		return nil, net.ErrClosed
	default:
		return nil, f.err
	}
}

func (f *failListener) Close() error   { close(f.closed); return nil }
func (f *failListener) Addr() net.Addr { return &net.TCPAddr{} }

// captureErrOut swaps errOut behind a synchronized buffer so tests can assert
// on log lines without racing an async drain.
func captureErrOut(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var sb strings.Builder
	old := errOut
	errOut = writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return sb.Write(p)
	})
	t.Cleanup(func() { errOut = old })
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return sb.String()
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// #2240: a persistently failing Accept must neither peg a core (the old bare
// `continue` hot-looped, worst exactly at fd exhaustion) nor pass silently.
// Driven with a shrunk backoff window so this runs in milliseconds; the loop
// must also end cleanly when the listener closes.
func TestAcceptLoopBacksOffAndLogsOnPersistentFailure(t *testing.T) {
	read := captureErrOut(t)

	const minBackoff = 5 * time.Millisecond
	ln := newFailListener(errors.New("accept: too many open files"))

	exited := make(chan struct{})
	go func() {
		defer close(exited)
		spawn := func(c net.Conn) { t.Error("no conn should ever be spawned") }
		acceptLoop(ln, "127.0.0.1:9", spawn,
			acceptOptions{backoffMin: minBackoff, backoffMax: 20 * time.Millisecond, logEvery: 25})
	}()

	time.Sleep(300 * time.Millisecond)

	out := read()
	if !strings.Contains(out, "still retrying") {
		t.Fatalf("persistent accept failure produced no log line:\n%s", out)
	}
	if !strings.Contains(out, "too many open files") {
		t.Fatalf("log line does not name the underlying error:\n%s", out)
	}

	// Closing the listener is the clean exit -- nothing else terminates the
	// loop, which is the deliberate restart-by-backoff semantics (#2240).
	ln.Close()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("acceptLoop did not exit after listener close")
	}
}

// udpEcho spins up an echo server that stands in for the upstream target and
// returns its UDP address.
func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := up.ReadFromUDP(buf)
			if err != nil {
				return
			}
			up.WriteToUDP(buf[:n], from)
		}
	}()
	t.Cleanup(func() { up.Close() })
	return up.LocalAddr().(*net.UDPAddr)
}

// The forwarder clock is faked forward manually so eviction/shed behavior is
// deterministic without waiting out a real reply window.
var fakeNow = time.Unix(1_700_000_000, 0)

func advance(d time.Duration) { fakeNow = fakeNow.Add(d) }

func newTestForwarder(t *testing.T, max int, echo *net.UDPAddr) *udpForwarder {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("front listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &udpForwarder{
		label:    "test",
		conn:     conn,
		target:   echo,
		max:      max,
		shedLog:  &rateLimitedLog{interval: time.Minute},
		sessions: map[string]*udpSession{},
		now:      func() time.Time { return fakeNow },
	}
}

// dialFresh mints a client with its own distinct source tuple and round-trips
// one datagram through the forwarder to the echo server, asserting the reply
// path still works -- the property #2240's cap must never break.
func dialFresh(t *testing.T, f *udpForwarder, label string) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp", nil, f.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("%s dial: %v", label, err)
	}
	msg := []byte(fmt.Sprintf("hello-%s", label))
	f.forward(c.LocalAddr().(*net.UDPAddr), msg)

	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("%s reply broken: %v", label, err)
	}
	return c
}

// A table full of sessions whose most recent use is older than the reply
// window must evict the oldest one to admit the newcomer rather than shed it,
// and fresh sessions must survive the sweep untouched.
func TestUDPTableEvictsStaleSessionAtCap(t *testing.T) {
	echo := udpEcho(t)
	read := captureErrOut(t)
	f := newTestForwarder(t, 2, echo)

	a := dialFresh(t, f, "a")
	defer a.Close()
	b := dialFresh(t, f, "b")
	defer b.Close()

	f.mu.Lock()
	f.sessions[a.LocalAddr().String()].lastUse = fakeNow.Add(-4 * udpReplyWindow)
	f.mu.Unlock()

	dialFresh(t, f, "c") // forces eviction of exactly a

	f.mu.Lock()
	size := len(f.sessions)
	_, aLive := f.sessions[a.LocalAddr().String()]
	bLive := f.sessions[b.LocalAddr().String()] != nil
	f.mu.Unlock()

	if size != 2 {
		t.Fatalf("table size = %d, want 2", size)
	}
	if aLive {
		t.Fatal("stale session a was not evicted")
	}
	if !bLive {
		t.Fatal("fresh session b was wrongly evicted")
	}
	if out := read(); !strings.Contains(out, "evicted stale session") {
		t.Fatalf("eviction not logged:\n%s", out)
	}
}

// A table full of LIVE sessions (everyone touched inside the reply window)
// must keep them and shed the brand-new client instead, with a log line that
// names the churn pattern; afterwards the established session still works.
func TestUDPTableShedsFreshClientWhenFullOfLiveSessions(t *testing.T) {
	echo := udpEcho(t)
	read := captureErrOut(t)
	f := newTestForwarder(t, 1, echo)

	a := dialFresh(t, f, "a")
	defer a.Close()
	advance(time.Second) // a stays well inside the reply window

	n := f.forward(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 99), Port: 44444}, []byte("intruder"))
	if n != 0 {
		t.Fatalf("fresh datagram was not dropped when table was live-full: n=%d", n)
	}
	f.mu.Lock()
	size := len(f.sessions)
	f.mu.Unlock()
	if size != 1 {
		t.Fatalf("shedding changed table size: %d", size)
	}
	if out := read(); !strings.Contains(out, "dropping datagram") ||
		!strings.Contains(out, "cycling source ports") {
		t.Fatalf("shed not logged with churn hint:\n%s", out)
	}

	// The pre-existing live session keeps working afterwards.
	msg := []byte("ping-a")
	f.forward(a.LocalAddr().(*net.UDPAddr), msg)
	a.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := a.Read(buf); err != nil {
		t.Fatalf("live session broke after shedding: %v", err)
	}
}
