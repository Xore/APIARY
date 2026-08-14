package main

import (
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestEmittedSensorFieldMatchesLogDirectoryName guards against the exact
// failure shape #549 (conpot persona extraction) found this same session:
// event.sensor in Elasticsearch comes from this field, and
// loadSensorEventsES's query is keyed off the log directory name
// (docker-compose.endlessh.yml mounts logs/endlessh). A mismatch here
// makes ES-preferred reads for this sensor silently return zero results
// forever.
func TestEmittedSensorFieldMatchesLogDirectoryName(t *testing.T) {
	buf := &syncBuffer{}
	log := &logger{out: buf}
	log.emit(event{Event: "connect"})
	events := buf.lines(t)
	if len(events) != 1 || events[0].Sensor != "endlessh" {
		t.Fatalf(`emitted event.sensor = %q, want "endlessh" (must match the logs/endlessh directory name docker-compose.endlessh.yml mounts)`, events[0].Sensor)
	}
}

func TestRandomBannerLineNeverStartsWithSSHPrefix(t *testing.T) {
	for i := 0; i < 500; i++ {
		line := randomBannerLine()
		if len(line) < 3 || len(line) > 30 {
			t.Fatalf("line length %d out of [3,30]: %q", len(line), line)
		}
		if strings.HasPrefix(line, "SSH-") {
			t.Fatalf("line must never start with the real SSH identification prefix: %q", line)
		}
		for _, r := range line {
			if r < 0x20 || r > 0x7e {
				t.Fatalf("line must be printable ASCII, got %q", line)
			}
		}
	}
}

// TestResolveDelayRejectsNonPositive covers #1349: DELAY_MS=0 (or negative)
// must be rejected here, at startup, rather than reaching serve's
// time.NewTicker(delay), which panics for any non-positive duration inside
// a per-connection goroutine with no recover.
func TestResolveDelayRejectsNonPositive(t *testing.T) {
	for _, ms := range []int{0, -1, -10000} {
		if _, err := resolveDelay(ms); err == nil {
			t.Errorf("resolveDelay(%d) = nil error, want a rejection", ms)
		}
	}
}

func TestResolveDelayAcceptsPositive(t *testing.T) {
	d, err := resolveDelay(10000)
	if err != nil {
		t.Fatalf("resolveDelay(10000) = %v, want no error", err)
	}
	if d != 10*time.Second {
		t.Fatalf("resolveDelay(10000) = %s, want 10s", d)
	}
}

// TestNextAcceptBackoffDoublesAndCaps covers #1349: repeated Accept()
// errors must back off instead of retrying unconditionally (which spins a
// CPU core at 100% under persistent fd exhaustion), and the backoff must
// not grow unbounded.
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

func TestPortOfParsesListenAddr(t *testing.T) {
	cases := map[string]int{":2222": 2222, "0.0.0.0:22": 22, "not-an-addr": 0}
	for addr, want := range cases {
		if got := portOf(addr); got != want {
			t.Errorf("portOf(%q) = %d, want %d", addr, got, want)
		}
	}
}

// syncBuffer lets the logger's io.Writer be read concurrently with emit()'s
// own mutex-protected writes, since serve() logs from a goroutine.
type syncBuffer struct {
	mu   sync.Mutex
	data []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *syncBuffer) lines(t *testing.T) []event {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var events []event
	for _, line := range strings.Split(strings.TrimSpace(string(b.data)), "\n") {
		if line == "" {
			continue
		}
		var e event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("logged line is not valid JSON: %q: %v", line, err)
		}
		events = append(events, e)
	}
	return events
}

// TestServeHoldsConnectionAndDripFeedsLines proves the actual point of the
// tarpit: the connection stays open and receives multiple non-SSH-prefixed
// lines over time rather than a single burst, and logs connect then
// disconnect with the real line count and held duration once the client
// gives up.
func TestServeHoldsConnectionAndDripFeedsLines(t *testing.T) {
	buf := &syncBuffer{}
	log := &logger{out: buf}
	server, client := net.Pipe()

	done := make(chan struct{})
	go func() {
		serve(server, log, 2222, 5*time.Millisecond)
		close(done)
	}()

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf2 := make([]byte, 512)
	total := 0
	for total < 20 { // wait for a few drip-fed lines before giving up
		n, err := client.Read(buf2[total:])
		if err != nil {
			t.Fatalf("reading from the tarpit connection failed before enough data arrived: %v", err)
		}
		total += n
	}
	got := string(buf2[:total])
	if strings.Contains(got, "SSH-") {
		t.Fatalf("tarpit connection must never send the real SSH identification string: %q", got)
	}
	if !strings.Contains(got, "\r\n") {
		t.Fatalf("banner lines must be CRLF-terminated: %q", got)
	}

	client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serve() did not return after the client disconnected")
	}

	events := buf.lines(t)
	if len(events) != 2 {
		t.Fatalf("got %d logged events, want exactly 2 (connect, disconnect): %+v", len(events), events)
	}
	if events[0].Event != "connect" {
		t.Fatalf("first event = %q, want \"connect\"", events[0].Event)
	}
	last := events[len(events)-1]
	if last.Event != "disconnect" {
		t.Fatalf("last event = %q, want \"disconnect\"", last.Event)
	}
	if last.Lines == 0 {
		t.Fatal("disconnect event must record a non-zero line count")
	}
	if last.HeldMS == 0 {
		t.Fatal("disconnect event must record a non-zero held duration")
	}
}
