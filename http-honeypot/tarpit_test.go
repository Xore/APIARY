package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewMarkovChainGeneratesVariedNonEmptyText(t *testing.T) {
	chain := newMarkovChain(markovSeedCorpus)
	if len(chain) == 0 {
		t.Fatal("chain built from a non-empty corpus must not be empty")
	}
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		out := chain.generate(20)
		words := strings.Fields(out)
		if len(words) != 20 {
			t.Fatalf("generate(20) produced %d words, want 20: %q", len(words), out)
		}
		seen[out] = true
	}
	if len(seen) < 2 {
		t.Fatal("10 generations of a random walk must not all be identical")
	}
}

func TestMarkovChainGenerateOnEmptyChainReturnsEmpty(t *testing.T) {
	var empty markovChain
	if got := empty.generate(10); got != "" {
		t.Fatalf("generate on an empty chain = %q, want empty", got)
	}
}

func TestTarpitCategoryMatchesScanAndRceProbeOnly(t *testing.T) {
	cases := []struct {
		category string
		want     bool
	}{
		{"scan", true},
		{"rce-probe", true},
		{"wordpress", false},
		{"login-probe", false},
		{"landing", false},
		{"cloud-metadata", false},
	}
	for _, c := range cases {
		if got := tarpitCategory(c.category); got != c.want {
			t.Errorf("tarpitCategory(%q) = %v, want %v", c.category, got, c.want)
		}
	}
}

// TestTarpitStreamsChunksUntilContextCancelled overrides the chunk delay to
// keep this fast (real production timing is exercised only by the constant
// itself, not by how many iterations the loop below runs) and cancels the
// context after a short wall-clock window -- tarpit() must return promptly
// once cancelled, having written the HTML preamble plus at least one
// Markov-generated chunk.
func TestTarpitStreamsChunksUntilContextCancelled(t *testing.T) {
	original := tarpitChunkDelay
	tarpitChunkDelay = time.Millisecond
	defer func() { tarpitChunkDelay = original }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	rec := httptest.NewRecorder()
	n, held := tarpit(ctx, rec)

	if n == 0 {
		t.Fatal("tarpit must write at least the HTML preamble before being cancelled")
	}
	if !strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Fatalf("tarpit response missing expected HTML preamble: %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "<p>") {
		t.Fatalf("tarpit response never wrote a Markov chunk within the window: %q", rec.Body.String())
	}
	if held <= 0 || held > time.Second {
		t.Fatalf("held duration = %v, want roughly the ~20ms context timeout", held)
	}
	if rec.Code != 200 {
		t.Fatalf("tarpit status = %d, want 200", rec.Code)
	}
}

// TestServeHTTPTarpitsUnrecognizedScanPath is an end-to-end check through
// ServeHTTP itself: an unrecognized path (classify() -> "scan") with
// tarpitting enabled must log Tarpitted with non-zero TarpitBytes, instead
// of going through serve()'s normal fast-404 path.
func TestServeHTTPTarpitsUnrecognizedScanPath(t *testing.T) {
	original := tarpitChunkDelay
	tarpitChunkDelay = time.Millisecond
	defer func() { tarpitChunkDelay = original }()

	var logged event
	// Capture what gets logged without depending on the real logger's
	// stdout/file writer.
	captured := make(chan event, 1)
	s := &server{
		log:           &logger{out: captureWriter{ch: captured}},
		sensor:        "http-honeypot",
		serverHdr:     "nginx/1.24.0 (Ubuntu)",
		tarpitEnabled: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest("GET", "/this-path-matches-nothing-defined", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	s.ServeHTTP(rec, req)

	select {
	case logged = <-captured:
	default:
		t.Fatal("ServeHTTP did not log an event")
	}
	if !logged.Tarpitted {
		t.Fatalf("expected the unrecognized-path request to be tarpitted, got event: %+v", logged)
	}
	if logged.TarpitBytes == 0 {
		t.Fatal("Tarpitted request must record non-zero TarpitBytes")
	}
	if logged.Category != "scan" {
		t.Fatalf("Category = %q, want \"scan\"", logged.Category)
	}
}

// captureWriter lets the tests above avoid writing to real stdout/files
// while still exercising logger.log's real JSON-encoding path.
type captureWriter struct{ ch chan event }

func (w captureWriter) Write(p []byte) (int, error) {
	var e event
	if err := json.Unmarshal(p, &e); err == nil {
		select {
		case w.ch <- e:
		default:
		}
	}
	return len(p), nil
}
