package main

import (
	"testing"
	"time"
)

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
