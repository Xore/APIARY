package main

import (
	"sync/atomic"
	"testing"
	"time"
)

// #1980: one panicking cycle must cost the cycle, not the process — the
// loop keeps ticking and runs the next cycle, which is what keeps the
// derived indexes refreshing after a malformed document.
//
// Deliberately no timing assertions here: runLoop's cadence honesty is
// trivially reviewed code, and wall-clock assertions in CI trade flakiness
// for coverage (see the repo's own flaky-test history, #2209/#2113).
func TestRunLoopContinuesAfterAPanickingCycle(t *testing.T) {
	var cycles atomic.Int32
	restarted := make(chan struct{})
	stopped := make(chan struct{})
	defer close(stopped)

	go runLoop("test-worker", time.Millisecond, func() {
		switch cycles.Add(1) {
		case 1:
			panic("simulated malformed-document panic (#1980)")
		case 2:
			// Only reachable if runLoop survived cycle one's panic.
			close(restarted)
			<-stopped
		default:
			<-stopped
		}
	})

	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatalf("loop did not survive the panicking cycle; cycles observed: %d", cycles.Load())
	}
}
