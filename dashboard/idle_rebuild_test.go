package main

import (
	"testing"
	"time"
)

// #486: the periodic rebuild loop skips its ES/log round-trip once
// idleSince() exceeds rebuildIdleThreshold. These tests cover the store-side
// half of that decision (touchActivity/idleSince); the loop itself is a
// straight comparison against these two, exercised live in main().

func TestIdleSinceIsZeroBeforeAnyActivity(t *testing.T) {
	s := &store{}
	if got := s.idleSince(); got != 0 {
		t.Fatalf("idleSince() before touchActivity = %v, want 0 (must not read as idle before the first request)", got)
	}
}

func TestTouchActivityResetsIdleClock(t *testing.T) {
	s := &store{}
	s.touchActivity()
	if got := s.idleSince(); got < 0 || got > time.Second {
		t.Fatalf("idleSince() immediately after touchActivity = %v, want ~0", got)
	}
}

func TestIdleSinceGrowsWithoutFurtherActivity(t *testing.T) {
	s := &store{}
	s.lastActivity.Store(time.Now().Add(-5 * time.Minute).Unix())
	if got := s.idleSince(); got < rebuildIdleThreshold {
		t.Fatalf("idleSince() = %v, want >= rebuildIdleThreshold (%v) for a 5m-old touch", got, rebuildIdleThreshold)
	}
}
