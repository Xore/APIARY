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

// #266: DASHBOARD_BACKGROUND_LOOPS=false opts a secondary rolling-update
// replica out of notifyLoop/reportScheduleLoop so exactly one replica ever
// fires webhook alerts or generates scheduled reports -- unset (the default,
// every existing single-instance deployment) must keep running them.
func TestBackgroundLoopsEnabledDefaultsTrue(t *testing.T) {
	t.Setenv("DASHBOARD_BACKGROUND_LOOPS", "")
	if !backgroundLoopsEnabled() {
		t.Fatal("background loops must run by default (unset env var)")
	}
}

func TestBackgroundLoopsDisabledOnlyByExactlyFalse(t *testing.T) {
	t.Setenv("DASHBOARD_BACKGROUND_LOOPS", "false")
	if backgroundLoopsEnabled() {
		t.Fatal("DASHBOARD_BACKGROUND_LOOPS=false must disable the background loops")
	}
	t.Setenv("DASHBOARD_BACKGROUND_LOOPS", "0")
	if !backgroundLoopsEnabled() {
		t.Fatal(`only the exact value "false" should disable background loops, not "0"`)
	}
}
