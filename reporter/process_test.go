package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestProcessor(t *testing.T, minHits int) (*processor, *strings.Builder) {
	t.Helper()
	st, err := openStore(filepath.Join(t.TempDir(), "reported.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	wl, err := loadWhitelist("")
	if err != nil {
		t.Fatal(err)
	}
	var audit strings.Builder
	al := newAuditLog(&audit)
	send := dryRunSender{audit: al}
	return newProcessor(wl, st, send, al, 24*time.Hour, minHits), &audit
}

func lastAuditEntry(t *testing.T, audit *strings.Builder) auditEntry {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(audit.String()), "\n")
	var e auditEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestProcessorSkipsWhitelistedSource(t *testing.T) {
	proc, audit := newTestProcessor(t, 1)
	proc.handle("cowrie", []byte(`{"eventid":"cowrie.login.failed","src_ip":"10.8.0.1"}`))
	e := lastAuditEntry(t, audit)
	if e.Action != "skipped" || !strings.Contains(e.Reason, "tunnel peer") {
		t.Fatalf("got %+v, want a skipped/tunnel-peer entry", e)
	}
}

func TestProcessorSkipsUncategorizedEvent(t *testing.T) {
	proc, audit := newTestProcessor(t, 1)
	proc.handle("some-unknown-sensor", []byte(`{"src_ip":"203.0.113.7","eventid":"whatever"}`))
	e := lastAuditEntry(t, audit)
	if e.Action != "skipped" || e.Reason != "uncategorized event" {
		t.Fatalf("got %+v, want skipped/uncategorized", e)
	}
}

func TestProcessorEnforcesMinimumEventThreshold(t *testing.T) {
	proc, audit := newTestProcessor(t, 3)
	line := []byte(`{"eventid":"cowrie.login.failed","src_ip":"203.0.113.7"}`)

	proc.handle("cowrie", line)
	e := lastAuditEntry(t, audit)
	if e.Action != "skipped" || e.Reason != "below minimum event threshold" {
		t.Fatalf("hit 1: got %+v, want skipped/below threshold", e)
	}

	proc.handle("cowrie", line)
	e = lastAuditEntry(t, audit)
	if e.Action != "skipped" || e.Reason != "below minimum event threshold" {
		t.Fatalf("hit 2: got %+v, want skipped/below threshold", e)
	}

	proc.handle("cowrie", line)
	e = lastAuditEntry(t, audit)
	if e.Action != "would_report" {
		t.Fatalf("hit 3 (meets threshold): got %+v, want would_report", e)
	}
}

func TestProcessorRespectsCooldownAfterReporting(t *testing.T) {
	proc, audit := newTestProcessor(t, 1)
	line := []byte(`{"eventid":"cowrie.login.failed","src_ip":"203.0.113.7"}`)

	proc.handle("cowrie", line)
	e := lastAuditEntry(t, audit)
	if e.Action != "would_report" {
		t.Fatalf("first hit: got %+v, want would_report", e)
	}

	proc.handle("cowrie", line)
	e = lastAuditEntry(t, audit)
	if e.Action != "skipped" || e.Reason != "within cooldown window" {
		t.Fatalf("second hit inside cooldown: got %+v, want skipped/cooldown", e)
	}
}

// TestProcessorDedupesBackfilledHistoryDespiteOldEventTimestamps is the
// regression case for the bug caught during #68's live verification: a
// fresh reporter's first poll reads the *entire* existing log backlog, all
// of it with timestamps from days ago. If cooldown bookkeeping used the
// event's own timestamp instead of wall-clock now, "time since a 3-day-old
// event" is never less than a 24h window, so every event past the
// minimum-hits threshold re-triggered would_report throughout the whole
// backfill instead of deduping after the first one -- confirmed live,
// 49,105 would_report entries where cooldown should have collapsed most of
// them to a handful.
func TestProcessorDedupesBackfilledHistoryDespiteOldEventTimestamps(t *testing.T) {
	proc, audit := newTestProcessor(t, 1)
	// A timestamp from days before "now" -- exactly what a first-ever poll
	// of an existing sensor log looks like.
	old := `{"eventid":"cowrie.login.failed","src_ip":"203.0.113.7","time":"2026-07-28T12:00:00Z"}`

	proc.handle("cowrie", []byte(old))
	e := lastAuditEntry(t, audit)
	if e.Action != "would_report" {
		t.Fatalf("first old-timestamped event: got %+v, want would_report", e)
	}

	proc.handle("cowrie", []byte(old))
	e = lastAuditEntry(t, audit)
	if e.Action != "skipped" || e.Reason != "within cooldown window" {
		t.Fatalf("second old-timestamped event for the same IP: got %+v, want skipped/cooldown -- "+
			"if this is would_report again, cooldown bookkeeping regressed to using the event's own "+
			"historical timestamp instead of wall-clock now", e)
	}
}

func TestProcessorIgnoresLinesWithNoIP(t *testing.T) {
	proc, audit := newTestProcessor(t, 1)
	proc.handle("cowrie", []byte(`{"eventid":"cowrie.session.closed"}`))
	if audit.Len() != 0 {
		t.Fatalf("a line with no IP should produce no audit entry at all, got: %s", audit.String())
	}
}
