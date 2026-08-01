package main

import (
	"strings"
	"testing"
	"time"
)

// TestEarliestEventByShasum (#205): the /payloads list and payload-analysis
// detail page both need "which event produced this capture", recovered by
// matching a file's hash against the event feed's Shasum field. Several
// events can share a hash (the same payload downloaded more than once) --
// the earliest one is the one that actually brought the file in, so that is
// the one that must win, regardless of feed order.
func TestEarliestEventByShasum(t *testing.T) {
	t0 := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	events := []storedEvent{
		{Shasum: "aaa", Sensor: "cowrie", Session: "sess-2", when: t0.Add(2 * time.Hour)},
		{Shasum: "aaa", Sensor: "cowrie", Session: "sess-1", when: t0},
		{Shasum: "bbb", Sensor: "dionaea", when: t0.Add(time.Hour)},
		{Shasum: "", Sensor: "cowrie", when: t0}, // no shasum: must not appear in the result
	}
	origins := earliestEventByShasum(events)

	if len(origins) != 2 {
		t.Fatalf("expected 2 hashes with an origin, got %d: %+v", len(origins), origins)
	}
	got, ok := origins["aaa"]
	if !ok {
		t.Fatal(`missing origin for "aaa"`)
	}
	if got.Session != "sess-1" || !got.when.Equal(t0) {
		t.Fatalf("earliest event for %q must win, got session=%q when=%v", "aaa", got.Session, got.when)
	}
	if got2 := origins["bbb"]; got2.Sensor != "dionaea" {
		t.Fatalf(`expected "bbb"'s origin sensor to be dionaea, got %q`, got2.Sensor)
	}
	if _, ok := origins[""]; ok {
		t.Fatal("an event with no shasum must not produce an origin entry")
	}
}

// TestPayloadsPageDropsRedundantActionButtons (#205): the standalone
// Analyze-in-sandbox and Disassemble-with-Ghidra buttons on /payloads and
// /payload-analysis/{hash} duplicated what the analysis workbench already
// does -- they were removed in favor of the workbench link plus a per-row
// kebab menu for the remaining secondary actions (preview/download/related
// events/publish). This pins that removal so it cannot silently regress.
func TestPayloadsPageDropsRedundantActionButtons(t *testing.T) {
	for _, gone := range []string{`action="/sandbox/submit"`, `action="/ghidra/submit"`} {
		if strings.Contains(pagePayloads, gone) {
			t.Fatalf("payloads/payload-analysis templates still post to %q -- "+
				"this action belongs in the analysis workbench now, not a standalone button", gone)
		}
	}
	if !strings.Contains(pagePayloads, `class="action-menu"`) {
		t.Fatal("payloads list row is missing the per-row action-menu kebab that replaced the flat button row")
	}
	if !strings.Contains(pagePayloads, "origin event") {
		t.Fatal(`payloads list header is missing the "origin event" column (#205)`)
	}
}
