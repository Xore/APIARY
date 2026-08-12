package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// #280: /commands (and /export/commands.csv) gained the same query-string
// filtering /events already had.

func TestCommandsDataAppliesFilter(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Command: "id", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.2", Sensor: "dionaea", Command: "wget", Time: "2026-08-01 01:01"},
	}}
	page := s.commandsData(httptest.NewRequest("GET", "/commands?sensor=cowrie", nil))
	if len(page.Rows) != 1 || page.Rows[0].Command != "id" {
		t.Fatalf("sensor filter did not narrow /commands to the matching row: %+v", page.Rows)
	}
	if len(page.Filters) != 1 || page.Filters[0] != "sensor = cowrie" {
		t.Fatalf("expected a sensor filter chip, got %+v", page.Filters)
	}
}

// #1241: a trailing (or leading) space some sensors emit on an otherwise
// identical command used to group separately from the untrimmed version,
// showing up as a visually-indistinguishable duplicate row.
func TestCommandsDataTrimsWhitespaceBeforeGrouping(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Command: "enable", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.2", Sensor: "cowrie", Command: "enable ", Time: "2026-08-01 01:01"},
		{SrcIP: "203.0.113.3", Sensor: "cowrie", Command: " enable", Time: "2026-08-01 01:02"},
	}}
	page := s.commandsData(httptest.NewRequest("GET", "/commands", nil))
	if len(page.Rows) != 1 {
		t.Fatalf("expected the three whitespace variants to merge into one row, got %+v", page.Rows)
	}
	if page.Rows[0].Command != "enable" || page.Rows[0].Count != 3 {
		t.Fatalf("got %+v", page.Rows[0])
	}
}

func TestCommandsDataWhitespaceOnlyCommandExcluded(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Command: "   ", Time: "2026-08-01 01:00"},
	}}
	page := s.commandsData(httptest.NewRequest("GET", "/commands", nil))
	if len(page.Rows) != 0 {
		t.Fatalf("a whitespace-only command should not produce a row, got %+v", page.Rows)
	}
}

func TestCommandsDataUnfilteredShowsEveryRow(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Command: "id", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.2", Sensor: "dionaea", Command: "wget", Time: "2026-08-01 01:01"},
	}}
	page := s.commandsData(httptest.NewRequest("GET", "/commands", nil))
	if len(page.Rows) != 2 {
		t.Fatalf("expected both rows with no filter active, got %+v", page.Rows)
	}
}

// TestCommandsDataOrderIsDeterministicOnFullTie (#40): commandsData's sort
// used to tiebreak equal Counts purely by Last, which is minute-granularity
// ("2006-01-02 15:04") -- routine for the several distinct commands a burst
// of automated exploit traffic delivers within the same minute. With no
// further tiebreaker, sort.Slice (not stable) plus Go's per-process
// randomized map iteration order (groups is a map) meant two dashboard
// instances reading byte-identical underlying events could render /commands
// in a different row order -- confirmed live by running two fresh instances
// against one frozen, shared log snapshot. Runs the sort many times over
// fresh stores (each rebuilding its internal map from scratch, so iteration
// order varies run to run) and requires every run to agree.
func TestCommandsDataOrderIsDeterministicOnFullTie(t *testing.T) {
	when := time.Date(2026, 8, 3, 20, 26, 0, 0, time.UTC)
	events := []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "multipot", Command: "SLAVEOF NO ONE", Time: "2026-08-03 20:26", when: when},
		{SrcIP: "203.0.113.1", Sensor: "multipot", Command: "config set dbfilename dump.rdb", Time: "2026-08-03 20:26", when: when},
		{SrcIP: "203.0.113.1", Sensor: "multipot", Command: "config set dir .", Time: "2026-08-03 20:26", when: when},
	}
	var want []string
	for i := 0; i < 20; i++ {
		s := &store{events: append([]storedEvent(nil), events...)}
		page := s.commandsData(httptest.NewRequest("GET", "/commands", nil))
		got := make([]string, len(page.Rows))
		for j, r := range page.Rows {
			got[j] = r.Command
		}
		if want == nil {
			want = got
			continue
		}
		if len(got) != len(want) {
			t.Fatalf("run %d: row count changed: got %v, want %v", i, got, want)
		}
		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("run %d: order is not deterministic across runs: got %v, want %v", i, got, want)
			}
		}
	}
}

func TestExportCommandsCSVRespectsFilter(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Command: "id", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.2", Sensor: "dionaea", Command: "wget", Time: "2026-08-01 01:01"},
	}}
	rec := httptest.NewRecorder()
	s.exportCommandsCSV(rec, httptest.NewRequest("GET", "/export/commands.csv?sensor=cowrie", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "id") || strings.Contains(body, "wget") {
		t.Fatalf("expected the CSV export to respect the sensor filter, got: %s", body)
	}
}
