package main

import (
	"net/http/httptest"
	"testing"
)

// #1268: /recordings gives TTY session replays a dedicated, browsable entry
// point -- previously the only way to find one was to already know a
// session ID, or spot the one event row (buried in /events or
// /sessions/<id>) whose TTYReplay field happens to be set.

func TestRecordingsDataOnlyIncludesEventsWithReplay(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Session: "abc", Time: "2026-08-01 01:00", UTC: "2026-08-01T01:00:00Z", TTYReplay: "/tty/deadbeef"},
		{SrcIP: "203.0.113.2", Sensor: "cowrie", Command: "id", Time: "2026-08-01 01:01", UTC: "2026-08-01T01:01:00Z"},
	}}
	page := s.recordingsData(httptest.NewRequest("GET", "/recordings", nil))
	if len(page.Rows) != 1 {
		t.Fatalf("expected only the event carrying TTYReplay, got %+v", page.Rows)
	}
	if page.Rows[0].SrcIP != "203.0.113.1" || page.Rows[0].Session != "abc" || page.Rows[0].TTYReplay != "/tty/deadbeef" {
		t.Fatalf("got %+v", page.Rows[0])
	}
}

func TestRecordingsDataNewestFirst(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Time: "2026-08-01 01:00", UTC: "2026-08-01T01:00:00Z", TTYReplay: "/tty/older"},
		{SrcIP: "203.0.113.2", Sensor: "cowrie", Time: "2026-08-01 02:00", UTC: "2026-08-01T02:00:00Z", TTYReplay: "/tty/newer"},
	}}
	page := s.recordingsData(httptest.NewRequest("GET", "/recordings", nil))
	if len(page.Rows) != 2 || page.Rows[0].TTYReplay != "/tty/newer" || page.Rows[1].TTYReplay != "/tty/older" {
		t.Fatalf("expected newest-first order, got %+v", page.Rows)
	}
}

func TestRecordingsDataAppliesIPFilter(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Time: "2026-08-01 01:00", UTC: "2026-08-01T01:00:00Z", TTYReplay: "/tty/a"},
		{SrcIP: "203.0.113.2", Sensor: "cowrie", Time: "2026-08-01 01:01", UTC: "2026-08-01T01:01:00Z", TTYReplay: "/tty/b"},
	}}
	page := s.recordingsData(httptest.NewRequest("GET", "/recordings?ip=203.0.113.1", nil))
	if len(page.Rows) != 1 || page.Rows[0].TTYReplay != "/tty/a" {
		t.Fatalf("ip filter did not narrow to the matching row: %+v", page.Rows)
	}
	if len(page.Filters) != 1 || page.Filters[0] != "ip = 203.0.113.1" {
		t.Fatalf("expected an ip filter chip, got %+v", page.Filters)
	}
}

func TestRecordingsDataEmptyWithNoRecordings(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Command: "id", Time: "2026-08-01 01:00"},
	}}
	page := s.recordingsData(httptest.NewRequest("GET", "/recordings", nil))
	if len(page.Rows) != 0 {
		t.Fatalf("expected no rows, got %+v", page.Rows)
	}
}
