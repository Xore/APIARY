package main

import (
	"net/http/httptest"
	"strings"
	"testing"
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
