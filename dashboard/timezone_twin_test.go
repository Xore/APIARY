package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// #512: several pages rendered a "First"/"Last"/"Timestamp"/"Mtime" field as
// plain server-formatted text with no data-hp-utc twin, so hp-app.js's
// applyTimeDisplay() (the timezone/clock-format preference conversion
// events.html/alerts.html/overview.html already had) never touched them --
// an operator with a non-default timezone preference saw a silently wrong
// time on these pages. These tests assert the UTC twin is now populated
// alongside the existing display string, for every page's own data
// function, not just the template markup.

func TestAttackerDataCarriesUTCTwins(t *testing.T) {
	when := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.9", Sensor: "cowrie", Time: "2026-08-01 12:00", UTC: utcOrEmpty(when)},
	}}
	profile, ok := s.attackerData("203.0.113.9")
	if !ok {
		t.Fatal("attackerData: no profile")
	}
	want := utcOrEmpty(when)
	if profile.FirstUTC != want || profile.LastUTC != want {
		t.Fatalf("attacker profile UTC twins = %q/%q, want %q", profile.FirstUTC, profile.LastUTC, want)
	}
}

func TestSessionDataCarriesUTCTwins(t *testing.T) {
	when := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.9", Sensor: "cowrie", Session: "sess-a", Time: "2026-08-01 12:00", UTC: utcOrEmpty(when)},
	}}
	page, ok := s.sessionData("sess-a")
	if !ok {
		t.Fatal("sessionData: no page")
	}
	want := utcOrEmpty(when)
	if page.FirstUTC != want || page.LastUTC != want {
		t.Fatalf("session page UTC twins = %q/%q, want %q", page.FirstUTC, page.LastUTC, want)
	}
}

func TestBuildIPsDataCarriesUTCTwins(t *testing.T) {
	when := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.9", Sensor: "cowrie", Time: "2026-08-01 12:00", UTC: utcOrEmpty(when)},
	}}
	page := s.buildIPsData(filter{})
	if len(page.Rows) != 1 {
		t.Fatalf("expected 1 ip row, got %d", len(page.Rows))
	}
	want := utcOrEmpty(when)
	if page.Rows[0].FirstUTC != want || page.Rows[0].LastUTC != want {
		t.Fatalf("ip row UTC twins = %q/%q, want %q", page.Rows[0].FirstUTC, page.Rows[0].LastUTC, want)
	}
}

func TestCommandsDataCarriesUTCTwins(t *testing.T) {
	when := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.9", Sensor: "cowrie", Command: "id", Time: "2026-08-01 12:00", when: when},
	}}
	page := s.commandsData(httptest.NewRequest("GET", "/commands", nil))
	if len(page.Rows) != 1 {
		t.Fatalf("expected 1 command row, got %d", len(page.Rows))
	}
	want := utcOrEmpty(when)
	if page.Rows[0].FirstUTC != want || page.Rows[0].LastUTC != want {
		t.Fatalf("command row UTC twins = %q/%q, want %q", page.Rows[0].FirstUTC, page.Rows[0].LastUTC, want)
	}
}

func TestCorrelateCampaignsCarriesUTCTwins(t *testing.T) {
	when := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	evs := []storedEvent{
		{SrcIP: "203.0.113.9", Sensor: "cowrie", when: when},
	}
	rows := correlateCampaigns(evs, when.Add(-time.Hour))
	if len(rows) != 1 {
		t.Fatalf("expected 1 campaign row, got %d", len(rows))
	}
	want := utcOrEmpty(when)
	if rows[0].FirstUTC != want || rows[0].LastUTC != want {
		t.Fatalf("campaign row UTC twins = %q/%q, want %q", rows[0].FirstUTC, rows[0].LastUTC, want)
	}
}

func TestScanPayloadsCarriesMtimeUTC(t *testing.T) {
	dir := t.TempDir()
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	path := filepath.Join(dir, hash)
	if err := os.WriteFile(path, []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &store{payloadDirs: []string{dir}}
	page := s.scanPayloads()
	if len(page.Files) != 1 {
		t.Fatalf("expected 1 captured file, got %d", len(page.Files))
	}
	if page.Files[0].MtimeUTC == "" {
		t.Fatal("captured file MtimeUTC must be populated")
	}
}
