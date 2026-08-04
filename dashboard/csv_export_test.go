package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// #513: /ips, /campaigns, and /clusters had no CSV export at all, unlike
// their sibling investigate pages (/events, /commands). These mirror
// TestExportModalURLReflectsCurrentFilterNotUnfilteredSet's own shape (#59):
// the export URL must carry the current filter, and the export itself must
// return only the matching rows, never the unfiltered set.

func TestExportIPsCSVReflectsCurrentFilter(t *testing.T) {
	s := &store{events: []storedEvent{
		{Time: "2026-08-01 10:00", Sensor: "cowrie", SrcIP: "203.0.113.9"},
		{Time: "2026-08-01 10:01", Sensor: "dionaea", SrcIP: "198.51.100.7"},
	}}
	page := s.ipsData(httptest.NewRequest("GET", "/ips?sensor=cowrie", nil))
	if page.ExportURL != "/export/ips.csv?sensor=cowrie" {
		t.Fatalf("ExportURL did not carry the filter: got %q", page.ExportURL)
	}
	unfiltered := s.ipsData(httptest.NewRequest("GET", "/ips", nil))
	if unfiltered.ExportURL != "/export/ips.csv" {
		t.Fatalf("unfiltered ExportURL should carry no query: got %q", unfiltered.ExportURL)
	}

	rec := httptest.NewRecorder()
	s.exportIPsCSV(rec, httptest.NewRequest("GET", "/export/ips.csv?sensor=cowrie", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "203.0.113.9") {
		t.Fatal("filtered export is missing the matching IP")
	}
	if strings.Contains(body, "198.51.100.7") {
		t.Fatal("filtered export leaked an IP outside the current filter")
	}
}

func TestExportCampaignsCSVReflectsCurrentFilter(t *testing.T) {
	now := time.Now()
	s := &store{events: []storedEvent{
		{Time: "2026-08-01 10:00", Sensor: "cowrie", SrcIP: "203.0.113.9", when: now},
		{Time: "2026-08-01 10:01", Sensor: "dionaea", SrcIP: "198.51.100.100", when: now},
	}}
	page := s.campaignsData(httptest.NewRequest("GET", "/campaigns?sensor=cowrie", nil))
	if page.ExportURL != "/export/campaigns.csv?sensor=cowrie" {
		t.Fatalf("ExportURL did not carry the filter: got %q", page.ExportURL)
	}
	unfiltered := s.campaignsData(httptest.NewRequest("GET", "/campaigns", nil))
	if unfiltered.ExportURL != "/export/campaigns.csv" {
		t.Fatalf("unfiltered ExportURL should carry no query: got %q", unfiltered.ExportURL)
	}

	rec := httptest.NewRecorder()
	s.exportCampaignsCSV(rec, httptest.NewRequest("GET", "/export/campaigns.csv?sensor=cowrie", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "203.0.113.0/24") {
		t.Fatalf("filtered export is missing the matching network: %s", body)
	}
	if strings.Contains(body, "198.51.100.0/24") {
		t.Fatal("filtered export leaked a network outside the current filter")
	}
}

func TestExportClustersCSVReflectsCurrentFilterIncludingKind(t *testing.T) {
	now := time.Now()
	shasum := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	s := &store{events: []storedEvent{
		{Time: "2026-08-01 10:00", Sensor: "cowrie", SrcIP: "203.0.113.9", Shasum: shasum, when: now},
		{Time: "2026-08-01 10:01", Sensor: "cowrie", SrcIP: "198.51.100.7", Shasum: shasum, when: now},
		{Time: "2026-08-01 10:02", Sensor: "cowrie", SrcIP: "203.0.113.10", Fingerprint: "fp-x", when: now},
		{Time: "2026-08-01 10:03", Sensor: "cowrie", SrcIP: "198.51.100.8", Fingerprint: "fp-x", when: now},
	}}
	rec := httptest.NewRecorder()
	s.exportClustersCSV(rec, httptest.NewRequest("GET", "/export/clusters.csv?kind=Payload", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "Payload") {
		t.Fatalf("kind=Payload filter should keep the payload cluster row: %s", body)
	}
	if strings.Contains(body, "Fingerprint") {
		t.Fatalf("kind=Payload filter must exclude the fingerprint cluster row: %s", body)
	}
	rec2 := httptest.NewRecorder()
	s.exportClustersCSV(rec2, httptest.NewRequest("GET", "/export/clusters.csv?kind=Fingerprint", nil))
	body2 := rec2.Body.String()
	if !strings.Contains(body2, "Fingerprint") {
		t.Fatalf("kind=Fingerprint filter should keep the fingerprint cluster row: %s", body2)
	}
	if strings.Contains(body2, "Payload") {
		t.Fatalf("kind=Fingerprint filter must exclude the payload cluster row: %s", body2)
	}
}

func TestExportAttackerProfileEventsCSVIsIPScoped(t *testing.T) {
	s := &store{events: []storedEvent{
		{Time: "2026-08-01 10:00", Sensor: "cowrie", SrcIP: "203.0.113.9"},
		{Time: "2026-08-01 10:01", Sensor: "dionaea", SrcIP: "198.51.100.7"},
	}}
	profile, ok := s.attackerData("203.0.113.9")
	if !ok {
		t.Fatal("attackerData: no profile")
	}
	// #513: the attacker profile page reuses /export/events.csv?ip=... rather
	// than a dedicated endpoint -- exportEventsCSV already filters via
	// parseFilter(r), which already supports ip=. Prove the profile's own IP
	// round-trips through that existing filter correctly.
	rec := httptest.NewRecorder()
	s.exportEventsCSV(rec, httptest.NewRequest("GET", "/export/events.csv?ip="+profile.IP, nil))
	body := rec.Body.String()
	if !strings.Contains(body, "203.0.113.9") {
		t.Fatal("attacker profile export is missing the profile's own events")
	}
	if strings.Contains(body, "198.51.100.7") {
		t.Fatal("attacker profile export leaked an event for a different IP")
	}
}
