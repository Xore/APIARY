package main

import (
	"net/http/httptest"
	"testing"
)

// #280: /ips (and its lazy-load continuation, /api/ip-rows) gained the same
// query-string filtering /events already had.

func TestIPsDataAppliesFilter(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.2", Sensor: "dionaea", Time: "2026-08-01 01:01"},
	}}
	page := s.ipsData(httptest.NewRequest("GET", "/ips?sensor=cowrie", nil))
	if page.Total != 1 || len(page.Rows) != 1 || page.Rows[0].IP != "203.0.113.1" {
		t.Fatalf("sensor filter did not narrow /ips to the matching IP: %+v", page)
	}
	if len(page.Filters) != 1 || page.Filters[0] != "sensor = cowrie" {
		t.Fatalf("expected a sensor filter chip, got %+v", page.Filters)
	}
}

func TestIPsDataUnfilteredRequestsShareTheCache(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Time: "2026-08-01 01:00"},
	}}
	first := s.ipsData(httptest.NewRequest("GET", "/ips", nil))
	if first.Total != 1 {
		t.Fatalf("unexpected initial total: %+v", first)
	}
	// Mutate the underlying events without going through the cache -- an
	// unfiltered request within the 30s window must still see the cached
	// (stale) result, proving the cache path is actually being used.
	s.events = append(s.events, storedEvent{SrcIP: "203.0.113.2", Sensor: "dionaea", Time: "2026-08-01 01:01"})
	second := s.ipsData(httptest.NewRequest("GET", "/ips", nil))
	if second.Total != 1 {
		t.Fatalf("expected the cached (stale) total to survive within the cache window, got %+v", second)
	}
}

func TestIPsDataFilteredRequestsBypassTheCache(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Time: "2026-08-01 01:00"},
	}}
	// Populate the unfiltered cache first.
	s.ipsData(httptest.NewRequest("GET", "/ips", nil))
	s.events = append(s.events, storedEvent{SrcIP: "203.0.113.2", Sensor: "cowrie", Time: "2026-08-01 01:01"})
	// A filtered request must recompute fresh, not reuse the unfiltered
	// cache entry (which would be wrong for a completely different query)
	// or itself get cached across a different, later filter value.
	page := s.ipsData(httptest.NewRequest("GET", "/ips?sensor=cowrie", nil))
	if page.Total != 2 {
		t.Fatalf("expected the filtered request to see the freshly-added event, got %+v", page)
	}
}

func TestIPsDataRowsURLPreservesFilterButDropsOffset(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Time: "2026-08-01 01:00"},
	}}
	page := s.ipsData(httptest.NewRequest("GET", "/ips?sensor=cowrie&offset=25", nil))
	want := "/api/ip-rows?sensor=cowrie"
	if page.RowsURL != want {
		t.Fatalf("RowsURL = %q, want %q", page.RowsURL, want)
	}
}

func TestIPsDataRowsURLIsBareWhenUnfiltered(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Time: "2026-08-01 01:00"},
	}}
	page := s.ipsData(httptest.NewRequest("GET", "/ips", nil))
	if page.RowsURL != "/api/ip-rows" {
		t.Fatalf("RowsURL = %q, want the bare path with no query string", page.RowsURL)
	}
}
