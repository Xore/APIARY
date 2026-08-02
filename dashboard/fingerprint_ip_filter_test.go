package main

import (
	"net/http/httptest"
	"testing"
)

// #278: isolate one IP among several sharing a client fingerprint via a
// check/uncheck list on /events.

func TestFingerprintIPCorrelationPreFillsAllChecked(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Fingerprint: "abc123", FingerKind: "HASSH", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Fingerprint: "abc123", FingerKind: "HASSH", Time: "2026-08-01 01:01"},
		{SrcIP: "203.0.113.2", Sensor: "cowrie", Fingerprint: "abc123", FingerKind: "HASSH", Time: "2026-08-01 01:02"},
		{SrcIP: "203.0.113.3", Sensor: "cowrie", Fingerprint: "zzz999", FingerKind: "HASSH", Time: "2026-08-01 01:03"},
	}}
	page := s.eventsData(httptest.NewRequest("GET", "/events?fingerprint=abc123", nil))
	if len(page.FingerprintIPs) != 2 {
		t.Fatalf("expected 2 correlated IPs, got %+v", page.FingerprintIPs)
	}
	// Sorted by count desc: .1 (2 events) before .2 (1 event).
	if page.FingerprintIPs[0].IP != "203.0.113.1" || page.FingerprintIPs[0].Count != 2 || !page.FingerprintIPs[0].Checked {
		t.Fatalf("unexpected first correlated IP: %+v", page.FingerprintIPs[0])
	}
	if page.FingerprintIPs[1].IP != "203.0.113.2" || page.FingerprintIPs[1].Count != 1 || !page.FingerprintIPs[1].Checked {
		t.Fatalf("unexpected second correlated IP: %+v", page.FingerprintIPs[1])
	}
	if page.ResetIPsURL != "" {
		t.Fatalf("no ips= narrowing active, expected no reset URL, got %q", page.ResetIPsURL)
	}
}

func TestFingerprintIPCorrelationNilWithOnlyOneIP(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Fingerprint: "abc123", FingerKind: "HASSH", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Fingerprint: "abc123", FingerKind: "HASSH", Time: "2026-08-01 01:01"},
	}}
	page := s.eventsData(httptest.NewRequest("GET", "/events?fingerprint=abc123", nil))
	if page.FingerprintIPs != nil {
		t.Fatalf("nothing to isolate with a single IP behind the fingerprint, got %+v", page.FingerprintIPs)
	}
}

func TestFingerprintIPCorrelationNilWithoutFingerprintFilter(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Fingerprint: "abc123", FingerKind: "HASSH", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.2", Sensor: "cowrie", Fingerprint: "abc123", FingerKind: "HASSH", Time: "2026-08-01 01:01"},
	}}
	page := s.eventsData(httptest.NewRequest("GET", "/events", nil))
	if page.FingerprintIPs != nil {
		t.Fatalf("no fingerprint filter active, expected no correlation facet, got %+v", page.FingerprintIPs)
	}
}

func TestIncludeIPsIsolatesOneIPAndKeepsTheFullChecklist(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Fingerprint: "abc123", FingerKind: "HASSH", Command: "from-.1", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.2", Sensor: "cowrie", Fingerprint: "abc123", FingerKind: "HASSH", Command: "from-.2", Time: "2026-08-01 01:01"},
	}}
	page := s.eventsData(httptest.NewRequest("GET", "/events?fingerprint=abc123&ips=203.0.113.1", nil))
	if page.Total != 1 || len(page.Events) != 1 || page.Events[0].SrcIP != "203.0.113.1" {
		t.Fatalf("expected events narrowed to the checked IP only: %+v", page)
	}
	// The checklist itself still lists every IP behind the fingerprint --
	// unchecking one must not also shrink the menu down to just itself.
	if len(page.FingerprintIPs) != 2 {
		t.Fatalf("expected the full checklist to survive narrowing, got %+v", page.FingerprintIPs)
	}
	for _, ip := range page.FingerprintIPs {
		want := ip.IP == "203.0.113.1"
		if ip.Checked != want {
			t.Fatalf("unexpected checked state for %s: %+v", ip.IP, ip)
		}
	}
	if page.ResetIPsURL == "" {
		t.Fatal("narrowing is active, expected a non-empty reset URL")
	}
	found := false
	for _, chip := range page.Filters {
		if chip == "isolated to ip = 203.0.113.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an 'isolated to ip' filter chip, got %+v", page.Filters)
	}
}

func TestIncludeIPsIgnoresBlankFreeTextEntry(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Time: "2026-08-01 01:00"},
	}}
	// A plain <input type="text" name="ips"> left empty still submits
	// "ips=" alongside any checked checkboxes -- must not be treated as an
	// includeIPs restriction that matches nothing.
	page := s.eventsData(httptest.NewRequest("GET", "/events?ips=", nil))
	if page.Total != 1 {
		t.Fatalf("blank ips= must not filter out every event, got total=%d", page.Total)
	}
}

func TestIncludeIPsFreeTextCanAddAnIPOutsideTheFacet(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Fingerprint: "abc123", FingerKind: "HASSH", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.2", Sensor: "cowrie", Fingerprint: "abc123", FingerKind: "HASSH", Time: "2026-08-01 01:01"},
		// Same IP as .1, but a different fingerprint -- e.g. it also showed
		// up on another sensor. A user typing it in manually should still
		// be able to isolate it alongside the checked facet IPs.
		{SrcIP: "203.0.113.9", Sensor: "cowrie", Fingerprint: "zzz999", FingerKind: "HASSH", Time: "2026-08-01 01:02"},
	}}
	page := s.eventsData(httptest.NewRequest("GET", "/events?fingerprint=abc123&ips=203.0.113.1&ips=203.0.113.9", nil))
	if page.Total != 1 {
		t.Fatalf("expected only the matching fingerprint+IP event, got total=%d", page.Total)
	}
}
