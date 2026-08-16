package main

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestExportModalURLReflectsCurrentFilterNotUnfilteredSet is #59's own
// stated constraint for this modal: "Must export the filtered scope the
// user is looking at, not the unfiltered set." exportEventsCSV
// (investigate.go) already filters correctly via parseFilter(r) -- the gap
// was that /events had no export entry point wiring the current filter
// through to it at all. eventsData's ExportURL is that wiring; this proves
// it carries every filter param the page itself is using and strips only
// pagination (page/per_page), which has no meaning for a full CSV export.
func TestExportModalURLReflectsCurrentFilterNotUnfilteredSet(t *testing.T) {
	s := &store{}
	s.events = []storedEvent{
		{Time: "2026-08-01 10:00", Sensor: "cowrie", SrcIP: "203.0.113.9"},
		{Time: "2026-08-01 10:01", Sensor: "dionaea", SrcIP: "198.51.100.7"},
	}
	req := httptest.NewRequest("GET", "/events?sensor=cowrie&page=2&per_page=100", nil)
	page := s.eventsData(req)

	if page.ExportURL != "/export/events.csv?sensor=cowrie" {
		t.Fatalf("ExportURL did not carry the filter and strip pagination: got %q", page.ExportURL)
	}

	// The unfiltered request must produce a bare export URL, proving this
	// isn't just a filter that happens to always be present.
	unfiltered := s.eventsData(httptest.NewRequest("GET", "/events", nil))
	if unfiltered.ExportURL != "/export/events.csv" {
		t.Fatalf("unfiltered ExportURL should carry no query at all: got %q", unfiltered.ExportURL)
	}

	// End to end: exportEventsCSV against the SAME filtered request the page
	// used must return only the matching row, not both.
	rec := httptest.NewRecorder()
	filteredReq := httptest.NewRequest("GET", "/export/events.csv?sensor=cowrie", nil)
	s.exportEventsCSV(rec, filteredReq)
	body := rec.Body.String()
	if !strings.Contains(body, "203.0.113.9") {
		t.Fatal("filtered export is missing the matching event")
	}
	if strings.Contains(body, "198.51.100.7") {
		t.Fatal("filtered export leaked an event outside the current filter -- exported the unfiltered set")
	}
}

// TestExportModalTriggerRendersOnEventsPage pins the data-attribute contract
// the click handler in hp-modals.js depends on: a button carrying the
// server-computed export URL and count, not a value reconstructed in JS
// that could drift from what the page is actually showing.
func TestExportModalTriggerRendersOnEventsPage(t *testing.T) {
	s := &store{}
	s.events = []storedEvent{{Time: "2026-08-01 10:00", Sensor: "cowrie", SrcIP: "203.0.113.9"}}
	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))
	page := s.eventsData(httptest.NewRequest("GET", "/events?sensor=cowrie", nil))

	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "events", &page); err != nil {
		t.Fatalf("events page does not render: %v", err)
	}
	html := out.String()

	for _, want := range []string{
		`data-hp-export-url="/export/events.csv?sensor=cowrie"`,
		`data-hp-export-count="1"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("export trigger is missing %q", want)
		}
	}
}
