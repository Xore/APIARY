package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #303: the shared distinct-value lookup (/api/filter-values) and the
// filterField Kind/Options generalization it's paired with.

func filterValuesTestStore() *store {
	return &store{
		expected: []string{"cowrie", "dionaea", "silent-sensor"},
		events: []storedEvent{
			{Sensor: "cowrie", Country: "Germany", SrcIP: "203.0.113.1", Port: "22", ASN: 64500, Org: "Example Networks"},
			{Sensor: "cowrie", Country: "Germany", SrcIP: "203.0.113.1", Port: "22", ASN: 64500, Org: "Example Networks"},
			{Sensor: "cowrie", Country: "China", SrcIP: "203.0.113.2", Port: "23", Alert: "ET SCAN Potential SSH Scan"},
			{Sensor: "dionaea", Country: "China", SrcIP: "203.0.113.3", Port: "445"},
		},
	}
}

func TestDistinctFilterValuesRanksByFrequency(t *testing.T) {
	s := filterValuesTestStore()
	values := distinctFilterValues(s.events, s.expected, "sensor", "", filterValuesLimit)
	if len(values) != 3 {
		t.Fatalf("expected 3 distinct sensors (2 observed + 1 expected-but-silent), got %+v", values)
	}
	if values[0].Value != "cowrie" || values[0].Count != 3 {
		t.Fatalf("most frequent sensor should lead: %+v", values[0])
	}
}

func TestDistinctFilterValuesIncludesSilentExpectedSensors(t *testing.T) {
	s := filterValuesTestStore()
	values := distinctFilterValues(s.events, s.expected, "sensor", "", filterValuesLimit)
	found := false
	for _, v := range values {
		if v.Value == "silent-sensor" {
			found = true
			if v.Count != 0 {
				t.Fatalf("a configured-but-silent sensor should have count 0, got %d", v.Count)
			}
		}
	}
	if !found {
		t.Fatalf("expected 'silent-sensor' (configured, zero events) to still be selectable: %+v", values)
	}
}

func TestDistinctFilterValuesFiltersBySubstring(t *testing.T) {
	s := filterValuesTestStore()
	values := distinctFilterValues(s.events, s.expected, "country", "chin", filterValuesLimit)
	if len(values) != 1 || values[0].Value != "China" {
		t.Fatalf("substring query 'chin' should match only China, got %+v", values)
	}
	// Case-insensitive.
	values = distinctFilterValues(s.events, s.expected, "country", "GERM", filterValuesLimit)
	if len(values) != 1 || values[0].Value != "Germany" {
		t.Fatalf("substring query should be case-insensitive, got %+v", values)
	}
}

func TestDistinctFilterValuesRespectsLimit(t *testing.T) {
	s := filterValuesTestStore()
	values := distinctFilterValues(s.events, s.expected, "sensor", "", 1)
	if len(values) != 1 {
		t.Fatalf("expected exactly 1 value under a limit of 1, got %d", len(values))
	}
}

func TestDistinctFilterValuesASNIncludesOrgInLabelNotValue(t *testing.T) {
	s := filterValuesTestStore()
	values := distinctFilterValues(s.events, s.expected, "asn", "", filterValuesLimit)
	if len(values) != 1 {
		t.Fatalf("expected exactly one distinct ASN, got %+v", values)
	}
	// Value must match filter.match()'s own f.asn comparison exactly
	// (filters.go: strconv.FormatUint(e.ASN,10) against a "AS"-trimmed
	// input) -- an "AS" prefix, no org text mixed in.
	if values[0].Value != "AS64500" {
		t.Fatalf("ASN Value = %q, want AS64500 (bare, matching filter semantics)", values[0].Value)
	}
	if values[0].Label != "AS64500 — Example Networks" {
		t.Fatalf("ASN Label = %q, want the org name included for readability", values[0].Label)
	}
}

func TestDistinctFilterValuesSkipsEventsWithNoValueForTheField(t *testing.T) {
	s := filterValuesTestStore()
	// Only one of the 4 fixture events has an Alert (signature) set.
	values := distinctFilterValues(s.events, s.expected, "sig", "", filterValuesLimit)
	if len(values) != 1 || values[0].Value != "ET SCAN Potential SSH Scan" {
		t.Fatalf("expected exactly the one event with a signature, got %+v", values)
	}
	// And ASN: only one of the 4 fixture events has ASN != 0.
	values = distinctFilterValues(s.events, s.expected, "asn", "", filterValuesLimit)
	if len(values) != 1 {
		t.Fatalf("expected exactly one event with a non-zero ASN, got %+v", values)
	}
}

func TestDistinctFilterValuesUnknownFieldReturnsNil(t *testing.T) {
	s := filterValuesTestStore()
	if values := distinctFilterValues(s.events, s.expected, "not-a-real-field", "", filterValuesLimit); values != nil {
		t.Fatalf("unknown field should return nil, got %+v", values)
	}
}

func TestServeFilterValuesReturnsJSON(t *testing.T) {
	s := filterValuesTestStore()
	r := httptest.NewRequest(http.MethodGet, "/api/filter-values?field=sensor&q=cow", nil)
	w := httptest.NewRecorder()
	s.serveFilterValues(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var body struct {
		Values []filterValueOption `json:"values"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(body.Values) != 1 || body.Values[0].Value != "cowrie" {
		t.Fatalf("field=sensor&q=cow = %+v, want just cowrie", body.Values)
	}
}

func TestServeFilterValuesEmptyQueryReturnsTopValues(t *testing.T) {
	s := filterValuesTestStore()
	r := httptest.NewRequest(http.MethodGet, "/api/filter-values?field=sensor", nil)
	w := httptest.NewRecorder()
	s.serveFilterValues(w, r)
	if !strings.Contains(w.Body.String(), `"value":"cowrie"`) {
		t.Fatalf("expected the empty query to return real values, got %q", w.Body.String())
	}
}

func TestServeFilterValuesRejectsUnknownField(t *testing.T) {
	s := filterValuesTestStore()
	r := httptest.NewRequest(http.MethodGet, "/api/filter-values?field=not-a-real-field", nil)
	w := httptest.NewRecorder()
	s.serveFilterValues(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown field", w.Code)
	}
}

func TestServeFilterValuesRejectsNonGET(t *testing.T) {
	s := filterValuesTestStore()
	r := httptest.NewRequest(http.MethodPost, "/api/filter-values?field=sensor", nil)
	w := httptest.NewRecorder()
	s.serveFilterValues(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

// #303: buildFilterBar upgrades a field to a real <select> (fixed enum) or
// an autocomplete-enabled input (real backing data) automatically, purely
// from its query-param name -- none of the 6 existing call sites change.

func TestBuildFilterBarUpgradesFixedEnumFieldsToSelect(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/ml-anomalies?severity=high", nil)
	bar := buildFilterBar(r, "/ml-anomalies",
		[2]string{"severity", "Severity"}, [2]string{"event_type", "Event type"}, [2]string{"country", "Country"})

	severity := bar.FilterFields[0]
	if severity.Kind != "select" {
		t.Fatalf("severity Kind = %q, want select", severity.Kind)
	}
	if severity.Value != "high" {
		t.Fatalf("severity Value = %q, want high (pre-filled from the request)", severity.Value)
	}
	found := false
	for _, opt := range severity.Options {
		if opt.Value == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatalf("severity Options missing 'critical': %+v", severity.Options)
	}

	if bar.FilterFields[1].Kind != "select" {
		t.Fatalf("event_type Kind = %q, want select", bar.FilterFields[1].Kind)
	}
	if bar.FilterFields[2].Kind != "autocomplete" {
		t.Fatalf("country Kind = %q, want autocomplete", bar.FilterFields[2].Kind)
	}
}

func TestBuildFilterBarLeavesUnclassifiedFieldsAsText(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/commands", nil)
	bar := buildFilterBar(r, "/commands", [2]string{"q", "Command contains"}, [2]string{"cidr", "Network (CIDR)"})
	for _, f := range bar.FilterFields {
		if f.Kind != "text" {
			t.Fatalf("field %q Kind = %q, want text (free-text/user-authored fields are not autocomplete-eligible)", f.Name, f.Kind)
		}
	}
}

func TestFilterAutocompleteFieldsMatchFilterValueFields(t *testing.T) {
	// filters.go's allowlist and filter_values.go's data source must name
	// the same fields -- a mismatch would silently wire up an <input
	// data-hp-filter-field="X"> that /api/filter-values can never answer
	// (400 unknown field), or vice versa.
	for name := range filterAutocompleteFields {
		if _, ok := filterValueFields[name]; !ok {
			t.Fatalf("%q is autocomplete-eligible (filters.go) but has no data source (filter_values.go)", name)
		}
	}
	for name := range filterValueFields {
		if !filterAutocompleteFields[name] {
			t.Fatalf("%q has a data source (filter_values.go) but is not marked autocomplete-eligible (filters.go)", name)
		}
	}
}
