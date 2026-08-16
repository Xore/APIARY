package main

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
)

// #344: the Event Explorer had no interactive filter bar at all -- every
// filter had to be hand-typed into the URL. These mirror
// alerts_test.go's TestAlertsFilterBarPreFillsFromRequest and
// TestAlertsPageRendersFilterBarAndClientSideFilterWiring for the same
// shared buildFilterBar/{{template "filterbar"}} plumbing on /events.

func TestEventTypeIsAClosedFiveValueEnum(t *testing.T) {
	opts, ok := filterSelectOptions["type"]
	if !ok {
		t.Fatal(`filterSelectOptions["type"] is missing -- type should render as a <select>, not free text`)
	}
	got := map[string]bool{}
	for _, o := range opts {
		got[o.Value] = true
	}
	// Must match filter.match's switch on f.typ exactly (any/login/command/
	// alert/download) -- a select option with no matching case would look
	// like a working filter that silently matches everything.
	for _, want := range []string{"", "login", "command", "alert", "download"} {
		if !got[want] {
			t.Errorf("type options missing %q: %+v", want, opts)
		}
	}
	if len(opts) != 5 {
		t.Errorf("type should have exactly 5 options (any/login/command/alert/download), got %+v", opts)
	}
}

func TestEventsFilterBarPreFillsFromRequest(t *testing.T) {
	s := &store{}
	r := httptest.NewRequest("GET", "/events?sensor=cowrie&type=login", nil)
	page := s.eventsData(r)
	if page.FilterAction != "/events" {
		t.Fatalf("FilterAction = %q, want /events", page.FilterAction)
	}
	names := map[string]string{}
	kinds := map[string]string{}
	for _, f := range page.FilterFields {
		names[f.Name], kinds[f.Name] = f.Value, f.Kind
	}
	if names["sensor"] != "cowrie" {
		t.Errorf("sensor field not pre-filled: %+v", page.FilterFields)
	}
	if names["type"] != "login" || kinds["type"] != "select" {
		t.Errorf("type field not pre-filled as a select: %+v", page.FilterFields)
	}
	for _, want := range []string{"sensor", "proto", "ip", "port", "country", "type", "since"} {
		if _, ok := names[want]; !ok {
			t.Errorf("events filter bar missing expected field %q: %+v", want, page.FilterFields)
		}
	}
}

// The "attack path" field is proto under the hood -- rdp/sip/pop3/hl7/etc.,
// not just the handful of protocols with their own dedicated filter field.
// It must resolve to filterField's autocomplete Kind (not plain text) and
// be pickable through the same /api/filter-values widget sensor/country/ip
// already use.
func TestEventsFilterBarAttackPathIsAutocomplete(t *testing.T) {
	s := &store{}
	r := httptest.NewRequest("GET", "/events?proto=rdp", nil)
	page := s.eventsData(r)
	for _, f := range page.FilterFields {
		if f.Name != "proto" {
			continue
		}
		if f.Kind != "autocomplete" {
			t.Fatalf("proto field Kind = %q, want autocomplete", f.Kind)
		}
		if f.Value != "rdp" {
			t.Fatalf("proto field not pre-filled: %+v", f)
		}
		return
	}
	t.Fatal("proto (attack path) field missing from the events filter bar")
}

func TestFilterValuesServesDistinctProtocols(t *testing.T) {
	s := &store{events: []storedEvent{
		{Sensor: "multipot", Proto: "rdp"},
		{Sensor: "multipot", Proto: "rdp"},
		{Sensor: "multipot", Proto: "sip"},
		{Sensor: "cowrie", Proto: "ssh"},
	}}
	values := distinctFilterValues(s.getEvents(), nil, "proto", "", filterValuesLimit)
	got := map[string]int{}
	for _, v := range values {
		got[v.Value] = v.Count
	}
	if got["rdp"] != 2 || got["sip"] != 1 || got["ssh"] != 1 {
		t.Fatalf("unexpected proto value counts: %+v", got)
	}
}

// End-to-end through the real template: the filter bar disclosure renders
// with the type <select> pre-filled.
func TestEventsPageRendersFilterBar(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))
	s := &store{}
	r := httptest.NewRequest("GET", "/events?type=command", nil)
	page := s.eventsData(r)
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "events", &page); err != nil {
		t.Fatalf("events page does not render: %v", err)
	}
	html := out.String()
	if !strings.Contains(html, `data-hp-filter-field=`) && !strings.Contains(html, `name="type"`) {
		t.Fatalf("events page does not render the filter bar's type field")
	}
	if !strings.Contains(html, `<option value="command" selected>command</option>`) {
		t.Fatalf("events page filter bar does not pre-fill type=command as selected:\n%s", html)
	}
}
