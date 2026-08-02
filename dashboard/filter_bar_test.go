package main

import (
	"bytes"
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
)

// #280 Phase 4/5: the shared filter-bar infrastructure (buildFilterBar,
// {{template "filterbar"}}) and its wiring into all six pages that lacked
// any on-page filter controls.

func TestBuildFilterBarPreFillsFromRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/ips?ip=203.0.113.9&country=DE&page=2", nil)
	bar := buildFilterBar(r, "/ips", [2]string{"ip", "IP"}, [2]string{"country", "Country"}, [2]string{"sensor", "Sensor"})

	if len(bar.FilterFields) != 3 {
		t.Fatalf("expected 3 filter fields regardless of which are set, got %+v", bar.FilterFields)
	}
	if bar.FilterFields[0] != (filterField{Name: "ip", Label: "IP", Value: "203.0.113.9"}) {
		t.Fatalf("ip field not pre-filled: %+v", bar.FilterFields[0])
	}
	if bar.FilterFields[1] != (filterField{Name: "country", Label: "Country", Value: "DE"}) {
		t.Fatalf("country field not pre-filled: %+v", bar.FilterFields[1])
	}
	if bar.FilterFields[2] != (filterField{Name: "sensor", Label: "Sensor", Value: ""}) {
		t.Fatalf("sensor field should be empty, got %+v", bar.FilterFields[2])
	}

	// page=2 is not one of the filter bar's own fields -- it must round-trip
	// as a hidden field so submitting the filter form doesn't silently drop
	// an unrelated, currently active query parameter.
	foundHidden := false
	for _, h := range bar.FilterHidden {
		if h.Key == "page" && h.Value == "2" {
			foundHidden = true
		}
		if h.Key == "ip" || h.Key == "country" || h.Key == "sensor" {
			t.Fatalf("the filter bar's own fields must not also appear as hidden fields: %+v", h)
		}
	}
	if !foundHidden {
		t.Fatalf("expected page=2 preserved as a hidden field, got %+v", bar.FilterHidden)
	}

	if bar.FilterAction != "/ips" {
		t.Fatalf("FilterAction = %q, want /ips", bar.FilterAction)
	}
	if bar.FilterResetURL == "" || !strings.Contains(bar.FilterResetURL, "page=2") {
		t.Fatalf("expected a reset URL preserving the unrelated page= param, got %q", bar.FilterResetURL)
	}
	if strings.Contains(bar.FilterResetURL, "ip=") || strings.Contains(bar.FilterResetURL, "country=") {
		t.Fatalf("reset URL must drop the filter bar's own fields, got %q", bar.FilterResetURL)
	}
}

func TestBuildFilterBarNoResetURLWhenNothingIsActive(t *testing.T) {
	r := httptest.NewRequest("GET", "/commands", nil)
	bar := buildFilterBar(r, "/commands", [2]string{"sensor", "Sensor"}, [2]string{"q", "Command contains"})
	if bar.FilterResetURL != "" {
		t.Fatalf("no field is set, expected no reset link, got %q", bar.FilterResetURL)
	}
}

func TestIPsDataAttachesFilterBar(t *testing.T) {
	s := &store{events: []storedEvent{{SrcIP: "203.0.113.1", Sensor: "cowrie", Country: "DE", Time: "2026-08-01 01:00"}}}
	page := s.ipsData(httptest.NewRequest("GET", "/ips?sensor=cowrie", nil))
	if page.FilterAction != "/ips" {
		t.Fatalf("FilterAction = %q, want /ips", page.FilterAction)
	}
	if len(page.FilterFields) != 5 {
		t.Fatalf("expected 5 filter fields (ip, cidr, sensor, country, since), got %+v", page.FilterFields)
	}
	var sensorField *filterField
	for i := range page.FilterFields {
		if page.FilterFields[i].Name == "sensor" {
			sensorField = &page.FilterFields[i]
		}
	}
	if sensorField == nil || sensorField.Value != "cowrie" {
		t.Fatalf("sensor field not pre-filled from the active filter: %+v", page.FilterFields)
	}
}

func TestCommandsDataAttachesFilterBar(t *testing.T) {
	s := &store{events: []storedEvent{{SrcIP: "203.0.113.1", Sensor: "cowrie", Command: "whoami", Time: "2026-08-01 01:00"}}}
	page := s.commandsData(httptest.NewRequest("GET", "/commands?q=who", nil))
	if page.FilterAction != "/commands" {
		t.Fatalf("FilterAction = %q, want /commands", page.FilterAction)
	}
	names := map[string]string{}
	for _, f := range page.FilterFields {
		names[f.Name] = f.Value
	}
	if _, ok := names["sensor"]; !ok {
		t.Fatalf("expected a sensor field, got %+v", page.FilterFields)
	}
	if names["q"] != "who" {
		t.Fatalf("expected the command-contains field pre-filled from q=, got %+v", page.FilterFields)
	}
	if _, ok := names["since"]; !ok {
		t.Fatalf("expected a since field, got %+v", page.FilterFields)
	}
}

func TestCampaignsDataAttachesFilterBar(t *testing.T) {
	s := &store{}
	page := s.campaignsData(httptest.NewRequest("GET", "/campaigns?asn=15169", nil))
	if page.FilterAction != "/campaigns" {
		t.Fatalf("FilterAction = %q, want /campaigns", page.FilterAction)
	}
	names := map[string]string{}
	for _, f := range page.FilterFields {
		names[f.Name] = f.Value
	}
	for _, want := range []string{"cidr", "asn", "sensor", "since"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("missing expected filter field %q: %+v", want, page.FilterFields)
		}
	}
	if names["asn"] != "15169" {
		t.Fatalf("asn field not pre-filled: %+v", page.FilterFields)
	}
}

func TestMLAnomaliesDataAttachesFilterBar(t *testing.T) {
	s := &store{}
	page := s.mlAnomaliesData(httptest.NewRequest("GET", "/ml-anomalies?severity=critical", nil))
	names := map[string]string{}
	for _, f := range page.FilterFields {
		names[f.Name] = f.Value
	}
	for _, want := range []string{"severity", "min_score", "country", "event_type"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("missing expected filter field %q: %+v", want, page.FilterFields)
		}
	}
	if names["severity"] != "critical" {
		t.Fatalf("severity field not pre-filled: %+v", page.FilterFields)
	}
	// Disabled (no Elasticsearch) must still carry a usable filter bar --
	// the early return in mlAnomaliesData must not skip attaching it.
	disabled := (&store{}).mlAnomaliesData(httptest.NewRequest("GET", "/ml-anomalies", nil))
	if disabled.FilterAction != "/ml-anomalies" {
		t.Fatalf("expected filter bar attached even when ml anomalies are unavailable, got %+v", disabled.filterBar)
	}
}

func TestClustersRouteAppliesKindFilterAndAttachesFilterBar(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Fingerprint: "fp1", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.2", Sensor: "cowrie", Fingerprint: "fp1", Time: "2026-08-01 01:01"},
		{SrcIP: "203.0.113.3", Sensor: "cowrie", Shasum: "abc", Time: "2026-08-01 01:02"},
		{SrcIP: "203.0.113.4", Sensor: "cowrie", Shasum: "abc", Time: "2026-08-01 01:03"},
	}}
	all := s.clustersData(filter{})
	if len(all.Rows) != 2 {
		t.Fatalf("expected both a Fingerprint and a Payload cluster before any kind filter, got %+v", all.Rows)
	}

	r := httptest.NewRequest("GET", "/clusters?kind=Payload", nil)
	data := s.clustersData(parseFilter(r))
	var filtered []clusterRow
	for _, row := range data.Rows {
		if row.Kind == "Payload" {
			filtered = append(filtered, row)
		}
	}
	data.Rows = filtered
	if len(data.Rows) != 1 || data.Rows[0].Kind != "Payload" {
		t.Fatalf("kind=Payload should narrow to just the payload cluster, got %+v", data.Rows)
	}
}

func TestSearchAttachesFilterBar(t *testing.T) {
	s := searchTestStore(t)
	r := httptest.NewRequest("GET", "/search?q=evil.example&sensor=cowrie", nil)
	rec := httptest.NewRecorder()
	tmpl, err := template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	s.serveSearch(rec, r, tmpl)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `name="sensor" value="cowrie"`) {
		t.Fatalf("expected the sensor filter field pre-filled in the rendered page")
	}
}

// The filter-bar disclosure itself must render only when a page actually
// supplies fields, and pre-fill values/hidden fields correctly end-to-end
// through the real template, not just the Go-side struct.
func TestFilterBarTemplateRendersPreFilledFields(t *testing.T) {
	tmpl, err := template.New("dashboard").Funcs(templateFuncs(nil, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	bar := buildFilterBar(
		httptest.NewRequest("GET", "/ips?sensor=cowrie&extra=1", nil),
		"/ips", [2]string{"sensor", "Sensor"}, [2]string{"country", "Country"},
	)
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "filterbar", bar); err != nil {
		t.Fatalf("filterbar template does not execute: %v", err)
	}
	html := buf.String()
	if !strings.Contains(html, `action="/ips"`) {
		t.Fatalf("missing form action: %s", html)
	}
	if !strings.Contains(html, `name="sensor" value="cowrie"`) {
		t.Fatalf("sensor field not pre-filled in rendered HTML: %s", html)
	}
	if !strings.Contains(html, `name="country" value=""`) {
		t.Fatalf("country field should render empty: %s", html)
	}
	if !strings.Contains(html, `type="hidden" name="extra" value="1"`) {
		t.Fatalf("extra= should round-trip as a hidden field: %s", html)
	}
	if !strings.Contains(html, "Reset") {
		t.Fatalf("an active filter should render a reset link: %s", html)
	}
}

func TestFilterBarTemplateRendersNothingWithoutFields(t *testing.T) {
	tmpl, err := template.New("dashboard").Funcs(templateFuncs(nil, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "filterbar", filterBar{}); err != nil {
		t.Fatalf("filterbar template does not execute on a zero value: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "" {
		t.Fatalf("a page with no filter fields must render nothing, got %q", buf.String())
	}
}
