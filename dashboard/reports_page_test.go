package main

import (
	"html/template"
	"strings"
	"testing"
)

// TestReportsPageMarkers pins the Reports studio contract (R3): the designer
// lives in the main content area of the dashboard layout, exposes template
// presets, element selection, scope criteria, dark/light PDF themes, and
// branding fields, and loads the studio controller script.
func TestReportsPageMarkers(t *testing.T) {
	for _, marker := range []string{
		`{{define "reports"}}`,
		`data-hp-page-content`,
		`data-hp-reports`,
		`id="hp-rp-templates"`, // template picker (executive, security, threat, incident, sensors, sandbox, custom)
		`id="hp-rp-elements"`,  // element selection checklist
		`id="hp-rp-scope-ip"`,  // search criteria…
		`id="hp-rp-scope-network"`,
		`id="hp-rp-scope-sensor"`,
		`id="hp-rp-scope-signature"`,
		`id="hp-rp-scope-text"`,
		`data-theme="dark"`, // PDF theme toggle…
		`data-theme="light"`,
		`id="hp-rp-brand-title"`, // branding…
		`id="hp-rp-brand-author"`,
		`id="hp-rp-brand-header-left"`,
		`id="hp-rp-brand-footer"`,
		`id="hp-rp-brand-classification"`,
		`id="hp-rp-sandbox-job"`,      // sandbox job selector
		`id="hp-rp-schedule-section"`, // recurring generation (R4)…
		`id="hp-rp-sched-frequency"`,
		`id="hp-rp-sched-weekday-field"`,
		`id="hp-rp-sched-monthday-field"`,
		`id="hp-rp-definitions"`,  // saved definitions table
		`id="hp-rp-generated"`,    // generated reports table
		`id="hp-rp-viewer-frame"`, // inline PDF viewer
		`/static/hp-reports.js`,   // studio controller
		`Reports studio`,
	} {
		if !strings.Contains(pageReports, marker) {
			t.Fatalf("reports page is missing %q", marker)
		}
	}
}

// TestReportsPageRenders proves the page template parses and renders inside
// the shared shell with the standard template funcs.
func TestReportsPageRenders(t *testing.T) {
	tmpl, err := template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "reports", snapshot{}); err != nil {
		t.Fatalf("render reports page: %v", err)
	}
	html := out.String()
	for _, want := range []string{"Reports studio", `data-hp-nav="/reports"`, `class="app-main"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("rendered reports page is missing %q", want)
		}
	}
}
