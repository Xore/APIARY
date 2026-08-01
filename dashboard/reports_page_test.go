package main

import (
	"html/template"
	"os"
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

// Generated reports render as a .project-grid/.project-card grid (#227,
// following #221/#226), not the old <table>. Each card is a role="button"
// (hp-reports.js), since it can't be a real <a>/<button> -- the Download
// link and Delete button nested inside it are both interactive content,
// which HTML forbids inside another interactive element.
func TestReportsPageGeneratedReportsUseCardGrid(t *testing.T) {
	if strings.Contains(pageReports, `id="hp-rp-generated-table"`) {
		t.Fatal("reports page still has the old generated-reports <table>")
	}
	if !strings.Contains(pageReports, `class="project-grid" id="hp-rp-generated"`) {
		t.Fatal("reports page is missing the .project-grid container for generated reports")
	}

	body, err := os.ReadFile("static/hp-reports.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, want := range []string{
		`data-hp-report-card="${escapeHTML(report.id)}"`,
		`role="button"`,
		`data-hp-report-actions`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("hp-reports.js is missing %q", want)
		}
	}
	// The old per-row "View" button is gone -- the whole card is the trigger now.
	if strings.Contains(source, `data-view="${escapeHTML(report.id)}">View</button>`) {
		t.Fatal("hp-reports.js still has the standalone per-row View button")
	}
}
