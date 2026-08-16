package main

import (
	"html/template"
	"strings"
	"testing"
)

// Regression tests for three live UX reports against the deployed
// dashboard: the "Start analysis" tab/chip is renamed to "Payload
// workbench" everywhere it appears, and the single-artifact workbench
// page's "back" chip returns to the payload picker it was reached from
// (/payloads#start-analysis) instead of the unrelated Analysis results
// listing it used to point at.

func TestPayloadsTabIsLabeledPayloadWorkbench(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "payloads", &payloadsPage{}); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := out.String()
	if strings.Contains(body, ">Start analysis<") {
		t.Fatal("payloads page still shows the old 'Start analysis' tab label")
	}
	// The internal tab id/hash (#start-analysis, data-dashboard-tab) stays
	// stable on purpose -- only the visible label changed, not the URL
	// fragment existing bookmarks/links use.
	if !strings.Contains(body, `data-dashboard-tab="start-analysis"`) || !strings.Contains(body, "Payload workbench</button>") {
		t.Fatalf("payloads page's second tab is not labeled Payload workbench (with a stable start-analysis id): %s", body)
	}
}

func TestWorkbenchResultsChipIsLabeledPayloadWorkbench(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "workbench-results", &evidenceResultsPageData{}); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := out.String()
	if strings.Contains(body, ">Start analysis<") {
		t.Fatal("workbench-results page still shows the old 'Start analysis' chip label")
	}
	if !strings.Contains(body, `href="/payloads#start-analysis">Payload workbench</a>`) {
		t.Fatalf("workbench-results page is missing the renamed Payload workbench chip: %s", body)
	}
}

// TestPayloadWorkbenchBackLinkReturnsToThePicker is a regression test for a
// live report: the single-artifact workbench page's "back" chip pointed at
// /payload-workbench/results (Analysis results, a different page an
// operator reaching this page via /payloads#start-analysis never came
// from) instead of back to the picker itself.
func TestPayloadWorkbenchBackLinkReturnsToThePicker(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "payload-workbench", &workbenchPageData{SHA256: shaA}); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := out.String()
	// Not a bare href check: the sidebar nav also links to
	// /payload-workbench/results (a legitimate, unrelated global nav
	// entry) -- the old back-chip label text is the specific thing that
	// must be gone.
	if strings.Contains(body, "workbench results</a>") {
		t.Fatal("payload-workbench page's back chip still points at /payload-workbench/results")
	}
	if !strings.Contains(body, `href="/payloads#start-analysis">&larr; payload workbench</a>`) {
		t.Fatalf("payload-workbench page's back chip does not return to the payload picker: %s", body)
	}
}
