package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func sampleReportData(now time.Time) reportData {
	var events []storedEvent
	for i := 0; i < 145; i++ {
		events = append(events, storedEvent{
			when: now.Add(-time.Duration(i) * time.Minute), Time: now.Add(-time.Duration(i) * time.Minute).Format(time.RFC3339),
			Sensor: "suricata", SrcIP: "203.0.113.42", ASN: 64500, Org: "Example Network",
			Port: "445", Alert: "ET TEST Representative alert signature", Severity: 1,
			Detail: "Representative defensive test event with a safely escaped value (sample).",
		})
	}
	return reportData{
		Generated: now, Title: "Honeypot Executive Security Report", Scope: "ip = 203.0.113.42 AND type = alert",
		Filters: []string{"ip = 203.0.113.42", "type = alert"}, Events: events,
		Summary: reportSummary{
			Events: 145, Alerts: 145, HighSeverity: 145, UniqueSources: 1, Sensors: 1,
			FirstSeen: now.Add(-144 * time.Minute).Format(time.RFC3339), LastSeen: now.Format(time.RFC3339),
			RiskScore: 80, RiskLevel: "critical",
		},
		TopSensors:      []kv{{Key: "suricata", Count: 145}},
		TopSources:      []kv{{Key: "203.0.113.42", Count: 145}},
		TopSignatures:   []kv{{Key: "ET TEST Representative alert signature", Count: 145}},
		TopASNs:         []kv{{Key: "AS64500 Example Network", Count: 145}},
		Findings:        []string{"Representative high-severity activity was observed."},
		Recommendations: []string{"Review the matching packet and session evidence."},
	}
}

// testAllReportElements exercises every selectable section in the designer's
// canonical order, mirroring what an operator who selects everything in the
// Reports studio would produce.
var testAllReportElements = []string{
	elementCover, elementMetrics, elementAssessment, elementFindings, elementRecommendations,
	elementTopSensors, elementTopSources, elementTopSignatures, elementTopASNs, elementTopCountries,
	elementTopPorts, elementOperationalAlert, elementEventAppendix, elementParameters,
}

// renderFullReportPDF drives renderDefinitionPDF (the live Reports studio
// render path) with every element selected, standing in for the pre-R2
// fixed-layout renderer these tests used to call directly.
func renderFullReportPDF(data reportData, theme string, branding reportBranding) []byte {
	return renderDefinitionPDF(data, reportDefinition{Theme: theme, Branding: branding, Elements: testAllReportElements, AppendixLimit: 120})
}

func TestRenderSecurityReportPDF(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	data := sampleReportData(now)
	body := renderFullReportPDF(data, "dark", reportBranding{})
	if !bytes.HasPrefix(body, []byte("%PDF-1.4")) || !bytes.Contains(body, []byte("%%EOF")) {
		t.Fatal("renderFullReportPDF() did not produce a complete PDF")
	}
	if !bytes.Contains(body, []byte("Honeypot Executive Security Report")) || !bytes.Contains(body, []byte("/Count ")) {
		t.Fatal("rendered PDF is missing expected report content or page tree")
	}
	if strings.Count(string(body), "/Type /Page ") < 2 {
		t.Fatal("representative evidence should produce a multi-page report")
	}
	if output := os.Getenv("PDF_TEST_OUTPUT"); output != "" {
		if err := os.WriteFile(output, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestEventAppendixTruncatesOversizedField (#885): a single event field with
// no upstream size cap (e.g. cowrie's free-text command capture) must not be
// allowed to inflate the appendix into a proportionally huge number of PDF
// lines/pages -- eventAppendixDetailCap bounds it defensively regardless of
// what any given sensor's own capture path lets through.
func TestEventAppendixTruncatesOversizedField(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	data := sampleReportData(now)
	oversized := strings.Repeat("A", eventAppendixDetailCap*5)
	data.Events = []storedEvent{{
		when: now, Time: now.Format(time.RFC3339), Sensor: "cowrie", SrcIP: "203.0.113.42", Port: "22",
		Command: oversized,
	}}
	data.Summary.Events = 1

	body := renderFullReportPDF(data, "dark", reportBranding{})
	// PDF string literals escape "(" and ")" with a backslash (escapePDFText),
	// so the marker survives as \(truncated\) in the raw stream -- search
	// without the parens to match either form.
	if !bytes.Contains(body, []byte("truncated")) {
		t.Fatal("expected the oversized field to be marked as truncated in the rendered PDF")
	}
	// Loosely bounds the page count: untruncated, a 5x-cap field wraps into
	// roughly 5x as many appendix lines/pages as a capped one -- this just
	// needs to prove the cap actually limited growth, not pin an exact count.
	if pages := strings.Count(string(body), "/Type /Page "); pages > 10 {
		t.Fatalf("expected the truncation cap to keep this to a small page count, got %d pages", pages)
	}
}

// TestRenderThemedReportPDF proves the theme palettes and the configurable
// branding flow into the rendered document: the light theme paints its page
// background from the canonical Xore/theme light tokens, custom header /
// footer / author / classification copy replaces the defaults, and the risk
// rating carries the theme's semantic danger color.
func TestRenderThemedReportPDF(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	data := sampleReportData(now)
	branding := reportBranding{
		HeaderLeft:     "ACME//SOC",
		HeaderRight:    "WEEKLY THREAT REVIEW",
		FooterLeft:     "CONFIDENTIAL - ACME SOC",
		Classification: "TLP:AMBER - handle with care",
		Author:         "Jane Analyst",
	}
	body := renderFullReportPDF(data, "light", branding)
	text := string(body)

	for _, want := range []string{
		"ACME//SOC", "WEEKLY THREAT REVIEW", "CONFIDENTIAL - ACME SOC",
		"Classification: TLP:AMBER - handle with care", "Author: Jane Analyst",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("themed PDF missing custom branding %q", want)
		}
	}
	light := pdfThemeLight()
	pageColor := fmt.Sprintf("%.3f %.3f %.3f rg", light.Page.r, light.Page.g, light.Page.b)
	if !strings.Contains(text, pageColor) {
		t.Fatalf("light theme page background %q not painted", pageColor)
	}
	dangerColor := fmt.Sprintf("%.3f %.3f %.3f rg", light.Danger.r, light.Danger.g, light.Danger.b)
	if !strings.Contains(text, dangerColor) {
		t.Fatalf("critical risk rating must use the theme danger color %q", dangerColor)
	}
	if strings.Contains(text, "PRIVATE - APIARY") {
		t.Fatal("custom branding must fully replace the default header and footer")
	}

	// The dark default keeps the canonical APIARY identity and palette.
	dark := string(renderFullReportPDF(data, "dark", reportBranding{}))
	if !strings.Contains(dark, "APIARY") || !strings.Contains(dark, "PRIVATE - APIARY") {
		t.Fatal("default report must keep the deployment header and footer")
	}
	darkPage := pdfThemeDark().Page
	darkColor := fmt.Sprintf("%.3f %.3f %.3f rg", darkPage.r, darkPage.g, darkPage.b)
	if !strings.Contains(dark, darkColor) {
		t.Fatalf("dark theme page background %q not painted", darkColor)
	}
	if output := os.Getenv("PDF_TEST_OUTPUT_LIGHT"); output != "" {
		if err := os.WriteFile(output, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
