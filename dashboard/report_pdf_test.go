package main

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestReportURLPreservesScopeAndDropsPagination(t *testing.T) {
	values := url.Values{"ip": {"58.221.195.130"}, "type": {"alert"}, "page": {"9"}, "per_page": {"25"}}
	got := reportURL(values)
	want := "/export/report.pdf?ip=58.221.195.130&type=alert"
	if got != want {
		t.Fatalf("reportURL() = %q, want %q", got, want)
	}
}

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

func TestRenderSecurityReportPDF(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	data := sampleReportData(now)
	body := renderSecurityReportPDF(data)
	if !bytes.HasPrefix(body, []byte("%PDF-1.4")) || !bytes.Contains(body, []byte("%%EOF")) {
		t.Fatal("renderSecurityReportPDF() did not produce a complete PDF")
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

// TestRenderThemedReportPDF proves the theme palettes and the configurable
// branding flow into the rendered document: the light theme paints its page
// background from the canonical Xore/theme light tokens, custom header /
// footer / author / classification copy replaces the defaults, and the risk
// rating carries the theme's semantic danger color.
func TestRenderThemedReportPDF(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	data := sampleReportData(now)
	branding := pdfBranding{
		HeaderLeft:     "ACME//SOC",
		HeaderRight:    "WEEKLY THREAT REVIEW",
		FooterLeft:     "CONFIDENTIAL - ACME SOC",
		Classification: "TLP:AMBER - handle with care",
		Author:         "Jane Analyst",
	}
	body := renderThemedReportPDF(data, pdfThemeLight(), branding)
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
	if strings.Contains(text, "XORE//HONEYPOT") {
		t.Fatal("custom branding must fully replace the default header and footer")
	}

	// The dark default keeps the historical identity and palette.
	dark := string(renderSecurityReportPDF(data))
	if !strings.Contains(dark, "XORE//HONEYPOT") || !strings.Contains(dark, "PRIVATE - XORE//HONEYPOT") {
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
