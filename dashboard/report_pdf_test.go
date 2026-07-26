package main

import (
	"bytes"
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

func TestRenderSecurityReportPDF(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	var events []storedEvent
	for i := 0; i < 145; i++ {
		events = append(events, storedEvent{
			when: now.Add(-time.Duration(i) * time.Minute), Time: now.Add(-time.Duration(i) * time.Minute).Format(time.RFC3339),
			Sensor: "suricata", SrcIP: "203.0.113.42", ASN: 64500, Org: "Example Network",
			Port: "445", Alert: "ET TEST Representative alert signature", Severity: 1,
			Detail: "Representative defensive test event with a safely escaped value (sample).",
		})
	}
	data := reportData{
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
