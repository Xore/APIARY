package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression test for #1337: sanitizeCSVField must neutralize a leading =,
// +, -, or @ (the CSV/spreadsheet-formula-injection prefixes), leave
// anything else untouched, and be a no-op on the empty string.
func TestSanitizeCSVField(t *testing.T) {
	cases := map[string]string{
		`=HYPERLINK("http://evil.example/x","click")`: `'=HYPERLINK("http://evil.example/x","click")`,
		"+1-800-555-0100": "'+1-800-555-0100",
		"-2+3":            "'-2+3",
		"@SUM(A1:A9)":     "'@SUM(A1:A9)",
		"wget http://x/y": "wget http://x/y",
		"":                "",
		"root":            "root",
		"password123":     "password123",
	}
	for in, want := range cases {
		if got := sanitizeCSVField(in); got != want {
			t.Errorf("sanitizeCSVField(%q) = %q, want %q", in, got, want)
		}
	}
}

// Regression test for #1337: exportEventsCSV must not let an attacker's
// Cowrie command/username/password/path/detail become a live spreadsheet
// formula when the exported CSV is opened in Excel/Sheets/LibreOffice.
func TestExportEventsCSVSanitizesFormulaInjection(t *testing.T) {
	s := &store{events: []storedEvent{
		{
			Time: "2026-08-01 10:00", Sensor: "cowrie", SrcIP: "203.0.113.9",
			User:    `=HYPERLINK("http://evil.example/steal","click")`,
			Pass:    "+cmd|'/c calc'!A1",
			Command: "-2+3+cmd|' /c calc'!A0",
			Path:    "@SUM(1+1)*cmd|' /c calc'!A0",
			Detail:  "=1+1",
		},
	}}
	rec := httptest.NewRecorder()
	s.exportEventsCSV(rec, httptest.NewRequest("GET", "/export/events.csv", nil))
	body := rec.Body.String()

	for _, mustContain := range []string{
		`'=HYPERLINK`, `'+cmd`, `'-2+3`, `'@SUM`, `'=1+1`,
	} {
		if !strings.Contains(body, mustContain) {
			t.Fatalf("expected exported CSV to contain sanitized field %q, got:\n%s", mustContain, body)
		}
	}
	// None of the raw, unprefixed attacker strings should appear on their
	// own -- every occurrence must carry the leading single-quote guard.
	for _, raw := range []string{"=HYPERLINK", "@SUM(1+1)"} {
		if strings.Contains(body, raw) && !strings.Contains(body, "'"+raw) {
			t.Fatalf("found unsanitized formula-triggering field %q in export:\n%s", raw, body)
		}
	}
}

// Regression test for #1337: exportCommandsCSV's command field must be
// sanitized the same way exportEventsCSV's is.
func TestExportCommandsCSVSanitizesFormulaInjection(t *testing.T) {
	s := &store{events: []storedEvent{
		{Time: "2026-08-01 10:00", Sensor: "cowrie", SrcIP: "203.0.113.9", Command: "=cmd|' /c calc'!A0"},
	}}
	rec := httptest.NewRecorder()
	s.exportCommandsCSV(rec, httptest.NewRequest("GET", "/export/commands.csv", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "'=cmd") {
		t.Fatalf("expected sanitized command field, got:\n%s", body)
	}
}
