package main

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxResultsAreBoundedAndValidated(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", dir)
	valid := `{"version":1,"job":"linux-test","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","completed_at":"2026-01-01T00:00:00Z","stdout":"<script>"}`
	if err := os.WriteFile(filepath.Join(dir, "linux-test.json"), []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	windows := `{"version":2,"job":"windows-test","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","completed_at":"2026-01-02T00:00:00Z","windows_forensics":{"detected":true,"execution_mode":"wine","pe_type":"PE32+","imphash":"test"},"network_summary":{"dns_queries":["raw.githubusercontent.com"],"guest_packets":12}}`
	if err := os.WriteFile(filepath.Join(dir, "windows-test.json"), []byte(windows), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "linux-invalid.json"), []byte(`{"job":"bad","sha256":"../escape"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := loadSandboxResults()
	if len(rows) != 2 || rows[0].Job != "windows-test" || !rows[0].Windows.Detected ||
		rows[0].Windows.ExecutionMode != "wine" || len(rows[0].NetworkSummary.DNSQueries) != 1 ||
		rows[1].Job != "linux-test" || rows[1].Stdout != "<script>" {
		t.Fatalf("unexpected sandbox rows: %#v", rows)
	}
	data, err := sandboxData("linux-test", "")
	if err != nil || data.Detail == nil {
		t.Fatalf("detail lookup failed: %v", err)
	}
	filtered, err := sandboxData("", "does-not-match")
	if err != nil || len(filtered.Rows) != 0 {
		t.Fatalf("sandbox search was not applied: %#v %v", filtered.Rows, err)
	}
}

func TestSandboxStatusAndTemplate(t *testing.T) {
	dir := t.TempDir()
	requests := t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", dir)
	t.Setenv("SANDBOX_REQUEST_DIR", requests)
	status := `{"updated_at":"2026-01-01T00:00:00Z","worker_state":"idle","counts":{"queued":2,"running":0,"completed":4,"failed":1},"jobs":[]}`
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded := loadSandboxStatus()
	if loaded.WorkerState != "idle" || loaded.Counts.Queued != 2 || loaded.Counts.Failed != 1 {
		t.Fatalf("unexpected status: %#v", loaded)
	}
	hash := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(requests, hash+".request"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded = loadSandboxStatus(); loaded.Handoff != 1 {
		t.Fatalf("handoff=%d want=1", loaded.Handoff)
	}
	funcs := template.FuncMap{
		"worldMap": func() template.HTML { return "" },
		"json":     func(any) string { return "" },
		"dict":     func(...any) map[string]any { return nil },
	}
	if _, err := template.New("dashboard").Funcs(funcs).Parse(pageTemplate); err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
}
