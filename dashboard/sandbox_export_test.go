package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSandboxPCAPExportRequiresAdminAndServesRegularCapture(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", dir)
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	job := "linux-20260726T000000Z-0123456789ab"
	hash := strings.Repeat("a", 64)
	result := `{"version":3,"job":"` + job + `","sha256":"` + hash + `"}`
	if err := os.WriteFile(filepath.Join(dir, job+".json"), []byte(result), 0o600); err != nil {
		t.Fatal(err)
	}
	pcap := make([]byte, 24)
	copy(pcap, []byte{0xd4, 0xc3, 0xb2, 0xa1})
	if err := os.WriteFile(filepath.Join(dir, job+".host.pcap"), pcap, 0o600); err != nil {
		t.Fatal(err)
	}
	path := "/export/sandbox/" + job + ".host.pcap"

	denied := httptest.NewRecorder()
	serveSandboxExport(denied, httptest.NewRequest(http.MethodGet, path, nil))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unauthorized status = %d, want %d", denied.Code, http.StatusForbidden)
	}

	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("X-Auth-Role", "admin")
	allowed := httptest.NewRecorder()
	serveSandboxExport(allowed, request)
	if allowed.Code != http.StatusOK || allowed.Body.Len() != len(pcap) {
		t.Fatalf("authorized response = status %d, bytes %d", allowed.Code, allowed.Body.Len())
	}
	if got := allowed.Header().Get("Content-Type"); got != "application/vnd.tcpdump.pcap" {
		t.Fatalf("content type = %q", got)
	}
}

func TestSandboxDiagnosticsExportRequiresAdmin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", dir)
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	job := "windows-20260729T000000Z-0123456789ab"
	hash := strings.Repeat("b", 64)
	result := `{"version":3,"job":"` + job + `","sha256":"` + hash + `"}`
	if err := os.WriteFile(filepath.Join(dir, job+".json"), []byte(result), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := []byte("PK\x05\x06" + strings.Repeat("\x00", 18))
	if err := os.WriteFile(filepath.Join(dir, job+".diagnostics.zip"), bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	path := "/export/sandbox/" + job + ".diagnostics.zip"

	denied := httptest.NewRecorder()
	serveSandboxExport(denied, httptest.NewRequest(http.MethodGet, path, nil))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unauthorized status = %d, want %d", denied.Code, http.StatusForbidden)
	}

	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("X-Auth-Role", "admin")
	allowed := httptest.NewRecorder()
	serveSandboxExport(allowed, request)
	if allowed.Code != http.StatusOK || allowed.Body.Len() != len(bundle) {
		t.Fatalf("authorized response = status %d, bytes %d", allowed.Code, allowed.Body.Len())
	}
	if got := allowed.Header().Get("Content-Type"); got != "application/zip" {
		t.Fatalf("content type = %q", got)
	}
}

func TestSandboxPDFExportRequiresAdmin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", dir)
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	job := "linux-20260729T164848Z-cbe0b83cb4a0"
	hash := strings.Repeat("c", 64)
	result := `{
		"version":3,
		"job":"` + job + `",
		"sha256":"` + hash + `",
		"run_status":"completed",
		"guest_started":true,
		"risk_score":22,
		"risk_level":"low",
		"duration_seconds":14.5,
		"analysis_path":"Linux executable detonation",
		"network_summary":{"dns_queries":["ntp.ubuntu.com","api.snapcraft.io"]},
		"artifacts":{
			"processes_before":["root 10 0 0 1 1 ? S 00:00 0:00 /usr/bin/old"],
			"processes_after":["root 20 0 0 1 1 ? S 00:01 0:00 /usr/bin/new"]
		},
		"sockets_before":["tcp LISTEN 0 10 127.0.0.1:1 0.0.0.0:*"],
		"sockets_after":["tcp LISTEN 0 10 127.0.0.1:2 0.0.0.0:*"]
	}`
	if err := os.WriteFile(filepath.Join(dir, job+".json"), []byte(result), 0o600); err != nil {
		t.Fatal(err)
	}
	path := "/export/sandbox/" + job + ".pdf"

	denied := httptest.NewRecorder()
	serveSandboxExport(denied, httptest.NewRequest(http.MethodGet, path, nil))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unauthorized status = %d, want %d", denied.Code, http.StatusForbidden)
	}

	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("X-Auth-Role", "admin")
	allowed := httptest.NewRecorder()
	serveSandboxExport(allowed, request)
	if allowed.Code != http.StatusOK || !bytes.HasPrefix(allowed.Body.Bytes(), []byte("%PDF-1.4")) {
		t.Fatalf("authorized response = status %d, PDF prefix %t", allowed.Code, bytes.HasPrefix(allowed.Body.Bytes(), []byte("%PDF-1.4")))
	}
	if got := allowed.Header().Get("Content-Type"); got != "application/pdf" {
		t.Fatalf("content type = %q", got)
	}
	if disposition := allowed.Header().Get("Content-Disposition"); !strings.Contains(disposition, job+"-report.pdf") {
		t.Fatalf("content disposition = %q", disposition)
	}
}

func TestRenderSandboxReportPDF(t *testing.T) {
	result := sandboxResult{
		Job: "linux-20260729T164848Z-cbe0b83cb4a0", SHA256: strings.Repeat("c", 64),
		Hashes:    sandboxHashes{MD5: strings.Repeat("a", 32), SHA1: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64)},
		RunStatus: "completed", GuestStarted: true, RiskScore: 22, RiskLevel: "low", Duration: 14.5,
		StartedAt: "2026-07-29T16:48:48Z", CompletedAt: "2026-07-29T16:49:03Z",
		AnalysisPath: "Linux executable detonation", ExecutionMode: "native guest execution",
		ProcessDiff: sandboxDifference{Added: []string{"root /usr/bin/sample --detonate"}, Removed: []string{"root /usr/bin/old"}},
		SocketDiff:  sandboxDifference{Added: []string{"tcp ESTAB 127.0.0.1:5000 127.0.0.1:53"}},
		NetworkSummary: sandboxNetwork{
			Packets: 24, Bytes: 4096, GuestPackets: 18, GuestPCAPBytes: 2048,
			DNSQueries: []string{"ntp.ubuntu.com", "api.snapcraft.io"},
			Attempts:   []string{"UDP 10.0.2.15:40200 -> 10.0.2.3:53"},
		},
		ChangedFiles: []string{"/tmp/sandbox-observation"},
		TopSyscalls:  []sandboxCount{{Name: "openat", Count: 42}},
		Techniques:   []sandboxTechnique{{ID: "T1059", Name: "Command and Scripting Interpreter", Evidence: "sample executed in the guest"}},
	}
	for index := 0; index < 35; index++ {
		result.TopSyscalls = append(result.TopSyscalls, sandboxCount{Name: "representative_call_" + strconv.Itoa(index), Count: 100 - index})
	}
	body := renderSandboxReportPDF(result, time.Date(2026, 7, 29, 17, 0, 0, 0, time.UTC))
	if !bytes.HasPrefix(body, []byte("%PDF-1.4")) || !bytes.Contains(body, []byte("%%EOF")) {
		t.Fatal("renderSandboxReportPDF() did not produce a complete PDF")
	}
	for _, expected := range []string{"Sandbox Dynamic Analysis Report", "Process difference", "Sockets difference", "ntp.ubuntu.com", "api.snapcraft.io"} {
		if !bytes.Contains(body, []byte(expected)) {
			t.Fatalf("rendered PDF is missing %q", expected)
		}
	}
	if output := os.Getenv("SANDBOX_PDF_TEST_OUTPUT"); output != "" {
		if err := os.WriteFile(output, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSandboxResultActionsIncludePDFAndVirusTotal(t *testing.T) {
	for _, expected := range []string{
		`href="/export/sandbox/{{.Detail.Job}}.pdf"`,
		`href="https://www.virustotal.com/gui/file/{{.Detail.SHA256}}"`,
		`rel="noopener noreferrer"`,
	} {
		if !strings.Contains(pageSandbox, expected) {
			t.Fatalf("sandbox result actions are missing %q", expected)
		}
	}
}

func TestSandboxResultComputesProcessAndSocketDifferences(t *testing.T) {
	row := sandboxResult{
		Artifacts: sandboxArtifacts{
			ProcessesBefore: []string{"USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND", "root 10 0 0 1 1 ? S 00:00 0:00 /usr/bin/old --flag"},
			ProcessesAfter:  []string{"root 42 1 2 3 4 ? S 00:01 0:01 /usr/bin/new --flag", "root 43 0 0 0 0 ? I 00:01 0:00 [kworker/0:1-events]"},
		},
		SocketsBefore: []string{"tcp LISTEN 0 10 127.0.0.1:1 0.0.0.0:*"},
		SocketsAfter:  []string{"tcp LISTEN 0 10 127.0.0.1:2 0.0.0.0:*"},
	}
	normalizeSandboxResult(&row)
	if len(row.ProcessDiff.Added) != 1 || row.ProcessDiff.Added[0] != "root /usr/bin/new --flag" {
		t.Fatalf("unexpected added processes: %#v", row.ProcessDiff.Added)
	}
	if len(row.ProcessDiff.Removed) != 1 || row.ProcessDiff.Removed[0] != "root /usr/bin/old --flag" {
		t.Fatalf("unexpected removed processes: %#v", row.ProcessDiff.Removed)
	}
	if len(row.SocketDiff.Added) != 1 || len(row.SocketDiff.Removed) != 1 {
		t.Fatalf("unexpected socket difference: %#v", row.SocketDiff)
	}
}
