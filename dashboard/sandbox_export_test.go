package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestSandboxResultComputesProcessAndSocketDifferences(t *testing.T) {
	row := sandboxResult{
		Artifacts: sandboxArtifacts{
			ProcessesBefore: []string{"USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND", "root 10 0 0 1 1 ? S 00:00 0:00 /usr/bin/old --flag"},
			ProcessesAfter:  []string{"root 42 1 2 3 4 ? S 00:01 0:01 /usr/bin/new --flag"},
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
