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
