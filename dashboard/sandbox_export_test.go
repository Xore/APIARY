package main

import (
	"bytes"
	"html/template"
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
	job := "linux-20260726T000000Z-0123456789ab"
	hash := strings.Repeat("a", 64)
	pcap := make([]byte, 24)
	copy(pcap, []byte{0xd4, 0xc3, 0xb2, 0xa1})
	// #638/#764: the artifact itself comes from sandbox-export-artifacts-v1;
	// #1103: the base result (sandboxData's own job lookup, which runs
	// before the admin check below) comes from sandbox-analysis-v1 now too
	// -- one server answers both request shapes, routed by path.
	artifacts := sandboxArtifactStub(t, chunkDocs(job, "host_pcap", "application/vnd.tcpdump.pcap", job+".host.pcap", pcap, 1<<20))
	results := esResultsStub(t, map[string][]map[string]any{
		"sandbox-analysis-v1": {{"sandbox": map[string]any{"version": 3, "job": job, "sha256": hash}}},
	})
	esSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/_doc/") {
			artifacts(w, r)
			return
		}
		results(w, r)
	}))
	defer esSrv.Close()
	withESResultsClient(t, esSrv.URL)
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	path := "/export/sandbox/" + job + ".host.pcap"

	denied := httptest.NewRecorder()
	(&store{}).serveSandboxExport(denied, httptest.NewRequest(http.MethodGet, path, nil))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unauthorized status = %d, want %d", denied.Code, http.StatusForbidden)
	}

	request := httptest.NewRequest(http.MethodGet, path, nil)
	addIdentityTestCookie(request)
	allowed := httptest.NewRecorder()
	(&store{}).serveSandboxExport(allowed, request)
	if allowed.Code != http.StatusOK || allowed.Body.Len() != len(pcap) {
		t.Fatalf("authorized response = status %d, bytes %d", allowed.Code, allowed.Body.Len())
	}
	if got := allowed.Header().Get("Content-Type"); got != "application/vnd.tcpdump.pcap" {
		t.Fatalf("content type = %q", got)
	}
}

func TestSandboxDiagnosticsExportRequiresAdmin(t *testing.T) {
	job := "windows-20260729T000000Z-0123456789ab"
	hash := strings.Repeat("b", 64)
	bundle := []byte("PK\x05\x06" + strings.Repeat("\x00", 18))
	artifacts := sandboxArtifactStub(t, chunkDocs(job, "diagnostics", "application/zip", job+".diagnostics.zip", bundle, 1<<20))
	results := esResultsStub(t, map[string][]map[string]any{
		"sandbox-analysis-v1": {{"sandbox": map[string]any{"version": 3, "job": job, "sha256": hash}}},
	})
	esSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/_doc/") {
			artifacts(w, r)
			return
		}
		results(w, r)
	}))
	defer esSrv.Close()
	withESResultsClient(t, esSrv.URL)
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	path := "/export/sandbox/" + job + ".diagnostics.zip"

	denied := httptest.NewRecorder()
	(&store{}).serveSandboxExport(denied, httptest.NewRequest(http.MethodGet, path, nil))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unauthorized status = %d, want %d", denied.Code, http.StatusForbidden)
	}

	request := httptest.NewRequest(http.MethodGet, path, nil)
	addIdentityTestCookie(request)
	allowed := httptest.NewRecorder()
	(&store{}).serveSandboxExport(allowed, request)
	if allowed.Code != http.StatusOK || allowed.Body.Len() != len(bundle) {
		t.Fatalf("authorized response = status %d, bytes %d", allowed.Code, allowed.Body.Len())
	}
	if got := allowed.Header().Get("Content-Type"); got != "application/zip" {
		t.Fatalf("content type = %q", got)
	}
}

// TestSandboxPDFExportRemoved proves PDF generation is consolidated in the
// Reports studio (R2): the legacy per-run export path no longer serves PDFs,
// not even to administrators. Sandbox PDFs are produced from a report
// definition with the sandbox template instead.
func TestSandboxPDFExportRemoved(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", dir)
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
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
	request := httptest.NewRequest(http.MethodGet, "/export/sandbox/"+job+".pdf", nil)
	addIdentityTestCookie(request)
	response := httptest.NewRecorder()
	(&store{}).serveSandboxExport(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("legacy sandbox PDF export status = %d, want %d", response.Code, http.StatusNotFound)
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
	body := renderThemedSandboxReportPDF(result, time.Date(2026, 7, 29, 17, 0, 0, 0, time.UTC), pdfThemeDark(), defaultPDFBranding())
	if !bytes.HasPrefix(body, []byte("%PDF-1.4")) || !bytes.Contains(body, []byte("%%EOF")) {
		t.Fatal("renderThemedSandboxReportPDF() did not produce a complete PDF")
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

func TestSandboxResultActionsLinkVirusTotalWithoutAReportShortcut(t *testing.T) {
	for _, expected := range []string{
		`href="https://www.virustotal.com/gui/file/{{.Detail.SHA256}}"`,
		`rel="noopener noreferrer"`,
	} {
		if !strings.Contains(pageSandbox, expected) {
			t.Fatalf("sandbox result actions are missing %q", expected)
		}
	}
	if strings.Contains(pageSandbox, `/export/sandbox/{{.Detail.Job}}.pdf`) {
		t.Fatal("sandbox result page must not offer a direct PDF export; only the Reports studio generates PDFs")
	}
	// Reports are reached through the left navigation only; per-page shortcuts
	// were removed so every page has one obvious route to the studio.
	if strings.Contains(pageSandbox, `href="/reports"`) {
		t.Fatal("sandbox result page must not carry its own Reports studio shortcut")
	}
}

// Every page-level "Report …" button was removed; the sidebar entry is the
// single way into the Reports studio.
func TestOnlyTheNavigationLinksTheReportsStudio(t *testing.T) {
	pages := map[string]string{
		"overview": pageOverview, "events": pageEvents, "ips": pageIPs,
		"session": pageSession, "intel": pageIntel, "ops": pageOps,
		"sandbox": pageSandbox, "payloads": pagePayloads, "search": pageSearch,
	}
	for name, page := range pages {
		if strings.Contains(page, `href="/reports"`) {
			t.Fatalf("%s still links the Reports studio outside the navigation", name)
		}
	}
	if !strings.Contains(pageStyle, `data-hp-nav="/reports" href="/reports"`) {
		t.Fatal("the sidebar must keep the Reports studio navigation entry")
	}
}

// Re-analysis is only offered while the capture is still on disk, and it must
// carry the job back so a queued run returns to the investigation it came from.
func TestSandboxDetailOffersReanalysisOnlyWhileTheCaptureExists(t *testing.T) {
	tmpl, err := template.New("dashboard").Funcs(templateFuncs(nil, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	render := func(available bool) string {
		data := sandboxPageData{
			Generated: time.Now(),
			Detail: &sandboxResult{
				Job:              "job-2026-07-30",
				SHA256:           strings.Repeat("a", 64),
				CaptureAvailable: available,
			},
		}
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, "sandbox", data); err != nil {
			t.Fatalf("render(available=%v): %v", available, err)
		}
		return buf.String()
	}

	withCapture := render(true)
	for _, expected := range []string{
		`action="/sandbox/submit"`,
		`name="return" value="/sandbox/job-2026-07-30"`,
		`Re-analyze`,
	} {
		if !strings.Contains(withCapture, expected) {
			t.Fatalf("re-analysis control is missing %q", expected)
		}
	}

	withoutCapture := render(false)
	if strings.Contains(withoutCapture, `action="/sandbox/submit"`) {
		t.Fatal("re-analysis must not be offered once the capture is gone")
	}
	if !strings.Contains(withoutCapture, "no longer in a payload directory") {
		t.Fatal("a missing capture must be explained rather than silently dropping the control")
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

// #514: the sandbox results grid showed only the absolute "completed"
// timestamp, unlike the queue list one card up which already gives an
// operator this same relative-age context via Status.Handoff/HandoffOld.
func TestNormalizeSandboxResultComputesCompletedAgo(t *testing.T) {
	row := sandboxResult{CompletedAt: time.Now().Add(-90 * time.Minute).UTC().Format(time.RFC3339)}
	normalizeSandboxResult(&row)
	if row.CompletedAgo != "1h ago" {
		t.Fatalf("CompletedAgo = %q, want %q", row.CompletedAgo, "1h ago")
	}

	unparseable := sandboxResult{CompletedAt: "not-a-timestamp"}
	normalizeSandboxResult(&unparseable)
	if unparseable.CompletedAgo != "" {
		t.Fatalf("an unparseable CompletedAt must leave CompletedAgo empty, got %q", unparseable.CompletedAgo)
	}
}
