package main

import (
	"encoding/base64"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSandboxResultsAreBoundedAndValidated(t *testing.T) {
	// The invalid-hash doc ("../escape") is included to prove
	// loadSandboxResultsES applies the same hashName validation
	// loadSandboxResultsLocal always did -- ES has no such thing as a
	// stray non-result file mixed into a directory, so that half of the
	// original local-only test is dropped, not translated.
	esResultsClientFor(t, map[string][]map[string]any{
		"sandbox-analysis-v1": {
			{"sandbox": map[string]any{"version": 1, "job": "linux-test", "sha256": strings.Repeat("a", 64), "completed_at": "2026-01-01T00:00:00Z", "stdout": "<script>"}},
			{"sandbox": map[string]any{
				"version": 2, "job": "windows-test", "sha256": strings.Repeat("b", 64), "completed_at": "2026-01-02T00:00:00Z",
				"windows_forensics": map[string]any{"detected": true, "execution_mode": "wine", "pe_type": "PE32+", "imphash": "test"},
				"network_summary":   map[string]any{"dns_queries": []string{"raw.githubusercontent.com"}, "guest_packets": 12},
			}},
			{"sandbox": map[string]any{"job": "bad", "sha256": "../escape"}},
			{"sandbox": map[string]any{
				"version": 2, "job": "linux-timeout", "sha256": strings.Repeat("c", 64), "completed_at": "2026-01-03T00:00:00Z",
				"exit_status": "unknown", "timeout_reason": "host deadline", "risk_score": 20, "risk_level": "low",
			}},
		},
	})
	rows := loadSandboxResults()
	if len(rows) != 3 || rows[0].Job != "linux-timeout" || !rows[0].Incomplete ||
		rows[0].RunStatus != "failed" || rows[0].FailureReason == "" ||
		rows[0].ExitStatus != "host-timeout" || rows[0].RiskScore != 0 || rows[0].RiskLevel != "unrated" ||
		rows[1].Job != "windows-test" || !rows[1].Windows.Detected ||
		rows[1].Windows.ExecutionMode != "wine" || len(rows[1].NetworkSummary.DNSQueries) != 1 ||
		rows[2].Job != "linux-test" || rows[2].Stdout != "<script>" {
		t.Fatalf("unexpected sandbox rows: %#v", rows)
	}
	s := &store{}
	data, err := s.sandboxData("linux-test", "")
	if err != nil || data.Detail == nil {
		t.Fatalf("detail lookup failed: %v", err)
	}
	seedSandboxCache(s, rows...)
	filtered, err := s.sandboxData("", "does-not-match")
	if err != nil || len(filtered.Rows) != 0 {
		t.Fatalf("sandbox search was not applied: %#v %v", filtered.Rows, err)
	}
}

// seedSandboxCache primes s.sandboxCache directly, the same
// seedGitHubAnalysisCache/seedGhidraCache convention
// (github_analysis_test.go/ghidra_test.go) -- bypassing
// refreshSandboxCacheAsync's own background goroutine so a listing-mode
// s.sandboxData("", ...) call sees rows deterministically instead of racing
// an in-process ES stub round trip.
func seedSandboxCache(s *store, rows ...sandboxResult) {
	s.sandboxCache = rows
	s.sandboxCacheAt = time.Now()
}

// TestSandboxDataListLoadingBeforeFirstRefresh covers #1156-follow-up: a
// request that reaches sandboxData's list branch before
// refreshSandboxCacheAsync's first cycle ever completes must report
// Loading=true with no rows, not an empty result --
// ui/sandbox.html's sandboxresultspanel uses exactly this to choose a
// skeleton over "No completed sandbox exports match this view."
func TestSandboxDataListLoadingBeforeFirstRefresh(t *testing.T) {
	s := &store{}
	// Simulates the moment a request reaches sandboxData while
	// refreshSandboxCacheAsync's background goroutine is still running its
	// very first cycle -- set directly rather than racing the real
	// (near-instant, in-process) ES stub round trip a live
	// esResultsClientFor(t, ...) call would complete before this
	// goroutine-free assertion could ever observe the in-flight state.
	s.sandboxRefreshing = true

	data, err := s.sandboxData("", "")
	if err != nil {
		t.Fatal(err)
	}
	if !data.Loading {
		t.Fatal("Loading must be true while the cache has never been populated and a refresh is in flight")
	}
	if len(data.Rows) != 0 {
		t.Fatalf("expected no rows before the first refresh completes, got %+v", data.Rows)
	}
}

// TestSandboxDataListNeverMasksRealDataRegardlessOfLoading pairs with
// skeleton_placeholders_test.go's own
// TestListingPagesNeverMaskRealDataRegardlessOfReady -- a warm cache with
// real rows must render them even if a background refresh happens to be in
// flight (Loading only means "never populated", not "currently
// refreshing").
func TestSandboxDataListNeverMasksRealDataRegardlessOfLoading(t *testing.T) {
	s := &store{}
	seedSandboxCache(s, sandboxResult{Job: "linux-a", SHA256: strings.Repeat("a", 64)})
	s.sandboxRefreshing = true

	data, err := s.sandboxData("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Rows) != 1 || data.Rows[0].Job != "linux-a" {
		t.Fatalf("real cached data must render even mid-refresh: %+v", data.Rows)
	}
	if data.Loading {
		t.Fatal("Loading must be false once the cache has been populated at least once, even mid-refresh")
	}
}

// TestRefreshSandboxCacheAsyncBoundsAndCachesTheListing covers #1156-follow-up
// end to end: refreshSandboxCacheAsync must populate s.sandboxCache from a
// single bounded searchNamespaceLimit request (not searchNamespace's
// whole-namespace pagination), and a second call within sandboxCacheTTL must
// not repeat the round trip.
func TestRefreshSandboxCacheAsyncBoundsAndCachesTheListing(t *testing.T) {
	stub := esResultsStub(t, map[string][]map[string]any{
		"sandbox-analysis-v1": {
			{"sandbox": map[string]any{"version": 2, "job": "linux-a", "sha256": strings.Repeat("a", 64), "completed_at": "2026-01-01T00:00:00Z"}},
		},
	})
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		stub(w, r)
	}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	s := &store{}
	s.refreshSandboxCacheAsync()
	waitForSandboxCache(t, s)
	if len(s.sandboxCache) != 1 || s.sandboxCache[0].Job != "linux-a" {
		t.Fatalf("refreshSandboxCacheAsync did not populate the cache: %#v", s.sandboxCache)
	}
	if requests != 1 {
		t.Fatalf("expected a single bounded ES request, got %d", requests)
	}

	s.refreshSandboxCacheAsync()
	if requests != 1 {
		t.Fatalf("a refresh within sandboxCacheTTL must not repeat the ES round trip, got %d requests", requests)
	}
}

func waitForSandboxCache(t *testing.T, s *store) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.sandboxMu.Lock()
		done := !s.sandboxCacheAt.IsZero()
		s.sandboxMu.Unlock()
		if done {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("refreshSandboxCacheAsync did not populate the cache in time")
}

// #638/#764: attachSandboxDownloads/serveSandboxExport no longer read
// GHIDRA_RESULTS_DIR-style disk paths at all -- the CodeQL path-injection
// concern sandboxArtifactFile existed to close (issue #80, alerts #4/#21)
// no longer applies, since there is no disk read left in this path to
// inject a traversal into. See sandbox_artifacts_es_test.go for this
// area's replacement coverage (fetching by job+kind from Elasticsearch,
// never a client- or worker-supplied filename turned into a filesystem
// path).

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
	funcs := templateFuncs(nil, "")
	if _, err := template.New("dashboard").Funcs(funcs).Parse(pageTemplate); err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
}

// The Windows guest writes to its own spool and its own export directory. The
// sandbox page is a single list, so both have to merge into one view without
// either backend's absence breaking the other's.
func TestSandboxMergesBothBackends(t *testing.T) {
	linuxResults, windowsResults := t.TempDir(), t.TempDir()
	linuxRequests, windowsRequests := t.TempDir(), t.TempDir()
	t.Setenv("SANDBOX_RESULTS_DIR", linuxResults)
	t.Setenv("WINDOWS_SANDBOX_RESULTS_DIR", windowsResults)
	t.Setenv("SANDBOX_REQUEST_DIR", linuxRequests)
	t.Setenv("WINDOWS_SANDBOX_REQUEST_DIR", windowsRequests)

	write := func(dir, name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// loadSandboxStatus below still reads status.json directly from these
	// same dirs (unrelated to #1103 -- status polling was never part of the
	// local-fallback pattern); the two jobs loadSandboxResults sees come
	// from ES now, one merged stream regardless of which backend produced
	// each job -- that merge itself no longer depends on which directory a
	// result's file happened to live in.
	esResultsClientFor(t, map[string][]map[string]any{
		"sandbox-analysis-v1": {
			{"sandbox": map[string]any{"version": 2, "job": "linux-a", "sha256": strings.Repeat("a", 64), "completed_at": "2026-01-01T00:00:00Z", "platform": "Linux"}},
			{"sandbox": map[string]any{"version": 2, "job": "windows-b", "sha256": strings.Repeat("b", 64), "completed_at": "2026-01-02T00:00:00Z", "platform": "Windows"}},
		},
	})

	rows := loadSandboxResults()
	if len(rows) != 2 || rows[0].Job != "windows-b" || rows[1].Job != "linux-a" {
		t.Fatalf("results did not merge in completion order: %#v", rows)
	}
	if _, err := (&store{}).sandboxData("windows-b", ""); err != nil {
		t.Fatalf("a Windows run is not reachable by job id: %v", err)
	}

	// A Windows worker that is configured but has never run has no status
	// file. Reporting the whole queue as unavailable because of that would
	// call a healthy Linux stack broken.
	write(linuxResults, "status.json",
		`{"updated_at":"2026-01-01T00:00:00Z","worker_state":"idle","counts":{"queued":1,"running":0,"completed":2,"failed":0},"jobs":[]}`)
	if got := loadSandboxStatus(); got.WorkerState != "idle" || got.Counts.Completed != 2 {
		t.Fatalf("a missing Windows status poisoned the merge: %#v", got)
	}

	write(windowsResults, "status.json",
		`{"updated_at":"2026-01-02T00:00:00Z","worker_state":"running","counts":{"queued":3,"running":1,"completed":5,"failed":2},"jobs":[]}`)
	got := loadSandboxStatus()
	if got.Counts.Queued != 4 || got.Counts.Completed != 7 || got.Counts.Failed != 2 {
		t.Fatalf("counts did not sum across backends: %#v", got.Counts)
	}
	// The Windows file claims "running" but its timestamp is far in the past,
	// so the per-backend staleness check demotes it before the merge, and the
	// merge then prefers it over the healthy Linux "idle". Both halves matter:
	// a wedged backend must not hide behind a working one.
	if got.WorkerState != "stale" {
		t.Fatalf("worker_state=%q, want the degraded backend's state to win", got.WorkerState)
	}
	if got.UpdatedAt != "2026-01-02T00:00:00Z" {
		t.Fatalf("updated_at=%q, want the most recent report", got.UpdatedAt)
	}

	// Both spools feed one handoff count, so a backlog on either one is
	// visible on the page.
	write(linuxRequests, strings.Repeat("a", 64)+".request", "")
	write(windowsRequests, strings.Repeat("b", 64)+".request", "")
	if got = loadSandboxStatus(); got.Handoff != 2 {
		t.Fatalf("handoff=%d, want both spools counted", got.Handoff)
	}
}

// Exports resolve per artifact rather than from a single directory, or every
// Windows run's PCAP and diagnostics bundle would 404. #638/#764: the
// artifact itself now comes from sandbox-export-artifacts-v1, not disk --
// see sandbox_artifacts_es_test.go for the ES stub this uses.
func TestSandboxExportsResolveAcrossBackends(t *testing.T) {
	sha := strings.Repeat("c", 64)
	pcap := append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, make([]byte, 64)...)
	artifacts := sandboxArtifactStub(t, map[string]sandboxArtifactChunkDoc{
		sandboxArtifactChunkID("windows-c", "host_pcap", 0): {
			Job: "windows-c", Kind: "host_pcap", Filename: "windows-c.host.pcap",
			ContentType: "application/vnd.tcpdump.pcap", ChunkIndex: 0, TotalChunks: 1,
			SizeBytes: int64(len(pcap)), DataBase64: base64.StdEncoding.EncodeToString(pcap),
		},
	})
	results := esResultsStub(t, map[string][]map[string]any{
		"sandbox-analysis-v1": {
			{"sandbox": map[string]any{"version": 2, "job": "windows-c", "sha256": sha, "completed_at": "2026-01-03T00:00:00Z"}},
		},
	})
	// loadSandboxResults() now needs ES for the base result (#1103), on top
	// of this test's existing artifact-doc stub for the PCAP itself -- one
	// server answers both request shapes, routed by path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/_doc/") {
			artifacts(w, r)
			return
		}
		results(w, r)
	}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	data, err := (&store{}).sandboxData("windows-c", "")
	if err != nil || data.Detail == nil {
		t.Fatalf("detail lookup failed: %v", err)
	}
	if data.Detail.HostPCAPURL != "/export/sandbox/windows-c.host.pcap" || data.Detail.HostPCAPSize != int64(len(pcap)) {
		t.Fatalf("host PCAP was not found via the ES artifact store: %#v", data.Detail)
	}
}

// The sandbox results list renders as a .project-grid/.project-card grid
// (#227, following #221/#226), not the old <table>. Each card links
// straight to /sandbox/{job} -- the same destination the old "investigate"
// link used, not the hash cell's /payload-analysis/ link.
func TestSandboxResultsPageRendersAsCardGrid(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	shaOK := strings.Repeat("e", 64)
	data := sandboxPageData{
		Generated: time.Now(),
		Rows: []sandboxResult{
			{
				Job: "job-1", SHA256: shaOK, Source: "dionaea", CompletedAt: "2026-08-01T10:00:00Z",
				RiskScore: 80, RiskLevel: "high", Duration: 42.5, ExitStatus: "ok",
				NetworkSummary: sandboxNetwork{Packets: 12},
			},
			{
				Job: "job-2", SHA256: strings.Repeat("f", 64), Source: "cowrie", CompletedAt: "2026-08-01T09:00:00Z",
				ExitStatus: "error",
			},
		},
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "sandbox", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	if strings.Contains(body, `id="sandbox-results"><p`) && strings.Contains(body, "<table") {
		t.Fatal("sandbox results still render as a table, want a card grid")
	}
	if !strings.Contains(body, "project-grid") || !strings.Contains(body, "project-card") {
		t.Fatal("sandbox results are missing the .project-grid/.project-card markup")
	}
	if !strings.Contains(body, `href="/sandbox/job-1"`) {
		t.Fatalf("card for %s does not link to /sandbox/job-1", shaOK)
	}
	if strings.Contains(body, `href="/payload-analysis/`+shaOK+`"`) {
		t.Fatal("sandbox card should no longer link the hash to /payload-analysis/ -- that is a click away from the detail page")
	}
	if !strings.Contains(body, ">error<") {
		t.Fatal("exit-status badge for the failed run is missing")
	}
}
