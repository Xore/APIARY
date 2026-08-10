package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeGitHubAnalysisResult writes {dir}/{sha}.json -- unlike ghidra's
// {sha}_ghidra.json, both producer scripts write the bare hash as the
// filename.
func writeGitHubAnalysisResult(t *testing.T, dir, sha string, row map[string]any) {
	t.Helper()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sha+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// esGitHubAnalysisResult points esResultsClient (#1103: loadGitHubAnalysisResults'
// only source now) at a stub serving rows -- each row wrapped under
// "github_analysis" per searchNamespace's field-name contract (see
// github_analysis.go's own searchNamespace call).
func esGitHubAnalysisResult(t *testing.T, rows ...map[string]any) {
	t.Helper()
	docs := make([]map[string]any, len(rows))
	for i, row := range rows {
		docs[i] = map[string]any{"github_analysis": row}
	}
	esResultsClientFor(t, map[string][]map[string]any{"github-analysis-v1": docs})
}

func TestLoadGitHubAnalysisResults(t *testing.T) {
	esGitHubAnalysisResult(t,
		map[string]any{
			"sha256": shaA, "version": 1, "exit_status": "ok", "completed_at": "2026-07-31T10:00:00+00:00",
			"family": "mirai",
		},
		map[string]any{
			"sha256": shaB, "version": 1, "exit_status": "error", "error": "boom",
			"completed_at": "2026-07-31T12:00:00+00:00",
		},
	)

	rows := loadGitHubAnalysisResults()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(rows), rows)
	}
	// Newest first.
	if rows[0].SHA256 != shaB {
		t.Errorf("rows are not newest-first: got %s first", rows[0].SHA256[:8])
	}
	// A failed analysis is still a visible result, with its reason.
	if rows[0].ExitStatus != "error" || rows[0].Error != "boom" {
		t.Errorf("failed result lost its status/reason: %+v", rows[0])
	}
	// export_url is always offered, unlike ghidra's PDF-gated link.
	if rows[0].ExportURL != "/export/github-analysis/"+shaB {
		t.Errorf("unexpected export url: %q", rows[0].ExportURL)
	}
}

// Bash-written statuses (dry_run, denylist_blocked, quota_exceeded, error)
// never include started_at or commit. Confirm the zero value decodes rather
// than a stray JSON null breaking Unmarshal.
func TestLoadGitHubAnalysisResultsBashWrittenStatusOmitsCommit(t *testing.T) {
	esGitHubAnalysisResult(t, map[string]any{
		"sha256": shaA, "version": 1, "requested_at": "2026-07-31T09:00:00+00:00",
		"completed_at": "2026-07-31T09:00:01+00:00", "exit_status": "denylist_blocked",
		"reason": "path outside allowlist",
	})

	rows := loadGitHubAnalysisResults()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	row := rows[0]
	if row.Reason != "path outside allowlist" {
		t.Errorf("reason did not decode: %+v", row)
	}
	if row.StartedAt != "" || row.Commit != "" {
		t.Errorf("bash-written status should leave started_at/commit empty, got %+v", row)
	}
}

func TestLoadGitHubAnalysisStatus(t *testing.T) {
	t.Run("unconfigured", func(t *testing.T) {
		t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", "")
		if s := loadGitHubAnalysisStatus(); s.Configured {
			t.Error("unset results dir should report Configured=false")
		}
	})

	t.Run("configured but never run", func(t *testing.T) {
		t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", t.TempDir())
		s := loadGitHubAnalysisStatus()
		if !s.Configured || !s.Stale {
			t.Errorf("missing status.json should be Configured+Stale, got %+v", s)
		}
	})

	t.Run("fresh status", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
		raw := `{"version":1,"queued":2,"running":1,"failed":0,"done":5,"timeout":1}`
		if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		s := loadGitHubAnalysisStatus()
		if s.Queued != 2 || s.Running != 1 || s.Done != 5 || s.Timeout != 1 {
			t.Errorf("counts not parsed: %+v", s)
		}
		if s.Stale {
			t.Error("a just-written status.json should not be stale")
		}
	})

	t.Run("stale status", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
		path := filepath.Join(dir, "status.json")
		if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-2 * githubAnalysisStatusStaleAfter)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		if s := loadGitHubAnalysisStatus(); !s.Stale {
			t.Error("an old status.json should be reported stale")
		}
	})

	// Handoff is scanned unconditionally -- it is GITHUB_ANALYSIS_REQUEST_DIR's
	// own count, independent of whether the results side ever produced a
	// status.json, the same way loadSandboxStatus scans its request dirs
	// regardless of the merged results status.
	t.Run("handoff pending but fresh", func(t *testing.T) {
		t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", t.TempDir())
		requestDir := t.TempDir()
		t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requestDir)
		if err := os.WriteFile(filepath.Join(requestDir, shaA+".request"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		s := loadGitHubAnalysisStatus()
		if s.Handoff != 1 {
			t.Errorf("Handoff = %d, want 1", s.Handoff)
		}
		if s.HandoffOld {
			t.Error("a freshly written request marker should not be handoff_stale")
		}
	})

	t.Run("handoff stalled", func(t *testing.T) {
		t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", t.TempDir())
		requestDir := t.TempDir()
		t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requestDir)
		path := filepath.Join(requestDir, shaA+".request")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-2 * githubAnalysisHandoffStaleAfter)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		if s := loadGitHubAnalysisStatus(); !s.HandoffOld {
			t.Error("an old request marker should be reported handoff_stale")
		}
	})

	t.Run("handoff ignores non-request files", func(t *testing.T) {
		t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", t.TempDir())
		requestDir := t.TempDir()
		t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requestDir)
		if err := os.WriteFile(filepath.Join(requestDir, "status.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if s := loadGitHubAnalysisStatus(); s.Handoff != 0 {
			t.Errorf("Handoff = %d, want 0 for a non-.request file", s.Handoff)
		}
	})
}

func TestGitHubAnalysisDataQuery(t *testing.T) {
	esGitHubAnalysisResult(t,
		map[string]any{"sha256": shaA, "exit_status": "ok", "family": "mirai"},
		map[string]any{"sha256": shaB, "exit_status": "ok", "family": "qbot"},
	)

	s := &store{}
	data, err := s.githubAnalysisData("", "mirai")
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Rows) != 1 || data.Rows[0].SHA256 != shaA {
		t.Fatalf("query did not filter by family: %+v", data.Rows)
	}
}

// #149 acceptance: fixture tests cover missing, single, conflicting, and
// updated attribution.
func TestGitHubAnalysisHashesForFamily(t *testing.T) {
	t.Run("missing: unconfigured host resolves nothing", func(t *testing.T) {
		t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", "")
		if hashes := githubAnalysisHashesForFamily("mirai"); len(hashes) != 0 {
			t.Errorf("unconfigured host resolved hashes: %v", hashes)
		}
	})

	t.Run("missing: no result carries this family", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
		writeGitHubAnalysisResult(t, dir, shaA, map[string]any{"exit_status": "ok", "family": "qbot"})
		if hashes := githubAnalysisHashesForFamily("mirai"); len(hashes) != 0 {
			t.Errorf("unmatched family resolved hashes: %v", hashes)
		}
	})

	t.Run("missing: empty family string resolves nothing, never every hash", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
		writeGitHubAnalysisResult(t, dir, shaA, map[string]any{"exit_status": "ok", "family": "qbot"})
		if hashes := githubAnalysisHashesForFamily("   "); len(hashes) != 0 {
			t.Errorf("blank family must not match everything, got: %v", hashes)
		}
	})

	t.Run("single: one hash, one family", func(t *testing.T) {
		esGitHubAnalysisResult(t, map[string]any{"sha256": shaA, "exit_status": "ok", "family": "mirai"})
		hashes := githubAnalysisHashesForFamily("mirai")
		if len(hashes) != 1 || !hashes[shaA] {
			t.Fatalf("single-hash resolution failed: %v", hashes)
		}
	})

	// "Conflicting" attribution: two different samples carry the same family
	// under different casing/whitespace. Matching must be normalized so they
	// resolve to one family's hash set, not fragment into two dead ends that
	// each silently miss half the real evidence.
	t.Run("conflicting: casing and whitespace do not fragment the family", func(t *testing.T) {
		esGitHubAnalysisResult(t,
			map[string]any{"sha256": shaA, "exit_status": "ok", "family": "Mirai"},
			map[string]any{"sha256": shaB, "exit_status": "ok", "family": " mirai "},
		)

		for _, query := range []string{"mirai", "Mirai", " MIRAI "} {
			hashes := githubAnalysisHashesForFamily(query)
			if len(hashes) != 2 || !hashes[shaA] || !hashes[shaB] {
				t.Errorf("query %q did not unify both casings: %v", query, hashes)
			}
		}
	})

	// "Updated" attribution: a result that appears after the first resolution
	// must be picked up on the next call -- there is no stale cache to
	// invalidate, since loadGitHubAnalysisResults() always queries fresh.
	t.Run("updated: a later result is picked up without any cache to bust", func(t *testing.T) {
		if hashes := githubAnalysisHashesForFamily("mirai"); len(hashes) != 0 {
			t.Fatalf("expected no hashes before any result exists, got: %v", hashes)
		}
		esGitHubAnalysisResult(t, map[string]any{"sha256": shaA, "exit_status": "ok", "family": "mirai"})
		hashes := githubAnalysisHashesForFamily("mirai")
		if len(hashes) != 1 || !hashes[shaA] {
			t.Fatalf("newly written result was not picked up: %v", hashes)
		}
	})
}

func TestGitHubAnalysisDataDetailNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{"exit_status": "ok"})

	s := &store{}
	if _, err := s.githubAnalysisData(shaB, ""); err == nil {
		t.Fatal("expected an error for an unknown hash")
	}
}

func TestServeGitHubAnalysisAPI(t *testing.T) {
	// loadGitHubAnalysisStatus's "status" subtest below still reads
	// GITHUB_ANALYSIS_RESULTS_DIR directly (unrelated to #1103 -- queue
	// status polling was never part of the local-fallback pattern); the
	// actual result data comes from ES.
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", t.TempDir())
	esGitHubAnalysisResult(t, map[string]any{"sha256": shaA, "exit_status": "ok", "family": "mirai"})
	s := &store{}

	t.Run("list", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.serveGitHubAnalysisAPI(w, httptest.NewRequest(http.MethodGet, "/api/github-analysis", nil))
		var rows []githubAnalysisResult
		if err := json.NewDecoder(w.Body).Decode(&rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].SHA256 != shaA {
			t.Fatalf("unexpected list payload: %+v", rows)
		}
	})

	t.Run("detail", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.serveGitHubAnalysisAPI(w, httptest.NewRequest(http.MethodGet, "/api/github-analysis/"+shaA, nil))
		var row githubAnalysisResult
		if err := json.NewDecoder(w.Body).Decode(&row); err != nil {
			t.Fatal(err)
		}
		if row.SHA256 != shaA {
			t.Fatalf("unexpected detail payload: %+v", row)
		}
	})

	t.Run("unknown hash is 404", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.serveGitHubAnalysisAPI(w, httptest.NewRequest(http.MethodGet, "/api/github-analysis/"+shaB, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("got %d, want 404", w.Code)
		}
	})

	t.Run("malformed hash is 404, not a directory read", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.serveGitHubAnalysisAPI(w, httptest.NewRequest(http.MethodGet, "/api/github-analysis/../../etc", nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("got %d, want 404", w.Code)
		}
	})

	t.Run("status", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.serveGitHubAnalysisAPI(w, httptest.NewRequest(http.MethodGet, "/api/github-analysis/status", nil))
		var status githubAnalysisQueueStatus
		if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
			t.Fatal(err)
		}
		if !status.Configured {
			t.Error("status should report Configured with a results dir set")
		}
	})
}

func TestGitHubAnalysisRequester(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	s := &store{settings: &settingsService{audit: newAuditLogger(auditPath)}}

	s.settings.audit.log(auditEvent{Action: "github_analysis.submit", Fields: []string{shaB}, Result: "queued", Username: "someone-else"})
	s.settings.audit.log(auditEvent{Action: "github_analysis.submit", Fields: []string{shaA}, Result: "missing_consent", Username: "ignored"})
	s.settings.audit.log(auditEvent{Action: "github_analysis.submit", Fields: []string{shaA}, Result: "queued", Username: "xore"})

	if got := s.githubAnalysisRequester(shaA); got != "xore" {
		t.Errorf("githubAnalysisRequester(shaA) = %q, want %q", got, "xore")
	}
	if got := s.githubAnalysisRequester("c" + strings.Repeat("c", 63)); got != "" {
		t.Errorf("unmatched hash should return empty, got %q", got)
	}

	// nil settings must not panic -- the field is nil in partial test fixtures.
	bare := &store{}
	if got := bare.githubAnalysisRequester(shaA); got != "" {
		t.Errorf("nil settings should return empty, got %q", got)
	}
}

// githubAnalysisAlertMessages mirrors ghidraAlertMessages: s.alerts == nil
// means "no dedupe sink", so every check that fires emits unconditionally --
// exactly what a unit test wants. hasAlert is defined in ghidra_test.go.
func githubAnalysisAlertMessages(t *testing.T) []string {
	t.Helper()
	var messages []string
	githubAnalysisAlerts(&store{}, &messages, false)
	return messages
}

// An unconfigured host has not run install-github-publisher.sh; alerting
// about a subsystem nobody deployed is pure noise. #148 acceptance: disabled.
func TestGitHubAnalysisAlertsSilentWhenUnconfigured(t *testing.T) {
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", "")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", "")
	if messages := githubAnalysisAlertMessages(t); len(messages) != 0 {
		t.Fatalf("unconfigured host produced alerts: %v", messages)
	}
}

// #148 acceptance: handoff state.
func TestGitHubAnalysisAlertsOnHandoffStalled(t *testing.T) {
	resultsDir, requestDir := t.TempDir(), t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", resultsDir)
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requestDir)
	if err := os.WriteFile(filepath.Join(resultsDir, "status.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(requestDir, shaA+".request")
	if err := os.WriteFile(requestPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * githubAnalysisHandoffStaleAfter)
	if err := os.Chtimes(requestPath, old, old); err != nil {
		t.Fatal(err)
	}
	messages := githubAnalysisAlertMessages(t)
	if !hasAlert(messages, "handoff stalled") {
		t.Fatalf("no handoff alert: %v", messages)
	}
	if !hasAlert(messages, "1 request") {
		t.Errorf("handoff alert omits the count: %v", messages)
	}
}

// #148 acceptance: recovered. A request marker that is still within the
// staleness window must not page -- that is normal, momentary queue depth,
// not a stalled handoff.
func TestGitHubAnalysisAlertsHandoffRecoversWhenFresh(t *testing.T) {
	resultsDir, requestDir := t.TempDir(), t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", resultsDir)
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requestDir)
	if err := os.WriteFile(filepath.Join(resultsDir, "status.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(requestDir, shaA+".request"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if messages := githubAnalysisAlertMessages(t); hasAlert(messages, "handoff stalled") {
		t.Errorf("a freshly queued request alerted before the staleness threshold: %v", messages)
	}
}

// #148 acceptance: stale state (publisher or collector stopped refreshing
// status.json).
func TestGitHubAnalysisAlertsOnStaleWorker(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", "")
	path := filepath.Join(dir, "status.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"queued":3,"running":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * githubAnalysisStatusStaleAfter)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	messages := githubAnalysisAlertMessages(t)
	if !hasAlert(messages, "worker unhealthy") {
		t.Fatalf("no stale-worker alert: %v", messages)
	}
	// The queue depth belongs in the message so the reader knows whether
	// anything is actually waiting behind the stopped collector.
	if !hasAlert(messages, "queued=3") || !hasAlert(messages, "running=1") {
		t.Errorf("stale-worker alert omits the queue depth: %v", messages)
	}
}

// #148 acceptance: failed state.
func TestGitHubAnalysisAlertsOnFailedQueue(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", "")
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{"version":1,"failed":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if messages := githubAnalysisAlertMessages(t); !hasAlert(messages, "2 failed request") {
		t.Fatalf("no failed-queue alert: %v", messages)
	}
}

// #148 acceptance: high-verdict state, and the configurable, bounded
// threshold (GITHUB_ANALYSIS_ALERT_POSITIVES) required by the issue.
func TestGitHubAnalysisAlertsOnHighVerdict(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", "")
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	esGitHubAnalysisResult(t, map[string]any{
		"sha256": shaA, "exit_status": "ok", "family": "mirai",
		"verdict": map[string]any{"malicious": 12, "suspicious": 3, "total": 20, "level": "malicious"},
	})

	messages := githubAnalysisAlertMessages(t)
	if !hasAlert(messages, "high-verdict") || !hasAlert(messages, "malicious=12/20") || !hasAlert(messages, "family=mirai") {
		t.Fatalf("no high-verdict alert: %v", messages)
	}

	// Raising the threshold above this sample's count must quiet it -- proves
	// the env var is actually read, not just defaulted.
	t.Setenv("GITHUB_ANALYSIS_ALERT_POSITIVES", "15")
	if messages := githubAnalysisAlertMessages(t); hasAlert(messages, "high-verdict") {
		t.Errorf("verdict below the configured threshold alerted: %v", messages)
	}
}

// #148 acceptance: queued/disabled. The four bash-written exit statuses
// (dry_run, denylist_blocked, quota_exceeded, error) never carry a Verdict,
// and must not be treated as a quiet malicious=0 result worth alerting on.
func TestGitHubAnalysisAlertsIgnoreResultsWithoutVerdict(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", "")
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{"exit_status": "dry_run"})
	writeGitHubAnalysisResult(t, dir, shaB, map[string]any{"exit_status": "denylist_blocked", "reason": "path outside allowlist"})
	if messages := githubAnalysisAlertMessages(t); len(messages) != 0 {
		t.Fatalf("bash-written statuses without a verdict alerted: %v", messages)
	}
}

// #148: honeypot_github_analysis_queue{state=...} alongside the existing
// honeypot_sandbox_queue gauges (dashboard/metrics.go).
func TestGitHubAnalysisMetricsExposed(t *testing.T) {
	resultsDir, requestDir := t.TempDir(), t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", resultsDir)
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requestDir)
	if err := os.WriteFile(filepath.Join(resultsDir, "status.json"),
		[]byte(`{"version":1,"queued":2,"running":1,"failed":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(requestDir, shaA+".request"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	s := &store{}
	recorder := httptest.NewRecorder()
	s.serveMetrics(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()

	exact := []string{
		`honeypot_github_analysis_queue{state="handoff"} 1`,
		`honeypot_github_analysis_queue{state="queued"} 2`,
		`honeypot_github_analysis_queue{state="running"} 1`,
		`honeypot_github_analysis_queue{state="failed"} 3`,
	}
	for _, line := range exact {
		if !strings.Contains(body, line+"\n") {
			t.Errorf("metrics output missing %q, got:\n%s", line, body)
		}
	}
}

// An unconfigured host must still report the gauge at zero, not omit it --
// scrapers alert on a metric disappearing, and "never deployed" is a
// different state from "the exporter stopped".
func TestGitHubAnalysisMetricsZeroWhenUnconfigured(t *testing.T) {
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", "")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", "")
	s := &store{}
	recorder := httptest.NewRecorder()
	s.serveMetrics(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	if !strings.Contains(body, `honeypot_github_analysis_queue{state="handoff"} 0`+"\n") {
		t.Errorf("unconfigured host should still expose a zero gauge, got:\n%s", body)
	}
}
