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

func TestLoadGitHubAnalysisResults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)

	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{
		"version": 1, "exit_status": "ok", "completed_at": "2026-07-31T10:00:00+00:00",
		"family": "mirai",
	})
	writeGitHubAnalysisResult(t, dir, shaB, map[string]any{
		"version": 1, "exit_status": "error", "error": "boom",
		"completed_at": "2026-07-31T12:00:00+00:00",
	})
	// Malformed JSON must not hide the valid results alongside it.
	if err := os.WriteFile(filepath.Join(dir, "c"+strings.Repeat("c", 63)+".json"),
		[]byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// status.json lives in the same directory and must be ignored as a result.
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

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

// Identity comes from the filename, which both producer scripts derive from
// the sample's validated content SHA-256 -- not from the document body.
func TestLoadGitHubAnalysisResultsTrustsFilenameOverBody(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{"sha256": shaB, "exit_status": "ok"})

	rows := loadGitHubAnalysisResults()
	if len(rows) != 1 || rows[0].SHA256 != shaA {
		t.Fatalf("body sha256 overrode the filename: %+v", rows)
	}
}

// Bash-written statuses (dry_run, denylist_blocked, quota_exceeded, error)
// never include started_at or commit. Confirm the zero value decodes rather
// than a stray JSON null breaking Unmarshal.
func TestLoadGitHubAnalysisResultsBashWrittenStatusOmitsCommit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{
		"version": 1, "sha256": shaA, "requested_at": "2026-07-31T09:00:00+00:00",
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
}

func TestGitHubAnalysisDataQuery(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{
		"exit_status": "ok", "family": "mirai",
	})
	writeGitHubAnalysisResult(t, dir, shaB, map[string]any{
		"exit_status": "ok", "family": "qbot",
	})

	s := &store{}
	data, err := s.githubAnalysisData("", "mirai")
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Rows) != 1 || data.Rows[0].SHA256 != shaA {
		t.Fatalf("query did not filter by family: %+v", data.Rows)
	}
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
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{"exit_status": "ok", "family": "mirai"})
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
