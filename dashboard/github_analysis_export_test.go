package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestServeGitHubAnalysisExportRejectsBadHash(t *testing.T) {
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", t.TempDir())
	s := &store{}
	for _, path := range []string{
		"/export/github-analysis/../../etc/passwd",
		"/export/github-analysis/not-a-hash",
		"/export/github-analysis/",
	} {
		w := httptest.NewRecorder()
		s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, w.Code)
		}
	}
}

func TestServeGitHubAnalysisExportUnconfigured(t *testing.T) {
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", "")
	s := &store{}
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, "/export/github-analysis/"+shaA, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
}

func TestServeGitHubAnalysisExportMissingResult(t *testing.T) {
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", t.TempDir())
	s := &store{}
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, "/export/github-analysis/"+shaA, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
}

// The key divergence from ghidra's exporter: a valid PDF + commit redirects
// to the public repo instead of streaming local bytes, since the dashboard
// container never mounts GITHUB_CLONE.
func TestServeGitHubAnalysisExportRedirectsToPDF(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	commit := "0123456789abcdef0123456789abcdef01234567"
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{
		"exit_status": "ok", "commit": commit, "report_pdf": "reports/" + shaA + ".pdf",
	})
	s := &store{}
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, "/export/github-analysis/"+shaA, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("got %d, want 302", w.Code)
	}
	want := "https://raw.githubusercontent.com/Xore/honeypot/" + commit + "/reports/" + shaA + ".pdf"
	if got := w.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

// No PDF exists (dry_run, denylist_blocked, quota_exceeded, error, timeout,
// or an ok result the worker never reported a report_pdf for) -- unlike
// ghidra's 404, the dashboard falls back to serving the JSON record so the
// link is never a dead end.
func TestServeGitHubAnalysisExportFallsBackToJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{
		"exit_status": "quota_exceeded", "daily_cap": 10,
	})
	s := &store{}
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, "/export/github-analysis/"+shaA, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); cd == "" {
		t.Error("missing Content-Disposition attachment header")
	}
	var row githubAnalysisResult
	if err := json.NewDecoder(w.Body).Decode(&row); err != nil {
		t.Fatal(err)
	}
	if row.SHA256 != shaA || row.ExitStatus != "quota_exceeded" || row.DailyCap != 10 {
		t.Errorf("unexpected JSON fallback payload: %+v", row)
	}
}

// Commit and ReportPDF are producer-controlled but become URL path
// segments -- both must be re-validated even though they came from a file
// the collector wrote, mirroring attachGhidraDownload's posture toward a
// worker-written filename.
func TestGitHubAnalysisPDFURLRejectsUntrustedInputs(t *testing.T) {
	validCommit := "0123456789abcdef0123456789abcdef01234567"
	cases := []struct {
		name string
		row  githubAnalysisResult
	}{
		{"no report_pdf", githubAnalysisResult{Commit: validCommit}},
		{"no commit", githubAnalysisResult{ReportPDF: "reports/a.pdf"}},
		{"short commit", githubAnalysisResult{Commit: "abc123", ReportPDF: "reports/a.pdf"}},
		{"uppercase commit", githubAnalysisResult{Commit: "0123456789ABCDEF0123456789ABCDEF01234567", ReportPDF: "reports/a.pdf"}},
		{"traversal in report_pdf", githubAnalysisResult{Commit: validCommit, ReportPDF: "../../etc/passwd"}},
		{"absolute report_pdf", githubAnalysisResult{Commit: validCommit, ReportPDF: "/etc/passwd"}},
	}
	for _, c := range cases {
		if _, ok := githubAnalysisPDFURL(c.row); ok {
			t.Errorf("%s: expected rejection, got a URL", c.name)
		}
	}

	valid := githubAnalysisResult{Commit: validCommit, ReportPDF: "reports/x.pdf"}
	got, ok := githubAnalysisPDFURL(valid)
	if !ok {
		t.Fatal("expected a valid PDF URL to be accepted")
	}
	want := "https://raw.githubusercontent.com/Xore/honeypot/" + validCommit + "/reports/x.pdf"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// analyze.yml commits the PDF in its own commit, after the original push
// Commit records -- a URL built from Commit 404s, since the file does not
// exist there yet (#255). ReportCommit must win whenever it is present;
// falling back to Commit is only for results collect-results.py wrote
// before ReportCommit existed.
func TestGitHubAnalysisPDFURLPrefersReportCommit(t *testing.T) {
	pushCommit := "0123456789abcdef0123456789abcdef01234567"
	reportCommit := "abcdef0123456789abcdef0123456789abcdef01"
	row := githubAnalysisResult{Commit: pushCommit, ReportCommit: reportCommit, ReportPDF: "reports/pdf/samples/x.pdf"}

	got, ok := githubAnalysisPDFURL(row)
	if !ok {
		t.Fatal("expected a valid PDF URL to be accepted")
	}
	want := "https://raw.githubusercontent.com/Xore/honeypot/" + reportCommit + "/reports/pdf/samples/x.pdf"
	if got != want {
		t.Errorf("got %q, want the URL built from ReportCommit: %q", got, want)
	}

	// An invalid ReportCommit must not silently fall back to a still-valid
	// Commit -- both are producer-controlled and untrusted independently.
	bad := githubAnalysisResult{Commit: pushCommit, ReportCommit: "not-a-commit", ReportPDF: "reports/pdf/samples/x.pdf"}
	if _, ok := githubAnalysisPDFURL(bad); ok {
		t.Error("expected rejection when ReportCommit is present but malformed")
	}
}

// A traversal attempt reaching serveGitHubAnalysisExport through the on-disk
// result body (not the URL) must fall back to JSON rather than redirecting
// off the validated report path.
func TestServeGitHubAnalysisExportRejectsTraversalInBody(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{
		"exit_status": "ok",
		"commit":      "0123456789abcdef0123456789abcdef01234567",
		"report_pdf":  "../../../etc/passwd",
	})
	s := &store{}
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, "/export/github-analysis/"+shaA, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (JSON fallback)", w.Code)
	}
	if w.Header().Get("Location") != "" {
		t.Error("traversal in report_pdf must not produce a redirect")
	}
}

// Malformed JSON on disk must not panic the exporter, nor silently succeed.
func TestServeGitHubAnalysisExportRejectsMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, shaA+".json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &store{}
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, "/export/github-analysis/"+shaA, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
}
