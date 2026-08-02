package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #309: the Report card's inline viewer needs a same-origin endpoint --
// framing raw.githubusercontent.com directly would be silently blocked by
// the dashboard's own CSP frame-src (render.go). These tests fake the
// upstream fetch via githubAnalysisPDFClient's Transport rather than
// hitting the real network.

type fakeGitHubAnalysisRoundTripper struct {
	status int
	body   string
	err    error
}

func (f fakeGitHubAnalysisRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

func withFakeGitHubAnalysisUpstream(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	original := githubAnalysisPDFClient.Transport
	githubAnalysisPDFClient.Transport = rt
	t.Cleanup(func() { githubAnalysisPDFClient.Transport = original })
}

const githubAnalysisTestCommit = "0123456789abcdef0123456789abcdef01234567"

func TestLoadGitHubAnalysisResultsSetsViewURLOnlyWhenAPDFExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{
		"exit_status": "ok", "commit": githubAnalysisTestCommit, "report_pdf": "reports/" + shaA + ".pdf",
	})
	writeGitHubAnalysisResult(t, dir, shaB, map[string]any{
		"exit_status": "quota_exceeded", "daily_cap": 10,
	})

	rows := loadGitHubAnalysisResults()
	byHash := map[string]githubAnalysisResult{}
	for _, row := range rows {
		byHash[row.SHA256] = row
	}
	if got, want := byHash[shaA].ViewURL, "/export/github-analysis/"+shaA+"/pdf"; got != want {
		t.Errorf("shaA ViewURL = %q, want %q", got, want)
	}
	if got := byHash[shaB].ViewURL; got != "" {
		t.Errorf("shaB has no PDF and must not get a ViewURL, got %q", got)
	}
	// ExportURL stays offered for both regardless (existing behavior, #309
	// must not narrow it).
	if byHash[shaA].ExportURL == "" || byHash[shaB].ExportURL == "" {
		t.Errorf("ExportURL must still be set for every row: %+v", byHash)
	}
}

func TestServeGitHubAnalysisPDFProxyStreamsInlineByDefault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{
		"exit_status": "ok", "commit": githubAnalysisTestCommit, "report_pdf": "reports/" + shaA + ".pdf",
	})
	withFakeGitHubAnalysisUpstream(t, fakeGitHubAnalysisRoundTripper{status: http.StatusOK, body: "%PDF-fake-bytes"})

	s := &store{}
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, "/export/github-analysis/"+shaA+"/pdf", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Errorf("Content-Type = %q, want application/pdf", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "inline") {
		t.Errorf("Content-Disposition = %q, want inline by default", cd)
	}
	if w.Body.String() != "%PDF-fake-bytes" {
		t.Errorf("body = %q, want the fetched upstream bytes verbatim", w.Body.String())
	}
}

func TestServeGitHubAnalysisPDFProxyDownloadQueryParamSwitchesToAttachment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{
		"exit_status": "ok", "commit": githubAnalysisTestCommit, "report_pdf": "reports/" + shaA + ".pdf",
	})
	withFakeGitHubAnalysisUpstream(t, fakeGitHubAnalysisRoundTripper{status: http.StatusOK, body: "bytes"})

	s := &store{}
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, "/export/github-analysis/"+shaA+"/pdf?download=1", nil))

	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want attachment when ?download=1", cd)
	}
}

func TestServeGitHubAnalysisPDFProxyNoReportGivesNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{"exit_status": "quota_exceeded", "daily_cap": 10})

	s := &store{}
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, "/export/github-analysis/"+shaA+"/pdf", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when no PDF has ever been generated", w.Code)
	}
}

func TestServeGitHubAnalysisPDFProxyUpstreamErrorGivesBadGateway(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{
		"exit_status": "ok", "commit": githubAnalysisTestCommit, "report_pdf": "reports/" + shaA + ".pdf",
	})
	withFakeGitHubAnalysisUpstream(t, fakeGitHubAnalysisRoundTripper{status: http.StatusNotFound, body: "404: Not Found"})

	s := &store{}
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, "/export/github-analysis/"+shaA+"/pdf", nil))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when the upstream fetch itself fails", w.Code)
	}
}

func TestServeGitHubAnalysisPDFProxyRejectsBadHash(t *testing.T) {
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", t.TempDir())
	s := &store{}
	for _, path := range []string{
		"/export/github-analysis/not-a-hash/pdf",
		"/export/github-analysis/../../etc/passwd/pdf",
	} {
		w := httptest.NewRecorder()
		s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, w.Code)
		}
	}
}

// The pre-existing base route (no /pdf suffix) must keep redirecting
// straight to raw.githubusercontent.com, unaffected by #309 -- the
// dashboard-proxied inline view is additive, not a replacement.
func TestServeGitHubAnalysisExportBaseRouteStillRedirects(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GITHUB_ANALYSIS_RESULTS_DIR", dir)
	writeGitHubAnalysisResult(t, dir, shaA, map[string]any{
		"exit_status": "ok", "commit": githubAnalysisTestCommit, "report_pdf": "reports/" + shaA + ".pdf",
	})
	s := &store{}
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisExport(w, httptest.NewRequest(http.MethodGet, "/export/github-analysis/"+shaA, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (the pre-existing redirect behavior, unchanged)", w.Code)
	}
}
