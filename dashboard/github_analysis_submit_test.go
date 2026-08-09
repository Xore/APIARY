package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitHubAnalysisSubmitWritesOnlyValidatedExistingHash(t *testing.T) {
	payloads, requests := t.TempDir(), t.TempDir()
	hash := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(payloads, hash), []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requests)
	s := &store{payloadDirs: []string{payloads}}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit",
		strings.NewReader("hash="+hash+"&confirm=publish"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisSubmit(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(requests, hash+".request")); err != nil {
		t.Fatalf("request missing: %v", err)
	}
}

// Dionaea's captures are MD5-named (32 hex), not SHA-256 — the same reason
// analysis/github/resolve-sample.sh accepts 32-64 hex. A stricter check here
// would silently refuse every Dionaea-sourced submission from the payloads
// page, which has no way to know a given row's hash length in advance.
func TestGitHubAnalysisSubmitAcceptsMD5LengthHash(t *testing.T) {
	payloads, requests := t.TempDir(), t.TempDir()
	hash := strings.Repeat("b", 32)
	if err := os.WriteFile(filepath.Join(payloads, hash), []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requests)
	s := &store{payloadDirs: []string{payloads}}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit",
		strings.NewReader("hash="+hash+"&confirm=publish"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisSubmit(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(requests, hash+".request")); err != nil {
		t.Fatalf("request missing: %v", err)
	}
}

func TestGitHubAnalysisSubmitRejectsMissingConsent(t *testing.T) {
	payloads, requests := t.TempDir(), t.TempDir()
	hash := strings.Repeat("c", 64)
	if err := os.WriteFile(filepath.Join(payloads, hash), []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requests)
	s := &store{payloadDirs: []string{payloads}}
	for _, body := range []string{"hash=" + hash, "hash=" + hash + "&confirm=yes", "hash=" + hash + "&confirm="} {
		r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addIdentityTestCookie(r)
		r.Header.Set("Origin", "https://honeypot.example")
		w := httptest.NewRecorder()
		s.serveGitHubAnalysisSubmit(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body=%q status=%d, want 400", body, w.Code)
		}
	}
	if entries, _ := os.ReadDir(requests); len(entries) != 0 {
		t.Fatalf("a request marker was written despite missing consent: %v", entries)
	}
}

func TestGitHubAnalysisSubmitRejectsUnknownPayload(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", t.TempDir())
	s := &store{payloadDirs: []string{t.TempDir()}}
	hash := strings.Repeat("d", 64)
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit",
		strings.NewReader("hash="+hash+"&confirm=publish"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisSubmit(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestGitHubAnalysisSubmitRejectsBadHash(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", t.TempDir())
	s := &store{payloadDirs: []string{t.TempDir()}}
	for _, hash := range []string{"", "not-hex", strings.Repeat("a", 10), strings.Repeat("a", 65), strings.Repeat("g", 64)} {
		r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit",
			strings.NewReader("hash="+hash+"&confirm=publish"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addIdentityTestCookie(r)
		r.Header.Set("Origin", "https://honeypot.example")
		w := httptest.NewRecorder()
		s.serveGitHubAnalysisSubmit(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("hash=%q status=%d, want 400", hash, w.Code)
		}
	}
}

func TestGitHubAnalysisSubmitDisabledWithoutSpool(t *testing.T) {
	payloads := t.TempDir()
	hash := strings.Repeat("e", 64)
	if err := os.WriteFile(filepath.Join(payloads, hash), []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", "")
	s := &store{payloadDirs: []string{payloads}}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit",
		strings.NewReader("hash="+hash+"&confirm=publish"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisSubmit(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestGitHubAnalysisSubmitIsIdempotent(t *testing.T) {
	payloads, requests := t.TempDir(), t.TempDir()
	hash := strings.Repeat("f", 64)
	if err := os.WriteFile(filepath.Join(payloads, hash), []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requests)
	s := &store{payloadDirs: []string{payloads}}
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit",
			strings.NewReader("hash="+hash+"&confirm=publish"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addIdentityTestCookie(r)
		r.Header.Set("Origin", "https://honeypot.example")
		w := httptest.NewRecorder()
		s.serveGitHubAnalysisSubmit(w, r)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("attempt %d: status=%d body=%s", i, w.Code, w.Body.String())
		}
	}
}

func TestGitHubAnalysisSubmitReturnsToTheInitiatingPage(t *testing.T) {
	payloads, requests := t.TempDir(), t.TempDir()
	hash := strings.Repeat("1", 64)
	if err := os.WriteFile(filepath.Join(payloads, hash), []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requests)
	s := &store{payloadDirs: []string{payloads}}
	body := "hash=" + hash + "&confirm=publish&return=" + url.QueryEscape("/payload-analysis/"+hash)
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisSubmit(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "/payload-analysis/"+hash+"?") || !strings.Contains(location, "analysis=queued") {
		t.Fatalf("location=%q, want the initiating page with the queued marker", location)
	}
}

// An operator-supplied return target must never become an open redirect or a
// route outside the github-analysis/payload surfaces.
func TestGitHubAnalysisReturnURLRejectsForeignTargets(t *testing.T) {
	hash := strings.Repeat("2", 64)
	fallback := "/payloads?analysis=queued&hash=" + hash + "&target=github-analysis"
	for _, raw := range []string{
		"", "   ",
		"https://evil.example/github-analysis/x",
		"//evil.example/github-analysis/x",
		"/settings",
		"/events?ip=1.2.3.4",
		"http://honeypot.example/payloads",
	} {
		if got := githubAnalysisReturnURL(raw, hash); got != fallback {
			t.Fatalf("githubAnalysisReturnURL(%q) = %q, want the payload inventory fallback", raw, got)
		}
	}
	got := githubAnalysisReturnURL("/github-analysis/"+hash+"#top", hash)
	if strings.Contains(got, "#") || !strings.HasPrefix(got, "/github-analysis/"+hash+"?") {
		t.Fatalf("githubAnalysisReturnURL kept an unexpected shape: %q", got)
	}
}

func TestGitHubAnalysisSubmitRejectsCrossSite(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", t.TempDir())
	hash := strings.Repeat("3", 64)
	s := &store{payloadDirs: []string{t.TempDir()}}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit",
		strings.NewReader("hash="+hash+"&confirm=publish"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisSubmit(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", w.Code)
	}
}

func TestGitHubAnalysisSubmitRejectsNonAdmin(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "user")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", t.TempDir())
	hash := strings.Repeat("4", 64)
	s := &store{payloadDirs: []string{t.TempDir()}}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit",
		strings.NewReader("hash="+hash+"&confirm=publish"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisSubmit(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", w.Code)
	}
}

// Every submission -- accepted or refused -- is written to the audit log
// with the admin identity and the sample's hash, per the roadmap's consent
// requirements. Reuses the existing settings audit sink rather than a
// second one.
func TestGitHubAnalysisSubmitAudits(t *testing.T) {
	payloads, requests := t.TempDir(), t.TempDir()
	hash := strings.Repeat("5", 64)
	if err := os.WriteFile(filepath.Join(payloads, hash), []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("GITHUB_ANALYSIS_REQUEST_DIR", requests)
	dir := t.TempDir()
	s := &store{
		payloadDirs: []string{payloads},
		settings: newSettingsService(
			nil, // no Elasticsearch needed -- this test only exercises audit logging
			filepath.Join(dir, "audit.jsonl"),
			filepath.Join(dir, "history.jsonl"),
		),
	}

	// Accepted attempt.
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit",
		strings.NewReader("hash="+hash+"&confirm=publish"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://honeypot.example")
	s.serveGitHubAnalysisSubmit(httptest.NewRecorder(), r)

	// Refused attempt: missing consent.
	r2 := httptest.NewRequest(http.MethodPost, "https://honeypot.example/github-analysis/submit",
		strings.NewReader("hash="+hash))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r2)
	r2.Header.Set("Origin", "https://honeypot.example")
	s.serveGitHubAnalysisSubmit(httptest.NewRecorder(), r2)

	events := s.settings.audit.read(10)
	if len(events) != 2 {
		t.Fatalf("got %d audit events, want 2: %+v", len(events), events)
	}
	byResult := map[string]bool{}
	for _, e := range events {
		if e.Action != "github_analysis.submit" {
			t.Fatalf("unexpected action %q", e.Action)
		}
		if len(e.Fields) != 1 || e.Fields[0] != hash {
			t.Fatalf("event fields = %v, want [%s]", e.Fields, hash)
		}
		if e.Username != "analyst" {
			t.Fatalf("event username = %q, want analyst", e.Username)
		}
		byResult[e.Result] = true
	}
	if !byResult["queued"] || !byResult["missing_consent"] {
		t.Fatalf("expected both queued and missing_consent results, got %+v", events)
	}
}

func TestGitHubAnalysisSubmitOnlyAcceptsPOST(t *testing.T) {
	s := &store{}
	r := httptest.NewRequest(http.MethodGet, "https://honeypot.example/github-analysis/submit", nil)
	w := httptest.NewRecorder()
	s.serveGitHubAnalysisSubmit(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", w.Code)
	}
}
