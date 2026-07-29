package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxSubmitWritesOnlyValidatedExistingHash(t *testing.T) {
	payloads, requests := t.TempDir(), t.TempDir()
	hash := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(payloads, hash), []byte("sample"), 0o600); err != nil {
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
