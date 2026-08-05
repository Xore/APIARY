package main

import (
	"testing"
	"time"
)

// #498: newestSandboxResult must match windows-ghosts jobs
// (sandbox/ghosts/run_pending.sh names them windows-ghosts-<job>.json) to
// their own analyzer, and must not let a windows-sandbox child accept a
// windows-ghosts result just because both job names start with "windows-".
func TestNewestSandboxResultDistinguishesGhostsFromWindows(t *testing.T) {
	after := time.Now().Add(-time.Hour)
	completedAt := time.Now().Format(time.RFC3339Nano)
	results := []sandboxResult{
		{SHA256: "deadbeef", Job: "windows-20260101T000000Z-deadbeef00", CompletedAt: completedAt},
		{SHA256: "deadbeef", Job: "windows-ghosts-20260101T000100Z-deadbeef00", CompletedAt: completedAt},
	}

	ghosts, ok := newestSandboxResult("windows-ghosts", "deadbeef", results, after)
	if !ok || ghosts.Job != "windows-ghosts-20260101T000100Z-deadbeef00" {
		t.Fatalf("windows-ghosts child did not match its own result: %+v, ok=%v", ghosts, ok)
	}

	windows, ok := newestSandboxResult("windows-sandbox", "deadbeef", results, after)
	if !ok || windows.Job != "windows-20260101T000000Z-deadbeef00" {
		t.Fatalf("windows-sandbox child matched the wrong result (or none): %+v, ok=%v", windows, ok)
	}
}

// Before #498's fix, "windows-ghosts" fell through to the default "linux-"
// prefix and could never match any real result.
func TestNewestSandboxResultGhostsNeverMatchedLinuxPrefixRegression(t *testing.T) {
	after := time.Now().Add(-time.Hour)
	completedAt := time.Now().Format(time.RFC3339Nano)
	results := []sandboxResult{
		{SHA256: "deadbeef", Job: "windows-ghosts-20260101T000000Z-deadbeef00", CompletedAt: completedAt},
	}
	if _, ok := newestSandboxResult("windows-ghosts", "deadbeef", results, after); !ok {
		t.Fatal("windows-ghosts analyzer must match its own windows-ghosts- prefixed result")
	}
}

func TestWorkbenchMarkerDirIncludesWindowsGhosts(t *testing.T) {
	t.Setenv("GHOSTS_SANDBOX_REQUEST_DIR", "/tmp/ghosts-requests")
	if got := workbenchMarkerDir("windows-ghosts"); got != "/tmp/ghosts-requests" {
		t.Fatalf("workbenchMarkerDir(%q) = %q, want the GHOSTS_SANDBOX_REQUEST_DIR value", "windows-ghosts", got)
	}
}
