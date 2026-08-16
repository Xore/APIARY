package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

// Regression test for #1343: reconcileWorkbenchRun's per-child switch had
// no case for analyzerID "windows-ghosts" -- newestSandboxResult and
// workbenchMarkerDir both already handle it correctly (proved by the tests
// above), but the reconcile loop never called them for a windows-ghosts
// child, so it fell straight through to the bottom-of-loop deadline checks
// and could only ever end up "timed_out", regardless of a real, completed
// GHOSTS result sitting on disk.
func TestReconcileWorkbenchRunHandlesWindowsGhostsChild(t *testing.T) {
	s, root := newWorkbenchFixture(t, []byte("MZ"+strings.Repeat("\x00", 200)))
	ghostsRequests := filepath.Join(root, "ghosts-requests")
	ghostsResults := filepath.Join(root, "ghosts-results")
	for _, dir := range []string{ghostsRequests, ghostsResults} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GHOSTS_SANDBOX_REQUEST_DIR", ghostsRequests)
	t.Setenv("GHOSTS_SANDBOX_RESULTS_DIR", ghostsResults)

	run, _, err := s.createWorkbenchRun(workbenchRunRequest{
		PayloadSHA256: workbenchTestHash,
		Analyzers:     []workbenchSelection{{AnalyzerID: "windows-ghosts", Options: defaultWorkbenchOptions("windows-ghosts")}},
	}, "owner-a")
	if err != nil {
		t.Fatalf("createWorkbenchRun: %v", err)
	}
	if len(run.Children) != 1 || run.Children[0].State != "queued" {
		t.Fatalf("expected one queued windows-ghosts child, got %+v", run.Children)
	}

	// Drop a completed result, exactly as sandbox/ghosts/run_pending.sh would.
	resultBody := fmt.Sprintf(`{"sha256":%q,"job":"windows-ghosts-20260101T000000Z-%s","risk_score":40,"risk_level":"medium","completed_at":%q}`,
		workbenchTestHash, workbenchTestHash[:10], time.Now().Format(time.RFC3339Nano))
	if err := os.WriteFile(filepath.Join(ghostsResults, "windows-ghosts-20260101T000000Z-"+workbenchTestHash[:10]+".json"), []byte(resultBody), 0o600); err != nil {
		t.Fatal(err)
	}

	reconciled, changed := s.reconcileWorkbenchRun(run)
	if !changed {
		t.Fatal("reconcile did not report a change after a matching GHOSTS result appeared on disk")
	}
	if got := reconciled.Children[0].State; got != "completed" {
		t.Fatalf("windows-ghosts child state = %q, want completed (result on disk: %s)", got, resultBody)
	}
}

// Regression test for #1343: createWorkbenchMarker's queue-depth check and
// its O_EXCL marker creation used to run with no lock across them, so a
// burst of concurrent callers could all observe pending < cap and all
// create their marker, pushing the on-disk queue past workbenchMaxQueueDepth.
func TestCreateWorkbenchMarkerSerializesQueueCapUnderConcurrency(t *testing.T) {
	dir := t.TempDir()
	const attempts = workbenchMaxQueueDepth + 50

	var start sync.WaitGroup
	start.Add(1)
	var wg sync.WaitGroup
	var accepted atomic.Int64
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start.Wait()
			if err := createWorkbenchMarker(dir, fmt.Sprintf("%064x", i)); err == nil {
				accepted.Add(1)
			}
		}(i)
	}
	start.Done() // release every goroutine at once, to maximize contention
	wg.Wait()

	if got := accepted.Load(); got > workbenchMaxQueueDepth {
		t.Fatalf("createWorkbenchMarker accepted %d markers under concurrent submission, want <= %d (workbenchMaxQueueDepth)", got, workbenchMaxQueueDepth)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	pending := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".request") {
			pending++
		}
	}
	if pending > workbenchMaxQueueDepth {
		t.Fatalf("dir ended up with %d .request markers on disk, want <= %d (workbenchMaxQueueDepth)", pending, workbenchMaxQueueDepth)
	}
}
