package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const workbenchTestHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func newWorkbenchFixture(t *testing.T, sample []byte) (*store, string) {
	t.Helper()
	root := t.TempDir()
	payloads := filepath.Join(root, "payloads")
	if err := os.MkdirAll(payloads, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payloads, workbenchTestHash), sample, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "false")
	esStore := newMemESDocStore()
	esSrv := httptest.NewServer(esStore.handler())
	t.Cleanup(esSrv.Close)
	es := newESClient(esSrv.URL, "")
	return &store{payloadDirs: []string{payloads}, es: es, workbench: newWorkbenchService(es)}, root
}

// workbenchTestSampleSHA256 is the sample's real, content-derived SHA-256 --
// deliberately different from workbenchTestHash, the placeholder used as
// the fixture's on-disk filename, mirroring a real Dionaea capture (#787:
// on-disk MD5 identity vs. true content SHA-256). The ghidra/revdeck
// analyzers resolve and use this one; every other analyzer still uses
// workbenchTestHash.
func workbenchTestSampleSHA256(sample []byte) string {
	sum := sha256.Sum256(sample)
	return hex.EncodeToString(sum[:])
}

func deterministicSelection() []workbenchSelection {
	return []workbenchSelection{{AnalyzerID: "deterministic", Options: defaultWorkbenchOptions("deterministic")}}
}

func TestWorkbenchDeterministicRunAndIdempotency(t *testing.T) {
	s, _ := newWorkbenchFixture(t, []byte("#!/bin/sh\ncurl http://example.invalid/x\n"))
	request := workbenchRunRequest{PayloadSHA256: workbenchTestHash, RecipeName: "Static first", Analyzers: deterministicSelection()}
	run, reused, err := s.createWorkbenchRun(request, "owner-a")
	if err != nil || reused {
		t.Fatalf("first run = reused %v, err %v", reused, err)
	}
	if run.State != "completed" || len(run.Children) != 1 || run.Children[0].State != "completed" {
		t.Fatalf("unexpected deterministic run: %+v", run)
	}
	if run.Children[0].ResultURL != "/payload-analysis/"+workbenchTestHash {
		t.Fatalf("unsafe or missing native result URL: %q", run.Children[0].ResultURL)
	}
	again, reused, err := s.createWorkbenchRun(request, "owner-a")
	if err != nil || !reused || again.ID != run.ID {
		t.Fatalf("duplicate run = %#v reused=%v err=%v, want same id", again, reused, err)
	}
	count, err := s.workbench.countRuns()
	if err != nil || count != 1 {
		t.Fatalf("duplicate submission created extra records: count=%d err=%v", count, err)
	}
}

func TestWorkbenchConcurrentDuplicateSubmissionsDedupe(t *testing.T) {
	s, _ := newWorkbenchFixture(t, []byte("#!/bin/sh\ncurl http://example.invalid/x\n"))
	request := workbenchRunRequest{PayloadSHA256: workbenchTestHash, RecipeName: "Static first", Analyzers: deterministicSelection()}

	const goroutines = 8
	ids := make([]string, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			run, _, err := s.createWorkbenchRun(request, "owner-a")
			ids[i] = run.ID
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: unexpected error: %v", i, err)
		}
	}
	for i, id := range ids {
		if id == "" || id != ids[0] {
			t.Fatalf("goroutine %d produced id %q, want all equal to %q", i, id, ids[0])
		}
	}
	count, err := s.workbench.countRuns()
	if err != nil || count != 1 {
		t.Fatalf("concurrent duplicate submissions created extra records: count=%d err=%v", count, err)
	}
}

func TestWorkbenchRegistryDerivesApplicabilityAndAvailability(t *testing.T) {
	_, root := newWorkbenchFixture(t, []byte("MZ"+strings.Repeat("\x00", 200)))
	ghidraRequests, ghidraResults := filepath.Join(root, "ghidra-requests"), filepath.Join(root, "ghidra-results")
	windowsRequests, windowsResults := filepath.Join(root, "windows-requests"), filepath.Join(root, "windows-results")
	revdeckRequests, revdeckResults := filepath.Join(root, "revdeck-requests"), filepath.Join(root, "revdeck-results")
	for _, dir := range []string{ghidraRequests, ghidraResults, windowsRequests, windowsResults, revdeckRequests, revdeckResults} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ghidraResults, "status.json"), []byte(`{"version":1,"updated_at":"`+time.Now().UTC().Format(time.RFC3339)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHIDRA_REQUEST_DIR", ghidraRequests)
	t.Setenv("GHIDRA_RESULTS_DIR", ghidraResults)
	t.Setenv("WINDOWS_SANDBOX_REQUEST_DIR", windowsRequests)
	t.Setenv("WINDOWS_SANDBOX_RESULTS_DIR", windowsResults)
	t.Setenv("REVDECK_REQUEST_DIR", revdeckRequests)
	t.Setenv("REVDECK_RESULTS_DIR", revdeckResults)
	registry := workbenchRegistry(classifyPayload([]byte("MZ" + strings.Repeat("\x00", 200))))
	ghidra, _ := workbenchAnalyzerByID(registry, "ghidra")
	windows, _ := workbenchAnalyzerByID(registry, "windows-sandbox")
	linux, _ := workbenchAnalyzerByID(registry, "linux-sandbox")
	revdeck, _ := workbenchAnalyzerByID(registry, "revdeck")
	if !ghidra.Applicable || !ghidra.Available || !windows.Applicable || !windows.Available || linux.Applicable {
		t.Fatalf("server-derived registry is wrong: ghidra=%+v windows=%+v linux=%+v", ghidra, windows, linux)
	}
	if !revdeck.Available || revdeck.ResultLinkShape != "/revdeck/{sha256}" {
		t.Fatalf("revdeck should be available with the standalone spool configured: %+v", revdeck)
	}
}

// Absent GHOSTS_SANDBOX_REQUEST_DIR/_RESULTS_DIR (the default), the
// WAN-permitted route must read as unavailable, same as windows-sandbox
// before its own env vars are set -- not silently fall back to the
// air-gapped spool, which would run a payload with real internet access
// nobody asked for.
func TestWorkbenchRegistryGhostsUnconfiguredByDefault(t *testing.T) {
	registry := workbenchRegistry(classifyPayload([]byte("MZ" + strings.Repeat("\x00", 200))))
	ghosts, ok := workbenchAnalyzerByID(registry, "windows-ghosts")
	if !ok {
		t.Fatal("windows-ghosts analyzer missing from registry")
	}
	if ghosts.Available {
		t.Fatalf("windows-ghosts should be unavailable with no spool configured: %+v", ghosts)
	}
	if !ghosts.Applicable {
		t.Fatalf("windows-ghosts should be applicable to a Windows-dynamic payload regardless of spool config: %+v", ghosts)
	}
}

// Configured, it behaves like windows-sandbox but queues into its own,
// separate spool -- confirms the two routes never share a request
// directory, which would let a GHOSTS submission land on the air-gapped
// guest or vice versa.
func TestWorkbenchRegistryGhostsConfiguredUsesOwnSpool(t *testing.T) {
	_, root := newWorkbenchFixture(t, []byte("MZ"+strings.Repeat("\x00", 200)))
	windowsRequests := filepath.Join(root, "windows-requests")
	windowsResults := filepath.Join(root, "windows-results")
	ghostsRequests := filepath.Join(root, "ghosts-requests")
	ghostsResults := filepath.Join(root, "ghosts-results")
	for _, dir := range []string{windowsRequests, windowsResults, ghostsRequests, ghostsResults} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("WINDOWS_SANDBOX_REQUEST_DIR", windowsRequests)
	t.Setenv("WINDOWS_SANDBOX_RESULTS_DIR", windowsResults)
	t.Setenv("GHOSTS_SANDBOX_REQUEST_DIR", ghostsRequests)
	t.Setenv("GHOSTS_SANDBOX_RESULTS_DIR", ghostsResults)
	registry := workbenchRegistry(classifyPayload([]byte("MZ" + strings.Repeat("\x00", 200))))
	ghosts, _ := workbenchAnalyzerByID(registry, "windows-ghosts")
	if !ghosts.Available || !ghosts.Applicable {
		t.Fatalf("windows-ghosts should be available once its own spool is configured: %+v", ghosts)
	}
	if sandboxRequestDir(targetGhosts) == sandboxRequestDir(targetWindows) {
		t.Fatal("ghosts and windows request dirs must never be the same directory")
	}
}

// Absent REVDECK_REQUEST_DIR/_RESULTS_DIR (the default) must leave the
// standalone adapter unavailable, distinct from the "revdeck" field embedded
// inside a "ghidra" analyzer result, which this Go process cannot see or
// health-check at all (#78).
func TestWorkbenchRegistryRevdeckUnconfiguredByDefault(t *testing.T) {
	_, _ = newWorkbenchFixture(t, []byte("MZ"+strings.Repeat("\x00", 200)))
	registry := workbenchRegistry(classifyPayload([]byte("MZ" + strings.Repeat("\x00", 200))))
	revdeck, _ := workbenchAnalyzerByID(registry, "revdeck")
	if revdeck.Available || revdeck.Availability != "unconfigured" {
		t.Fatalf("revdeck should be unconfigured with no spool set: %+v", revdeck)
	}
}

// TestWorkbenchGhidraRejectsMD5IdentityMarkerFilename is #787's precise
// regression case: a Dionaea capture's real on-disk identity is that
// sensor's own MD5 (32 hex chars), not a SHA-256 (64). Confirmed live
// against the real host-side worker (analysis/ghidra/worker/ghidra-worker.py)
// that it validates the request marker's filename with a strict
// SHA256_RE.fullmatch and discards (renames *.request.invalid) anything
// that doesn't match -- so every real Dionaea payload silently never got
// analyzed. This reproduces that exact filename shape rather than just a
// same-length placeholder, so a future change to workbenchTestHash's length
// alone couldn't accidentally make this pass without the real fix.
func TestWorkbenchGhidraRejectsMD5IdentityMarkerFilename(t *testing.T) {
	sample := []byte("MZ" + strings.Repeat("\x00", 200))
	sum := sha256.Sum256(sample)
	trueHash := hex.EncodeToString(sum[:])

	root := t.TempDir()
	payloads := filepath.Join(root, "payloads")
	if err := os.MkdirAll(payloads, 0o700); err != nil {
		t.Fatal(err)
	}
	md5Identity := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 hex chars, real MD5 shape
	if err := os.WriteFile(filepath.Join(payloads, md5Identity), sample, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "false")
	esStore := newMemESDocStore()
	esSrv := httptest.NewServer(esStore.handler())
	t.Cleanup(esSrv.Close)
	es := newESClient(esSrv.URL, "")
	s := &store{payloadDirs: []string{payloads}, es: es, workbench: newWorkbenchService(es)}

	requests, results := filepath.Join(root, "ghidra-requests"), filepath.Join(root, "ghidra-results")
	for _, dir := range []string{requests, results} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(results, "status.json"), []byte(`{"version":1,"updated_at":"`+time.Now().UTC().Format(time.RFC3339)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHIDRA_REQUEST_DIR", requests)
	t.Setenv("GHIDRA_RESULTS_DIR", results)

	run, _, err := s.createWorkbenchRun(workbenchRunRequest{
		PayloadSHA256: md5Identity,
		Analyzers:     []workbenchSelection{{AnalyzerID: "ghidra", Options: defaultWorkbenchOptions("ghidra")}},
	}, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	if markerExists(requests, md5Identity, ".request") {
		t.Fatal("a marker filed under the 32-char MD5 identity is exactly the bug: the real worker's SHA256_RE rejects it outright")
	}
	if !markerExists(requests, trueHash, ".request") {
		t.Fatal("marker must be filed under the payload's true 64-char SHA-256")
	}
	if run.Children[0].TargetHash != trueHash {
		t.Fatalf("child.TargetHash = %q, want the resolved true SHA-256 %q", run.Children[0].TargetHash, trueHash)
	}
}

// TestWorkbenchGhidraMissingSampleMarkerIsRetryable is #1114's own smaller
// finding: markerState()'s three failure-shaped outcomes
// (.request.failed/.request.invalid/.request.missing-sample) never set
// child.Retryable, unlike every result-based failure path in reconcile
// (see TestWorkbenchGhidraQueueCancelAndPartialFailure below). Without it,
// an operator who hits one of these -- most commonly missing-sample, before
// #1114's own resolve_sample() fix -- has no "Retry child" button, only
// changing an analyzer option to force a new idempotency key or
// resubmitting from scratch.
func TestWorkbenchGhidraMissingSampleMarkerIsRetryable(t *testing.T) {
	sample := []byte("MZ" + strings.Repeat("\x00", 200))
	trueHash := workbenchTestSampleSHA256(sample)
	s, root := newWorkbenchFixture(t, sample)
	requests, results := filepath.Join(root, "ghidra-requests"), filepath.Join(root, "ghidra-results")
	for _, dir := range []string{requests, results} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(results, "status.json"), []byte(`{"version":1,"updated_at":"`+time.Now().UTC().Format(time.RFC3339)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHIDRA_REQUEST_DIR", requests)
	t.Setenv("GHIDRA_RESULTS_DIR", results)

	run, _, err := s.createWorkbenchRun(workbenchRunRequest{
		PayloadSHA256: workbenchTestHash,
		Analyzers:     []workbenchSelection{{AnalyzerID: "ghidra", Options: defaultWorkbenchOptions("ghidra")}},
	}, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	if !markerExists(requests, trueHash, ".request") {
		t.Fatal("Ghidra request marker missing")
	}
	// Simulate exactly what ghidra-worker.py does on an unresolvable sample:
	// rename the marker in place, no result file written at all.
	if err := os.Rename(
		filepath.Join(requests, trueHash+".request"),
		filepath.Join(requests, trueHash+".request.missing-sample"),
	); err != nil {
		t.Fatal(err)
	}

	reconciled, err := s.getWorkbenchRun(run.ID, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	child := reconciled.Children[0]
	if child.State != "failed" {
		t.Fatalf("child.State = %q, want failed", child.State)
	}
	if !child.Retryable {
		t.Fatalf("a .request.missing-sample marker must leave the child retryable, same as any other terminal failure: %+v", child)
	}
}

func TestWorkbenchGhidraQueueCancelAndPartialFailure(t *testing.T) {
	sample := []byte("MZ" + strings.Repeat("\x00", 200))
	trueHash := workbenchTestSampleSHA256(sample)
	s, root := newWorkbenchFixture(t, sample)
	requests, results := filepath.Join(root, "ghidra-requests"), filepath.Join(root, "ghidra-results")
	for _, dir := range []string{requests, results} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(results, "status.json"), []byte(`{"version":1,"updated_at":"`+time.Now().UTC().Format(time.RFC3339)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHIDRA_REQUEST_DIR", requests)
	t.Setenv("GHIDRA_RESULTS_DIR", results)
	selections := append(deterministicSelection(), workbenchSelection{AnalyzerID: "ghidra", Options: defaultWorkbenchOptions("ghidra")})
	run, _, err := s.createWorkbenchRun(workbenchRunRequest{PayloadSHA256: workbenchTestHash, Analyzers: selections}, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	if !markerExists(requests, trueHash, ".request") {
		t.Fatal("Ghidra request marker missing")
	}
	if markerExists(requests, workbenchTestHash, ".request") {
		t.Fatal("Ghidra request marker must be filed under the true content SHA-256, not the on-disk placeholder identity")
	}
	cancelled, err := s.workbenchChildAction(run.ID, "ghidra", "cancel", "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Children[1].State != "cancelled" || markerExists(requests, trueHash, ".request") {
		t.Fatalf("cancel did not stay inside queued marker: %+v", cancelled.Children[1])
	}

	// A separate recipe revision creates a new idempotency key. Its failed
	// Ghidra result must leave the deterministic result visible as partial.
	selections[1].Options.TimeoutSeconds++
	run, _, err = s.createWorkbenchRun(workbenchRunRequest{PayloadSHA256: workbenchTestHash, Analyzers: selections}, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]any{"version": 2, "sha256": trueHash, "requested_at": run.CreatedAt.Format(time.RFC3339Nano), "started_at": run.CreatedAt.Format(time.RFC3339Nano), "completed_at": run.CreatedAt.Add(time.Second).Format(time.RFC3339Nano), "exit_status": "error", "error": "synthetic backend failure"}
	body, _ := json.Marshal(result)
	if err := os.WriteFile(filepath.Join(results, trueHash+"_ghidra.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	reconciled, err := s.getWorkbenchRun(run.ID, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.State != "partial" || reconciled.Children[0].State != "completed" || reconciled.Children[1].State != "failed" || !reconciled.Children[1].Retryable {
		t.Fatalf("partial failure was not preserved: %+v", reconciled)
	}
}

// The standalone revdeck adapter (#78) submits to its own spool, independent
// of the "ghidra" analyzer above -- selecting only "revdeck" must not create
// a Ghidra request marker at all.
func TestWorkbenchRevdeckStandaloneQueueAndResult(t *testing.T) {
	sample := []byte("MZ" + strings.Repeat("\x00", 200))
	trueHash := workbenchTestSampleSHA256(sample)
	s, root := newWorkbenchFixture(t, sample)
	ghidraRequests := filepath.Join(root, "ghidra-requests")
	requests, results := filepath.Join(root, "revdeck-requests"), filepath.Join(root, "revdeck-results")
	for _, dir := range []string{ghidraRequests, requests, results} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GHIDRA_REQUEST_DIR", ghidraRequests)
	t.Setenv("REVDECK_REQUEST_DIR", requests)
	t.Setenv("REVDECK_RESULTS_DIR", results)
	selections := append(deterministicSelection(), workbenchSelection{AnalyzerID: "revdeck", Options: defaultWorkbenchOptions("ghidra")})
	run, _, err := s.createWorkbenchRun(workbenchRunRequest{PayloadSHA256: workbenchTestHash, Analyzers: selections}, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	if !markerExists(requests, trueHash, ".request") {
		t.Fatal("Rev·Deck request marker missing")
	}
	if markerExists(requests, workbenchTestHash, ".request") {
		t.Fatal("Rev·Deck request marker must be filed under the true content SHA-256, not the on-disk placeholder identity")
	}
	if markerExists(ghidraRequests, workbenchTestHash, ".request") || markerExists(ghidraRequests, trueHash, ".request") {
		t.Fatal("selecting revdeck alone must not also queue a Ghidra request")
	}

	// A failed standalone run: RevDeck is nil and exit_status is "error" --
	// the failure mode drain_revdeck() actually writes when REVDECK_API_BASE
	// is unset or the answer comes back empty.
	failResult := map[string]any{"version": 1, "sha256": trueHash, "requested_at": run.CreatedAt.Format(time.RFC3339Nano), "started_at": run.CreatedAt.Format(time.RFC3339Nano), "completed_at": run.CreatedAt.Add(time.Second).Format(time.RFC3339Nano), "exit_status": "error", "error": "REVDECK_API_BASE is not configured on this worker", "revdeck": nil}
	body, _ := json.Marshal(failResult)
	if err := os.WriteFile(filepath.Join(results, trueHash+"_revdeck.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	reconciled, err := s.getWorkbenchRun(run.ID, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	revdeckChild := reconciled.Children[1]
	if revdeckChild.State != "failed" || revdeckChild.Reason != "REVDECK_API_BASE is not configured on this worker" || revdeckChild.ResultURL != "/revdeck/"+trueHash || !revdeckChild.Retryable {
		t.Fatalf("failed standalone revdeck result not reconciled: %+v", revdeckChild)
	}

	// A separate recipe revision, this time completing successfully.
	selections[1].Options.TimeoutSeconds++
	run, _, err = s.createWorkbenchRun(workbenchRunRequest{PayloadSHA256: workbenchTestHash, Analyzers: selections}, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	okResult := map[string]any{"version": 1, "sha256": trueHash, "requested_at": run.CreatedAt.Format(time.RFC3339Nano), "started_at": run.CreatedAt.Format(time.RFC3339Nano), "completed_at": run.CreatedAt.Add(time.Second).Format(time.RFC3339Nano), "exit_status": "ok", "revdeck": map[string]any{"workflow": "program_triage", "status": "complete", "answer": "looks benign", "tool_calls": 3}}
	body, _ = json.Marshal(okResult)
	if err := os.WriteFile(filepath.Join(results, trueHash+"_revdeck.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	reconciled, err = s.getWorkbenchRun(run.ID, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	revdeckChild = reconciled.Children[1]
	if revdeckChild.State != "completed" || !strings.Contains(revdeckChild.Summary, "program_triage") || !strings.Contains(revdeckChild.Summary, "3 tool call") {
		t.Fatalf("completed standalone revdeck result not reconciled: %+v", revdeckChild)
	}
}

func TestWorkbenchRecipeRevisionsAreImmutable(t *testing.T) {
	s, _ := newWorkbenchFixture(t, []byte("payload"))
	first, err := s.workbench.saveRecipe(workbenchRecipe{Name: "Accuracy first", Scope: "private", Analyzers: deterministicSelection()}, "owner-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	secondInput := first
	secondInput.Description = "second immutable revision"
	second, err := s.workbench.saveRecipe(secondInput, "owner-a", first.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 1 || second.Revision != 2 || first.CreatedAt.Equal(second.CreatedAt) {
		t.Fatalf("unexpected revisions: first=%+v second=%+v", first, second)
	}
	if _, err := s.workbench.saveRecipe(secondInput, "owner-a", first.Revision); !errors.Is(err, errWorkbenchConflict) {
		t.Fatalf("stale base revision error = %v, want conflict", err)
	}
	visible := s.workbench.listRecipes("owner-a")
	if len(visible) != 2 || visible[0].Revision != 2 || visible[1].Revision != 1 {
		t.Fatalf("immutable history missing: %+v", visible)
	}
}

// #920: saveRecipe's own "latest revision" scan (docSearchAll) is only
// eventually consistent -- a save that doesn't wait for its write to refresh
// before returning could let a very-next save to the same recipe compute a
// stale "latest" and spuriously reject a non-conflicting baseRevision. The
// fix is Elasticsearch's own refresh=wait_for write parameter
// (docIndexWaitForRefresh); this test asserts saveRecipe's PUT actually
// requests it, not just that saveRecipe still returns the right values
// (TestWorkbenchRecipeRevisionsAreImmutable already covers that, but the
// mock ES store here is fully synchronous and so cannot itself reproduce
// the timing race -- this test only proves the fix is wired to the real
// Elasticsearch write path, which is what closes the race against a real
// cluster).
func TestSaveRecipeAndCreateRunRequestWaitForRefresh(t *testing.T) {
	root := t.TempDir()
	payloads := filepath.Join(root, "payloads")
	if err := os.MkdirAll(payloads, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payloads, workbenchTestHash), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "false")

	esStore := newMemESDocStore()
	var lastPUTQuery string
	esSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			lastPUTQuery = r.URL.RawQuery
		}
		esStore.handler().ServeHTTP(w, r)
	}))
	t.Cleanup(esSrv.Close)
	es := newESClient(esSrv.URL, "")
	s := &store{payloadDirs: []string{payloads}, es: es, workbench: newWorkbenchService(es)}

	if _, err := s.workbench.saveRecipe(workbenchRecipe{Name: "Accuracy first", Scope: "private", Analyzers: deterministicSelection()}, "owner-a", 0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastPUTQuery, "refresh=wait_for") {
		t.Fatalf("saveRecipe's write did not request refresh=wait_for: %q", lastPUTQuery)
	}

	lastPUTQuery = ""
	request := workbenchRunRequest{PayloadSHA256: workbenchTestHash, RecipeName: "Static first", Analyzers: deterministicSelection()}
	if _, _, err := s.createWorkbenchRun(request, "owner-a"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastPUTQuery, "refresh=wait_for") {
		t.Fatalf("createOrReuseRun's write did not request refresh=wait_for: %q", lastPUTQuery)
	}
}

func TestWorkbenchRejectsUnsafeAndUnboundedOptions(t *testing.T) {
	bad := []workbenchSelection{{AnalyzerID: "ghidra", Options: workbenchOptions{TimeoutSeconds: 1, MaxQueueAgeSeconds: 60}}}
	if _, err := validateWorkbenchSelections(bad); err == nil {
		t.Fatal("under-minimum timeout accepted")
	}
	bad[0].Options = workbenchOptions{TimeoutSeconds: 60, MaxQueueAgeSeconds: 60, RetryLimit: 4}
	if _, err := validateWorkbenchSelections(bad); err == nil {
		t.Fatal("unbounded retry accepted")
	}
	bad[0].AnalyzerID = "https://evil.example/analyze"
	if _, err := validateWorkbenchSelections(bad); err == nil {
		t.Fatal("arbitrary analyzer endpoint accepted")
	}
}

func TestWorkbenchHTTPRequiresSameOriginAndClosedJSON(t *testing.T) {
	s, _ := newWorkbenchFixture(t, []byte("payload"))
	unsafeBody := `{"payload_sha256":"` + workbenchTestHash + `","analyzers":[{"analyzer_id":"deterministic","options":{"timeout_seconds":60,"max_queue_age_seconds":60,"retry_limit":0}}],"endpoint":"https://evil.example"}`
	request := httptest.NewRequest(http.MethodPost, "/api/payload-workbench/runs", bytes.NewBufferString(unsafeBody))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	s.serveWorkbenchRuns(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin mutation = %d, want 403", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/payload-workbench/runs", bytes.NewBufferString(unsafeBody))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response = httptest.NewRecorder()
	s.serveWorkbenchRuns(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown endpoint field = %d body=%s, want 400", response.Code, response.Body.String())
	}
	if count, err := s.workbench.countRuns(); err != nil || count != 0 {
		t.Fatalf("unsafe request created run state: count=%d err=%v", count, err)
	}
}

func TestWorkbenchMissingPayloadAndPathTraversal(t *testing.T) {
	s, _ := newWorkbenchFixture(t, []byte("payload"))
	if _, _, err := s.createWorkbenchRun(workbenchRunRequest{PayloadSHA256: strings.Repeat("b", 64), Analyzers: deterministicSelection()}, "owner-a"); !errors.Is(err, errWorkbenchNotFound) {
		t.Fatalf("missing sample error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/payload-workbench/../../etc/passwd", nil)
	response := httptest.NewRecorder()
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	s.serveWorkbenchPage(response, request, tmpl)
	if response.Code != http.StatusNotFound {
		t.Fatalf("path traversal status = %d", response.Code)
	}
}

// TestPayloadsPageOffersStartAnalysisTab (#1139): the standalone
// /payload-workbench artifact-selection index merged into /payloads' second
// tab, so /payloads itself (not a separate route) must offer the picker.
func TestPayloadsPageOffersStartAnalysisTab(t *testing.T) {
	s, _ := newWorkbenchFixture(t, []byte("payload"))
	// #483: payloadsData's Enabled flag now also requires a configured ES
	// client; unreachable is fine since payloadCacheAt is seeded fresh here.
	s.es = newESClient("http://127.0.0.1:1", "")
	s.payloadCache = payloadsPage{UniqueTotal: 1, Files: []capturedFile{{Hash: workbenchTestHash}}}
	s.payloadCacheAt = time.Now()
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	data := s.payloadsData(payloadsFilter{})
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "payloads", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "/payload-workbench/"+workbenchTestHash) || !strings.Contains(body, "Select a captured payload") {
		t.Fatalf("payloads page does not offer a captured payload for analysis: %s", body)
	}
	if !strings.Contains(body, `data-dashboard-tab="start-analysis"`) {
		t.Fatal("payloads page is missing the Start analysis tab")
	}
	partial := mustReadUI("partials/dashboard.html")
	if strings.Contains(partial, `data-hp-nav="/payload-workbench" href="/payload-workbench"`) {
		t.Fatal("sidebar still carries the merged-away standalone workbench index link")
	}
}

func TestWorkbenchResultsAreSearchableAndOwnerIsolated(t *testing.T) {
	s, _ := newWorkbenchFixture(t, []byte("payload"))
	if _, _, err := s.createWorkbenchRun(workbenchRunRequest{PayloadSHA256: workbenchTestHash, RecipeName: "Accuracy first", Analyzers: deterministicSelection()}, "owner-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.createWorkbenchRun(workbenchRunRequest{PayloadSHA256: workbenchTestHash, RecipeName: "Other owner", Analyzers: deterministicSelection()}, "owner-b"); err != nil {
		t.Fatal(err)
	}
	data := s.workbenchResultsData("accuracy", "owner-a")
	if len(data.Runs) != 1 || data.Runs[0].Owner != "owner-a" || data.Counts.Completed != 1 {
		t.Fatalf("owner-isolated results = %+v", data)
	}
	if got := s.workbenchResultsData("other owner", "owner-a"); len(got.Runs) != 0 {
		t.Fatalf("search leaked another owner's run: %+v", got.Runs)
	}
}

// TestReconcileWorkbenchRunSkipsWorkOnceEveryChildIsTerminal (#348):
// getWorkbenchRun called reconcileWorkbenchRun -- four full result-directory
// scans -- and persisted the run back to disk on every single call, even for
// runs whose children were all long finished and could never change again.
// A results-listing page with hundreds of historical runs paid that cost on
// every view, confirmed live as a ~30s hang. reconcileWorkbenchRun must skip
// the scans once every child is terminal, and getWorkbenchRun must skip the
// redundant disk write when nothing changed.
func TestReconcileWorkbenchRunSkipsWorkOnceEveryChildIsTerminal(t *testing.T) {
	s, _ := newWorkbenchFixture(t, []byte("payload"))
	run, _, err := s.createWorkbenchRun(workbenchRunRequest{PayloadSHA256: workbenchTestHash, Analyzers: deterministicSelection()}, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	if run.State != "completed" {
		t.Fatalf("fixture run must already be all-terminal, got state %q", run.State)
	}

	if reconciled, changed := s.reconcileWorkbenchRun(run); changed {
		t.Fatalf("reconcile of an all-terminal run reported changed=true, should be a no-op: %+v", reconciled)
	}

	before, found, err := s.es.docGet(workbenchRunsIndex, run.ID)
	if err != nil || !found {
		t.Fatalf("docGet before: found=%v err=%v", found, err)
	}
	if _, err := s.getWorkbenchRun(run.ID, "owner-a"); err != nil {
		t.Fatal(err)
	}
	after, found, err := s.es.docGet(workbenchRunsIndex, run.ID)
	if err != nil || !found {
		t.Fatalf("docGet after: found=%v err=%v", found, err)
	}
	if before.SeqNo != after.SeqNo {
		t.Fatalf("getWorkbenchRun rewrote an unchanged all-terminal run: seq_no %d -> %d", before.SeqNo, after.SeqNo)
	}
}

// TestWorkbenchResultsDataReconcilesWithoutPerRunESRoundTrip (#1157):
// workbenchResultsData used to call getWorkbenchRun per candidate --
// updateRun's own fresh docGet, purely to obtain a current SeqNo/
// PrimaryTerm for an optimistic-concurrency write -- on every single run in
// the list, up to workbenchMaxRuns (500) sequential ES round trips on every
// load of this listing page. #348 already stopped that path from doing its
// four local-file scans or persisting a no-op write once a run's children
// are all terminal, but the redundant per-run docGet itself remained
// unconditional. listRunsForOwner already returns fully-populated run docs
// from a single docSearchAll -- reconcileWorkbenchRun must be applied
// in-memory to those, with no further ES traffic, while still reflecting
// non-terminal state changes (like a timeout) in the returned data.
func TestWorkbenchResultsDataReconcilesWithoutPerRunESRoundTrip(t *testing.T) {
	s, root := newWorkbenchFixture(t, []byte("MZ"+strings.Repeat("\x00", 200)))
	requests, results := filepath.Join(root, "ghidra-requests"), filepath.Join(root, "ghidra-results")
	for _, dir := range []string{requests, results} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(results, "status.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHIDRA_REQUEST_DIR", requests)
	t.Setenv("GHIDRA_RESULTS_DIR", results)
	if err := os.Chtimes(filepath.Join(results, "status.json"), time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	run, _, err := s.createWorkbenchRun(workbenchRunRequest{PayloadSHA256: workbenchTestHash, Analyzers: []workbenchSelection{{AnalyzerID: "ghidra", Options: workbenchOptions{TimeoutSeconds: 60, MaxQueueAgeSeconds: 10, RetryLimit: 1}}}}, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	run.Children[0].QueueDeadline = time.Now().Add(-time.Second)
	if _, err := s.workbench.updateRun(run.ID, "owner-a", func(current *workbenchRun) (bool, error) {
		*current = run
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}

	before, found, err := s.es.docGet(workbenchRunsIndex, run.ID)
	if err != nil || !found {
		t.Fatalf("docGet before: found=%v err=%v", found, err)
	}

	data := s.workbenchResultsData("", "owner-a")
	if len(data.Runs) != 1 || data.Runs[0].Children[0].State != "timed_out" || !data.Runs[0].Children[0].Retryable {
		t.Fatalf("workbenchResultsData did not reconcile the listed run: %+v", data.Runs)
	}
	if data.Counts.Failed != 1 {
		t.Fatalf("Counts.Failed = %d, want 1 (timed_out is a failure state)", data.Counts.Failed)
	}

	after, found, err := s.es.docGet(workbenchRunsIndex, run.ID)
	if err != nil || !found {
		t.Fatalf("docGet after: found=%v err=%v", found, err)
	}
	if before.SeqNo != after.SeqNo {
		t.Fatalf("workbenchResultsData wrote back to ES (seq_no %d -> %d) -- it must reconcile for display only, not persist, to avoid the per-run round trip this fix removes", before.SeqNo, after.SeqNo)
	}
}

func TestWorkbenchTimeoutAndOwnerIsolation(t *testing.T) {
	s, root := newWorkbenchFixture(t, []byte("MZ"+strings.Repeat("\x00", 200)))
	requests, results := filepath.Join(root, "ghidra-requests"), filepath.Join(root, "ghidra-results")
	for _, dir := range []string{requests, results} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(results, "status.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHIDRA_REQUEST_DIR", requests)
	t.Setenv("GHIDRA_RESULTS_DIR", results)
	// Keep the status artifact fresh even though its payload is minimal.
	if err := os.Chtimes(filepath.Join(results, "status.json"), time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	run, _, err := s.createWorkbenchRun(workbenchRunRequest{PayloadSHA256: workbenchTestHash, Analyzers: []workbenchSelection{{AnalyzerID: "ghidra", Options: workbenchOptions{TimeoutSeconds: 60, MaxQueueAgeSeconds: 10, RetryLimit: 1}}}}, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	run.Children[0].QueueDeadline = time.Now().Add(-time.Second)
	if _, err := s.workbench.updateRun(run.ID, "owner-a", func(current *workbenchRun) (bool, error) {
		*current = run
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	timed, err := s.getWorkbenchRun(run.ID, "owner-a")
	if err != nil || timed.Children[0].State != "timed_out" || !timed.Children[0].Retryable {
		t.Fatalf("timeout = %+v err=%v", timed, err)
	}
	if _, err := s.getWorkbenchRun(run.ID, "owner-b"); !errors.Is(err, errWorkbenchNotFound) {
		t.Fatalf("other owner read error = %v", err)
	}
}

func TestWorkbenchTemplateAndScriptUseEscapedDOMSinks(t *testing.T) {
	if !strings.Contains(pageTemplate, `data-wb-root`) || !strings.Contains(pageTemplate, `never in Run all`) {
		t.Fatal("workbench template not embedded")
	}
	body, err := os.ReadFile("static/hp-workbench.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, unsafe := range []string{"reason.innerHTML", "summary.innerHTML", "title.innerHTML", "display_name).innerHTML"} {
		if strings.Contains(source, unsafe) {
			t.Fatalf("untrusted result uses an HTML sink: %s", unsafe)
		}
	}
	for _, safe := range []string{"title.textContent = child.display_name", "reason.textContent = child.summary || child.reason"} {
		if !strings.Contains(source, safe) {
			t.Fatalf("missing escaped DOM sink: %s", safe)
		}
	}
}

// TestWorkbenchRunButtonGivesImmediateFeedback (#349): the "Start analysis
// run" button only disabled itself on click, with no visible state change
// and no status message until the fetch resolved -- indistinguishable from
// the click not registering at all if the request took more than an instant
// (the workbench results page's reconcile lock, #348, could make it take up
// to ~30s). The submit handler must post a status message and swap the
// button's own label to a busy state before the fetch starts, not after.
func TestWorkbenchRunButtonGivesImmediateFeedback(t *testing.T) {
	body, err := os.ReadFile("static/hp-workbench.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, `say("Submitting analysis run…")`) {
		t.Fatal(`submitting the workbench run form must post an immediate status message before the fetch starts`)
	}
	if !strings.Contains(source, `withBusyButton(button, "Starting…"`) {
		t.Fatal(`the Start analysis run button must switch to a visible busy label while the request is in flight, not just disable`)
	}
}

// The workbench results list renders as a .project-grid/.project-card grid
// (#227, following #221/#226), not one full-width card per run with a
// nested per-analyzer table. Each card links to /payload-workbench/{sha} --
// the same "Manage run" destination the old card offered -- whose own
// data-wb-runs section (hp-workbench.js) already renders the full
// per-analyzer breakdown for every run on that payload, so nothing here is
// lost by dropping the inline table from the list view.
func TestWorkbenchResultsPageRendersAsCardGrid(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	sha := strings.Repeat("e", 64)
	now := time.Now()
	data := evidenceResultsPageData{
		Generated: now,
		Workbench: workbenchResultsPageData{
			Generated: now,
			Runs: []workbenchRun{{
				ID: "run_1234567890abcdef", PayloadSHA256: sha, PayloadKind: "binary",
				RecipeName: "Static first", RecipeRevision: 1, State: "completed", CreatedAt: now,
				Children: []workbenchChild{
					{AnalyzerID: "deterministic", DisplayName: "Deterministic", State: "completed", UpdatedAt: now, ResultURL: "/payload-analysis/" + sha},
					{AnalyzerID: "ghidra", DisplayName: "Ghidra", State: "failed", UpdatedAt: now, Reason: "timed out"},
				},
			}},
		},
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "workbench-results", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	if strings.Contains(body, "<table") {
		t.Fatal("workbench results still render an inline analyzer table, want a card grid")
	}
	if !strings.Contains(body, "project-grid") || !strings.Contains(body, "project-card") {
		t.Fatal("workbench results are missing the .project-grid/.project-card markup")
	}
	if !strings.Contains(body, `href="/payload-workbench/`+sha+`"`) {
		t.Fatal("workbench card does not link to the Manage run destination")
	}
	if !strings.Contains(body, `wb-state--completed`) {
		t.Fatal("workbench card is missing the run's overall state badge")
	}
	if !strings.Contains(body, "2 analyzers") {
		t.Fatal("workbench card is missing the analyzer count summary")
	}
}

// TestWorkbenchResultsPageOffersGhidraTab (#1180-adjacent): Ghidra folded
// into Analysis results as a fourth tab, the same consolidation #1139 gave
// sandbox/GitHub-analysis. Renders through the real "workbench-results"
// template (not a synthetic fixture) so a broken {{template
// "ghidraresultspanel" .Ghidra}} reference would fail this the same way it
// would fail every other page render.
func TestWorkbenchResultsPageOffersGhidraTab(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	data := evidenceResultsPageData{
		Generated: time.Now(),
		Ghidra: ghidraPageData{
			Generated: time.Now(),
			Status:    ghidraQueueStatus{Configured: true},
			Rows:      []ghidraResult{{SHA256: shaA, ExitStatus: "ok", CompletedAt: "2026-08-11T00:00:00Z"}},
		},
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "workbench-results", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	if !strings.Contains(body, `data-dashboard-tab="ghidra"`) || !strings.Contains(body, ">Ghidra</button>") {
		t.Fatal("workbench-results page is missing the Ghidra tab")
	}
	if !strings.Contains(body, `id="panel-ghidra"`) {
		t.Fatal("workbench-results page is missing the Ghidra panel")
	}
	if !strings.Contains(body, `href="/ghidra/`+shaA+`"`) {
		t.Fatal("Ghidra panel does not render the real result row")
	}
	// The panel's own filter form/clear-link must target this page's own
	// #ghidra hash, not the old standalone /ghidra route the bare route
	// now just redirects away from.
	if !strings.Contains(body, `action="/payload-workbench/results#ghidra"`) {
		t.Fatal("Ghidra panel's filter form does not post back to the merged results page")
	}
	if strings.Contains(body, `name="q"`) && !strings.Contains(body, `name="ghidra_q"`) {
		t.Fatal("Ghidra panel's search field still uses the old bare 'q' name, colliding with the Workbench tab's own")
	}
}

// TestWorkbenchResultsCardLinksDirectlyToSingleChildFindings (#350): a
// results-list card always linked to the recipe/orchestration page and
// showed a generic "N analyzers" line, never the actual findings -- landing
// there meant an extra click through "Open native result" before seeing
// anything a dynamic analyzer found. For the common single-analyzer-per-run
// case (#351: the workbench now queues even a plain Linux sandbox run this
// way), the card must link straight to that child's own detailed findings
// page and show its summary inline.
func TestWorkbenchResultsCardLinksDirectlyToSingleChildFindings(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	sha := strings.Repeat("f", 64)
	now := time.Now()
	data := evidenceResultsPageData{
		Generated: now,
		Workbench: workbenchResultsPageData{
			Generated: now,
			Runs: []workbenchRun{{
				ID: "run_abcdef1234567890", PayloadSHA256: sha, PayloadKind: "binary",
				RecipeName: "Linux sandbox", RecipeRevision: 1, State: "completed", CreatedAt: now,
				Children: []workbenchChild{
					{AnalyzerID: "linux-sandbox", DisplayName: "Linux sandbox", State: "completed", UpdatedAt: now, ResultURL: "/sandbox/job-123", Summary: "risk 62/100 (high); 4 techniques"},
				},
			}},
		},
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "workbench-results", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	if !strings.Contains(body, `href="/sandbox/job-123"`) {
		t.Fatal("a single-child completed run must link straight to that child's own findings page, not the orchestration page")
	}
	if strings.Contains(body, `href="/payload-workbench/`+sha+`"`) {
		t.Fatal("a single-child completed run should not still link to the orchestration page")
	}
	if !strings.Contains(body, "risk 62/100 (high); 4 techniques") {
		t.Fatal("workbench card must surface the child's findings summary instead of a generic analyzer count")
	}
}

// The workbench's payload picker ("Select a captured payload") renders as
// a .project-grid/.project-card grid too, matching the other card-grid
// conversions -- each card is a single whole-card link (unlike the
// captured-payloads inventory's cards, a picker row has exactly one
// action) straight to /payload-workbench/{hash}, the same destination the
// old "Open workbench" button used.
func TestWorkbenchIndexRendersAsCardGrid(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	hash := strings.Repeat("e", 64)
	data := payloadsPage{
		Generated: time.Now(), Enabled: true,
		Files: []capturedFile{{Hash: hash, Kind: "Binary", Platform: "Linux", MIME: "application/octet-stream", SizeH: "1 KiB", Sources: []string{"dionaea"}}},
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "payloads", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	if strings.Contains(body, "<table") {
		t.Fatal("workbench payload picker still renders a table, want a card grid")
	}
	if !strings.Contains(body, "project-grid") || !strings.Contains(body, "project-card") {
		t.Fatal("workbench payload picker is missing the .project-grid/.project-card markup")
	}
	if !strings.Contains(body, `href="/payload-workbench/`+hash+`"`) {
		t.Fatal("workbench picker card does not link to the workbench for that hash")
	}
	if strings.Contains(body, "Open workbench") {
		t.Fatal("the old standalone \"Open workbench\" button should be gone -- the whole card is the link now")
	}
}
