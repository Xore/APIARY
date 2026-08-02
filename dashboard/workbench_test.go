package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const workbenchTestHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func newWorkbenchFixture(t *testing.T, sample []byte) (*store, string) {
	t.Helper()
	root := t.TempDir()
	payloads := filepath.Join(root, "payloads")
	workbench := filepath.Join(root, "workbench")
	if err := os.MkdirAll(payloads, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payloads, workbenchTestHash), sample, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DASHBOARD_REQUIRE_ADMIN", "false")
	return &store{payloadDirs: []string{payloads}, workbench: newWorkbenchService(workbench)}, root
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
	if files, err := os.ReadDir(s.workbench.runsDir()); err != nil || len(files) != 1 {
		t.Fatalf("duplicate submission created extra records: files=%d err=%v", len(files), err)
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

func TestWorkbenchGhidraQueueCancelAndPartialFailure(t *testing.T) {
	s, root := newWorkbenchFixture(t, []byte("MZ"+strings.Repeat("\x00", 200)))
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
	if !markerExists(requests, workbenchTestHash, ".request") {
		t.Fatal("Ghidra request marker missing")
	}
	cancelled, err := s.workbenchChildAction(run.ID, "ghidra", "cancel", "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.Children[1].State != "cancelled" || markerExists(requests, workbenchTestHash, ".request") {
		t.Fatalf("cancel did not stay inside queued marker: %+v", cancelled.Children[1])
	}

	// A separate recipe revision creates a new idempotency key. Its failed
	// Ghidra result must leave the deterministic result visible as partial.
	selections[1].Options.TimeoutSeconds++
	run, _, err = s.createWorkbenchRun(workbenchRunRequest{PayloadSHA256: workbenchTestHash, Analyzers: selections}, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]any{"version": 2, "sha256": workbenchTestHash, "requested_at": run.CreatedAt.Format(time.RFC3339Nano), "started_at": run.CreatedAt.Format(time.RFC3339Nano), "completed_at": run.CreatedAt.Add(time.Second).Format(time.RFC3339Nano), "exit_status": "error", "error": "synthetic backend failure"}
	body, _ := json.Marshal(result)
	if err := os.WriteFile(filepath.Join(results, workbenchTestHash+"_ghidra.json"), body, 0o600); err != nil {
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
	s, root := newWorkbenchFixture(t, []byte("MZ"+strings.Repeat("\x00", 200)))
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
	if !markerExists(requests, workbenchTestHash, ".request") {
		t.Fatal("Rev·Deck request marker missing")
	}
	if markerExists(ghidraRequests, workbenchTestHash, ".request") {
		t.Fatal("selecting revdeck alone must not also queue a Ghidra request")
	}

	// A failed standalone run: RevDeck is nil and exit_status is "error" --
	// the failure mode drain_revdeck() actually writes when REVDECK_API_BASE
	// is unset or the answer comes back empty.
	failResult := map[string]any{"version": 1, "sha256": workbenchTestHash, "requested_at": run.CreatedAt.Format(time.RFC3339Nano), "started_at": run.CreatedAt.Format(time.RFC3339Nano), "completed_at": run.CreatedAt.Add(time.Second).Format(time.RFC3339Nano), "exit_status": "error", "error": "REVDECK_API_BASE is not configured on this worker", "revdeck": nil}
	body, _ := json.Marshal(failResult)
	if err := os.WriteFile(filepath.Join(results, workbenchTestHash+"_revdeck.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	reconciled, err := s.getWorkbenchRun(run.ID, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	revdeckChild := reconciled.Children[1]
	if revdeckChild.State != "failed" || revdeckChild.Reason != "REVDECK_API_BASE is not configured on this worker" || revdeckChild.ResultURL != "/revdeck/"+workbenchTestHash || !revdeckChild.Retryable {
		t.Fatalf("failed standalone revdeck result not reconciled: %+v", revdeckChild)
	}

	// A separate recipe revision, this time completing successfully.
	selections[1].Options.TimeoutSeconds++
	run, _, err = s.createWorkbenchRun(workbenchRunRequest{PayloadSHA256: workbenchTestHash, Analyzers: selections}, "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	okResult := map[string]any{"version": 1, "sha256": workbenchTestHash, "requested_at": run.CreatedAt.Format(time.RFC3339Nano), "started_at": run.CreatedAt.Format(time.RFC3339Nano), "completed_at": run.CreatedAt.Add(time.Second).Format(time.RFC3339Nano), "exit_status": "ok", "revdeck": map[string]any{"workflow": "program_triage", "status": "complete", "answer": "looks benign", "tool_calls": 3}}
	body, _ = json.Marshal(okResult)
	if err := os.WriteFile(filepath.Join(results, workbenchTestHash+"_revdeck.json"), body, 0o600); err != nil {
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
	if _, err := os.Stat(s.workbench.runsDir()); !os.IsNotExist(err) {
		t.Fatalf("unsafe request created run state: %v", err)
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

func TestWorkbenchIndexProvidesPayloadSelection(t *testing.T) {
	s, _ := newWorkbenchFixture(t, []byte("payload"))
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	response := httptest.NewRecorder()
	s.serveWorkbenchIndex(response, httptest.NewRequest(http.MethodGet, "/payload-workbench", nil), tmpl)
	if response.Code != http.StatusOK {
		t.Fatalf("workbench index status = %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "/payload-workbench/"+workbenchTestHash) || !strings.Contains(body, "Select a captured payload") {
		t.Fatalf("workbench index does not offer a captured payload: %s", body)
	}
	partial := mustReadUI("partials/dashboard.html")
	if !strings.Contains(partial, `data-hp-nav="/payload-workbench" href="/payload-workbench"`) {
		t.Fatal("workbench sidebar link does not target the workbench landing page")
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

	runPath := filepath.Join(s.workbench.runsDir(), run.ID+".json")
	before, err := os.Stat(runPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.getWorkbenchRun(run.ID, "owner-a"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(runPath)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("getWorkbenchRun rewrote an unchanged all-terminal run to disk: mtime %v -> %v", before.ModTime(), after.ModTime())
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
	s.workbench.mu.Lock()
	err = s.workbench.persistRunLocked(run)
	s.workbench.mu.Unlock()
	if err != nil {
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
	data := workbenchResultsPageData{
		Generated: now,
		Runs: []workbenchRun{{
			ID: "run_1234567890abcdef", PayloadSHA256: sha, PayloadKind: "binary",
			RecipeName: "Static first", RecipeRevision: 1, State: "completed", CreatedAt: now,
			Children: []workbenchChild{
				{AnalyzerID: "deterministic", DisplayName: "Deterministic", State: "completed", UpdatedAt: now, ResultURL: "/payload-analysis/" + sha},
				{AnalyzerID: "ghidra", DisplayName: "Ghidra", State: "failed", UpdatedAt: now, Reason: "timed out"},
			},
		}},
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
	data := workbenchResultsPageData{
		Generated: now,
		Runs: []workbenchRun{{
			ID: "run_abcdef1234567890", PayloadSHA256: sha, PayloadKind: "binary",
			RecipeName: "Linux sandbox", RecipeRevision: 1, State: "completed", CreatedAt: now,
			Children: []workbenchChild{
				{AnalyzerID: "linux-sandbox", DisplayName: "Linux sandbox", State: "completed", UpdatedAt: now, ResultURL: "/sandbox/job-123", Summary: "risk 62/100 (high); 4 techniques"},
			},
		}},
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
	if err := tmpl.ExecuteTemplate(&buf, "payload-workbench-index", &data); err != nil {
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
