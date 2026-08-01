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
	for _, dir := range []string{ghidraRequests, ghidraResults, windowsRequests, windowsResults} {
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
	registry := workbenchRegistry(classifyPayload([]byte("MZ" + strings.Repeat("\x00", 200))))
	ghidra, _ := workbenchAnalyzerByID(registry, "ghidra")
	windows, _ := workbenchAnalyzerByID(registry, "windows-sandbox")
	linux, _ := workbenchAnalyzerByID(registry, "linux-sandbox")
	if !ghidra.Applicable || !ghidra.Available || !windows.Applicable || !windows.Available || linux.Applicable {
		t.Fatalf("server-derived registry is wrong: ghidra=%+v windows=%+v linux=%+v", ghidra, windows, linux)
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
