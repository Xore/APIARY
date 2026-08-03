package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// revdeckSearchNamespaceStub answers es.searchNamespace's own request shape
// (a plain GET, size in the query string) with docs as the "revdeck"
// namespace field of each hit -- matching searchNamespace's own doc comment
// on how analysis/es-results-importer/importer.py's build_document nests
// each source under its own label.
func revdeckSearchNamespaceStub(t *testing.T, docs []map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		type hit struct {
			Source struct {
				Revdeck map[string]any `json:"revdeck"`
			} `json:"_source"`
		}
		hits := make([]hit, 0, len(docs))
		for _, d := range docs {
			var h hit
			h.Source.Revdeck = d
			hits = append(hits, h)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
	}
}

func writeRevdeckResult(t *testing.T, dir, sha string, row map[string]any) {
	t.Helper()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sha+"_revdeck.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRevdeckResults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("REVDECK_RESULTS_DIR", dir)

	writeRevdeckResult(t, dir, shaA, map[string]any{
		"version": 1, "exit_status": "ok", "completed_at": "2026-07-31T10:00:00+00:00",
		"revdeck": map[string]any{"workflow": "program_triage", "status": "complete", "answer": "benign", "tool_calls": 2},
	})
	writeRevdeckResult(t, dir, shaB, map[string]any{
		"version": 1, "exit_status": "error", "error": "REVDECK_API_BASE is not configured on this worker",
		"completed_at": "2026-07-31T12:00:00+00:00", "revdeck": nil,
	})
	// A non-result file in the same directory must be ignored -- this is the
	// same results directory the Ghidra worker's own _ghidra.json files could
	// share a mount with in principle, so the suffix match has to be exact.
	if err := os.WriteFile(filepath.Join(dir, shaA+"_ghidra.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	rows := loadRevdeckResults()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	// Newest first.
	if rows[0].SHA256 != shaB {
		t.Errorf("rows are not newest-first: got %s first", rows[0].SHA256[:8])
	}
	if rows[0].ExitStatus != "error" || rows[0].Error != "REVDECK_API_BASE is not configured on this worker" || rows[0].RevDeck != nil {
		t.Errorf("failed standalone result lost its status/reason: %+v", rows[0])
	}
	if rows[1].RevDeck == nil || rows[1].RevDeck.Workflow != "program_triage" || rows[1].RevDeck.ToolCalls != 2 {
		t.Errorf("successful standalone result did not decode: %+v", rows[1])
	}
}

// Absent (revdeckResultsDir() returns "") must not panic or synthesize
// results -- same convention as loadGhidraResults() when GHIDRA_RESULTS_DIR
// is unset.
func TestLoadRevdeckResultsAbsentIsEmpty(t *testing.T) {
	t.Setenv("REVDECK_RESULTS_DIR", "")
	if rows := loadRevdeckResults(); rows != nil {
		t.Fatalf("expected nil rows with no results dir configured, got %+v", rows)
	}
}

func TestRevdeckDataNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("REVDECK_RESULTS_DIR", dir)
	if _, err := revdeckData(shaA); err == nil {
		t.Fatal("expected an error for a hash with no standalone result")
	}
	if _, err := revdeckData(""); err == nil {
		t.Fatal("expected an error for an empty hash")
	}
}

func TestRevdeckDataFindsMatchingResult(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("REVDECK_RESULTS_DIR", dir)
	writeRevdeckResult(t, dir, shaA, map[string]any{
		"version": 1, "exit_status": "ok", "completed_at": "2026-07-31T10:00:00+00:00",
		"revdeck": map[string]any{"workflow": "program_triage", "status": "complete", "tool_calls": 1},
	})
	data, err := revdeckData(shaA)
	if err != nil {
		t.Fatal(err)
	}
	if data.Detail == nil || data.Detail.SHA256 != shaA {
		t.Fatalf("revdeckData did not find the matching result: %+v", data)
	}
}

// withESResultsClient points the package-level esResultsClient (normally
// set once in main.go) at a test server and restores the previous value
// (nil in every other test in this package) once the test finishes --
// required since loadGhidraResults/loadRevdeckResults/loadSandboxResults/
// loadGitHubAnalysisResults all read this same global to decide ES vs.
// local, and tests run in the same binary.
func withESResultsClient(t *testing.T, url string) {
	t.Helper()
	prev := esResultsClient
	esResultsClient = newESClient(url, "")
	t.Cleanup(func() { esResultsClient = prev })
}

// TestLoadRevdeckResultsPrefersESOverLocalFile (#404): matches
// loadGhidraResults' own ES-preferred behavior exactly -- when the
// revdeck-analysis-v1 mirror answers, the local *_revdeck.json file (even
// though it's present and would parse fine on its own) must not be read.
func TestLoadRevdeckResultsPrefersESOverLocalFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("REVDECK_RESULTS_DIR", dir)
	writeRevdeckResult(t, dir, shaA, map[string]any{
		"version": 1, "sha256": shaA, "exit_status": "ok", "completed_at": "2026-07-31T09:00:00+00:00",
		"revdeck": map[string]any{"workflow": "local-only", "status": "complete", "tool_calls": 1},
	})

	srv := httptest.NewServer(revdeckSearchNamespaceStub(t, []map[string]any{
		{"sha256": shaB, "exit_status": "ok", "completed_at": "2026-07-31T10:00:00+00:00",
			"revdeck": map[string]any{"workflow": "es-sourced", "status": "complete", "tool_calls": 5}},
	}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	rows := loadRevdeckResults()
	if len(rows) != 1 || rows[0].SHA256 != shaB || rows[0].RevDeck.Workflow != "es-sourced" {
		t.Fatalf("expected only the ES-sourced result, got %+v", rows)
	}
}

// TestLoadRevdeckResultsFallsBackToLocalOnESFailure (#404): matches
// loadGhidraResults' own fallback behavior -- an ES error must not blank
// the page when a local result is still available.
func TestLoadRevdeckResultsFallsBackToLocalOnESFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("REVDECK_RESULTS_DIR", dir)
	writeRevdeckResult(t, dir, shaA, map[string]any{
		"version": 1, "sha256": shaA, "exit_status": "ok", "completed_at": "2026-07-31T09:00:00+00:00",
		"revdeck": map[string]any{"workflow": "local-fallback", "status": "complete", "tool_calls": 1},
	})
	withESResultsClient(t, "http://127.0.0.1:1") // nothing listening

	rows := loadRevdeckResults()
	if len(rows) != 1 || rows[0].SHA256 != shaA || rows[0].RevDeck.Workflow != "local-fallback" {
		t.Fatalf("expected the local result as a fallback, got %+v", rows)
	}
}

// TestReconcileWorkbenchRunUsesLocalRevdeckResultsNotES (#404): matches
// the same freshness carve-out ghidra/sandbox already get (#384) -- job
// completion detection must never wait on the ES mirror's import interval.
func TestReconcileWorkbenchRunUsesLocalRevdeckResultsNotES(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("REVDECK_RESULTS_DIR", dir)
	writeRevdeckResult(t, dir, shaA, map[string]any{
		"version": 1, "sha256": shaA, "exit_status": "ok", "completed_at": "2026-07-31T09:00:00+00:00",
		"revdeck": map[string]any{"workflow": "local-only", "status": "complete", "tool_calls": 1},
	})
	// ES is configured but never queried for this: a request would fail this
	// test outright, proving the local variant is used unconditionally.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("reconcileWorkbenchRun must not query Elasticsearch for revdeck results")
	}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	created, err := time.Parse(time.RFC3339, "2026-07-31T08:00:00+00:00")
	if err != nil {
		t.Fatal(err)
	}
	s := &store{}
	run := workbenchRun{
		PayloadSHA256: shaA,
		Children: []workbenchChild{{
			AnalyzerID: "revdeck", State: "running", CreatedAt: created,
		}},
	}
	reconciled, changed := s.reconcileWorkbenchRun(run)
	if !changed || reconciled.Children[0].State != "completed" {
		t.Fatalf("expected the local revdeck result to complete the child, got %+v", reconciled.Children[0])
	}
}
