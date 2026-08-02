package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
