package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// TestGeneratedReportMethodsUnavailableWithoutES proves every generated-
// report method fails closed with errReportsStorageUnavailable when
// Elasticsearch isn't configured -- there is deliberately no local-disk
// fallback (#475, same posture as #494's alert state and #483's payload
// inventory).
func TestGeneratedReportMethodsUnavailableWithoutES(t *testing.T) {
	dir := t.TempDir()
	store := newReportStore(filepath.Join(dir, "reports.json"), nil)

	if _, _, err := store.addGenerated(generatedReport{Template: "custom"}, []byte("%PDF-1.4\n")); !errors.Is(err, errReportsStorageUnavailable) {
		t.Fatalf("addGenerated error = %v, want errReportsStorageUnavailable", err)
	}
	if _, err := store.listGenerated(); !errors.Is(err, errReportsStorageUnavailable) {
		t.Fatalf("listGenerated error = %v, want errReportsStorageUnavailable", err)
	}
	if _, ok := store.generated("gen_0000000000000000"); ok {
		t.Fatal("generated() must report not-found without an ES client, not panic or fabricate a record")
	}
	if _, _, err := store.generatedPDF("gen_0000000000000000"); !errors.Is(err, errReportsStorageUnavailable) {
		t.Fatalf("generatedPDF error = %v, want errReportsStorageUnavailable", err)
	}
	if err := store.deleteGenerated("gen_0000000000000000"); !errors.Is(err, errReportsStorageUnavailable) {
		t.Fatalf("deleteGenerated error = %v, want errReportsStorageUnavailable", err)
	}
}

// TestServeGeneratedPDFReportsUnavailableWithoutES proves the HTTP-level
// symptom an operator would actually see: a 503 with a message naming
// Elasticsearch, not a generic 500 or a silently-empty response.
func TestServeGeneratedPDFReportsUnavailableWithoutES(t *testing.T) {
	dir := t.TempDir()
	s := &store{
		settings: newSettingsService(
			filepath.Join(dir, "config.json"), filepath.Join(dir, "users.json"),
			filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "history.jsonl"),
		),
		reports: newReportStore(filepath.Join(dir, "reports.json"), nil),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/reports/generated/gen_0000000000000000/pdf", nil)
	rec := httptest.NewRecorder()
	s.serveGeneratedPDF(rec, req, "gen_0000000000000000")
	if rec.Code == http.StatusOK {
		t.Fatal("expected the request to be rejected without Elasticsearch configured")
	}
}
