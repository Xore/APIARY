package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
)

// TestGeneratedReportMethodsUnavailableWithoutES proves every generated-
// report method fails closed with errReportsStorageUnavailable when
// Elasticsearch isn't configured -- there is deliberately no local-disk
// fallback (#475, same posture as #494's alert state and #483's payload
// inventory).
func TestGeneratedReportMethodsUnavailableWithoutES(t *testing.T) {
	store := newReportStore(nil)

	if _, _, err := store.addGenerated(generatedReport{Template: "custom"}, []byte("%PDF-1.4\n")); !errors.Is(err, errReportsStorageUnavailable) {
		t.Fatalf("addGenerated error = %v, want errReportsStorageUnavailable", err)
	}
	if _, err := store.listGenerated(); !errors.Is(err, errReportsStorageUnavailable) {
		t.Fatalf("listGenerated error = %v, want errReportsStorageUnavailable", err)
	}
	if _, _, err := store.generatedPDF("gen_0000000000000000"); !errors.Is(err, errReportsStorageUnavailable) {
		t.Fatalf("generatedPDF error = %v, want errReportsStorageUnavailable", err)
	}
	if err := store.deleteGenerated("gen_0000000000000000"); !errors.Is(err, errReportsStorageUnavailable) {
		t.Fatalf("deleteGenerated error = %v, want errReportsStorageUnavailable", err)
	}
}

// Regression test for #1341: docSearchAllExcluding must actually request
// an ES `_source_excludes` filter (not just decode-and-discard the excluded
// field client-side after a full-body fetch).
func TestDocSearchAllExcludingRequestsSourceExcludesParam(t *testing.T) {
	var gotQuery url.Values
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"hits":{"hits":[]}}`)
	}))
	defer es.Close()

	c := newESClient(es.URL, "")
	if _, err := c.docSearchAllExcluding("some-index", 10, "big_field", "other_field"); err != nil {
		t.Fatalf("docSearchAllExcluding: %v", err)
	}
	if got := gotQuery.Get("_source_excludes"); got != "big_field,other_field" {
		t.Fatalf("_source_excludes = %q, want %q", got, "big_field,other_field")
	}

	// docSearchAll itself (no excludes) must not send the param at all.
	if _, err := c.docSearchAll("some-index", 10); err != nil {
		t.Fatalf("docSearchAll: %v", err)
	}
	if gotQuery.Has("_source_excludes") {
		t.Fatalf("docSearchAll must not send _source_excludes, got query %v", gotQuery)
	}
}

// Regression test for #1341: listGenerated() used to call docSearchAll,
// which always pulls full document bodies -- so every list/prune call
// downloaded the base64-encoded PDF bytes of every stored report just to
// read the small metadata fields listGenerated actually returns. It must
// now request pdf_base64 excluded from the source.
func TestListGeneratedExcludesPDFBase64FromSourceFilter(t *testing.T) {
	var gotQuery url.Values
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"hits":{"hits":[]}}`)
	}))
	defer es.Close()

	rs := &reportStore{es: newESClient(es.URL, "")}
	if _, err := rs.listGenerated(); err != nil {
		t.Fatalf("listGenerated: %v", err)
	}
	if got := gotQuery.Get("_source_excludes"); got != "pdf_base64" {
		t.Fatalf("listGenerated must request _source_excludes=pdf_base64, got %q (full query: %v)", got, gotQuery)
	}
}

// TestServeGeneratedPDFReportsUnavailableWithoutES proves the HTTP-level
// symptom an operator would actually see: a 503 with a message naming
// Elasticsearch, not a generic 500 or a silently-empty response.
func TestServeGeneratedPDFReportsUnavailableWithoutES(t *testing.T) {
	dir := t.TempDir()
	s := &store{
		settings: newSettingsService(
			nil, filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "history.jsonl"),
		),
		reports: newReportStore(nil),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/reports/generated/gen_0000000000000000/pdf", nil)
	rec := httptest.NewRecorder()
	s.serveGeneratedPDF(rec, req, "gen_0000000000000000")
	if rec.Code == http.StatusOK {
		t.Fatal("expected the request to be rejected without Elasticsearch configured")
	}
}
