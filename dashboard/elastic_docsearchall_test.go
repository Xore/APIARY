package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// #498: a dashboard-owned index (e.g. dashboard-workbench-runs-v1) is
// created lazily on first write. Before a first run/recipe/etc. is ever
// created, searching it must read as zero hits, not fail -- confirmed live
// on the homeserver that the Workbench's very first run submission failed
// outright with Elasticsearch's own index_not_found_exception because
// countRuns (which calls docSearchAll before any doc is ever indexed) did
// not tolerate a missing index.
func TestDocSearchAllTreatsMissingIndexAsZeroHits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"root_cause":[{"type":"index_not_found_exception","reason":"no such index [dashboard-workbench-runs-v1]"}],"type":"index_not_found_exception","reason":"no such index [dashboard-workbench-runs-v1]"},"status":404}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL, "")
	hits, err := es.docSearchAll("dashboard-workbench-runs-v1", 10000)
	if err != nil {
		t.Fatalf("docSearchAll on a missing index must not error, got: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("expected zero hits for a missing index, got %d", len(hits))
	}
}

// A real error (e.g. Elasticsearch unreachable/malformed query) must still
// surface as an error -- only the specific "index doesn't exist yet" case
// is forgiven.
func TestDocSearchAllStillErrorsOnOtherFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"cluster unavailable"}`))
	}))
	defer srv.Close()

	es := newESClient(srv.URL, "")
	if _, err := es.docSearchAll("dashboard-workbench-runs-v1", 10000); err == nil {
		t.Fatal("expected an error for a non-404 failure, got nil")
	}
}
