package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #920: docIndex must never request refresh=wait_for (it would add real
// per-write latency to every fire-and-forget write in this codebase), and
// docIndexWaitForRefresh must always request it -- the two are meant to stay
// clearly separated, not drift into "sometimes waits" behavior on either.
func TestDocIndexNeverRequestsWaitForRefresh(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"result":"created"}`))
	}))
	defer srv.Close()
	es := newESClient(srv.URL, "")

	if err := es.docIndex("some-index", "some-id", []byte(`{}`), true, 0, 0); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotQuery, "refresh") {
		t.Fatalf("docIndex sent a refresh param: %s", gotQuery)
	}

	if err := es.docIndex("some-index", "some-id", []byte(`{}`), false, 1, 1); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotQuery, "refresh") {
		t.Fatalf("docIndex (update path) sent a refresh param: %s", gotQuery)
	}
}

func TestDocIndexWaitForRefreshAlwaysRequestsIt(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"result":"created"}`))
	}))
	defer srv.Close()
	es := newESClient(srv.URL, "")

	if err := es.docIndexWaitForRefresh("some-index", "some-id", []byte(`{}`), true, 0, 0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "refresh=wait_for") {
		t.Fatalf("docIndexWaitForRefresh (create path) query = %q, missing refresh=wait_for", gotQuery)
	}
	if !strings.Contains(gotQuery, "op_type=create") {
		t.Fatalf("docIndexWaitForRefresh dropped op_type=create: %q", gotQuery)
	}

	if err := es.docIndexWaitForRefresh("some-index", "some-id", []byte(`{}`), false, 3, 2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "refresh=wait_for") {
		t.Fatalf("docIndexWaitForRefresh (update path) query = %q, missing refresh=wait_for", gotQuery)
	}
	if !strings.Contains(gotQuery, "if_seq_no=3") || !strings.Contains(gotQuery, "if_primary_term=2") {
		t.Fatalf("docIndexWaitForRefresh dropped its compare-and-swap params: %q", gotQuery)
	}
}

// TestDocIndexWaitForRefreshStillReportsConflict guards against the refresh
// param silently swallowing the existing 409 handling -- a caller retrying
// on errESConflict must keep working identically to the non-waiting path.
func TestDocIndexWaitForRefreshStillReportsConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":{"type":"version_conflict_engine_exception"}}`))
	}))
	defer srv.Close()
	es := newESClient(srv.URL, "")

	err := es.docIndexWaitForRefresh("some-index", "some-id", []byte(`{}`), true, 0, 0)
	if err != errESConflict {
		t.Fatalf("err = %v, want errESConflict", err)
	}
}
