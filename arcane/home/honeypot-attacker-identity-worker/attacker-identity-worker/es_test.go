package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Regression (caught live on first deploy): opening a PIT against an
// index that doesn't exist yet returns 404. docScrollAll must treat that
// as "zero existing documents", not a hard failure -- otherwise this
// worker can never get past its very first cycle, before it has ever
// written attackers-v1 for the first time.
func TestDocScrollAllTreatsMissingIndexAsEmptyNotFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		t.Fatalf("unexpected request past the HEAD existence check: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	docs, ok := docScrollAll[entity](es, "attackers-v1", 100)
	if !ok {
		t.Fatal("a missing index should not fail docScrollAll")
	}
	if len(docs) != 0 {
		t.Fatalf("expected no docs, got %+v", docs)
	}
}

// TestDocScrollAllFailsOnUnmarshalableSearchResponse covers #1345: a
// malformed/unparseable page response must be reported as a failure
// (ok=false), not silently treated the same as "no more hits" and reported
// as a complete, successful load -- otherwise entities whose IPs live only
// in the un-loaded remainder get forked into new duplicate entities instead
// of being merged into the real one.
func TestDocScrollAllFailsOnUnmarshalableSearchResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead:
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/attackers-v1/_pit":
			w.Write([]byte(`{"id":"pit123"}`))
		case r.URL.Path == "/_search":
			w.Write([]byte(`not valid json`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	_, ok := docScrollAll[entity](es, "attackers-v1", 100)
	if ok {
		t.Fatal("an unparseable search response must fail docScrollAll, not report a silently-truncated success")
	}
}

func TestDocScrollAllReturnsExistingDocs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead:
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/attackers-v1/_pit":
			w.Write([]byte(`{"id":"pit123"}`))
		case r.URL.Path == "/_search":
			w.Write([]byte(`{"hits":{"hits":[{"sort":[1],"_source":{"id":"e1"}}]}}`))
		case r.URL.Path == "/_pit" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	es := newESClient(srv.URL)
	docs, ok := docScrollAll[entity](es, "attackers-v1", 100)
	if !ok || len(docs) != 1 || docs[0].ID != "e1" {
		t.Fatalf("ok=%v docs=%+v", ok, docs)
	}
}
