package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #1142: searchNamespaceByHash exists specifically to avoid the whole-index
// fetch (see its own doc comment) -- these tests pin the request it sends
// (a scoped term query, not the bare "everything" GET searchNamespace
// itself issues) and its own guard rails, independent of any of the
// higher-level loaders (loadGhidraResultByHash and friends) that already
// cover the "does the right result come back" behavior against a stub
// server, same as before this function existed.
func TestSearchNamespaceByHashSendsAScopedTermQuery(t *testing.T) {
	var gotBody []byte
	var gotPath string
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hits":{"hits":[]}}`))
	}))
	defer es.Close()

	c := newESClient(es.URL, "")
	if _, err := c.searchNamespaceByHash("ghidra-analysis-v1", "ghidra", shaA, 5); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/ghidra-analysis-v1/_search" {
		t.Fatalf("queried %q, want /ghidra-analysis-v1/_search", gotPath)
	}
	var req struct {
		Query struct {
			Term map[string]string `json:"term"`
		} `json:"query"`
		Size int `json:"size"`
	}
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("request body is not valid JSON: %v (%s)", err, gotBody)
	}
	if req.Query.Term["file.hash.sha256"] != shaA {
		t.Fatalf("request did not scope to file.hash.sha256=%q, got %+v", shaA, req.Query.Term)
	}
	if req.Size != 5 {
		t.Fatalf("size = %d, want 5", req.Size)
	}
}

func TestSearchNamespaceByHashReturnsTheRequestedField(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hits":{"hits":[{"_source":{"ghidra":{"sha256":"` + shaA + `","exit_status":"ok"},"other_field":"ignored"}}]}}`))
	}))
	defer es.Close()

	c := newESClient(es.URL, "")
	raws, err := c.searchNamespaceByHash("ghidra-analysis-v1", "ghidra", shaA, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(raws) != 1 {
		t.Fatalf("got %d raw results, want 1", len(raws))
	}
	var row ghidraResult
	if err := json.Unmarshal(raws[0], &row); err != nil {
		t.Fatalf("result is not a valid ghidraResult: %v", err)
	}
	if row.SHA256 != shaA || row.ExitStatus != "ok" {
		t.Fatalf("unexpected row: %+v", row)
	}
}

func TestSearchNamespaceByHashRejectsMalformedHashWithoutQuerying(t *testing.T) {
	called := false
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte(`{"hits":{"hits":[]}}`))
	}))
	defer es.Close()

	c := newESClient(es.URL, "")
	for _, bad := range []string{"", "not-a-hash", `abc" OR "1`} {
		if _, err := c.searchNamespaceByHash("ghidra-analysis-v1", "ghidra", bad, 5); err == nil {
			t.Errorf("expected an error for malformed hash %q", bad)
		}
	}
	if called {
		t.Fatal("a malformed hash must never reach the Elasticsearch query")
	}
}

func TestSearchNamespaceByHashReturnsErrorWhenUnconfigured(t *testing.T) {
	var c *esClient
	if _, err := c.searchNamespaceByHash("ghidra-analysis-v1", "ghidra", shaA, 5); err == nil {
		t.Fatal("expected an error with no client configured")
	}
}

func TestSearchNamespaceByHashPropagatesServerErrors(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer es.Close()

	c := newESClient(es.URL, "")
	if _, err := c.searchNamespaceByHash("ghidra-analysis-v1", "ghidra", shaA, 5); err == nil {
		t.Fatal("expected an error when the server fails")
	} else if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error %v does not surface the server's own message", err)
	}
}
