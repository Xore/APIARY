package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #1156 regression: searchNamespace used to be a single request capped at
// 10000 (this deployment's index.max_result_window), silently dropping
// anything past that ceiling. These pin the fix -- a PIT + search_after
// pagination loop mirroring loadSensorEventsES's own (see events_es_test.go)
// -- against searchNamespace itself, independent of any of the five
// higher-level loaders (loadGhidraResults and friends) that already cover
// "does the right result come back" against esResultsStub.

// namespaceSearchStub serves up to searchNamespacePageSize docs per request
// under field, and honors search_after the same way honeypotSearchStub does:
// search_after[0] is the stub's own index-stand-in sort value, not a real
// timestamp.
func namespaceSearchStub(t *testing.T, field string, docs []map[string]any, gotPaths *[]string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "_pit") {
			if r.Method == http.MethodDelete {
				json.NewEncoder(w).Encode(map[string]bool{"succeeded": true})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"id": "test-pit-id"})
			return
		}

		body, _ := io.ReadAll(r.Body)
		*gotPaths = append(*gotPaths, string(body))

		var req struct {
			Size        int   `json:"size"`
			SearchAfter []any `json:"search_after"`
		}
		json.Unmarshal(body, &req)

		start := 0
		if len(req.SearchAfter) > 0 {
			if idx, ok := req.SearchAfter[0].(float64); ok {
				start = int(idx) + 1
			}
		}
		end := start + req.Size
		if end > len(docs) {
			end = len(docs)
		}

		type hit struct {
			Sort   []any                     `json:"sort"`
			Source map[string]map[string]any `json:"_source"`
		}
		hits := make([]hit, 0, end-start)
		for i := start; i < end; i++ {
			hits = append(hits, hit{
				Sort:   []any{i, fmt.Sprintf("id-%d", i)},
				Source: map[string]map[string]any{field: docs[i]},
			})
		}
		json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
	}
}

func TestSearchNamespaceReturnsEveryHitsFieldOnASinglePage(t *testing.T) {
	var gotPaths []string
	docs := []map[string]any{
		{"sha256": shaA, "exit_status": "ok"},
		{"sha256": shaB, "exit_status": "error"},
	}
	es := httptest.NewServer(namespaceSearchStub(t, "ghidra", docs, &gotPaths))
	defer es.Close()

	raws, err := newESClient(es.URL, "").searchNamespace("ghidra-analysis-v1", "ghidra")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gotPaths) != 1 {
		t.Fatalf("expected exactly one page for %d docs, got %d requests", len(docs), len(gotPaths))
	}
	if len(raws) != len(docs) {
		t.Fatalf("got %d results, want %d", len(raws), len(docs))
	}
	var row ghidraResult
	if err := json.Unmarshal(raws[0], &row); err != nil {
		t.Fatalf("result is not a valid ghidraResult: %v", err)
	}
	if row.SHA256 != shaA {
		t.Fatalf("row.SHA256 = %q, want %q", row.SHA256, shaA)
	}
	if !strings.Contains(gotPaths[0], `"@timestamp"`) {
		t.Fatalf("request body %q does not sort by @timestamp", gotPaths[0])
	}
}

// TestSearchNamespacePaginatesPastTheSizeCap is a regression test for #1156:
// a plain size=10000 request silently dropped anything past that ceiling. A
// namespace with more than searchNamespacePageSize documents must not lose
// the rest anymore.
func TestSearchNamespacePaginatesPastTheSizeCap(t *testing.T) {
	total := searchNamespacePageSize + 250 // forces exactly two pages
	docs := make([]map[string]any, total)
	for i := range docs {
		docs[i] = map[string]any{"sha256": shaA, "exit_status": "ok"}
	}
	var gotPaths []string
	es := httptest.NewServer(namespaceSearchStub(t, "ghidra", docs, &gotPaths))
	defer es.Close()

	raws, err := newESClient(es.URL, "").searchNamespace("ghidra-analysis-v1", "ghidra")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gotPaths) != 2 {
		t.Fatalf("expected exactly two pages for %d docs, got %d requests", total, len(gotPaths))
	}
	if !strings.Contains(gotPaths[1], `"search_after"`) {
		t.Fatalf("second page request did not carry search_after: %q", gotPaths[1])
	}
	if len(raws) != total {
		t.Fatalf("got %d results, want all %d (pagination dropped results)", len(raws), total)
	}
}

// TestSearchNamespaceStopsAtMaxPages confirms the pagination loop is
// bounded, not unbounded -- same "safety valve, not silent truncation
// forever" shape as loadSensorEventsES's own TestLoadSensorEventsESStopsAtMaxPages.
func TestSearchNamespaceStopsAtMaxPages(t *testing.T) {
	total := searchNamespacePageSize*searchNamespaceMaxPages + 1000 // one page more than the cap allows
	docs := make([]map[string]any, total)
	for i := range docs {
		docs[i] = map[string]any{"sha256": shaA, "exit_status": "ok"}
	}
	var gotPaths []string
	es := httptest.NewServer(namespaceSearchStub(t, "ghidra", docs, &gotPaths))
	defer es.Close()

	raws, err := newESClient(es.URL, "").searchNamespace("ghidra-analysis-v1", "ghidra")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gotPaths) != searchNamespaceMaxPages {
		t.Fatalf("expected exactly searchNamespaceMaxPages (%d) requests, got %d", searchNamespaceMaxPages, len(gotPaths))
	}
	if len(raws) != searchNamespacePageSize*searchNamespaceMaxPages {
		t.Fatalf("got %d results, want exactly the max-pages cap (%d)", len(raws), searchNamespacePageSize*searchNamespaceMaxPages)
	}
}

func TestSearchNamespacePropagatesFirstPageError(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "_pit") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"id": "test-pit-id"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer es.Close()

	_, err := newESClient(es.URL, "").searchNamespace("ghidra-analysis-v1", "ghidra")
	if err == nil {
		t.Fatal("expected an error when the first page fails")
	} else if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error %v does not surface the server's own message", err)
	}
}

func TestSearchNamespaceFailsWhenPointInTimeCannotBeOpened(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer es.Close()

	if _, err := newESClient(es.URL, "").searchNamespace("ghidra-analysis-v1", "ghidra"); err == nil {
		t.Fatal("expected an error when the PIT cannot be opened")
	}
}

// #1156-follow-up: searchNamespaceLimit is searchNamespace's own PIT/
// search_after pagination made pointless for a caller that only wants the
// newest few hundred rows -- see its own doc comment. These pin its request
// shape (a single bounded /{index}/_search, no PIT) independent of
// refreshGithubAnalysisCacheAsync, the one caller today (github_analysis.go).

func TestSearchNamespaceLimitSendsASingleBoundedRequestNoPIT(t *testing.T) {
	var gotPath string
	var gotBody []byte
	var pitRequested bool
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "_pit") {
			pitRequested = true
		}
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hits":{"hits":[]}}`))
	}))
	defer es.Close()

	if _, err := newESClient(es.URL, "").searchNamespaceLimit("github-analysis-v1", "github_analysis", 500); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pitRequested {
		t.Fatal("searchNamespaceLimit must not open a point-in-time -- it's a single bounded request, not a paginated walk")
	}
	if gotPath != "/github-analysis-v1/_search" {
		t.Fatalf("queried %q, want /github-analysis-v1/_search", gotPath)
	}
	var req struct {
		Size int              `json:"size"`
		Sort []map[string]any `json:"sort"`
	}
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("request body is not valid JSON: %v (%s)", err, gotBody)
	}
	if req.Size != 500 {
		t.Fatalf("size = %d, want 500", req.Size)
	}
	if len(req.Sort) == 0 || req.Sort[0]["@timestamp"] != "desc" {
		t.Fatalf("request did not sort newest-first by @timestamp: %+v", req.Sort)
	}
}

func TestSearchNamespaceLimitReturnsTheRequestedField(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hits":{"hits":[{"_source":{"github_analysis":{"sha256":"` + shaA + `","exit_status":"ok"},"other_field":"ignored"}}]}}`))
	}))
	defer es.Close()

	raws, err := newESClient(es.URL, "").searchNamespaceLimit("github-analysis-v1", "github_analysis", 500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(raws) != 1 {
		t.Fatalf("got %d raw results, want 1", len(raws))
	}
	var row githubAnalysisResult
	if err := json.Unmarshal(raws[0], &row); err != nil {
		t.Fatalf("result is not a valid githubAnalysisResult: %v", err)
	}
	if row.SHA256 != shaA || row.ExitStatus != "ok" {
		t.Fatalf("unexpected row: %+v", row)
	}
}

func TestSearchNamespaceLimitClampsOutOfRangeLimits(t *testing.T) {
	var gotBody []byte
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hits":{"hits":[]}}`))
	}))
	defer es.Close()
	c := newESClient(es.URL, "")

	for _, limit := range []int{0, -5, 20000} {
		if _, err := c.searchNamespaceLimit("github-analysis-v1", "github_analysis", limit); err != nil {
			t.Fatalf("limit=%d: unexpected error: %v", limit, err)
		}
		var req struct {
			Size int `json:"size"`
		}
		json.Unmarshal(gotBody, &req)
		if req.Size != 500 {
			t.Errorf("limit=%d: sent size=%d, want the clamped default 500", limit, req.Size)
		}
	}
}

func TestSearchNamespaceLimitReturnsErrorWhenUnconfigured(t *testing.T) {
	var c *esClient
	if _, err := c.searchNamespaceLimit("github-analysis-v1", "github_analysis", 500); err == nil {
		t.Fatal("expected an error with no client configured")
	}
}

func TestSearchNamespaceLimitPropagatesServerErrors(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer es.Close()

	c := newESClient(es.URL, "")
	if _, err := c.searchNamespaceLimit("github-analysis-v1", "github_analysis", 500); err == nil {
		t.Fatal("expected an error when the server fails")
	} else if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error %v does not surface the server's own message", err)
	}
}
