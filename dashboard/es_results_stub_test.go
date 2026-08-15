package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// esResultsStub answers the read-only Elasticsearch requests the ES-only
// analysis-result loaders make (loadGhidraResults, loadCapeResults,
// loadSandboxResults, loadRevdeckResults, loadGitHubAnalysisResults, #1103)
// -- keyed by index name to a list of already-_source-shaped hits, e.g.
// {"ghidra": {...row fields...}} for ghidra-analysis-v1, matching
// searchNamespace's own per-caller field-name contract (see ghidra.go/
// cape.go/sandbox.go/revdeck.go/github_analysis.go's own searchNamespace
// calls for the field name each index uses).
//
// Any index/path not present in docsByIndex -- most commonly
// ghidra-report-artifacts-v1's existence check (docListIDs) -- answers with
// an empty hit list. Every caller here already treats "nothing found" the
// same as "nothing to attach," not an error, so tests that don't care about
// artifact-download links never need to stub that index explicitly.
func esResultsStub(t *testing.T, docsByIndex map[string][]map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/_doc/") {
			parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/_doc/", 2)
			if len(parts) != 2 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			index, id := parts[0], parts[1]
			for _, source := range docsByIndex[index] {
				namespace, _ := source["sandbox"].(map[string]any)
				job, _ := namespace["job"].(string)
				if id == "sandbox:"+job {
					json.NewEncoder(w).Encode(map[string]any{"_id": id, "_source": source})
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.Contains(r.URL.Path, "_pit") {
			if r.Method == http.MethodDelete {
				json.NewEncoder(w).Encode(map[string]bool{"succeeded": true})
				return
			}
			// r.URL.Path is "/{indexPattern}/_pit" (openPointInTime's own
			// request shape). #1156: searchNamespace now searches via the
			// PIT-scoped global /_search endpoint instead of
			// /{index}/_search -- the index is only visible here, at
			// PIT-open time, so it's encoded into the returned PIT id and
			// recovered below.
			index := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/_pit")
			json.NewEncoder(w).Encode(map[string]string{"id": "test-pit-id:" + index})
			return
		}
		index := strings.TrimPrefix(r.URL.Path, "/")
		if i := strings.Index(index, "/"); i >= 0 {
			index = index[:i]
		}
		if index == "_search" {
			// PIT-scoped global search (#1156) -- the URL carries no index
			// of its own; recover it from the request body's pit.id.
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Pit struct {
					ID string `json:"id"`
				} `json:"pit"`
			}
			json.Unmarshal(body, &req)
			index = strings.TrimPrefix(req.Pit.ID, "test-pit-id:")
		}
		docs := docsByIndex[index]
		hits := make([]map[string]any, 0, len(docs))
		for _, d := range docs {
			hits = append(hits, map[string]any{"_source": d})
		}
		json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
	}
}

// esResultsClientFor points the package-level esResultsClient (the loaders'
// only signal that ES is configured at all -- see ghidra.go's own doc
// comment) at a test stub serving docsByIndex for the rest of this test,
// restoring the previous value once it finishes.
func esResultsClientFor(t *testing.T, docsByIndex map[string][]map[string]any) {
	t.Helper()
	srv := httptest.NewServer(esResultsStub(t, docsByIndex))
	t.Cleanup(srv.Close)
	prev := esResultsClient
	esResultsClient = newESClient(srv.URL, "")
	t.Cleanup(func() { esResultsClient = prev })
}
