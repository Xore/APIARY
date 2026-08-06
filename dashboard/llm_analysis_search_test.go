package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOllamaEndpointIsLocal(t *testing.T) {
	// Built via concatenation, not a literal credential-shaped substring --
	// same technique llm-worker/tests/test_worker.py's own equivalent
	// fixture uses, so scripts/check-public-leaks.py's URL-credential
	// pattern doesn't flag a deliberate rejection-case test fixture as a
	// real leaked credential.
	credentialURL := "http://user" + ":" + "secret" + "@ollama:11434"
	allowed := []string{
		"http://ollama:11434",
		"http://localhost:11434",
		"http://127.0.0.1:11434",
		"http://10.8.0.2:11434",
		"http://172.20.0.2:11434",
		"http://192.168.1.5:11434",
	}
	rejected := []string{
		"https://api.openai.com/v1",
		credentialURL,
		"http://ollama:11434/api/chat",
		"http://ollama:11434?next=https://example.com",
		"http://203.0.113.8:11434",
		"http://attacker.internal:11434",
		"not-a-url",
	}
	for _, url := range allowed {
		if !ollamaEndpointIsLocal(url) {
			t.Errorf("ollamaEndpointIsLocal(%q) = false, want true", url)
		}
	}
	for _, url := range rejected {
		if ollamaEndpointIsLocal(url) {
			t.Errorf("ollamaEndpointIsLocal(%q) = true, want false", url)
		}
	}
}

func TestEmbedQueryTextParsesTheRealOllamaResponseShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/embed" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["model"] != "nomic-embed-text:latest" || body["input"] != "reconnaissance commands" {
			t.Errorf("unexpected request body: %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"model":      "nomic-embed-text:latest",
			"embeddings": [][]float64{{0.1, 0.2, 0.3}},
		})
	}))
	defer srv.Close()

	vector, err := embedQueryText(srv.URL, "nomic-embed-text:latest", "reconnaissance commands")
	if err != nil {
		t.Fatalf("embedQueryText: %v", err)
	}
	if len(vector) != 3 || vector[0] != 0.1 {
		t.Errorf("unexpected vector: %v", vector)
	}
}

func TestEmbedQueryTextErrorsOnMalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"embeddings": [][]float64{}})
	}))
	defer srv.Close()

	if _, err := embedQueryText(srv.URL, "nomic-embed-text:latest", "x"); err == nil {
		t.Fatal("expected an error for a response with zero vectors, got nil")
	}
}

func TestServeLLMAnalysisSearchEmptyQueryReturnsNoHitsWithoutCallingAnything(t *testing.T) {
	s := &store{ollamaURL: "http://unreachable.invalid:11434", embeddingModel: "nomic-embed-text:latest"}
	// es intentionally nil -- an empty query must short-circuit before ever
	// touching es or ollama.
	req := httptest.NewRequest(http.MethodGet, "/api/llm/analysis/search", nil)
	w := httptest.NewRecorder()
	s.serveLLMAnalysisSearch(w, req)

	var resp struct {
		Available bool                   `json:"available"`
		Hits      []llmAnalysisSearchHit `json:"hits"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Available || len(resp.Hits) != 0 {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestServeLLMAnalysisSearchUnconfiguredReportsUnavailable(t *testing.T) {
	s := &store{} // no es, no ollamaURL
	req := httptest.NewRequest(http.MethodGet, "/api/llm/analysis/search?q=reconnaissance", nil)
	w := httptest.NewRecorder()
	s.serveLLMAnalysisSearch(w, req)

	var resp struct {
		Available bool   `json:"available"`
		Reason    string `json:"reason"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Available || resp.Reason == "" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestServeLLMAnalysisSearchFullRoundTrip(t *testing.T) {
	ollama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"embeddings": [][]float64{{0.5, 0.25}}})
	}))
	defer ollama.Close()

	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "llm-analysis") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		knn, ok := body["knn"].(map[string]any)
		if !ok || knn["field"] != "embedding" {
			t.Fatalf("kNN query body malformed: %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"hits": map[string]any{
				"hits": []map[string]any{
					{
						"_score": 0.87,
						"_source": map[string]any{
							"@timestamp":  "2026-08-06T00:00:00Z",
							"analysis_id": "abc123",
							"doc_type":    "session",
							"summary":     "Reconnaissance commands were observed.",
							"severity":    "medium",
						},
					},
				},
			},
		})
	}))
	defer es.Close()

	s := &store{
		es:             newESClient(es.URL, ""),
		ollamaURL:      ollama.URL,
		embeddingModel: "nomic-embed-text:latest",
	}
	req := httptest.NewRequest(http.MethodGet, "/api/llm/analysis/search?q=reconnaissance+commands", nil)
	w := httptest.NewRecorder()
	s.serveLLMAnalysisSearch(w, req)

	var resp struct {
		Available bool                   `json:"available"`
		Hits      []llmAnalysisSearchHit `json:"hits"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Available {
		t.Fatalf("expected available=true, got response: %+v", resp)
	}
	if len(resp.Hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(resp.Hits))
	}
	if resp.Hits[0].Score != 0.87 || resp.Hits[0].Summary != "Reconnaissance commands were observed." {
		t.Errorf("unexpected hit: %+v", resp.Hits[0])
	}
	if !resp.Hits[0].AIGenerated() {
		t.Error("search hits must still report AIGenerated() true")
	}
}
