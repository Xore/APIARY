package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAnalyzerDetailShellRoutesDoNotReadElasticsearch(t *testing.T) {
	var requests atomic.Int64
	esServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "fixture backend unavailable", http.StatusServiceUnavailable)
	}))
	defer esServer.Close()
	previous := esResultsClient
	esResultsClient = newESClient(esServer.URL, "")
	t.Cleanup(func() { esResultsClient = previous })

	s := &store{}
	mux := investigateTestMux(t, s)
	sha := strings.Repeat("a", 64)
	for _, tc := range []struct {
		path, marker string
	}{
		{"/revdeck/" + sha, "revdeck-detail-root"},
		{"/github-analysis/" + sha, "github-analysis-detail-root"},
	} {
		rec := doGet(mux, tc.path)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tc.marker) || !strings.Contains(rec.Body.String(), `aria-busy="true"`) {
			t.Fatalf("GET %s did not return its analyzer shell: status=%d", tc.path, rec.Code)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("analyzer shell routes made %d Elasticsearch requests, want 0", got)
	}

	for _, path := range []string{"/revdeck/" + sha + "/fragment", "/github-analysis/" + sha + "/fragment"} {
		rec := doGet(mux, path)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s returned %d, want fragment-level 404", path, rec.Code)
		}
	}
	if requests.Load() == 0 {
		t.Fatal("fragment routes did not perform their scoped Elasticsearch lookup")
	}
}

func TestAnalyzerShellsMatchTheirHydratedRegions(t *testing.T) {
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))
	sha := strings.Repeat("b", 64)
	for _, tc := range []struct {
		name string
		data any
		want []string
	}{
		{"revdeck", &revdeckPageData{Detail: &revdeckStandaloneResult{SHA256: sha}, Loading: true}, []string{"Rev&middot;Deck", "workflow", "tool calls", "card__scroll"}},
		{"github-analysis", &githubAnalysisPageData{Detail: &githubAnalysisResult{SHA256: sha}, DetailLoading: true}, []string{"Detections", "Risk level", "Family", "Scanner results", "Publication record", "Auto-generated YARA rules", "Report", "card__scroll"}},
	} {
		var out strings.Builder
		if err := tmpl.ExecuteTemplate(&out, tc.name, tc.data); err != nil {
			t.Fatalf("render %s: %v", tc.name, err)
		}
		for _, want := range tc.want {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("%s shell missing %q", tc.name, want)
			}
		}
	}
}
