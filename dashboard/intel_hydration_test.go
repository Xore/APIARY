package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestIntelAndInvestigationShellRoutesDoNotReadElasticsearch(t *testing.T) {
	var requests atomic.Int64
	esServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "shell route unexpectedly queried Elasticsearch", http.StatusServiceUnavailable)
	}))
	defer esServer.Close()

	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.9", Sensor: "cowrie", Time: "2026-08-15 12:00", Fingerprint: "shared"},
		{SrcIP: "203.0.113.10", Sensor: "cowrie", Time: "2026-08-15 12:01", Fingerprint: "shared"},
	}}
	s.es = newESClient(esServer.URL, "")
	s.ipBlocks = newIPBlockManager(s.es)
	s.ready.Store(true)
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	mux := s.routes(tmpl)

	cases := map[string]string{
		"/campaigns?sensor=cowrie":                           "data-hp-intel-fragment-url",
		"/clusters?kind=Fingerprint":                         "data-hp-intel-fragment-url",
		"/investigate/ip/203.0.113.9":                        "attacker-correlation-root",
		"/investigate/cidr/203.0.113.0/24":                   "cidr-correlation-root",
		"/investigate/cluster?kind=Fingerprint&value=shared": "cluster-correlation-root",
	}
	for path, shellMarker := range cases {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s returned %d: %s", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), shellMarker) || !strings.Contains(rec.Body.String(), `aria-busy="true"`) {
			t.Fatalf("GET %s did not render its hydrated shell", path)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("initial shell routes made %d Elasticsearch requests, want 0", got)
	}
}

func TestIntelShellsPreserveFilterAndExportURLs(t *testing.T) {
	campaigns := campaignsShell(httptest.NewRequest(http.MethodGet, "/campaigns?sensor=cowrie&since=24h", nil))
	for _, url := range []string{campaigns.ExportURL, campaigns.FragmentURL} {
		if !strings.Contains(url, "sensor=cowrie") || !strings.Contains(url, "since=24h") {
			t.Fatalf("campaign URL lost active filters: %s", url)
		}
	}
	clusters := clustersShell(httptest.NewRequest(http.MethodGet, "/clusters?kind=Fingerprint&sensor=cowrie", nil))
	for _, url := range []string{clusters.ExportURL, clusters.FragmentURL} {
		if !strings.Contains(url, "kind=Fingerprint") || !strings.Contains(url, "sensor=cowrie") {
			t.Fatalf("cluster URL lost active filters: %s", url)
		}
	}
}
