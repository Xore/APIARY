package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// esSearchStub serves /ml-anomalies/_search, returning docs whose
// @timestamp is strictly after the q= range filter's lower bound (if any) --
// close enough to real Elasticsearch range-query behavior to prove
// refreshMLAnomalies()'s checkpoint logic without needing a live cluster.
func esSearchStub(t *testing.T, docs []mlAnomaly, gotPaths *[]string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		*gotPaths = append(*gotPaths, r.URL.RequestURI())
		since := ""
		if q := r.URL.Query().Get("q"); q != "" {
			// q looks like: @timestamp:{2026-08-01T10:00:00Z TO *]
			start := strings.Index(q, "{") + 1
			end := strings.Index(q, " TO")
			if start > 0 && end > start {
				since = q[start:end]
			}
		}
		type hit struct {
			Source mlAnomaly `json:"_source"`
		}
		var hits []hit
		for _, d := range docs {
			if since == "" || d.Timestamp > since {
				hits = append(hits, hit{Source: d})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"hits": map[string]any{"hits": hits},
		})
	}
}

func mustDecodeQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestRefreshMLAnomaliesAdvancesCheckpoint proves the poll-since-last-seen
// contract: a second poll only asks Elasticsearch for documents after what
// the first poll already saw, and the cache accumulates both batches rather
// than losing the first one or re-fetching it.
func TestRefreshMLAnomaliesAdvancesCheckpoint(t *testing.T) {
	docs := []mlAnomaly{
		{Timestamp: "2026-08-01T10:00:00Z", SrcIP: "203.0.113.1", Severity: "high", CompositeScore: 0.9},
		{Timestamp: "2026-08-01T10:05:00Z", SrcIP: "203.0.113.2", Severity: "critical", CompositeScore: 0.97},
	}
	var gotPaths []string
	es := httptest.NewServer(esSearchStub(t, docs, &gotPaths))
	defer es.Close()

	s := &store{es: newESClient(es.URL, ""), mlAnomalies: &mlAnomalyStore{}}
	s.refreshMLAnomalies()

	cached := s.mlAnomalies.snapshot()
	if len(cached) != 2 {
		t.Fatalf("expected both docs cached after first poll, got %d", len(cached))
	}
	if s.mlAnomalies.checkpoint() != "2026-08-01T10:05:00Z" {
		t.Fatalf("checkpoint did not advance to the newest doc's timestamp: %q", s.mlAnomalies.checkpoint())
	}

	// Second poll: no new docs on the ES side, but the request itself must
	// carry the advanced checkpoint, not re-request from the beginning.
	s.refreshMLAnomalies()
	if len(gotPaths) != 2 {
		t.Fatalf("expected 2 requests to Elasticsearch, got %d", len(gotPaths))
	}
	q := mustDecodeQuery(t, strings.SplitN(gotPaths[1], "?", 2)[1]).Get("q")
	if !strings.Contains(q, "2026-08-01T10:05:00Z") {
		t.Fatalf("second poll did not use the advanced checkpoint as its lower bound: %q", q)
	}
	if len(s.mlAnomalies.snapshot()) != 2 {
		t.Fatal("an empty second poll must not lose the first poll's cached items")
	}
}

// TestMLAnomalyCacheRespectsCap proves the stated worst-case bound (#64,
// same reasoning as #62/#63's MAX_TRAIN_SAMPLES/MAX_TRAIN_WINDOWS): the
// dashboard is memory-capped on purpose, so the cache must never grow past
// mlAnomalyCacheCap regardless of how many documents ml-worker has written.
func TestMLAnomalyCacheRespectsCap(t *testing.T) {
	c := &mlAnomalyStore{}
	var batch []mlAnomaly
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < mlAnomalyCacheCap+50; i++ {
		batch = append(batch, mlAnomaly{
			Timestamp: base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339),
			SrcIP:     fmt.Sprintf("203.0.113.%d", i%255),
		})
	}
	c.absorb(batch)
	items := c.snapshot()
	if len(items) != mlAnomalyCacheCap {
		t.Fatalf("cache did not cap at %d, got %d", mlAnomalyCacheCap, len(items))
	}
	// The cap must keep the NEWEST items, not the oldest -- an operator
	// wants the most recent anomalies, not whatever happened to arrive first.
	if items[len(items)-1].Timestamp != batch[len(batch)-1].Timestamp {
		t.Fatal("cache trimmed the newest items instead of the oldest")
	}
}

// TestMLAnomaliesAPIFiltersAndOrdersNewestFirst pins the /api/ml/anomalies
// contract (docs/ml-worker-plan.md §8): limit, severity, and since filters,
// newest timestamp first regardless of poll order.
func TestMLAnomaliesAPIFiltersAndOrdersNewestFirst(t *testing.T) {
	c := &mlAnomalyStore{}
	c.absorb([]mlAnomaly{
		{Timestamp: "2026-08-01T10:00:00Z", Severity: "medium"},
		{Timestamp: "2026-08-01T10:05:00Z", Severity: "critical"},
		{Timestamp: "2026-08-01T10:10:00Z", Severity: "high"},
	})
	s := &store{mlAnomalies: c}

	rec := httptest.NewRecorder()
	s.serveMLAnomaliesAPI(rec, httptest.NewRequest("GET", "/api/ml/anomalies", nil))
	var all []mlAnomaly
	if err := json.Unmarshal(rec.Body.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].Timestamp != "2026-08-01T10:10:00Z" {
		t.Fatalf("expected newest-first ordering, got %+v", all)
	}

	rec = httptest.NewRecorder()
	s.serveMLAnomaliesAPI(rec, httptest.NewRequest("GET", "/api/ml/anomalies?severity=critical", nil))
	var filtered []mlAnomaly
	json.Unmarshal(rec.Body.Bytes(), &filtered)
	if len(filtered) != 1 || filtered[0].Severity != "critical" {
		t.Fatalf("severity filter did not narrow to the matching anomaly: %+v", filtered)
	}

	rec = httptest.NewRecorder()
	s.serveMLAnomaliesAPI(rec, httptest.NewRequest("GET", "/api/ml/anomalies?limit=1", nil))
	var limited []mlAnomaly
	json.Unmarshal(rec.Body.Bytes(), &limited)
	if len(limited) != 1 {
		t.Fatalf("limit=1 did not cap the response, got %d items", len(limited))
	}
}

// TestMLAnomalyStatsFrom24hCutoffAndTopIPs proves the /api/ml/stats
// aggregation: only anomalies within the last 24h count toward
// total/by_severity, and top_src_ips ranks by count and caps at 10.
func TestMLAnomalyStatsFrom24hCutoffAndTopIPs(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	items := []mlAnomaly{
		{Timestamp: now.Add(-1 * time.Hour).Format(time.RFC3339), Severity: "high", SrcIP: "203.0.113.1"},
		{Timestamp: now.Add(-1 * time.Hour).Format(time.RFC3339), Severity: "high", SrcIP: "203.0.113.1"},
		{Timestamp: now.Add(-25 * time.Hour).Format(time.RFC3339), Severity: "critical", SrcIP: "203.0.113.2"},
	}
	stats := mlAnomalyStatsFrom(items, now)
	if stats.Total24h != 2 {
		t.Fatalf("expected only the 2 anomalies within 24h counted, got %d", stats.Total24h)
	}
	if len(stats.BySeverity) != 1 || stats.BySeverity[0].Key != "high" || stats.BySeverity[0].Count != 2 {
		t.Fatalf("by_severity did not exclude the >24h-old anomaly: %+v", stats.BySeverity)
	}
	if len(stats.TopSrcIPs) != 1 || stats.TopSrcIPs[0].Key != "203.0.113.1" || stats.TopSrcIPs[0].Count != 2 {
		t.Fatalf("top_src_ips did not exclude the >24h-old anomaly: %+v", stats.TopSrcIPs)
	}
}

// TestMLAnomaliesPageRendersFromCache proves the page itself (not just the
// API) reflects the cache, and that a disabled/no-ES state renders a clear
// empty state instead of a broken or misleading table.
func TestSourceLinkPivotsToTheExactDocument(t *testing.T) {
	a := mlAnomaly{SourceEventID: "abc123", SourceIndex: "suricata-v2-flow-2026.08.01"}
	link := a.SourceLink()

	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("SourceLink produced an unparseable URL %q: %v", link, err)
	}
	if u.Path != "/history" {
		t.Fatalf("expected /history, got path %q", u.Path)
	}
	q := u.Query().Get("q")
	if !strings.Contains(q, `_id:"abc123"`) || !strings.Contains(q, `_index:"suricata-v2-flow-2026.08.01"`) {
		t.Fatalf("query %q is missing the exact _id/_index pin", q)
	}
}

func TestSourceLinkEmptyWhenEitherFieldMissing(t *testing.T) {
	for _, a := range []mlAnomaly{
		{SourceEventID: "", SourceIndex: "suricata-v2-flow-2026.08.01"},
		{SourceEventID: "abc123", SourceIndex: ""},
		{},
	} {
		if got := a.SourceLink(); got != "" {
			t.Fatalf("expected no link with a missing field, got %q", got)
		}
	}
}

func TestMLAnomaliesPageRendersFromCache(t *testing.T) {
	c := &mlAnomalyStore{}
	c.absorb([]mlAnomaly{
		{Timestamp: "2026-08-01T10:00:00Z", Severity: "critical", SrcIP: "203.0.113.9", CompositeScore: 0.96,
			ModelScores:   map[string]float64{"isolation_forest": 0.9, "lstm_ae": 0.95, "hbos": 0.8},
			Explanation:   "Port scan: 47 unique ports",
			SourceEventID: "abc123", SourceIndex: "suricata-v2-flow-2026.08.01"},
	})
	s := &store{mlAnomalies: c, es: &esClient{}}
	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))

	page := s.mlAnomaliesData()
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "ml-anomalies", &page); err != nil {
		t.Fatalf("ml-anomalies page does not render: %v", err)
	}
	html := out.String()
	for _, want := range []string{"203.0.113.9", "critical", "Port scan: 47 unique ports", "0.96", "/history?q="} {
		if !strings.Contains(html, want) {
			t.Fatalf("rendered page is missing %q", want)
		}
	}

	disabled := (&store{}).mlAnomaliesData()
	out.Reset()
	if err := tmpl.ExecuteTemplate(&out, "ml-anomalies", &disabled); err != nil {
		t.Fatalf("disabled ml-anomalies page does not render: %v", err)
	}
	if !strings.Contains(out.String(), "Elasticsearch integration is disabled") {
		t.Fatal("disabled state did not render a clear explanation")
	}
}
