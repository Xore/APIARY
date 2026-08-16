package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// agentCampaignsSearchStub mirrors esSearchStub (ml_anomalies_test.go) for
// the agent-intrusion-campaigns index -- same range-query approximation,
// same reason: proves refreshAgentCampaigns()'s checkpoint logic without a
// live cluster.
func agentCampaignsSearchStub(t *testing.T, docs []agentCampaign, gotPaths *[]string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		*gotPaths = append(*gotPaths, r.URL.RequestURI())
		since := ""
		if q := r.URL.Query().Get("q"); q != "" {
			start := strings.Index(q, "{") + 1
			end := strings.Index(q, " TO")
			if start > 0 && end > start {
				since = q[start:end]
			}
		}
		type hit struct {
			Source agentCampaign `json:"_source"`
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

// TestRefreshAgentCampaignsAdvancesCheckpoint mirrors
// TestRefreshMLAnomaliesAdvancesCheckpoint's proof for the campaign store.
func TestRefreshAgentCampaignsAdvancesCheckpoint(t *testing.T) {
	docs := []agentCampaign{
		{Timestamp: "2026-08-01T10:00:00Z", CampaignID: "c1", Severity: "high"},
		{Timestamp: "2026-08-01T10:05:00Z", CampaignID: "c2", Severity: "critical"},
	}
	var gotPaths []string
	es := httptest.NewServer(agentCampaignsSearchStub(t, docs, &gotPaths))
	defer es.Close()

	s := &store{es: newESClient(es.URL, ""), agentCampaigns: &agentCampaignStore{}}
	s.refreshAgentCampaigns()

	cached := s.agentCampaigns.snapshot()
	if len(cached) != 2 {
		t.Fatalf("expected both docs cached after first poll, got %d", len(cached))
	}
	if s.agentCampaigns.checkpoint() != "2026-08-01T10:05:00Z" {
		t.Fatalf("checkpoint did not advance to the newest doc's timestamp: %q", s.agentCampaigns.checkpoint())
	}

	s.refreshAgentCampaigns()
	if len(gotPaths) != 2 {
		t.Fatalf("expected 2 requests to Elasticsearch, got %d", len(gotPaths))
	}
	if len(s.agentCampaigns.snapshot()) != 2 {
		t.Fatal("an empty second poll must not lose the first poll's cached items")
	}
}

// TestAgentCampaignsAbsorbUpsertsByCampaignID proves the one real
// difference from mlAnomalyStore: a re-polled campaign_id replaces its
// prior entry rather than appending a duplicate, since worker.py rewrites
// the same ES document (same _id) every cycle a campaign is still active.
func TestAgentCampaignsAbsorbUpsertsByCampaignID(t *testing.T) {
	c := &agentCampaignStore{}
	c.absorb([]agentCampaign{{Timestamp: "2026-08-01T10:00:00Z", CampaignID: "c1", Severity: "high", EventCount: 3}})
	c.absorb([]agentCampaign{{Timestamp: "2026-08-01T11:00:00Z", CampaignID: "c1", Severity: "critical", EventCount: 5}})

	items := c.snapshot()
	if len(items) != 1 {
		t.Fatalf("expected the second poll to replace, not append, got %d items", len(items))
	}
	if items[0].Severity != "critical" || items[0].EventCount != 5 {
		t.Fatalf("expected the newer verdict to win, got %+v", items[0])
	}
}

// TestAgentCampaignCacheRespectsCap mirrors TestMLAnomalyCacheRespectsCap:
// this is fed by attacker-influenced correlation, and must never grow past
// agentCampaignCacheCap regardless of how many campaigns worker.py writes.
func TestAgentCampaignCacheRespectsCap(t *testing.T) {
	c := &agentCampaignStore{}
	var batch []agentCampaign
	for i := 0; i < agentCampaignCacheCap+50; i++ {
		batch = append(batch, agentCampaign{
			Timestamp:  "2026-08-01T10:00:00Z",
			CampaignID: "c" + string(rune('a'+i%26)) + string(rune('0'+i%10)) + string(rune('A'+i%26)),
		})
	}
	c.absorb(batch)
	items := c.snapshot()
	if len(items) > agentCampaignCacheCap {
		t.Fatalf("cache did not cap at %d, got %d", agentCampaignCacheCap, len(items))
	}
}

// TestAgentCampaignsAPIFiltersAndOrdersNewestFirst pins the
// /api/agent-campaigns contract: severity/category/id filters, newest
// timestamp first.
func TestAgentCampaignsAPIFiltersAndOrdersNewestFirst(t *testing.T) {
	c := &agentCampaignStore{}
	c.absorb([]agentCampaign{
		{Timestamp: "2026-08-01T10:00:00Z", CampaignID: "c1", Severity: "high", MatchedCategories: []string{"sensitive-path-read"}, CorrelationIdentifiers: []string{"ip:203.0.113.1"}},
		{Timestamp: "2026-08-01T10:05:00Z", CampaignID: "c2", Severity: "critical", MatchedCategories: []string{"metadata-service-probe"}, CorrelationIdentifiers: []string{"session:abc"}},
	})
	s := &store{agentCampaigns: c}

	rec := httptest.NewRecorder()
	s.serveAgentCampaignsAPI(rec, httptest.NewRequest("GET", "/api/agent-campaigns", nil))
	var all []agentCampaign
	if err := json.Unmarshal(rec.Body.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].CampaignID != "c2" {
		t.Fatalf("expected newest-first ordering, got %+v", all)
	}

	rec = httptest.NewRecorder()
	s.serveAgentCampaignsAPI(rec, httptest.NewRequest("GET", "/api/agent-campaigns?severity=critical", nil))
	var bySeverity []agentCampaign
	json.Unmarshal(rec.Body.Bytes(), &bySeverity)
	if len(bySeverity) != 1 || bySeverity[0].CampaignID != "c2" {
		t.Fatalf("severity filter did not narrow correctly: %+v", bySeverity)
	}

	rec = httptest.NewRecorder()
	s.serveAgentCampaignsAPI(rec, httptest.NewRequest("GET", "/api/agent-campaigns?category=sensitive-path-read", nil))
	var byCat []agentCampaign
	json.Unmarshal(rec.Body.Bytes(), &byCat)
	if len(byCat) != 1 || byCat[0].CampaignID != "c1" {
		t.Fatalf("category filter did not narrow correctly: %+v", byCat)
	}

	rec = httptest.NewRecorder()
	s.serveAgentCampaignsAPI(rec, httptest.NewRequest("GET", "/api/agent-campaigns?id=203.0.113.1", nil))
	var byID []agentCampaign
	json.Unmarshal(rec.Body.Bytes(), &byID)
	if len(byID) != 1 || byID[0].CampaignID != "c1" {
		t.Fatalf("identifier filter did not narrow correctly: %+v", byID)
	}
}

func TestCampaignEventSourceLinkPivotsToTheExactDocument(t *testing.T) {
	e := campaignEvent{EventID: "abc123", SourceIndex: "honeypot-v2-2026.08.01"}
	link := e.SourceLink()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("SourceLink produced an unparseable URL %q: %v", link, err)
	}
	if u.Path != "/history" {
		t.Fatalf("expected /history, got path %q", u.Path)
	}
	q := u.Query().Get("q")
	if !strings.Contains(q, `_id:"abc123"`) || !strings.Contains(q, `_index:"honeypot-v2-2026.08.01"`) {
		t.Fatalf("query %q is missing the exact _id/_index pin", q)
	}
}

func TestCampaignEventSourceLinkEmptyWhenEitherFieldMissing(t *testing.T) {
	for _, e := range []campaignEvent{
		{EventID: "", SourceIndex: "honeypot-v2-x"},
		{EventID: "abc", SourceIndex: ""},
		{},
	} {
		if got := e.SourceLink(); got != "" {
			t.Fatalf("expected no link with a missing field, got %q", got)
		}
	}
}

// TestIdentifierLinksRoutesEachKind proves each correlation-identifier
// prefix pivots to the right existing filter/search page.
func TestIdentifierLinksRoutesEachKind(t *testing.T) {
	c := agentCampaign{CorrelationIdentifiers: []string{"ip:203.0.113.1", "session:s1", "channel:ab12", "unknown:x"}}
	links := c.IdentifierLinks()
	if len(links) != 4 {
		t.Fatalf("expected one link entry per identifier, got %+v", links)
	}
	want := map[string]string{
		"ip:203.0.113.1": "/events?ip=203.0.113.1",
		"session:s1":     "/events?session=s1",
	}
	for _, l := range links {
		if wantLink, ok := want[l.Key]; ok && l.Link != wantLink {
			t.Errorf("%s: expected link %q, got %q", l.Key, wantLink, l.Link)
		}
		if l.Key == "channel:ab12" && !strings.HasPrefix(l.Link, "/history?q=") {
			t.Errorf("channel identifier did not route to /history: %+v", l)
		}
		if l.Key == "unknown:x" && l.Link != "" {
			t.Errorf("an unrecognized identifier kind should get no link, got %q", l.Link)
		}
	}
}

// TestFinalArtifactHashAndTransformPath proves the decode-chain summary
// helpers the template relies on instead of arithmetic/indexing.
func TestFinalArtifactHashAndTransformPath(t *testing.T) {
	m := campaignMatchedRule{DecodeChain: []decodeStep{
		{Transform: "base64", OutputSHA256: "aaa"},
		{Transform: "gzip", OutputSHA256: "bbb"},
	}}
	if m.FinalArtifactHash() != "bbb" {
		t.Fatalf("expected the last step's hash, got %q", m.FinalArtifactHash())
	}
	if m.TransformPath() != "base64 → gzip" {
		t.Fatalf("unexpected transform path: %q", m.TransformPath())
	}
	empty := campaignMatchedRule{}
	if empty.FinalArtifactHash() != "" {
		t.Fatalf("expected empty hash with no decode chain, got %q", empty.FinalArtifactHash())
	}
}

// TestAgentCampaignsDataAppliesFilter mirrors TestMLAnomaliesDataAppliesFilter.
func TestAgentCampaignsDataAppliesFilter(t *testing.T) {
	c := &agentCampaignStore{}
	c.absorb([]agentCampaign{
		{Timestamp: "2026-08-01T10:00:00Z", CampaignID: "c1", Severity: "critical", MatchedCategories: []string{"sensitive-path-read"}},
		{Timestamp: "2026-08-01T10:01:00Z", CampaignID: "c2", Severity: "high", MatchedCategories: []string{"metadata-service-probe"}},
	})
	s := &store{agentCampaigns: c, es: &esClient{}}

	all := s.agentCampaignsData(httptest.NewRequest("GET", "/agent-campaigns", nil))
	if len(all.Campaigns) != 2 {
		t.Fatalf("expected both campaigns unfiltered, got %+v", all.Campaigns)
	}

	narrowed := s.agentCampaignsData(httptest.NewRequest("GET", "/agent-campaigns?severity=critical", nil))
	if len(narrowed.Campaigns) != 1 || narrowed.Campaigns[0].CampaignID != "c1" {
		t.Fatalf("severity filter did not narrow the campaign list, got %+v", narrowed.Campaigns)
	}
	if len(narrowed.Filters) != 1 || narrowed.Filters[0] != "severity = critical" {
		t.Fatalf("expected a severity filter chip, got %+v", narrowed.Filters)
	}
}

func TestAgentCampaignsDataDisabledStoreHasNoFilters(t *testing.T) {
	page := (&store{}).agentCampaignsData(httptest.NewRequest("GET", "/agent-campaigns?severity=critical", nil))
	if page.Enabled {
		t.Fatal("expected Enabled=false with no store configured")
	}
	if len(page.Filters) != 1 {
		t.Fatalf("expected the filter chip to still be reported even with campaigns disabled, got %+v", page.Filters)
	}
}

// TestAgentCampaignsPageRendersFromCache proves the page renders the full
// evidence trail #154 phase 5 requires: rule, trust boundary, reason,
// decoded-artifact hash, and a link back to raw evidence.
func TestAgentCampaignsPageRendersFromCache(t *testing.T) {
	c := &agentCampaignStore{}
	c.absorb([]agentCampaign{
		{
			Timestamp: "2026-08-01T10:00:00Z", CampaignID: "camp1", Start: "2026-08-01T09:00:00Z", End: "2026-08-01T10:00:00Z",
			Severity: "critical", MatchedCategories: []string{"sensitive-path-read"}, CorrelationIdentifiers: []string{"session:s1"},
			EventCount: 1,
			Events: []campaignEvent{{
				EventID: "ev1", SourceIndex: "honeypot-v2-x", Timestamp: "2026-08-01T09:30:00Z",
				MatchedRules: []campaignMatchedRule{{
					Rule: "sensitive-path-read", Reason: "command references /proc/self/environ",
					TrustBoundary: "process/container -> host secret material",
					DecodeChain:   []decodeStep{{Transform: "base64", OutputSHA256: "deadbeef"}},
				}},
			}},
		},
	})
	s := &store{agentCampaigns: c, es: &esClient{}}
	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))

	page := s.agentCampaignsData(httptest.NewRequest("GET", "/agent-campaigns", nil))
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "agent-campaigns", &page); err != nil {
		t.Fatalf("agent-campaigns page does not render: %v", err)
	}
	html := out.String()
	for _, want := range []string{
		// "->" round-trips through html/template's auto-escaping as "-&gt;"
		// -- checking for that literally proves the trust-boundary text
		// actually made it into the page, not just present in the Go value.
		"sensitive-path-read", "process/container -&gt; host secret material",
		"command references /proc/self/environ", "deadbeef", "/history?q=",
		"critical", "session:s1",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("rendered page is missing %q", want)
		}
	}

	disabled := (&store{}).agentCampaignsData(httptest.NewRequest("GET", "/agent-campaigns", nil))
	out.Reset()
	if err := tmpl.ExecuteTemplate(&out, "agent-campaigns", &disabled); err != nil {
		t.Fatalf("disabled agent-campaigns page does not render: %v", err)
	}
	if !strings.Contains(out.String(), "Elasticsearch integration is disabled") {
		t.Fatal("disabled state did not render a clear explanation")
	}
}
