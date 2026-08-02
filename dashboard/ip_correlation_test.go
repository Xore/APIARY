package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// correlationSearchStub serves a fixed _search response and records the
// request path it was actually called with, so tests can assert on both the
// query built and the parsing of the response.
func correlationSearchStub(t *testing.T, gotPath *string, body string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		*gotPath = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}
}

const sampleCorrelationResponse = `{
  "hits": {
    "total": {"value": 3},
    "hits": [
      {
        "_index": "portbridge-v2-2026.08.02",
        "_source": {
          "@timestamp": "2026-08-02T19:26:28.544Z",
          "event": {"sensor": "portbridge", "category": "connect"},
          "destination": {"port": 5060},
          "network": {"transport": "udp"},
          "portbridge": {"os": "Linux 5.x", "via_port": 19106, "target": "10.8.0.2:5060"}
        }
      },
      {
        "_index": "honeypot-v2-2026.08.02",
        "_source": {
          "@timestamp": "2026-08-02T19:20:00.000Z",
          "event": {"sensor": "cowrie", "category": "login"},
          "honeypot": {"eventid": "cowrie.login.success"}
        }
      },
      {
        "_index": "suricata-v2-alert-2026.08.02",
        "_source": {
          "@timestamp": "2026-08-02T19:19:00.000Z",
          "event": {"sensor": "suricata"},
          "suricata": {"eve": {"event_type": "alert", "alert": {"signature": "ET SCAN Suspicious inbound"}}}
        }
      }
    ]
  }
}`

// TestCorrelateIPParsesAndAggregatesAcrossIndexFamilies (#354): correlateIP
// is the "ask the backend for everything about this IP" entry point --
// verify it queries all three index families that now share the
// geoip-honeypot pipeline's ECS envelope, and that the aggregate view
// (tunnel-connection count, distinct p0f OS guesses, per-sensor summary
// lines) is built correctly from heterogeneous hit shapes.
func TestCorrelateIPParsesAndAggregatesAcrossIndexFamilies(t *testing.T) {
	var gotPath string
	es := httptest.NewServer(correlationSearchStub(t, &gotPath, sampleCorrelationResponse))
	defer es.Close()

	c := newESClient(es.URL, "")
	result := c.correlateIP("203.0.113.5", 50)

	if !result.Available {
		t.Fatal("correlateIP reported unavailable despite a successful ES response")
	}
	if !strings.HasPrefix(gotPath, "/"+correlationIndices+"/_search") {
		t.Fatalf("query did not target all three correlated index families: %s", gotPath)
	}
	wantQ := url.QueryEscape(`source.ip:"203.0.113.5"`)
	if !strings.Contains(gotPath, "q="+wantQ) {
		t.Fatalf("query did not filter on the requested IP: %s", gotPath)
	}
	if result.Total != 3 || len(result.Records) != 3 {
		t.Fatalf("expected 3 total/records, got total=%d records=%d", result.Total, len(result.Records))
	}
	if result.TunnelConnections != 1 {
		t.Fatalf("TunnelConnections = %d, want 1", result.TunnelConnections)
	}
	if len(result.TunnelOSGuesses) != 1 || result.TunnelOSGuesses[0] != "Linux 5.x" {
		t.Fatalf("TunnelOSGuesses = %v, want [Linux 5.x]", result.TunnelOSGuesses)
	}
	summaries := map[string]bool{}
	for _, record := range result.Records {
		summaries[record.Summary] = true
	}
	if !summaries["tunnel connect · port 5060 · p0f: Linux 5.x"] {
		t.Errorf("missing expected portbridge summary, got: %+v", result.Records)
	}
	if !summaries["cowrie.login.success"] {
		t.Errorf("missing expected honeypot summary, got: %+v", result.Records)
	}
	if !summaries["suricata alert: ET SCAN Suspicious inbound"] {
		t.Errorf("missing expected suricata summary, got: %+v", result.Records)
	}
}

// TestCorrelateIPRejectsMalformedInputWithoutQuerying (#354): a malformed
// value must never reach the Lucene query string -- correlateIP/
// correlateCIDR re-validate defensively even though callers are expected to
// have already validated, since a query-injection surface here would be a
// real vulnerability, not just a correctness bug.
func TestCorrelateIPRejectsMalformedInputWithoutQuerying(t *testing.T) {
	called := false
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte(`{"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer es.Close()

	c := newESClient(es.URL, "")
	for _, bad := range []string{"", "not-an-ip", `1.2.3.4" OR "1`, "1.2.3.4/999"} {
		if result := c.correlateIP(bad, 50); result.Available {
			t.Errorf("correlateIP(%q) should be unavailable for a malformed IP, got %+v", bad, result)
		}
	}
	if _, _, err := (&esClient{}).correlate("irrelevant", 1); err == nil {
		t.Error("correlate against an unconfigured esClient must fail, not silently query nothing")
	}
	if called {
		t.Fatal("malformed input must never reach the Elasticsearch query")
	}
}

// TestCorrelateCIDRAcceptsRangeQuery (#354): campaigns are CIDR-scoped, not
// single-IP -- correlateCIDR must build a range query Elasticsearch's ip
// field type understands natively, reusing the same query/parse core as
// correlateIP.
func TestCorrelateCIDRAcceptsRangeQuery(t *testing.T) {
	var gotPath string
	es := httptest.NewServer(correlationSearchStub(t, &gotPath, sampleCorrelationResponse))
	defer es.Close()

	c := newESClient(es.URL, "")
	result := c.correlateCIDR("203.0.113.0/24", 50)
	if !result.Available {
		t.Fatal("correlateCIDR reported unavailable despite a successful ES response")
	}
	wantQ := url.QueryEscape(`source.ip:"203.0.113.0/24"`)
	if !strings.Contains(gotPath, "q="+wantQ) {
		t.Fatalf("query did not use a CIDR range filter: %s", gotPath)
	}

	if result := c.correlateCIDR("not-a-cidr", 50); result.Available {
		t.Error("correlateCIDR must reject a non-CIDR value without querying")
	}
}

// TestCIDRCorrelationDataRequiresBothValidCIDRAndAvailableES (#354):
// cidrCorrelationData powers campaigns' drill-down -- it must reject a
// malformed CIDR before ever touching Elasticsearch, and report "not found"
// rather than an empty shell page when Elasticsearch is unconfigured (a nil
// *esClient, the same state a store has when ELASTICSEARCH_URL is unset).
func TestCIDRCorrelationDataRequiresBothValidCIDRAndAvailableES(t *testing.T) {
	s := &store{}
	if _, ok := s.cidrCorrelationData("not-a-cidr"); ok {
		t.Fatal("cidrCorrelationData must reject a malformed CIDR")
	}
	if _, ok := s.cidrCorrelationData("203.0.113.0/24"); ok {
		t.Fatal("cidrCorrelationData must report not-found when Elasticsearch is unconfigured (s.es == nil)")
	}

	var gotPath string
	es := httptest.NewServer(correlationSearchStub(t, &gotPath, sampleCorrelationResponse))
	defer es.Close()
	s.es = newESClient(es.URL, "")

	page, ok := s.cidrCorrelationData("203.0.113.0/24")
	if !ok {
		t.Fatal("cidrCorrelationData should succeed once Elasticsearch is configured and returns data")
	}
	if page.CIDR != "203.0.113.0/24" || !page.Correlation.Available || page.Correlation.Total != 3 {
		t.Fatalf("unexpected page: %+v", page)
	}
	wantQ := url.QueryEscape(`source.ip:"203.0.113.0/24"`)
	if !strings.Contains(gotPath, "q="+wantQ) {
		t.Fatalf("query did not use a CIDR range filter: %s", gotPath)
	}
}

// TestAttackerPageRendersCorrelationSectionOnlyWhenAvailable (#354): the
// attacker-profile page's Elasticsearch correlation card must appear when
// data is available and stay absent (not an empty/broken card) when
// Elasticsearch is unconfigured or the query failed -- Available is the
// single flag every render decision hangs off.
func TestAttackerPageRendersCorrelationSectionOnlyWhenAvailable(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	base := attackerPage{IP: "203.0.113.5", Total: 1, Events: []storedEvent{{Time: "now", Sensor: "cowrie", SrcIP: "203.0.113.5"}}}

	withCorrelation := base
	withCorrelation.Correlation = ipCorrelation{
		Available: true, Total: 1, TunnelConnections: 1, TunnelOSGuesses: []string{"Linux 5.x"},
		Records: []correlatedRecord{{Time: time.Now(), Sensor: "portbridge", Summary: "tunnel connect · port 5060"}},
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "attacker", &withCorrelation); err != nil {
		t.Fatalf("render with correlation available: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "attacker-correlation") || !strings.Contains(body, "Linux 5.x") {
		t.Fatalf("correlation card missing or incomplete when Available=true: %s", body)
	}

	buf.Reset()
	if err := tmpl.ExecuteTemplate(&buf, "attacker", &base); err != nil {
		t.Fatalf("render without correlation: %v", err)
	}
	if strings.Contains(buf.String(), "attacker-correlation") {
		t.Fatal("correlation card must not render when Correlation.Available is false")
	}
}

// TestCIDRCorrelationPageRenders (#354) proves the campaigns drill-down
// template renders the CIDR, the aggregate metrics, and at least one
// correlated record row from real page data.
func TestCIDRCorrelationPageRenders(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("dashboard").Funcs(funcs).Parse(pageTemplate))

	data := cidrCorrelationPage{
		CIDR: "203.0.113.0/24",
		Correlation: ipCorrelation{
			Available: true, Total: 3, TunnelConnections: 1, TunnelOSGuesses: []string{"Linux 5.x"},
			Sensors: []kv{{Key: "portbridge", Count: 1}, {Key: "cowrie", Count: 1}},
			Records: []correlatedRecord{{Time: time.Now(), Sensor: "portbridge", Summary: "tunnel connect · port 5060"}},
		},
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "cidr-correlation", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "203.0.113.0/24") {
		t.Fatal("page does not render the CIDR")
	}
	if !strings.Contains(body, "tunnel connect · port 5060") {
		t.Fatal("page does not render a correlated record")
	}
	if !strings.Contains(body, `href="/events?cidr=203.0.113.0%2F24&amp;since=168h"`) {
		t.Fatalf("page is missing the in-memory-events cross-link, or the CIDR is not correctly URL-escaped in it: %s", body)
	}
}
