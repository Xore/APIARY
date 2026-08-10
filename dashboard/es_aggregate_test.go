package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// sensorFromSearchBody extracts the event.sensor value a loadSensorEventsES
// query is filtering on, distinguishing it from the #39 overview aggregation
// query, which carries no such term. #880 wrapped the term filter in a
// bool/filter alongside a time-range clause (see events_es.go), so the term
// can appear either at the top level (pre-#880 shape, kept for safety) or
// nested under query.bool.filter[] (current shape).
func sensorFromSearchBody(body []byte) (sensor string, isSensorQuery bool) {
	var req struct {
		Query struct {
			Term map[string]string `json:"term"`
			Bool struct {
				Filter []struct {
					Term map[string]string `json:"term"`
				} `json:"filter"`
			} `json:"bool"`
		} `json:"query"`
	}
	json.Unmarshal(body, &req)
	if v, ok := req.Query.Term["event.sensor"]; ok {
		return v, true
	}
	for _, f := range req.Query.Bool.Filter {
		if v, ok := f.Term["event.sensor"]; ok {
			return v, true
		}
	}
	return "", false
}

// esOverviewStub serves resp for the aggregation query and a 500 for a
// per-sensor events query -- a store configured with this stub as its ES
// client also runs the ES-preferred per-sensor read path (#34, events_es.go's
// loadSensorEventsES) on every rebuild for every sensor, not just
// esOnlySensors. These tests aren't exercising that path, and an
// empty-but-successful response would look like "ES has this sensor, and it
// has zero events" -- silently suppressing whatever local file fixtures a
// test seeded instead of falling back to them. A 500 correctly signals "ES
// has no answer for this sensor" and exercises the same local fallback
// these tests already relied on before #34.
//
// #583 moved loadSensorEventsES from a GET to a POST (search_after
// pagination needs a real query body), so the aggregation query and the
// per-sensor query are no longer distinguishable by HTTP method -- both are
// now POSTs to the same /honeypot-v2-*,suricata-v2-*/_search path (#1136:
// one multi-index query covers both index families, no separate
// suricata-v2-* query to distinguish anymore). Distinguish by body shape
// instead: a per-sensor query's body has a term query on event.sensor (see
// events_es.go), the aggregation query's does not.
func esOverviewStub(t *testing.T, resp esOverviewAggResponse) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		if _, isSensorQuery := sensorFromSearchBody(body); isSensorQuery {
			http.Error(w, "not stubbed", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(resp)
	}
}

func TestFetchESOverviewReturnsFalseWithoutAnESClient(t *testing.T) {
	s := &store{}
	if _, ok := s.fetchESOverview(time.Now()); ok {
		t.Fatal("expected ok=false when no ES client is configured")
	}
}

func TestFetchESOverviewReturnsFalseOnQueryFailure(t *testing.T) {
	s := &store{es: newESClient("http://127.0.0.1:1", "")} // nothing listening
	if _, ok := s.fetchESOverview(time.Now()); ok {
		t.Fatal("expected ok=false when the ES query fails")
	}
}

func TestFetchESOverviewParsesCountsAndTerms(t *testing.T) {
	var resp esOverviewAggResponse
	resp.Aggregations.Last24h.DocCount = 100
	resp.Aggregations.Previous24h.DocCount = 50
	resp.Aggregations.Unattributed.DocCount = 3
	resp.Aggregations.UniqueIPs.Value = 42
	resp.Aggregations.Sensors.Buckets = []esSensorBucket{
		{Key: "cowrie", DocCount: 80, LastSeen: struct {
			ValueAsString string `json:"value_as_string"`
		}{ValueAsString: "2026-08-03T19:00:00.000Z"}},
	}
	resp.Aggregations.Ports.Buckets = []esBucket{{Key: json.RawMessage(`22`), DocCount: 30}}
	resp.Aggregations.TopIPs.Buckets = []esBucket{{Key: json.RawMessage(`"203.0.113.9"`), DocCount: 10}}
	resp.Aggregations.Earliest.MinTS.ValueAsString = "2026-06-01T00:00:00.000Z"

	srv := httptest.NewServer(esOverviewStub(t, resp))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	out, ok := s.fetchESOverview(time.Now())
	if !ok {
		t.Fatal("expected ok=true")
	}
	if out.Total != 150 || out.Last24h != 100 || out.Previous24h != 50 {
		t.Fatalf("unexpected totals: %+v", out)
	}
	if out.Unattributed != 3 {
		t.Fatalf("Unattributed = %d, want 3", out.Unattributed)
	}
	if out.UniqueIPs != 42 {
		t.Fatalf("UniqueIPs = %d, want 42", out.UniqueIPs)
	}
	if out.SensorCounts["cowrie"] != 80 {
		t.Fatalf("SensorCounts[cowrie] = %d, want 80", out.SensorCounts["cowrie"])
	}
	wantSeen := time.Date(2026, 8, 3, 19, 0, 0, 0, time.UTC)
	if !out.SensorLastSeen["cowrie"].Equal(wantSeen) {
		t.Fatalf("SensorLastSeen[cowrie] = %v, want %v", out.SensorLastSeen["cowrie"], wantSeen)
	}
	if len(out.Ports) != 1 || out.Ports[0].Key != "22" || out.Ports[0].Count != 30 {
		t.Fatalf("unexpected ports: %+v", out.Ports)
	}
	if len(out.TopIPs) != 1 || out.TopIPs[0].Key != "203.0.113.9" || out.TopIPs[0].Count != 10 {
		t.Fatalf("unexpected top IPs: %+v", out.TopIPs)
	}
	wantEarliest := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if !out.EarliestSeen.Equal(wantEarliest) {
		t.Fatalf("EarliestSeen = %v, want %v", out.EarliestSeen, wantEarliest)
	}
}

// #1136: fetchESOverview queries /honeypot-v2-*,suricata-v2-*/_search as one
// multi-index pattern, so a "suricata" bucket in the SAME sensors terms
// aggregation as every other sensor is enough for it to reach
// SensorCounts/SensorLastSeen -- no second query, no synthetic merge step.
// This also pins that the query actually targets both index families
// (previously only honeypot-v2-*, silently excluding suricata from every
// field this function builds, not just the Sensors card).
func TestFetchESOverviewQueriesBothHoneypotAndSuricataIndices(t *testing.T) {
	var gotPath string
	var resp esOverviewAggResponse
	resp.Aggregations.Sensors.Buckets = []esSensorBucket{
		{Key: "cowrie", DocCount: 5},
		{Key: "suricata", DocCount: 3831, LastSeen: struct {
			ValueAsString string `json:"value_as_string"`
		}{ValueAsString: "2026-08-09T21:32:33.000Z"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		esOverviewStub(t, resp)(w, r)
	}))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	out, ok := s.fetchESOverview(time.Now())
	if !ok {
		t.Fatal("expected ok=true")
	}
	if gotPath != "/honeypot-v2-*,suricata-v2-*/_search" {
		t.Fatalf("queried %q, want the combined honeypot-v2-*,suricata-v2-* pattern", gotPath)
	}
	if out.SensorCounts["suricata"] != 3831 {
		t.Fatalf("SensorCounts[suricata] = %d, want 3831", out.SensorCounts["suricata"])
	}
	wantSeen := time.Date(2026, 8, 9, 21, 32, 33, 0, time.UTC)
	if !out.SensorLastSeen["suricata"].Equal(wantSeen) {
		t.Fatalf("SensorLastSeen[suricata] = %v, want %v", out.SensorLastSeen["suricata"], wantSeen)
	}
	if out.SensorCounts["cowrie"] != 5 {
		t.Fatalf("SensorCounts[cowrie] = %d, want 5 (suricata's bucket must not disturb it)", out.SensorCounts["cowrie"])
	}
}

func TestFetchESOverviewMergesProtocolsThroughNormalizeProtocol(t *testing.T) {
	var resp esOverviewAggResponse
	// smbd/mongod are raw, un-normalized values network.protocol actually
	// carries -- normalizeProtocol must collapse them the same way the old
	// in-process path did, not show them as separate rows.
	resp.Aggregations.Protocols.Buckets = []esBucket{
		{Key: json.RawMessage(`"smbd"`), DocCount: 5},
		{Key: json.RawMessage(`"ssh"`), DocCount: 20},
	}
	srv := httptest.NewServer(esOverviewStub(t, resp))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	out, ok := s.fetchESOverview(time.Now())
	if !ok {
		t.Fatal("expected ok=true")
	}
	byKey := map[string]int{}
	for _, kv := range out.Protocols {
		byKey[kv.Key] = kv.Count
	}
	if byKey["smb"] != 5 {
		t.Fatalf("expected smbd normalized to smb, got %+v", out.Protocols)
	}
	if byKey["ssh"] != 20 {
		t.Fatalf("unexpected protocols: %+v", out.Protocols)
	}
}

func TestFetchESOverviewParsesASNOrgAndMapPoints(t *testing.T) {
	var resp esOverviewAggResponse
	asnBucket := esASNBucket{Key: json.RawMessage(`15169`), DocCount: 7}
	asnBucket.Org.Buckets = []esBucket{{Key: json.RawMessage(`"Google LLC"`), DocCount: 7}}
	resp.Aggregations.ASNs.Buckets = []esASNBucket{asnBucket}

	place := esPlaceBucket{Key: []string{"Shanghai", "CN"}, DocCount: 12}
	place.Centroid.Location.Lat = 31.22
	place.Centroid.Location.Lon = 121.45
	place.UniqueIPs.Value = 3
	resp.Aggregations.Points.ByPlace.Buckets = []esPlaceBucket{place}

	srv := httptest.NewServer(esOverviewStub(t, resp))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	out, ok := s.fetchESOverview(time.Now())
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(out.ASNs) != 1 || out.ASNs[0].Key != "AS15169 Google LLC" || out.ASNs[0].Count != 7 {
		t.Fatalf("unexpected ASN row: %+v", out.ASNs)
	}
	if len(out.MapPoints) != 1 {
		t.Fatalf("expected 1 map point, got %+v", out.MapPoints)
	}
	p := out.MapPoints[0]
	if p.City != "Shanghai" || p.Country != "CN" || p.Count != 12 || p.IPCount != 3 || p.Lat != 31.22 || p.Lon != 121.45 {
		t.Fatalf("unexpected map point: %+v", p)
	}
}

func TestFetchESOverviewBuildsQuantizedHeatmap(t *testing.T) {
	var resp esOverviewAggResponse
	sb := esHeatmapSensorBucket{Key: "cowrie"}
	sb.Hourly.Buckets = []struct {
		KeyAsString string `json:"key_as_string"`
		DocCount    int    `json:"doc_count"`
	}{
		{KeyAsString: "2026-08-03T18:00:00.000Z", DocCount: 100},
		{KeyAsString: "2026-08-03T19:00:00.000Z", DocCount: 0},
	}
	resp.Aggregations.Heatmap.Sensors.Buckets = []esHeatmapSensorBucket{sb}

	srv := httptest.NewServer(esOverviewStub(t, resp))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	out, ok := s.fetchESOverview(time.Now())
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(out.SensorHeatmap) != 1 || out.SensorHeatmap[0].Sensor != "cowrie" {
		t.Fatalf("unexpected heatmap: %+v", out.SensorHeatmap)
	}
	cells := out.SensorHeatmap[0].Cells
	if len(cells) != 2 || cells[0].Pct != 100 || cells[1].Pct != 0 {
		t.Fatalf("unexpected quantization: %+v", cells)
	}
}

func TestBucketKeyStringHandlesStringsAndNumbers(t *testing.T) {
	if got := bucketKeyString(json.RawMessage(`"hello"`)); got != "hello" {
		t.Fatalf("got %q, want hello", got)
	}
	if got := bucketKeyString(json.RawMessage(`22`)); got != "22" {
		t.Fatalf("got %q, want 22", got)
	}
	if got := bucketKeyString(json.RawMessage(`15169`)); got != "15169" {
		t.Fatalf("got %q, want 15169", got)
	}
}
