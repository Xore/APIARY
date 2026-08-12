package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchNetflowVolumeReturnsFalseWithoutAnESClient(t *testing.T) {
	s := &store{}
	if _, ok := s.fetchNetflowVolume([]byte(netflowBytesQuery), "bytes"); ok {
		t.Fatal("expected ok=false when no ES client is configured")
	}
}

func TestFetchNetflowVolumeReturnsFalseOnQueryFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}
	if _, ok := s.fetchNetflowVolume([]byte(netflowBytesQuery), "bytes"); ok {
		t.Fatal("expected ok=false on a query failure")
	}
}

// TestFetchNetflowVolumeKeepsZeroBucketsUnlikeAvg pins that a sum
// aggregation's zero-value bucket is a real point (Elasticsearch's sum
// returns 0, not null, for an empty bucket) -- unlike
// fetchMLBacklogTrend's avg-based null skipping, every hourly bucket here
// belongs on the chart.
func TestFetchNetflowVolumeKeepsZeroBucketsUnlikeAvg(t *testing.T) {
	var resp netflowVolumeResponse
	resp.Aggregations.Hourly.Buckets = []struct {
		KeyAsString string `json:"key_as_string"`
		Total       struct {
			Value float64 `json:"value"`
		} `json:"total"`
	}{
		{KeyAsString: "2026-08-10T00:00:00.000Z", Total: struct {
			Value float64 `json:"value"`
		}{Value: 2220}},
		{KeyAsString: "2026-08-10T01:00:00.000Z", Total: struct {
			Value float64 `json:"value"`
		}{Value: 0}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	series, ok := s.fetchNetflowVolume([]byte(netflowBytesQuery), "bytes")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(series) != 1 || series[0].Name != "bytes" {
		t.Fatalf("unexpected series: %+v", series)
	}
	if len(series[0].Points) != 2 {
		t.Fatalf("expected both buckets kept (including the zero one), got %+v", series[0].Points)
	}
	if series[0].Points[0].Value != 2220 || series[0].Points[1].Value != 0 {
		t.Fatalf("unexpected values: %+v", series[0].Points)
	}
}

func TestServeNetflowBytesReturns503WhenESUnavailable(t *testing.T) {
	s := &store{}
	rec := httptest.NewRecorder()
	s.serveNetflowBytes(rec, httptest.NewRequest("GET", "/api/netflow-bytes", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestServeNetflowPacketsReturns503WhenESUnavailable(t *testing.T) {
	s := &store{}
	rec := httptest.NewRecorder()
	s.serveNetflowPackets(rec, httptest.NewRequest("GET", "/api/netflow-packets", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}
