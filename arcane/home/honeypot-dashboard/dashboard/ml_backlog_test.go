package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchMLBacklogTrendReturnsFalseWithoutAnESClient(t *testing.T) {
	s := &store{}
	if _, ok := s.fetchMLBacklogTrend(); ok {
		t.Fatal("expected ok=false when no ES client is configured")
	}
}

func TestFetchMLBacklogTrendReturnsFalseOnQueryFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}
	if _, ok := s.fetchMLBacklogTrend(); ok {
		t.Fatal("expected ok=false on a query failure")
	}
}

// TestFetchMLBacklogTrendParsesPerSourceSeries pins the terms+nested-
// date_histogram response shape (matching fetchSensorHeatmap's own
// es_aggregate.go pattern) into one mlBacklogSeries per source_index, and
// confirms a bucket with no avg_backlog value (Elasticsearch returns
// "value": null for an empty bucket) is skipped rather than surfacing as a
// bogus zero -- a real zero backlog and "no sample this hour" are not the
// same thing.
func TestFetchMLBacklogTrendParsesPerSourceSeries(t *testing.T) {
	var resp mlBacklogResponse
	resp.Aggregations.Sources.Buckets = []struct {
		Key    string `json:"key"`
		Hourly struct {
			Buckets []struct {
				KeyAsString string `json:"key_as_string"`
				AvgBacklog  struct {
					Value *float64 `json:"value"`
				} `json:"avg_backlog"`
			} `json:"buckets"`
		} `json:"hourly"`
	}{
		{
			Key: "honeypot-v2-*",
			Hourly: struct {
				Buckets []struct {
					KeyAsString string `json:"key_as_string"`
					AvgBacklog  struct {
						Value *float64 `json:"value"`
					} `json:"avg_backlog"`
				} `json:"buckets"`
			}{
				Buckets: []struct {
					KeyAsString string `json:"key_as_string"`
					AvgBacklog  struct {
						Value *float64 `json:"value"`
					} `json:"avg_backlog"`
				}{
					{KeyAsString: "2026-08-10T00:00:00.000Z", AvgBacklog: struct {
						Value *float64 `json:"value"`
					}{Value: floatPtr(12588)}},
					{KeyAsString: "2026-08-10T01:00:00.000Z", AvgBacklog: struct {
						Value *float64 `json:"value"`
					}{Value: nil}},
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	series, ok := s.fetchMLBacklogTrend()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(series) != 1 || series[0].Name != "honeypot-v2-*" {
		t.Fatalf("unexpected series: %+v", series)
	}
	if len(series[0].Points) != 1 {
		t.Fatalf("expected the null-value bucket to be skipped, got %+v", series[0].Points)
	}
	if series[0].Points[0].Value != 12588 {
		t.Fatalf("Value = %v, want 12588", series[0].Points[0].Value)
	}
}

func TestServeMLBacklogReturns503WhenESUnavailable(t *testing.T) {
	s := &store{}
	rec := httptest.NewRecorder()
	s.serveMLBacklog(rec, httptest.NewRequest("GET", "/api/ml-backlog", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func floatPtr(f float64) *float64 { return &f }
