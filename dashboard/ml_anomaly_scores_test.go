package main

import (
	"encoding/json"
	"net/http/httptest"
	"sort"
	"testing"
)

func TestFetchMLAnomalyScoresReturnsEmptySliceWithoutAStore(t *testing.T) {
	s := &store{}
	series := s.fetchMLAnomalyScores()
	if series == nil {
		t.Fatal("expected a non-nil empty slice, got nil")
	}
	if len(series) != 0 {
		t.Fatalf("expected no series, got %+v", series)
	}
}

// TestFetchMLAnomalyScoresBuildsOneSeriesPerModelPlusComposite pins the
// dynamic-discovery behavior: model names come from whatever ModelScores
// keys actually appear in the data, not a hardcoded isolation_forest/
// lstm_ae/hbos list, plus an always-present "composite" series.
func TestFetchMLAnomalyScoresBuildsOneSeriesPerModelPlusComposite(t *testing.T) {
	anomalies := &mlAnomalyStore{}
	anomalies.absorb([]mlAnomaly{
		{
			Timestamp:      "2026-08-12T18:00:00Z",
			CompositeScore: 0.75,
			ModelScores:    map[string]float64{"isolation_forest": 1.0, "hbos": 0.75},
		},
		{
			Timestamp:      "2026-08-12T19:00:00Z",
			CompositeScore: 0.5,
			ModelScores:    map[string]float64{"isolation_forest": 0.4},
		},
	})
	s := &store{mlAnomalies: anomalies}

	series := s.fetchMLAnomalyScores()
	names := make([]string, len(series))
	for i, sr := range series {
		names[i] = sr.Name
	}
	sort.Strings(names)
	want := []string{"composite", "hbos", "isolation_forest"}
	if len(names) != len(want) {
		t.Fatalf("series names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("series names = %v, want %v", names, want)
		}
	}

	for _, sr := range series {
		switch sr.Name {
		case "isolation_forest":
			if len(sr.Points) != 2 {
				t.Fatalf("isolation_forest should have a point from both anomalies, got %+v", sr.Points)
			}
		case "hbos":
			if len(sr.Points) != 1 {
				t.Fatalf("hbos should only have a point from the anomaly that scored it, got %+v", sr.Points)
			}
		case "composite":
			if len(sr.Points) != 2 {
				t.Fatalf("composite should have a point from every anomaly, got %+v", sr.Points)
			}
		}
	}
}

func TestServeMLAnomalyScoresRespondsWithEmptyArrayNotNull(t *testing.T) {
	s := &store{}
	rec := httptest.NewRecorder()
	s.serveMLAnomalyScores(rec, httptest.NewRequest("GET", "/api/ml-anomaly-scores", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var series []mlBacklogSeries
	if err := json.Unmarshal(rec.Body.Bytes(), &series); err != nil {
		t.Fatalf("response was not valid JSON: %v (body: %s)", err, rec.Body.String())
	}
	if series == nil {
		t.Fatal("expected an empty JSON array, got null")
	}
}
