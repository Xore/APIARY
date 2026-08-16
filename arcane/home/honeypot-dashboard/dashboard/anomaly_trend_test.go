package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAnomalyTrendGroupsByAppProtoIntoHourlyBuckets (#1279) pins the core
// shape: one series per AnomalyAppProto, one point per hour that saw at
// least one anomaly of that protocol, sorted for deterministic rendering
// across requests/instances (#40).
func TestAnomalyTrendGroupsByAppProtoIntoHourlyBuckets(t *testing.T) {
	hour1 := time.Date(2026, 8, 1, 10, 15, 0, 0, time.UTC)
	hour2 := time.Date(2026, 8, 1, 11, 45, 0, 0, time.UTC)
	s := &store{events: []storedEvent{
		{Category: "anomaly", AnomalyAppProto: "http", when: hour1},
		{Category: "anomaly", AnomalyAppProto: "http", when: hour1.Add(10 * time.Minute)},
		{Category: "anomaly", AnomalyAppProto: "http", when: hour2},
		{Category: "anomaly", AnomalyAppProto: "rdp", when: hour1},
		// non-anomaly rows must not leak into the trend at all
		{Category: "trojan-activity", AnomalyAppProto: "", when: hour1},
	}}

	series := s.anomalyTrend()
	if len(series) != 2 {
		t.Fatalf("expected 2 series (http, rdp), got %+v", series)
	}
	if series[0].Name != "http" {
		t.Fatalf("series[0].Name = %q, want http (alphabetically first)", series[0].Name)
	}
	if len(series[0].Points) != 2 {
		t.Fatalf("http series should have 2 hourly buckets, got %+v", series[0].Points)
	}
	if series[0].Points[0].Value != 2 {
		t.Fatalf("hour1 http bucket = %v, want 2 (two events same hour)", series[0].Points[0].Value)
	}
	if series[0].Points[1].Value != 1 {
		t.Fatalf("hour2 http bucket = %v, want 1", series[0].Points[1].Value)
	}
	if series[1].Name != "rdp" || len(series[1].Points) != 1 || series[1].Points[0].Value != 1 {
		t.Fatalf("unexpected rdp series: %+v", series[1])
	}
}

// TestAnomalyTrendGroupsMissingAppProtoUnderNone covers link-layer anomaly
// types that carry no app_proto -- must not be silently dropped, or the
// chart's total would undercount what /events?cat=anomaly shows.
func TestAnomalyTrendGroupsMissingAppProtoUnderNone(t *testing.T) {
	s := &store{events: []storedEvent{
		{Category: "anomaly", AnomalyAppProto: "", when: time.Now()},
	}}
	series := s.anomalyTrend()
	if len(series) != 1 || series[0].Name != "(none)" {
		t.Fatalf("expected a single \"(none)\" series, got %+v", series)
	}
}

func TestAnomalyTrendEmptyWithNoAnomalies(t *testing.T) {
	s := &store{events: []storedEvent{{Category: "trojan-activity", when: time.Now()}}}
	series := s.anomalyTrend()
	if len(series) != 0 {
		t.Fatalf("expected no series, got %+v", series)
	}
}

func TestServeAnomalyTrendWritesEmptyArrayNotNull(t *testing.T) {
	s := &store{}
	rec := httptest.NewRecorder()
	s.serveAnomalyTrend(rec, httptest.NewRequest("GET", "/api/anomaly-trend", nil))
	if rec.Body.String() != "[]\n" {
		t.Fatalf("expected an empty JSON array (not null), got %q", rec.Body.String())
	}
}

func TestServeAnomalyTrendWritesRealData(t *testing.T) {
	s := &store{events: []storedEvent{
		{Category: "anomaly", AnomalyAppProto: "http", when: time.Now()},
	}}
	rec := httptest.NewRecorder()
	s.serveAnomalyTrend(rec, httptest.NewRequest("GET", "/api/anomaly-trend", nil))
	var series []mlBacklogSeries
	if err := json.Unmarshal(rec.Body.Bytes(), &series); err != nil {
		t.Fatalf("invalid JSON: %v (body: %s)", err, rec.Body.String())
	}
	if len(series) != 1 || series[0].Name != "http" {
		t.Fatalf("unexpected series: %+v", series)
	}
}
