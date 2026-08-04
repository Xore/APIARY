package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

// buildSensorHeatmap's quantization logic (including the "global max, not
// per-row" scaling, the busiest-N-sensors cap, and alphabetical tie
// breaking) moved to es_aggregate.go's quantizeHeatmap as part of #39 --
// the heatmap is now built from a live Elasticsearch date_histogram
// aggregation (already capped/ordered by the query itself, see
// esOverviewAggQuery's "heatmap" aggregation) rather than accumulated
// in-process from every event on every rebuild cycle. See
// es_aggregate_test.go's TestFetchESOverviewBuildsQuantizedHeatmap for the
// equivalent coverage of quantizeHeatmap, and
// TestSyntheticSensorEventsReachTheOverviewHeatmap below for rebuild()
// wiring the ES-native result into the snapshot end to end.

// TestSyntheticSensorEventsReachTheOverviewHeatmap exercises the full path
// (ES aggregation response -> rebuild -> snapshot), proving SensorHeatmap is
// actually wired into rebuild(), not just unit-testable in isolation.
func TestSyntheticSensorEventsReachTheOverviewHeatmap(t *testing.T) {
	var resp esOverviewAggResponse
	for _, sensor := range []string{"cowrie", "conpot"} {
		sb := esHeatmapSensorBucket{Key: sensor}
		sb.Hourly.Buckets = []struct {
			KeyAsString string `json:"key_as_string"`
			DocCount    int    `json:"doc_count"`
		}{{KeyAsString: time.Now().UTC().Format(time.RFC3339), DocCount: 1}}
		resp.Aggregations.Heatmap.Sensors.Buckets = append(resp.Aggregations.Heatmap.Sensors.Buckets, sb)
	}

	esSrv := httptest.NewServer(esOverviewStub(t, resp))
	defer esSrv.Close()
	s := &store{dir: t.TempDir(), es: newESClient(esSrv.URL, "")}
	s.rebuild()

	seen := map[string]bool{}
	for _, row := range s.get().SensorHeatmap {
		seen[row.Sensor] = true
	}
	for _, sensor := range []string{"cowrie", "conpot"} {
		if !seen[sensor] {
			t.Fatalf("ES-reported %s heatmap row did not reach the snapshot: %+v", sensor, s.get().SensorHeatmap)
		}
	}
}

// TestChange24hSuppressedWithoutTwoFullBaselineWindows covers #469: a store
// that has only been collecting for a few hours has an empty/artificially
// low "previous 24h" window for reasons that have nothing to do with real
// traffic, so the spike badge must not fire until EarliestSeen reaches back
// past esOverviewWindowDuration.
func TestChange24hSuppressedWithoutTwoFullBaselineWindows(t *testing.T) {
	var resp esOverviewAggResponse
	resp.Aggregations.Last24h.DocCount = 1000
	resp.Aggregations.Previous24h.DocCount = 1
	resp.Aggregations.Earliest.MinTS.ValueAsString = time.Now().UTC().Add(-3 * time.Hour).Format(time.RFC3339)

	esSrv := httptest.NewServer(esOverviewStub(t, resp))
	defer esSrv.Close()
	s := &store{dir: t.TempDir(), es: newESClient(esSrv.URL, "")}
	s.rebuild()

	snap := s.get()
	if snap.ActivityState == "spike" {
		t.Fatalf("young store with no real baseline must not report a spike: %+v", snap)
	}
	if snap.ActivityState != "insufficient baseline" {
		t.Fatalf("ActivityState = %q, want %q", snap.ActivityState, "insufficient baseline")
	}
}

// TestChange24hReportsSpikeWithFullBaseline is the mirror case: once
// EarliestSeen reaches back past the full 48h window, the existing
// percentage-based spike/elevated/low classification applies as before.
func TestChange24hReportsSpikeWithFullBaseline(t *testing.T) {
	var resp esOverviewAggResponse
	resp.Aggregations.Last24h.DocCount = 200
	resp.Aggregations.Previous24h.DocCount = 50
	resp.Aggregations.Earliest.MinTS.ValueAsString = time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)

	esSrv := httptest.NewServer(esOverviewStub(t, resp))
	defer esSrv.Close()
	s := &store{dir: t.TempDir(), es: newESClient(esSrv.URL, "")}
	s.rebuild()

	snap := s.get()
	if snap.ActivityState != "spike" {
		t.Fatalf("ActivityState = %q, want %q for a store with full baseline history", snap.ActivityState, "spike")
	}
}

// TestRebuildUniquePayloadsMatchesPayloadCacheNotEventObservations covers
// #470: the overview page's "Captured payloads" count must come from the
// same disk-scan cache /payloads uses (distinct binaries), not from the
// much smaller and differently-scoped per-event Downloads counter.
func TestRebuildUniquePayloadsMatchesPayloadCacheNotEventObservations(t *testing.T) {
	s := &store{dir: t.TempDir()}
	s.payloadCache = payloadsPage{UniqueTotal: 313}
	s.payloadCacheAt = time.Now()
	s.rebuild()

	snap := s.get()
	if snap.UniquePayloads != 313 {
		t.Fatalf("UniquePayloads = %d, want 313 (from the payload cache)", snap.UniquePayloads)
	}
	if snap.UniquePayloads == snap.Downloads && snap.Downloads != 313 {
		t.Fatalf("UniquePayloads must not be confused with Downloads: %+v", snap)
	}
}
