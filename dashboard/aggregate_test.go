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
