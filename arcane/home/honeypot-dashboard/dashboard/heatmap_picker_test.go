package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// singleSensorHeatmapStub answers the POST hourly-histogram query
// fetchSensorHeatmap sends, with one bucket so the response round-trips
// through quantizeHeatmap without being empty.
func singleSensorHeatmapStub(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "not stubbed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var resp esSingleSensorHeatmapResponse
		resp.Aggregations.Hourly.Buckets = []struct {
			KeyAsString string `json:"key_as_string"`
			DocCount    int    `json:"doc_count"`
		}{
			{KeyAsString: time.Now().UTC().Format(time.RFC3339), DocCount: 7},
		}
		json.NewEncoder(w).Encode(resp)
	}
}

func TestFetchSensorHeatmapReturnsFalseWithoutAnESClient(t *testing.T) {
	s := &store{}
	if _, ok := s.fetchSensorHeatmap("cowrie", time.Now()); ok {
		t.Fatal("expected ok=false when no ES client is configured")
	}
}

func TestFetchSensorHeatmapParsesBuckets(t *testing.T) {
	srv := httptest.NewServer(singleSensorHeatmapStub(t))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	cells, ok := s.fetchSensorHeatmap("cowrie", time.Now())
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(cells) != 1 || cells[0].Count != 7 {
		t.Fatalf("unexpected cells: %+v", cells)
	}
}

// TestServeHeatmapAllSensorsReturnsSnapshot (#41 item 1): the default,
// no-sensor request must reflect the same SensorHeatmap the overview page
// itself was rendered with -- not re-query Elasticsearch, since that field
// is already the once-per-rebuild value covering every sensor (#791).
func TestServeHeatmapAllSensorsReturnsSnapshot(t *testing.T) {
	s := &store{}
	s.snap.SensorHeatmap = []heatmapRow{{Sensor: "cowrie", Cells: []heatmapCell{{Label: "00:00", Count: 3, Pct: 100}}}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/heatmap", nil)
	s.serveHeatmap(rr, req)

	var out struct {
		Sensor string
		Rows   []heatmapRow
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad JSON: %v (%s)", err, rr.Body.String())
	}
	if len(out.Rows) != 1 || out.Rows[0].Sensor != "cowrie" {
		t.Fatalf("expected the snapshot's SensorHeatmap back, got %+v", out)
	}
}

// TestServeHeatmapRejectsSuricataAndPortbridge (#41): these ship to their
// own index families, not honeypot-v2-*, so a query for them through this
// endpoint would always silently return zero -- the same masking bug fixed
// for the main event read in rebuild(). Reject explicitly instead of
// returning a convincing-looking empty heatmap.
func TestServeHeatmapRejectsSuricataAndPortbridge(t *testing.T) {
	srv := httptest.NewServer(singleSensorHeatmapStub(t))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	for _, sensor := range []string{"suricata", "portbridge"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/heatmap?sensor="+url.QueryEscape(sensor), nil)
		s.serveHeatmap(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("sensor=%s: expected 400, got %d", sensor, rr.Code)
		}
	}
}

// TestServeHeatmapSingleSensorQueriesES (#41 item 1): selecting one sensor
// must fetch it live via fetchSensorHeatmap rather than reading the
// snapshot field, so its data is never more than a request old.
func TestServeHeatmapSingleSensorQueriesES(t *testing.T) {
	srv := httptest.NewServer(singleSensorHeatmapStub(t))
	defer srv.Close()
	s := &store{es: newESClient(srv.URL, "")}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/heatmap?sensor=dionaea", nil)
	s.serveHeatmap(rr, req)

	var out struct {
		Sensor string
		Rows   []heatmapRow
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad JSON: %v (%s)", err, rr.Body.String())
	}
	if out.Sensor != "dionaea" || len(out.Rows) != 1 || out.Rows[0].Cells[0].Count != 7 {
		t.Fatalf("unexpected response: %+v", out)
	}
}

func TestServeHeatmapSingleSensorFailsWithoutESClient(t *testing.T) {
	s := &store{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/heatmap?sensor=cowrie", nil)
	s.serveHeatmap(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}
