package main

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// #539: the overview page's "Sensor feeds" card used to cap at the top 30
// sensors by event count (topN(esOverviewResult.SensorCounts, 30)), silently
// dropping anything past that cut -- reachable only through the heatmap's
// sensor filter (which ranks the full set before applying its own,
// separate cap), never from this card. rebuild() must now carry every
// ES-reported sensor into the snapshot.
func TestRebuildKeepsEverySensorNotJustTop30(t *testing.T) {
	var resp esOverviewAggResponse
	const sensorCount = 40
	for i := 0; i < sensorCount; i++ {
		b := esSensorBucket{Key: fmt.Sprintf("sensor-%02d", i), DocCount: sensorCount - i}
		resp.Aggregations.Sensors.Buckets = append(resp.Aggregations.Sensors.Buckets, b)
	}

	esSrv := httptest.NewServer(esOverviewStub(t, resp))
	defer esSrv.Close()
	s := &store{dir: t.TempDir(), es: newESClient(esSrv.URL, "")}
	s.rebuild()

	snap := s.get()
	if len(snap.Sensors) != sensorCount {
		t.Fatalf("snap.Sensors has %d entries, want all %d ES-reported sensors (no top-N cut)", len(snap.Sensors), sensorCount)
	}
	seen := map[string]bool{}
	for _, row := range snap.Sensors {
		seen[row.Name] = true
	}
	for i := 0; i < sensorCount; i++ {
		name := fmt.Sprintf("sensor-%02d", i)
		if !seen[name] {
			t.Fatalf("sensor %q missing from snap.Sensors: %+v", name, snap.Sensors)
		}
	}
}

func TestSensorCardHasScrollWrapperAndCountIndicator(t *testing.T) {
	body := mustReadUI("overview.html")
	for _, want := range []string{
		`class="sensor-card__scroll"`,
		`Showing all {{len .Sensors}} sensor`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("overview.html sensor-feeds card missing %q", want)
		}
	}
	css, err := staticAssets.ReadFile("static/theme.css")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(css, []byte(".sensor-card__scroll {")) {
		t.Fatal("theme.css must bound .sensor-card__scroll (max-height + overflow-y) so a long sensor list scrolls in place")
	}
}
