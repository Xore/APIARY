package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildSensorHeatmapReturnsNilWhenNoActivity(t *testing.T) {
	if got := buildSensorHeatmap(map[string]*[24]int{}, time.Now()); got != nil {
		t.Fatalf("empty input must return nil, got %#v", got)
	}
	allZero := map[string]*[24]int{"cowrie": {}}
	if got := buildSensorHeatmap(allZero, time.Now()); got != nil {
		t.Fatalf("a sensor with every hour at zero must be excluded, got %#v", got)
	}
}

func TestBuildSensorHeatmapQuantizesAgainstTheGlobalMax(t *testing.T) {
	hours := &[24]int{}
	hours[0] = 100 // busiest cell across the whole grid -> Pct 100
	hours[1] = 75  // exactly 3/4 of max -> Pct 75
	hours[2] = 50  // exactly 1/2 of max -> Pct 50
	hours[3] = 25  // exactly 1/4 of max -> Pct 25
	hours[4] = 1   // just above zero, well under 1/4 of max -> Pct 25 (lowest non-zero band)
	rows := buildSensorHeatmap(map[string]*[24]int{"cowrie": hours}, time.Now())
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	cells := rows[0].Cells
	want := map[int]int{0: 100, 1: 75, 2: 50, 3: 25, 4: 25}
	for i, pct := range want {
		if cells[i].Pct != pct {
			t.Fatalf("cell %d: Pct = %d, want %d (count=%d)", i, cells[i].Pct, pct, cells[i].Count)
		}
	}
	// Every hour with zero events must quantize to 0, not just "low".
	if cells[5].Pct != 0 || cells[5].Count != 0 {
		t.Fatalf("untouched hour must be Pct 0, got %#v", cells[5])
	}
}

func TestBuildSensorHeatmapScalesAgainstTheGlobalNotPerRowMax(t *testing.T) {
	// A quiet sensor's own busiest hour must not read as visually "hot" just
	// because it's that sensor's own maximum -- the shade is relative to the
	// single busiest cell across every selected row.
	loud := &[24]int{}
	loud[0] = 100
	quiet := &[24]int{}
	quiet[0] = 5 // this sensor's own peak, but tiny next to the loud sensor's
	rows := buildSensorHeatmap(map[string]*[24]int{"hp-cowrie": loud, "hp-conpot": quiet}, time.Now())
	var quietRow *heatmapRow
	for i := range rows {
		if rows[i].Sensor == "hp-conpot" {
			quietRow = &rows[i]
		}
	}
	if quietRow == nil {
		t.Fatal("quiet sensor missing from rows")
	}
	if quietRow.Cells[0].Pct >= 50 {
		t.Fatalf("quiet sensor's peak cell should read as low intensity against the global max, got Pct=%d", quietRow.Cells[0].Pct)
	}
}

func TestBuildSensorHeatmapCapsAndOrdersBySensorTotal(t *testing.T) {
	input := map[string]*[24]int{}
	// 8 sensors, distinct totals, to prove the cap keeps only the busiest
	// sensorHeatmapRows and orders them descending.
	totals := map[string]int{
		"s1": 80, "s2": 70, "s3": 60, "s4": 50,
		"s5": 40, "s6": 30, "s7": 20, "s8": 10,
	}
	for name, total := range totals {
		hours := &[24]int{}
		hours[0] = total
		input[name] = hours
	}
	rows := buildSensorHeatmap(input, time.Now())
	if len(rows) != sensorHeatmapRows {
		t.Fatalf("expected %d rows (capped), got %d", sensorHeatmapRows, len(rows))
	}
	wantOrder := []string{"s1", "s2", "s3", "s4", "s5", "s6"}
	for i, want := range wantOrder {
		if rows[i].Sensor != want {
			t.Fatalf("row %d: sensor = %q, want %q (full order: %v)", i, rows[i].Sensor, want, rowNames(rows))
		}
	}
}

func rowNames(rows []heatmapRow) []string {
	names := make([]string, len(rows))
	for i, r := range rows {
		names[i] = r.Sensor
	}
	return names
}

func TestBuildSensorHeatmapBreaksTiesAlphabetically(t *testing.T) {
	tied := func(n int) *[24]int { h := &[24]int{}; h[0] = n; return h }
	rows := buildSensorHeatmap(map[string]*[24]int{
		"zeta":  tied(10),
		"alpha": tied(10),
		"mu":    tied(10),
	}, time.Now())
	got := rowNames(rows)
	want := []string{"alpha", "mu", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestBuildSensorHeatmapCellLabelsAreHourlyTimestamps(t *testing.T) {
	now := time.Date(2026, 8, 1, 14, 0, 0, 0, time.UTC)
	hours := &[24]int{}
	hours[23] = 5 // the most recent hour (now's own hour)
	rows := buildSensorHeatmap(map[string]*[24]int{"cowrie": hours}, now)
	last := rows[0].Cells[23]
	if last.Label != now.Format("15")+":00" {
		t.Fatalf("last cell label = %q, want %q", last.Label, now.Format("15")+":00")
	}
	if last.Count != 5 {
		t.Fatalf("last cell count = %d, want 5", last.Count)
	}
}

// TestSyntheticSensorEventsReachTheOverviewHeatmap exercises the full path
// (log fixture -> rebuild -> snapshot) the same way
// TestSyntheticSensorsReachDashboardSnapshot does for the sensor-health
// table, proving SensorHeatmap is actually wired into rebuild(), not just
// unit-testable in isolation.
func TestSyntheticSensorEventsReachTheOverviewHeatmap(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	fixtures := map[string]map[string]any{
		"cowrie/cowrie.json": {"timestamp": now, "eventid": "cowrie.login.failed", "src_ip": "8.8.8.8", "username": "root", "password": "test", "session": "synthetic-cowrie"},
		"conpot/events.json": {"timestamp": now, "data_type": "modbus", "src_ip": "1.1.1.1", "dst_port": 502.0, "request": "read coils"},
	}
	for name, event := range fixtures {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		line, _ := json.Marshal(event)
		if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := &store{dir: root}
	s.rebuild()
	seen := map[string]bool{}
	for _, row := range s.get().SensorHeatmap {
		seen[row.Sensor] = true
	}
	for _, sensor := range []string{"cowrie", "conpot"} {
		if !seen[sensor] {
			t.Fatalf("synthetic %s event did not reach SensorHeatmap: %+v", sensor, s.get().SensorHeatmap)
		}
	}
}
