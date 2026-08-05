package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteMetricsSnapshotIsReadableJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	snap := metricsSnapshot{Attempted: 5, Sent: 2, DryRun: 3, UpdatedAt: time.Now().UTC()}
	if err := writeMetricsSnapshot(path, snap); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got metricsSnapshot
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("written file is not valid JSON: %v", err)
	}
	if got.Attempted != 5 || got.Sent != 2 || got.DryRun != 3 {
		t.Fatalf("snapshot mismatch: %+v", got)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file should have been renamed away, not left behind")
	}
}
