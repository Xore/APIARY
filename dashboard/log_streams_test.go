package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeLogStreamFixture(t *testing.T, path string, size int, modTime time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatal(err)
	}
}

func TestScanLogStreamsIncludesOnlyActiveRotatingJSON(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	writeLogStreamFixture(t, filepath.Join(root, "enriched", "cowrie.json"), 10, now)
	writeLogStreamFixture(t, filepath.Join(root, "enriched", "cowrie.json.20260816-000000"), 10, now)
	writeLogStreamFixture(t, filepath.Join(root, "enriched", "notes.log"), 10, now)
	writeLogStreamFixture(t, filepath.Join(root, "enriched", "nested", "ignored.json"), 10, now)
	writeLogStreamFixture(t, filepath.Join(root, "dionaea", "dionaea.json"), 10, now)
	writeLogStreamFixture(t, filepath.Join(root, "dionaea", "dionaea_incident.json"), 10, now)
	writeLogStreamFixture(t, filepath.Join(root, "dionaea", "other.json"), 10, now)

	streams := scanLogStreams(root)
	var names []string
	for _, stream := range streams {
		names = append(names, stream.Name)
	}
	want := []string{"dionaea/dionaea.json", "dionaea/dionaea_incident.json", "enriched/cowrie.json"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("streams = %v, want %v", names, want)
	}
}

func TestLogStreamAlertsBeforeRotationLimit(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	streams := []logStreamStat{
		{Name: "enriched/below.json", Size: 89, ModTime: now.Add(-time.Minute)},
		{Name: "enriched/warn.json", Size: 90, ModTime: now.Add(-2 * time.Minute)},
		{Name: "dionaea/dionaea_incident.json", Size: 101, ModTime: now.Add(-3 * time.Minute)},
	}
	alerts := logStreamAlerts(streams, 100, 90, now)
	if len(alerts) != 2 {
		t.Fatalf("got %d alerts, want 2: %+v", len(alerts), alerts)
	}
	if alerts[0].Key != "log-stream-size:enriched/warn.json" || !strings.Contains(alerts[0].Message, "age=2m0s") {
		t.Fatalf("first alert = %+v", alerts[0])
	}
	if got := logStreamAlerts(streams, 0, 90, now); len(got) != 0 {
		t.Fatalf("max=0 must disable alerts, got %+v", got)
	}
}

func TestWriteLogStreamMetricsExposesSizeAgeAndLimit(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	writeLogStreamFixture(t, filepath.Join(root, "enriched", "cowrie.json"), 42, now.Add(-75*time.Second))
	s := &store{dir: root, logStreamMaxBytes: 100}
	w := httptest.NewRecorder()
	s.writeLogStreamMetrics(w, now)
	body := w.Body.String()
	for _, want := range []string{
		"honeypot_log_stream_limit_bytes 100",
		"honeypot_log_stream_size_bytes{stream=\"enriched/cowrie.json\"} 42",
		"honeypot_log_stream_age_seconds{stream=\"enriched/cowrie.json\"} 75",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q:\n%s", want, body)
		}
	}
}

func TestLogStreamConfigValidation(t *testing.T) {
	if got := configuredLogStreamMaxBytes("0"); got != 0 {
		t.Fatalf("max 0 = %d, want 0", got)
	}
	if got := configuredLogStreamMaxBytes("bad"); got != defaultLogStreamMaxBytes {
		t.Fatalf("invalid max = %d", got)
	}
	if got := configuredLogStreamAlertPercent("100"); got != defaultLogStreamAlertPercent {
		t.Fatalf("invalid percent = %d", got)
	}
}
