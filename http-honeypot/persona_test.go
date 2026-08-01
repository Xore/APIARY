package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #120: http.json/api.json (this binary serves both, see docker-compose.yml)
// have no external rotation -- analysis/log-maintenance.sh intentionally
// exempts JSON event streams so Filebeat's inode/offset tracking survives,
// per #79 -- so the logger bounds its own size the way Suricata's
// rotate-interval bounds eve.json: close, rename aside, reopen fresh at the
// same path. This asserts the rename actually happens, the original path
// keeps receiving new lines afterward, and no line is lost across the
// rotation.
func TestLoggerRotatesAtMaxBytesWithoutLosingLines(t *testing.T) {
	t.Setenv("LOG_MAX_BYTES", "1")
	dir := t.TempDir()
	logPath := filepath.Join(dir, "http.json")
	log := newLogger(logPath)
	t.Cleanup(func() { log.f.Close() })

	log.log(event{Method: "GET", Path: "/"})
	log.log(event{Method: "GET", Path: "/"})

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var rotated, current int
	for _, f := range files {
		switch {
		case f.Name() == "http.json":
			current++
		case strings.HasPrefix(f.Name(), "http.json."):
			rotated++
		}
	}
	if rotated != 1 {
		t.Fatalf("want exactly 1 rotated file after 2 writes with LOG_MAX_BYTES=1, got %d (files: %v)", rotated, files)
	}
	if current != 1 {
		t.Fatalf("want the original path still present and receiving writes, got %d", current)
	}

	total := 0
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var rec event
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("corrupt line across rotation: %v (%q)", err, line)
			}
			total++
		}
	}
	if total != 2 {
		t.Fatalf("want both log lines to survive across the rotation, got %d", total)
	}
}

func TestAPIPlatformPersona(t *testing.T) {
	var output bytes.Buffer
	s := &server{log: &logger{out: &output}, sensor: "api-honeypot", serverHdr: "nginx", persona: "nexusai-platform", site: "nexusai-eu-cloud", asset: "platform-gw-03", org: "NexusAI Research GmbH"}
	r := httptest.NewRequest(http.MethodGet, "http://api.example/version", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"gitVersion":"v1.29.6-gke.1326000"`) {
		t.Fatalf("unexpected API response: %d %s", w.Code, w.Body.String())
	}
	var got event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Persona != "nexusai-platform" || got.Site != "nexusai-eu-cloud" || got.Asset != "platform-gw-03" {
		t.Fatalf("unexpected persona metadata: %+v", got)
	}
}
