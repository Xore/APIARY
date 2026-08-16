package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #120: multipot.json has no external rotation (analysis/log-maintenance.sh
// intentionally exempts JSON event streams so Filebeat's inode/offset
// tracking survives, per #79), so the logger bounds its own size the same
// way Suricata's rotate-interval bounds eve.json: close, rename aside,
// reopen fresh at the same path. This asserts the rename actually happens,
// the original path keeps receiving new lines afterward, and no line is
// lost across the rotation.
func TestLoggerRotatesAtMaxBytesWithoutLosingLines(t *testing.T) {
	t.Setenv("LOG_MAX_BYTES", "1")
	dir := t.TempDir()
	logPath := filepath.Join(dir, "multipot.json")
	log := newLogger(logPath)
	t.Cleanup(func() { log.f.Close() })

	log.emit(event{Proto: "redis", Event: "connect"})
	log.emit(event{Proto: "redis", Event: "connect"})

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var rotated, current int
	for _, f := range files {
		switch {
		case f.Name() == "multipot.json":
			current++
		case strings.HasPrefix(f.Name(), "multipot.json."):
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

func TestPersonaMetadataAndProtocolAssets(t *testing.T) {
	var output bytes.Buffer
	log := &sessionLogger{logger: &logger{out: &output}}
	log.emit(event{Proto: "redis", Event: "connect"})
	var got event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Persona != "nexusai-core" || got.Site != "nexusai-berlin-core" || got.Asset != "cache01" {
		t.Fatalf("unexpected persona metadata: %+v", got)
	}
}

func TestDockerPersonaResponse(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handleDocker(server, &sessionLogger{logger: &logger{out: &output}}, 2375)
	}()
	if _, err := io.WriteString(client, "GET /version HTTP/1.1\r\nHost: build01\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if !strings.Contains(string(response), `"Name":"build01"`) || !strings.Contains(string(response), `"Version":"25.0.5"`) {
		t.Fatalf("unexpected Docker response: %s", response)
	}
	if !strings.Contains(output.String(), `"asset_id":"build01"`) {
		t.Fatalf("Docker event missing persona asset: %s", output.String())
	}
}
