package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLogSessionWritesRelayPortAndClientIP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	f := openSessionLog(path)
	if f == nil {
		t.Fatal("openSessionLog returned nil for a writable path")
	}
	defer f.Close()

	logSession(f, 42285, "203.0.113.9")
	logSession(f, 42286, "203.0.113.10")
	f.Sync()

	rf, err := os.Open(path)
	if err != nil {
		t.Fatalf("could not reopen log: %v", err)
	}
	defer rf.Close()

	var lines []map[string]any
	sc := bufio.NewScanner(rf)
	for sc.Scan() {
		var e map[string]any
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line not valid JSON: %v (%s)", err, sc.Text())
		}
		lines = append(lines, e)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 session lines, got %d", len(lines))
	}
	if lines[0]["relay_port"] != float64(42285) || lines[0]["client_ip"] != "203.0.113.9" {
		t.Fatalf("unexpected first line: %+v", lines[0])
	}
	if lines[0]["timestamp"] == nil || lines[0]["timestamp"] == "" {
		t.Fatalf("expected a non-empty timestamp, got %+v", lines[0]["timestamp"])
	}
}

func TestLogSessionNilFileIsNoop(t *testing.T) {
	// Must not panic when the session log couldn't be opened -- logging
	// attribution must never be why the relay itself breaks.
	logSession(nil, 1, "203.0.113.9")
}

func TestOpenSessionLogUnwritablePathReturnsNilNotFatal(t *testing.T) {
	f := openSessionLog(filepath.Join(t.TempDir(), "no-such-dir", "sessions.json"))
	if f != nil {
		f.Close()
		t.Fatal("expected nil for a path whose parent directory doesn't exist")
	}
}
