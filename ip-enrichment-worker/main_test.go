package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverSourcesFindsEveryConpotPersonaByGlob(t *testing.T) {
	logsDir := t.TempDir()
	for _, dir := range []string{"cowrie", "dionaea", "dns-honeypot", "cisco-asa-honeypot", "conpot", "conpot-s7-1200", "conpot-kamstrup"} {
		full := filepath.Join(logsDir, dir)
		if err := os.MkdirAll(full, 0o750); err != nil {
			t.Fatal(err)
		}
		name := "conpot.json"
		switch dir {
		case "cowrie", "dionaea", "dns-honeypot", "cisco-asa-honeypot":
			name = dir + ".json"
		}
		if err := os.WriteFile(filepath.Join(full, name), nil, 0o640); err != nil {
			t.Fatal(err)
		}
	}

	sources := discoverSources(logsDir, t.TempDir(), t.TempDir())
	byName := map[string]*source{}
	for _, s := range sources {
		byName[s.name] = s
	}

	for _, want := range []string{"cowrie", "dionaea", "dionaea-incident", "dns-honeypot", "cisco-asa-honeypot", "conpot", "conpot-s7-1200", "conpot-kamstrup"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("expected a source named %q, got %+v", want, byName)
		}
	}
	if len(sources) != 8 {
		t.Fatalf("got %d sources, want 8 (no duplicates/collisions across conpot personas)", len(sources))
	}
	if byName["conpot-s7-1200"].input != filepath.Join(logsDir, "conpot-s7-1200", "conpot.json") {
		t.Fatalf("conpot-s7-1200 input path = %q", byName["conpot-s7-1200"].input)
	}
}
