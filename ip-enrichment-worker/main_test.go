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

	for _, want := range []string{
		"cowrie", "dionaea", "dionaea-incident", "dns-honeypot", "cisco-asa-honeypot",
		"conpot", "conpot-s7-1200", "conpot-kamstrup",
		"multipot", "tanner", "http-honeypot", "citrix-honeypot", "rdp-honeypot", // #1217
	} {
		if _, ok := byName[want]; !ok {
			t.Errorf("expected a source named %q, got %+v", want, byName)
		}
	}
	if len(sources) != 13 {
		t.Fatalf("got %d sources, want 13 (no duplicates/collisions across conpot personas)", len(sources))
	}
	if byName["conpot-s7-1200"].input != filepath.Join(logsDir, "conpot-s7-1200", "conpot.json") {
		t.Fatalf("conpot-s7-1200 input path = %q", byName["conpot-s7-1200"].input)
	}
	// #1217: locks in each sensor's real on-disk filename -- confirmed live
	// against the homeserver (2026-08-12), several of which don't match
	// the source name (http-honeypot's own log file is "http.json", not
	// "http-honeypot.json"; tanner's is "tanner_report.json").
	wantInputs := map[string]string{
		"multipot":        filepath.Join(logsDir, "multipot", "multipot.json"),
		"tanner":          filepath.Join(logsDir, "tanner", "tanner_report.json"),
		"http-honeypot":   filepath.Join(logsDir, "http-honeypot", "http.json"),
		"citrix-honeypot": filepath.Join(logsDir, "citrix-honeypot", "citrix-honeypot.json"),
		"rdp-honeypot":    filepath.Join(logsDir, "rdp-honeypot", "rdp-honeypot.json"),
	}
	for name, want := range wantInputs {
		if got := byName[name].input; got != want {
			t.Fatalf("%s input path = %q, want %q", name, got, want)
		}
		if got := byName[name].enrich; got == nil {
			t.Fatalf("%s has no enrich func wired", name)
		}
	}
}
