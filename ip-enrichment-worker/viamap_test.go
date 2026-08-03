package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writePortbridgeLog(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestBuildViaMapResolvesByViaPort(t *testing.T) {
	dir := t.TempDir()
	writePortbridgeLog(t, dir, "portbridge.json",
		`{"sensor":"portbridge","src_ip":"203.0.113.9","via_port":45282}`+"\n")

	m := buildViaMap(dir)
	if m[45282] != "203.0.113.9" {
		t.Fatalf("via_port 45282 = %q, want 203.0.113.9", m[45282])
	}
}

func TestBuildViaMapReadsPreviousGenerationBeforeLive(t *testing.T) {
	dir := t.TempDir()
	// Same via_port in both generations -- live (read second) must win.
	writePortbridgeLog(t, dir, "portbridge.json.1",
		`{"sensor":"portbridge","src_ip":"198.51.100.1","via_port":9000}`+"\n")
	writePortbridgeLog(t, dir, "portbridge.json",
		`{"sensor":"portbridge","src_ip":"203.0.113.9","via_port":9000}`+"\n")

	m := buildViaMap(dir)
	if m[9000] != "203.0.113.9" {
		t.Fatalf("newest-generation entry should win, got %q", m[9000])
	}
}

func TestBuildViaMapIgnoresNonPortbridgeAndMalformedLines(t *testing.T) {
	dir := t.TempDir()
	writePortbridgeLog(t, dir, "portbridge.json",
		`{"sensor":"cowrie","src_ip":"203.0.113.9","via_port":1}`+"\n"+
			`not json`+"\n"+
			`{"sensor":"portbridge","via_port":2}`+"\n"+ // no src_ip
			`{"sensor":"portbridge","src_ip":"203.0.113.10"}`+"\n") // no via_port

	m := buildViaMap(dir)
	if len(m) != 0 {
		t.Fatalf("expected no entries from non-portbridge/malformed/incomplete lines, got %+v", m)
	}
}

func TestBuildViaMapMissingFilesYieldsEmptyMap(t *testing.T) {
	m := buildViaMap(filepath.Join(t.TempDir(), "does-not-exist"))
	if len(m) != 0 {
		t.Fatalf("expected empty map for a missing directory, got %+v", m)
	}
}
