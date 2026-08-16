package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTftpSessionLog(t *testing.T, logsDir string, lines ...string) {
	t.Helper()
	dir := filepath.Join(logsDir, "tftp-relay")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "sessions.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("write sessions.json: %v", err)
	}
}

func TestBuildTftpSessionMapResolvesByRelayPort(t *testing.T) {
	dir := t.TempDir()
	writeTftpSessionLog(t, dir,
		`{"relay_port":42285,"client_ip":"203.0.113.9","timestamp":"2026-08-05T21:05:27Z"}`,
		`{"relay_port":42286,"client_ip":"203.0.113.10","timestamp":"2026-08-05T21:06:00Z"}`,
	)

	m := buildTftpSessionMap(dir)
	if m[42285] != "203.0.113.9" {
		t.Fatalf("m[42285] = %q, want 203.0.113.9", m[42285])
	}
	if m[42286] != "203.0.113.10" {
		t.Fatalf("m[42286] = %q, want 203.0.113.10", m[42286])
	}
}

func TestBuildTftpSessionMapLaterEntryWinsOnPortReuse(t *testing.T) {
	dir := t.TempDir()
	writeTftpSessionLog(t, dir,
		`{"relay_port":42285,"client_ip":"203.0.113.9"}`,
		`{"relay_port":42285,"client_ip":"203.0.113.99"}`,
	)

	m := buildTftpSessionMap(dir)
	if m[42285] != "203.0.113.99" {
		t.Fatalf("m[42285] = %q, want the later entry 203.0.113.99", m[42285])
	}
}

func TestBuildTftpSessionMapIgnoresMalformedLines(t *testing.T) {
	dir := t.TempDir()
	writeTftpSessionLog(t, dir,
		`not json`,
		`{"relay_port":42285}`,
		`{"client_ip":"203.0.113.9"}`,
		`{"relay_port":42286,"client_ip":"203.0.113.10"}`,
	)

	m := buildTftpSessionMap(dir)
	if len(m) != 1 || m[42286] != "203.0.113.10" {
		t.Fatalf("expected only the one well-formed entry, got %+v", m)
	}
}

func TestBuildTftpSessionMapMissingFileYieldsEmptyMap(t *testing.T) {
	m := buildTftpSessionMap(t.TempDir())
	if len(m) != 0 {
		t.Fatalf("expected empty map when sessions.json doesn't exist, got %+v", m)
	}
}

func TestIsTftpRelayRecordRequiresDionaeaAndProtocol(t *testing.T) {
	tftpShape := map[string]any{"connection": map[string]any{"protocol": "TftpServerHandler"}}
	if !isTftpRelayRecord(tftpShape, "dionaea") {
		t.Fatal("expected true for dionaea + TftpServerHandler")
	}
	if isTftpRelayRecord(tftpShape, "conpot") {
		t.Fatal("expected false for a non-dionaea persona")
	}
	otherShape := map[string]any{"connection": map[string]any{"protocol": "SMBDServer"}}
	if isTftpRelayRecord(otherShape, "dionaea") {
		t.Fatal("expected false for a non-TFTP dionaea connection")
	}
	if isTftpRelayRecord(map[string]any{}, "dionaea") {
		t.Fatal("expected false when there's no connection object at all")
	}
}
