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

// #1206: viaMapBuilder must see everything buildViaMap's one-shot full read
// would see, without re-parsing bytes it's already accounted for.

func TestViaMapBuilderSeedsFromBothGenerationsLikeBuildViaMap(t *testing.T) {
	dir := t.TempDir()
	writePortbridgeLog(t, dir, "portbridge.json.1",
		`{"sensor":"portbridge","src_ip":"198.51.100.1","via_port":9000}`+"\n")
	writePortbridgeLog(t, dir, "portbridge.json",
		`{"sensor":"portbridge","src_ip":"203.0.113.9","via_port":45282}`+"\n")

	b := newViaMapBuilder(dir)
	m := b.refresh()
	if m[9000] != "198.51.100.1" {
		t.Fatalf("via_port 9000 (from .1) = %q, want 198.51.100.1", m[9000])
	}
	if m[45282] != "203.0.113.9" {
		t.Fatalf("via_port 45282 (from live) = %q, want 203.0.113.9", m[45282])
	}
}

func TestViaMapBuilderPicksUpAppendedLinesOnNextRefresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "portbridge.json")
	writePortbridgeLog(t, dir, "portbridge.json",
		`{"sensor":"portbridge","src_ip":"203.0.113.9","via_port":1}`+"\n")

	b := newViaMapBuilder(dir)
	m := b.refresh()
	if m[1] != "203.0.113.9" {
		t.Fatalf("via_port 1 = %q, want 203.0.113.9", m[1])
	}
	if _, ok := m[2]; ok {
		t.Fatalf("via_port 2 should not exist yet, got %+v", m)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"sensor":"portbridge","src_ip":"198.51.100.2","via_port":2}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	m = b.refresh()
	if m[1] != "203.0.113.9" {
		t.Fatalf("via_port 1 should still be present after refresh, got %q", m[1])
	}
	if m[2] != "198.51.100.2" {
		t.Fatalf("via_port 2 (appended) = %q, want 198.51.100.2", m[2])
	}
}

func TestViaMapBuilderRetainsEntriesAcrossRotation(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "portbridge.json")
	gen := filepath.Join(dir, "portbridge.json.1")
	writePortbridgeLog(t, dir, "portbridge.json",
		`{"sensor":"portbridge","src_ip":"203.0.113.9","via_port":1}`+"\n"+
			`{"sensor":"portbridge","src_ip":"198.51.100.2","via_port":2}`+"\n")

	b := newViaMapBuilder(dir)
	m := b.refresh()
	if m[1] != "203.0.113.9" || m[2] != "198.51.100.2" {
		t.Fatalf("unexpected seed state: %+v", m)
	}

	// Simulate portbridge-log-rotate: old live file becomes the new .1
	// generation, a fresh (empty) live file takes its place.
	if err := os.Rename(live, gen); err != nil {
		t.Fatal(err)
	}
	writePortbridgeLog(t, dir, "portbridge.json",
		`{"sensor":"portbridge","src_ip":"203.0.113.10","via_port":3}`+"\n")

	m = b.refresh()
	if m[1] != "203.0.113.9" {
		t.Fatalf("via_port 1 from pre-rotation should survive, got %q", m[1])
	}
	if m[2] != "198.51.100.2" {
		t.Fatalf("via_port 2 from pre-rotation should survive, got %q", m[2])
	}
	if m[3] != "203.0.113.10" {
		t.Fatalf("via_port 3 from the new live file = %q, want 203.0.113.10", m[3])
	}
}

func TestViaMapBuilderRefreshReturnsIndependentSnapshots(t *testing.T) {
	dir := t.TempDir()
	writePortbridgeLog(t, dir, "portbridge.json",
		`{"sensor":"portbridge","src_ip":"203.0.113.9","via_port":1}`+"\n")

	b := newViaMapBuilder(dir)
	first := b.refresh()
	first[999] = "mutated-by-caller"

	second := b.refresh()
	if _, ok := second[999]; ok {
		t.Fatalf("mutating a returned snapshot must not affect a later refresh: %+v", second)
	}
}
