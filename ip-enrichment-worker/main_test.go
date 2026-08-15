package main

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// passthroughEnrich always "resolves" a line unchanged -- enough to drive
// processSourceTick's read/write/offset bookkeeping without depending on
// enrichLine's own join logic.
func passthroughEnrich(line []byte, vm, tftpVM viaMap, persona string) ([]byte, bool) {
	return line, true
}

func newTestSource(t *testing.T, input string) (*source, *atomic.Pointer[viaMap], *atomic.Pointer[viaMap]) {
	t.Helper()
	s := &source{
		name:      "test",
		input:     input,
		output:    filepath.Join(t.TempDir(), "test.json"),
		statePath: filepath.Join(t.TempDir(), "test.offset"),
		enrich:    passthroughEnrich,
	}
	var vm, tftpVM atomic.Pointer[viaMap]
	empty := viaMap{}
	vm.Store(&empty)
	tftpVM.Store(&empty)
	return s, &vm, &tftpVM
}

// TestProcessSourceTickDoesNotAdvanceOffsetOnWriteFailure covers #1351: a
// failed write to the output file must not advance/persist the input
// offset, or the lines that failed to write are never read again.
func TestProcessSourceTickDoesNotAdvanceOffsetOnWriteFailure(t *testing.T) {
	input := filepath.Join(t.TempDir(), "in.json")
	if err := os.WriteFile(input, []byte(`{"a":1}`+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	s, vm, tftpVM := newTestSource(t, input)

	out, err := newOutputWriter(s.output, 0)
	if err != nil {
		t.Fatal(err)
	}
	out.f.Close() // closed on purpose: any Write on it now fails

	marker := []byte(`"src_ip":"` + tunnelPeerIP + `"`)
	got := processSourceTick(s, vm, tftpVM, time.Second, out, marker, 0, time.Now())
	if got != 0 {
		t.Fatalf("offset = %d, want 0 (unchanged) after a write failure", got)
	}
	if _, ok := loadOffset(s.statePath); ok {
		t.Fatal("offset must not be persisted when the write failed")
	}
}

// TestProcessSourceTickDoesNotAdvanceOffsetOnSaveFailure covers #1351's
// second finding: if saveOffset fails, the in-memory offset returned to the
// caller must stay at the old value too, or the next tick reads from disk
// (loadOffset) and diverges from what was actually persisted -- previously
// this caused the same lines to be re-read, re-enriched and re-appended
// forever.
func TestProcessSourceTickDoesNotAdvanceOffsetOnSaveFailure(t *testing.T) {
	input := filepath.Join(t.TempDir(), "in.json")
	if err := os.WriteFile(input, []byte(`{"a":1}`+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	s, vm, tftpVM := newTestSource(t, input)
	// statePath's parent directory doesn't exist, so saveOffset fails
	// while the write to `out` still succeeds.
	s.statePath = filepath.Join(t.TempDir(), "does-not-exist", "test.offset")

	out, err := newOutputWriter(s.output, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	marker := []byte(`"src_ip":"` + tunnelPeerIP + `"`)
	got := processSourceTick(s, vm, tftpVM, time.Second, out, marker, 0, time.Now())
	if got != 0 {
		t.Fatalf("offset = %d, want 0 (unchanged) after a saveOffset failure", got)
	}
}

// TestProcessSourceTickAdvancesOffsetOnSuccess is the control case: a clean
// write and a clean save must advance the returned offset to newOffset and
// persist it, so the two failure-path tests above are actually exercising
// the failure branch and not just a no-op path.
func TestProcessSourceTickAdvancesOffsetOnSuccess(t *testing.T) {
	input := filepath.Join(t.TempDir(), "in.json")
	line := `{"a":1}` + "\n"
	if err := os.WriteFile(input, []byte(line), 0o640); err != nil {
		t.Fatal(err)
	}
	s, vm, tftpVM := newTestSource(t, input)

	out, err := newOutputWriter(s.output, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	marker := []byte(`"src_ip":"` + tunnelPeerIP + `"`)
	got := processSourceTick(s, vm, tftpVM, time.Second, out, marker, 0, time.Now())
	if got != int64(len(line)) {
		t.Fatalf("offset = %d, want %d", got, len(line))
	}
	persisted, ok := loadOffset(s.statePath)
	if !ok || persisted != got {
		t.Fatalf("loadOffset = (%d, %v), want (%d, true)", persisted, ok, got)
	}
}

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
		"beelzebub",  // #1418
		"hellpot",    // #1419
		"elasticpot", // #1423
		"galah",      // #1420
		"sentrypeer", // #1424
		"wordpot",    // #1421
		"mailoney",   // #1422
	} {
		if _, ok := byName[want]; !ok {
			t.Errorf("expected a source named %q, got %+v", want, byName)
		}
	}
	if len(sources) != 20 {
		t.Fatalf("got %d sources, want 20 (no duplicates/collisions across conpot personas)", len(sources))
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
