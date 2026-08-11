package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMirrorPayloadBytesWritesThenSkipsUnchangedOnRescan covers #762: the
// same "index once, skip on rescan" contract indexPayloadInventory already
// has, applied to raw bytes instead of metadata.
func TestMirrorPayloadBytesWritesThenSkipsUnchangedOnRescan(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	dir := t.TempDir()
	hash := strings.Repeat("a", 64)
	writeTestPayload(t, dir, hash, time.Now())

	s := &store{payloadDirs: []string{dir}, es: es}
	files := []capturedFile{{Hash: hash, Size: int64(len("payload-" + hash))}}

	s.mirrorPayloadBytes(files)
	data, tooLarge, found, _, err := s.fetchPayloadBytes(hash)
	if err != nil || !found {
		t.Fatalf("expected the payload to be mirrored: found=%v err=%v", found, err)
	}
	if tooLarge {
		t.Fatal("small payload incorrectly marked too large")
	}
	if string(data) != "payload-"+hash {
		t.Fatalf("mirrored bytes = %q, want %q", data, "payload-"+hash)
	}

	// A rescan with the same hash already present must not touch the file
	// again (no docGet-then-rewrite churn on every scan tick).
	hit, _, _ := es.docGet(payloadBytesIndex, hash)
	firstSeqNo := hit.SeqNo
	s.mirrorPayloadBytes(files)
	hit2, _, _ := es.docGet(payloadBytesIndex, hash)
	if hit2.SeqNo != firstSeqNo {
		t.Fatalf("already-mirrored payload was rewritten on rescan: seq_no %d -> %d", firstSeqNo, hit2.SeqNo)
	}
}

// TestMirrorPayloadBytesMarksOversizedAsTooLargeNotSilentlySkipped covers
// the size-cap path: a payload over payloadBytesRawCap gets an explicit
// TooLarge marker document, not silent omission indistinguishable from
// "never scanned."
func TestMirrorPayloadBytesMarksOversizedAsTooLargeNotSilentlySkipped(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	dir := t.TempDir()
	hash := strings.Repeat("b", 64)
	writeTestPayload(t, dir, hash, time.Now())

	s := &store{payloadDirs: []string{dir}, es: es}
	// capturedFile.Size drives the cap check, not the real (tiny) file on
	// disk -- exercises the marker path without writing a real 32MB fixture.
	files := []capturedFile{{Hash: hash, Size: payloadBytesRawCap + 1}}

	s.mirrorPayloadBytes(files)
	data, tooLarge, found, _, err := s.fetchPayloadBytes(hash)
	if err != nil || !found {
		t.Fatalf("expected a marker document to exist: found=%v err=%v", found, err)
	}
	if !tooLarge {
		t.Fatal("oversized payload should be marked TooLarge")
	}
	if data != nil {
		t.Fatal("a too-large marker document must not carry decoded data")
	}
}

// TestFetchPayloadBytesNotFoundVsUnavailable distinguishes "never mirrored"
// (found=false, err=nil) from "no ES client configured at all" (err set) --
// servePayload needs to tell these apart to return 404 vs 503.
func TestFetchPayloadBytesNotFoundVsUnavailable(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	s := &store{es: es}
	_, _, found, _, err := s.fetchPayloadBytes(strings.Repeat("c", 64))
	if err != nil || found {
		t.Fatalf("unmirrored hash: found=%v err=%v, want found=false err=nil", found, err)
	}

	sNoES := &store{}
	_, _, _, _, err = sNoES.fetchPayloadBytes(strings.Repeat("c", 64))
	if err != errPayloadStorageUnavailable {
		t.Fatalf("no ES client: err=%v, want errPayloadStorageUnavailable", err)
	}
}

// TestServePayloadReadsFromESNotDisk is the actual #762 regression guard:
// deletes the on-disk file after mirroring and confirms the download route
// still serves the content, proving it no longer touches the filesystem.
func TestServePayloadReadsFromESNotDisk(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	dir := t.TempDir()
	hash := strings.Repeat("d", 64)
	writeTestPayload(t, dir, hash, time.Now())

	s := &store{payloadDirs: []string{dir}, es: es}
	s.mirrorPayloadBytes([]capturedFile{{Hash: hash, Size: int64(len("payload-" + hash))}})

	if err := os.Remove(filepath.Join(dir, hash)); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/payload/"+hash, nil)
	w := httptest.NewRecorder()
	s.servePayload(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 (disk file was deleted -- serve must come from ES)", w.Code)
	}
	if body := w.Body.String(); body != "payload-"+hash {
		t.Fatalf("body = %q, want %q", body, "payload-"+hash)
	}
}

// TestServePayloadTooLargeReturns413 covers the operator-visible message
// for a payload that exceeded the mirror cap, instead of a bare 404 that
// looks identical to "doesn't exist."
func TestServePayloadTooLargeReturns413(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	dir := t.TempDir()
	hash := strings.Repeat("e", 64)
	writeTestPayload(t, dir, hash, time.Now())

	s := &store{payloadDirs: []string{dir}, es: es}
	s.mirrorPayloadBytes([]capturedFile{{Hash: hash, Size: payloadBytesRawCap + 1}})

	req := httptest.NewRequest("GET", "/payload/"+hash, nil)
	w := httptest.NewRecorder()
	s.servePayload(w, req)

	if w.Code != 413 {
		t.Fatalf("status = %d, want 413 (Request Entity Too Large)", w.Code)
	}
}
