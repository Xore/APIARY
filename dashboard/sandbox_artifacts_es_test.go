package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sandboxArtifactStub answers docGet's GET .../_doc/<id> against
// sandbox-export-artifacts-v1's chunk documents -- the only request this
// package makes against that index (unlike ghidra-report-artifacts-v1,
// nothing here ever needs the cheap docListIDs existence sweep:
// attachSandboxDownloads only ever checks the one job being viewed, not
// every row in a list -- see sandbox.go's own call site).
func sandboxArtifactStub(t *testing.T, docs map[string]sandboxArtifactChunkDoc) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/_doc/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/_doc/")+len("/_doc/"):]
		doc, ok := docs[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"_id": id, "_source": doc})
	}
}

func chunkDocs(job, kind, contentType, filename string, data []byte, chunkBytes int) map[string]sandboxArtifactChunkDoc {
	docs := map[string]sandboxArtifactChunkDoc{}
	total := (len(data) + chunkBytes - 1) / chunkBytes
	if total == 0 {
		total = 1
	}
	for i := 0; i < total; i++ {
		start := i * chunkBytes
		end := start + chunkBytes
		if end > len(data) {
			end = len(data)
		}
		docs[sandboxArtifactChunkID(job, kind, i)] = sandboxArtifactChunkDoc{
			Job: job, Kind: kind, Filename: filename, ContentType: contentType,
			ChunkIndex: i, TotalChunks: total, SizeBytes: int64(len(data)),
			DataBase64: base64.StdEncoding.EncodeToString(data[start:end]),
		}
	}
	return docs
}

func TestSandboxArtifactManifestReadsChunkZero(t *testing.T) {
	pcap := bytes.Repeat([]byte{0xAB}, 100)
	srv := httptest.NewServer(sandboxArtifactStub(t, chunkDocs("job1", "guest_pcap", "application/vnd.tcpdump.pcap", "job1.guest.pcap", pcap, 40)))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	manifest, ok := sandboxArtifactManifest(esResultsClient, "job1", "guest_pcap")
	if !ok {
		t.Fatal("expected a manifest")
	}
	if manifest.TotalChunks != 3 || manifest.SizeBytes != 100 || manifest.Filename != "job1.guest.pcap" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
}

func TestSandboxArtifactManifestFalseWhenMissing(t *testing.T) {
	srv := httptest.NewServer(sandboxArtifactStub(t, map[string]sandboxArtifactChunkDoc{}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	if _, ok := sandboxArtifactManifest(esResultsClient, "no-such-job", "guest_pcap"); ok {
		t.Fatal("expected no manifest for a job with no stored artifact")
	}
}

func TestSandboxArtifactManifestFalseWhenESNil(t *testing.T) {
	if _, ok := sandboxArtifactManifest(nil, "job1", "guest_pcap"); ok {
		t.Fatal("expected no manifest when es is nil")
	}
}

// The actual #764 payoff: reassembling a multi-chunk artifact must
// reproduce the original bytes exactly, chunk boundaries included.
func TestServeSandboxArtifactReassemblesChunksExactly(t *testing.T) {
	original := bytes.Repeat([]byte("chunked-pcap-content-"), 5000) // well over one chunk at the small chunk size below
	docs := chunkDocs("job2", "diagnostics", "application/zip", "job2.diagnostics.zip", original, 4096)
	if len(docs) < 3 {
		t.Fatalf("test fixture should span several chunks, got %d", len(docs))
	}
	srv := httptest.NewServer(sandboxArtifactStub(t, docs))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	w := httptest.NewRecorder()
	if err := serveSandboxArtifact(w, esResultsClient, "job2", "diagnostics"); err != nil {
		t.Fatalf("serveSandboxArtifact: %v", err)
	}
	if !bytes.Equal(w.Body.Bytes(), original) {
		t.Fatalf("reassembled artifact does not match the original: got %d bytes, want %d", w.Body.Len(), len(original))
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Content-Type = %q", ct)
	}
	if !strings.Contains(w.Header().Get("Content-Disposition"), "job2.diagnostics.zip") {
		t.Errorf("Content-Disposition missing filename: %q", w.Header().Get("Content-Disposition"))
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options: nosniff")
	}
}

func TestServeSandboxArtifactSingleChunkStillWorks(t *testing.T) {
	small := []byte("tiny pcap")
	docs := chunkDocs("job3", "host_pcap", "application/vnd.tcpdump.pcap", "job3.host.pcap", small, 4096)
	srv := httptest.NewServer(sandboxArtifactStub(t, docs))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	w := httptest.NewRecorder()
	if err := serveSandboxArtifact(w, esResultsClient, "job3", "host_pcap"); err != nil {
		t.Fatalf("serveSandboxArtifact: %v", err)
	}
	if !bytes.Equal(w.Body.Bytes(), small) {
		t.Fatalf("got %q, want %q", w.Body.Bytes(), small)
	}
}

func TestServeSandboxArtifactErrorsWithoutWritingWhenArtifactMissing(t *testing.T) {
	srv := httptest.NewServer(sandboxArtifactStub(t, map[string]sandboxArtifactChunkDoc{}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	w := httptest.NewRecorder()
	err := serveSandboxArtifact(w, esResultsClient, "no-such-job", "host_pcap")
	if err == nil {
		t.Fatal("expected an error for a missing artifact")
	}
	if w.Body.Len() != 0 || w.Header().Get("Content-Type") != "" {
		t.Fatalf("must not write anything before the manifest is confirmed to exist: body=%q header=%q",
			w.Body.String(), w.Header().Get("Content-Type"))
	}
}

// A chunk missing after the manifest was found (index >0 absent) must not
// panic or silently produce a truncated-but-"successful" response --
// serveSandboxExport's own caller distinguishes this from the
// nothing-written case by error identity, not by inspecting w.
func TestServeSandboxArtifactErrorsOnMissingLaterChunk(t *testing.T) {
	docs := chunkDocs("job4", "guest_pcap", "application/vnd.tcpdump.pcap", "job4.guest.pcap", bytes.Repeat([]byte{1}, 9000), 4096)
	delete(docs, sandboxArtifactChunkID("job4", "guest_pcap", 1))
	srv := httptest.NewServer(sandboxArtifactStub(t, docs))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	w := httptest.NewRecorder()
	err := serveSandboxArtifact(w, esResultsClient, "job4", "guest_pcap")
	if err == nil {
		t.Fatal("expected an error when a later chunk is missing")
	}
	// Chunk 0 (4096 bytes) was already written before the failure on chunk 1.
	if w.Body.Len() != 4096 {
		t.Fatalf("expected exactly chunk 0's bytes written before the failure, got %d", w.Body.Len())
	}
}
