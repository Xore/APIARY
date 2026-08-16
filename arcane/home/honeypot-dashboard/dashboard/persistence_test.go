package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIntelligenceArchiveES is a minimal stateful Elasticsearch double: it
// only understands the two calls persistence.go actually makes (PUT
// .../_doc/{id}?op_type=create, GET .../_search) -- enough to prove a real
// docIndex/docSearchAll round trip without needing a real cluster.
type fakeIntelligenceArchiveES struct {
	mu   sync.Mutex
	docs map[string]json.RawMessage
}

func newFakeIntelligenceArchiveES(t *testing.T) *httptest.Server {
	t.Helper()
	f := &fakeIntelligenceArchiveES{docs: map[string]json.RawMessage{}}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/_doc/"):
			id, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path[strings.LastIndex(r.URL.Path, "/_doc/"):], "/_doc/"))
			body, _ := io.ReadAll(r.Body)
			f.docs[id] = json.RawMessage(body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"_id": id, "result": "created"})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/_search"):
			hits := make([]map[string]any, 0, len(f.docs))
			for id, src := range f.docs {
				hits = append(hits, map[string]any{"_id": id, "_source": src})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestIntelligenceStoreSaveWritesToESArchive(t *testing.T) {
	es := newFakeIntelligenceArchiveES(t)
	defer es.Close()

	dir := t.TempDir()
	store := &intelligenceStore{path: filepath.Join(dir, "intelligence.json"), es: newESClient(es.URL, "")}

	snap := intelligenceSnapshot{
		Version:   1,
		Generated: time.Now().UTC(),
		Campaigns: []campaignRow{{CIDR: "203.0.113.0/24", Score: 80}},
	}
	store.save(snap)

	// The local file is still written (operator-inspectable, never served
	// over HTTP -- out of #638's scope) alongside the ES archive write.
	if _, err := os.Stat(store.path); err != nil {
		t.Fatalf("expected local snapshot file to still be written: %v", err)
	}

	rec := httptest.NewRecorder()
	store.serveArchive(rec, httptest.NewRequest(http.MethodGet, "/api/intelligence/archive", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("serveArchive status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "203.0.113.0/24") {
		t.Fatalf("archive response missing the saved snapshot: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("Content-Type = %q, want application/x-ndjson", ct)
	}
}

func TestIntelligenceStoreSaveThrottlesWithin5Minutes(t *testing.T) {
	es := newFakeIntelligenceArchiveES(t)
	defer es.Close()

	dir := t.TempDir()
	store := &intelligenceStore{path: filepath.Join(dir, "intelligence.json"), es: newESClient(es.URL, "")}

	store.save(intelligenceSnapshot{Version: 1, Campaigns: []campaignRow{{CIDR: "198.51.100.0/24"}}})
	store.save(intelligenceSnapshot{Version: 1, Campaigns: []campaignRow{{CIDR: "192.0.2.0/24"}}})

	rec := httptest.NewRecorder()
	store.serveArchive(rec, httptest.NewRequest(http.MethodGet, "/api/intelligence/archive", nil))
	body := rec.Body.String()
	if strings.Contains(body, "192.0.2.0/24") {
		t.Fatal("second save() within the 5-minute window must not have written a second archive entry")
	}
	if !strings.Contains(body, "198.51.100.0/24") {
		t.Fatalf("expected the first snapshot to still be archived: %s", body)
	}
}

func TestIntelligenceStoreServeArchiveUnavailableWithoutES(t *testing.T) {
	dir := t.TempDir()
	store := &intelligenceStore{path: filepath.Join(dir, "intelligence.json")} // es stays nil

	rec := httptest.NewRecorder()
	store.serveArchive(rec, httptest.NewRequest(http.MethodGet, "/api/intelligence/archive", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestIntelligenceStoreServeArchiveNilStoreDoesNotPanic(t *testing.T) {
	var store *intelligenceStore
	rec := httptest.NewRecorder()
	store.serveArchive(rec, httptest.NewRequest(http.MethodGet, "/api/intelligence/archive", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestIntelligenceStoreSaveNilStoreDoesNotPanic(t *testing.T) {
	var store *intelligenceStore
	store.save(intelligenceSnapshot{Version: 1}) // must not panic
}
