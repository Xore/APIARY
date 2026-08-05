package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestTTYStore(t *testing.T) (*store, *template.Template) {
	t.Helper()
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	t.Cleanup(srv.Close)
	es := newESClient(srv.URL, "")
	s := &store{es: es}
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))
	return s, tmpl
}

func seedTTYLog(t *testing.T, s *store, shasum string, raw []byte) {
	t.Helper()
	doc, err := json.Marshal(ttyLogDoc{Shasum: shasum, SizeBytes: int64(len(raw)), TTYLogBase64: base64.StdEncoding.EncodeToString(raw)})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.es.docIndex(cowrieTTYLogIndex, shasum, doc, true, 0, 0); err != nil {
		t.Fatalf("seed ttylog doc: %v", err)
	}
}

// buildSimpleTTYLog is a smaller helper than tty_replay_test.go's
// buildTTYLog, for tests that only need one OUTPUT record.
func buildSimpleTTYLog(text string) []byte {
	header := func(op, length, direction int32) []byte {
		h := make([]byte, ttyRecordHeaderSize)
		binary.LittleEndian.PutUint32(h[0:], uint32(op))
		binary.LittleEndian.PutUint32(h[8:], uint32(length))
		binary.LittleEndian.PutUint32(h[12:], uint32(direction))
		return h
	}
	var raw []byte
	raw = append(raw, header(ttyOpOpen, 0, 0)...)
	raw = append(raw, header(ttyOpWrite, int32(len(text)), ttyDirOutput)...)
	raw = append(raw, []byte(text)...)
	raw = append(raw, header(ttyOpClose, 0, 0)...)
	return raw
}

func TestServeTTYReplayViewerPageRendersWithoutESLookup(t *testing.T) {
	s, tmpl := newTestTTYStore(t)
	req := httptest.NewRequest(http.MethodGet, "/tty/"+strings.Repeat("a", 64), nil)
	w := httptest.NewRecorder()
	s.serveTTYReplay(w, req, tmpl)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for the viewer shell (it fetches ES client-side), got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), strings.Repeat("a", 64)) {
		t.Errorf("expected shasum in rendered page")
	}
}

func TestServeTTYReplayRejectsBadShasum(t *testing.T) {
	s, tmpl := newTestTTYStore(t)
	for _, path := range []string{"/tty/not-a-hash", "/tty/../../etc/passwd", "/tty/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		s.serveTTYReplay(w, req, tmpl)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: expected 404, got %d", path, w.Code)
		}
	}
}

func TestServeTTYReplayRawAndCastNotFoundWhenNotImported(t *testing.T) {
	s, tmpl := newTestTTYStore(t)
	shasum := strings.Repeat("b", 64)
	for _, suffix := range []string{".raw", ".cast", ".json"} {
		req := httptest.NewRequest(http.MethodGet, "/tty/"+shasum+suffix, nil)
		w := httptest.NewRecorder()
		s.serveTTYReplay(w, req, tmpl)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: expected 404 for a shasum never mirrored into ES, got %d: %s", suffix, w.Code, w.Body.String())
		}
	}
}

func TestServeTTYReplayRawServesOriginalBytes(t *testing.T) {
	s, tmpl := newTestTTYStore(t)
	shasum := strings.Repeat("c", 64)
	raw := buildSimpleTTYLog("hello attacker")
	seedTTYLog(t, s, shasum, raw)

	req := httptest.NewRequest(http.MethodGet, "/tty/"+shasum+".raw", nil)
	w := httptest.NewRecorder()
	s.serveTTYReplay(w, req, tmpl)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "hello attacker") {
		t.Errorf("raw download should contain the original bytes verbatim")
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("expected octet-stream content type, got %q", ct)
	}
}

func TestServeTTYReplayCastServesValidAsciicast(t *testing.T) {
	s, tmpl := newTestTTYStore(t)
	shasum := strings.Repeat("d", 64)
	seedTTYLog(t, s, shasum, buildSimpleTTYLog("hello attacker"))

	req := httptest.NewRequest(http.MethodGet, "/tty/"+shasum+".cast", nil)
	w := httptest.NewRecorder()
	s.serveTTYReplay(w, req, tmpl)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	lines := strings.Split(strings.TrimRight(w.Body.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected header + 1 event line, got %d: %s", len(lines), w.Body.String())
	}
	if !strings.Contains(lines[1], "hello attacker") {
		t.Errorf("event line missing the recorded text: %s", lines[1])
	}
}

func TestServeTTYReplayJSONServesRecords(t *testing.T) {
	s, tmpl := newTestTTYStore(t)
	shasum := strings.Repeat("e", 64)
	seedTTYLog(t, s, shasum, buildSimpleTTYLog("hello attacker"))

	req := httptest.NewRequest(http.MethodGet, "/tty/"+shasum+".json", nil)
	w := httptest.NewRecorder()
	s.serveTTYReplay(w, req, tmpl)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var payload struct {
		Shasum  string          `json:"shasum"`
		Records []ttyRecordJSON `json:"records"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not valid JSON: %v: %s", err, w.Body.String())
	}
	if len(payload.Records) != 1 || payload.Records[0].Data != "hello attacker" {
		t.Errorf("unexpected records: %+v", payload.Records)
	}
}

func TestServeTTYReplayESUnavailable(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))
	req := httptest.NewRequest(http.MethodGet, "/tty/"+strings.Repeat("f", 64)+".raw", nil)
	w := httptest.NewRecorder()
	s.serveTTYReplay(w, req, tmpl)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when Elasticsearch is not configured, got %d: %s", w.Code, w.Body.String())
	}
}
