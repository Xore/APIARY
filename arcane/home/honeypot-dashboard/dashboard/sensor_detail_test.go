package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sensorRawSearchStub serves a single, unpaginated _search response built
// from docs -- querySensorRaw (sensor_detail.go) issues one bounded query,
// no PIT/search_after pagination, unlike loadSensorEventsES's own stub in
// events_es_test.go, so this stub is simpler: it just echoes every doc back
// as a hit and records the request body for assertions.
func sensorRawSearchStub(t *testing.T, docs []map[string]any, gotBody *string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*gotBody = string(body)

		type hit struct {
			Source struct {
				Timestamp string         `json:"@timestamp"`
				Honeypot  map[string]any `json:"honeypot"`
			} `json:"_source"`
		}
		hits := make([]hit, len(docs))
		for i, d := range docs {
			hits[i].Source.Honeypot = d
			if ts, ok := d["timestamp"].(string); ok {
				hits[i].Source.Timestamp = ts
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
	}
}

func TestQuerySensorRawFiltersBySensorAndWindow(t *testing.T) {
	var gotBody string
	es := httptest.NewServer(sensorRawSearchStub(t, []map[string]any{
		{"sensor": "mailoney", "timestamp": "2026-08-01T00:00:00Z"},
	}, &gotBody))
	defer es.Close()

	hits, ok := querySensorRaw(newESClient(es.URL, ""), "mailoney", true)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if !strings.Contains(gotBody, `"event.sensor":"mailoney"`) {
		t.Fatalf("request body %q does not filter by event.sensor", gotBody)
	}
	if !strings.Contains(gotBody, `"@timestamp":"desc"`) {
		t.Fatalf("request body %q does not sort desc as requested", gotBody)
	}
	if !strings.Contains(gotBody, esOverviewWindow) {
		t.Fatalf("request body %q does not bound the query to esOverviewWindow", gotBody)
	}
}

func TestQuerySensorRawNilClient(t *testing.T) {
	if _, ok := querySensorRaw(nil, "mailoney", true); ok {
		t.Fatal("expected ok=false for a nil client")
	}
}

// TestLoadMailoneySessionsGroupsBySessionID is the core of this PR's #1538
// slice: verifies login/envelope/mail-body events sharing one session_id
// collapse into a single mailoneySession with the sender, every recipient
// (a real conversation can RCPT TO more than one address), and the mail
// body preview all populated -- exactly the "see the mail directly" gap
// the issue names.
func TestLoadMailoneySessionsGroupsBySessionID(t *testing.T) {
	docs := []map[string]any{
		{
			"sensor": "mailoney", "event": "login", "session_id": "sess-1",
			"src_ip": "203.0.113.9", "src_port": 51000.0,
			"username": "admin", "password": "hunter2",
			"timestamp": "2026-08-16T10:00:00Z",
		},
		{
			"sensor": "mailoney", "event": "envelope", "session_id": "sess-1",
			"command":   "mail from:<attacker@evil.example>",
			"timestamp": "2026-08-16T10:00:01Z",
		},
		{
			"sensor": "mailoney", "event": "envelope", "session_id": "sess-1",
			"command":   "rcpt to:<victim1@example.invalid>",
			"timestamp": "2026-08-16T10:00:02Z",
		},
		{
			"sensor": "mailoney", "event": "envelope", "session_id": "sess-1",
			"command":   "rcpt to:<victim2@example.invalid>",
			"timestamp": "2026-08-16T10:00:03Z",
		},
		{
			"sensor": "mailoney", "event": "mail-body", "session_id": "sess-1",
			"size": 256.0, "truncated": false, "body_path": "/data/mail/sess-1.eml",
			"body_preview": "Subject: urgent\r\n\r\nSend gift cards.",
			"timestamp":    "2026-08-16T10:00:04Z",
		},
		// A second, unrelated session must not bleed into the first.
		{
			"sensor": "mailoney", "event": "login", "session_id": "sess-2",
			"src_ip": "198.51.100.4", "src_port": 51100.0,
			"username": "root", "password": "toor",
			"timestamp": "2026-08-16T09:00:00Z",
		},
	}
	var gotBody string
	es := httptest.NewServer(sensorRawSearchStub(t, docs, &gotBody))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	sessions, ok := s.loadMailoneySessions()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 grouped sessions, got %d: %+v", len(sessions), sessions)
	}
	// Newest-session-first: sess-1 (10:00:04) before sess-2 (09:00:00).
	sess1 := sessions[0]
	if sess1.SessionID != "sess-1" {
		t.Fatalf("expected sess-1 first (newest), got %q", sess1.SessionID)
	}
	if !sess1.LoggedIn || sess1.User != "admin" || sess1.Pass != "hunter2" {
		t.Fatalf("login fields not promoted: %+v", sess1)
	}
	if sess1.IP != "203.0.113.9" || sess1.Port != "51000" {
		t.Fatalf("source IP/port not promoted: %+v", sess1)
	}
	if len(sess1.MailFrom) != 1 || sess1.MailFrom[0] != "mail from:<attacker@evil.example>" {
		t.Fatalf("unexpected MailFrom: %+v", sess1.MailFrom)
	}
	if len(sess1.RcptTo) != 2 || sess1.RcptTo[0] != "rcpt to:<victim1@example.invalid>" || sess1.RcptTo[1] != "rcpt to:<victim2@example.invalid>" {
		t.Fatalf("unexpected RcptTo (expected chronological order, both recipients): %+v", sess1.RcptTo)
	}
	if sess1.BodySize != 256 || sess1.BodyPath != "/data/mail/sess-1.eml" || sess1.BodyPreview != "Subject: urgent\r\n\r\nSend gift cards." {
		t.Fatalf("mail body fields not promoted: %+v", sess1)
	}
	if sess1.Truncated {
		t.Fatalf("truncated should be false: %+v", sess1)
	}

	sess2 := sessions[1]
	if sess2.SessionID != "sess-2" || !sess2.LoggedIn || sess2.User != "root" {
		t.Fatalf("second session not preserved distinctly: %+v", sess2)
	}
	if len(sess2.MailFrom) != 0 || len(sess2.RcptTo) != 0 {
		t.Fatalf("second session should carry no envelope data: %+v", sess2)
	}
}

func TestLoadHTTPHoneypotRequestsReadsRawFields(t *testing.T) {
	docs := []map[string]any{
		{
			"sensor": "http-honeypot", "method": "POST", "host": "example.invalid",
			"path": "/wp-login.php", "query": "action=login", "user_agent": "curl/8.0",
			"headers":  map[string]any{"X-JA4": "t13d..."},
			"body":     "log=admin&pwd=hunter2",
			"username": "admin", "password": "hunter2", "auth_type": "form",
			"status": 200.0, "category": "wordpress",
			"tarpitted": true, "tarpit_bytes": 4096.0, "tarpit_ms": 1500.0,
			"timestamp": "2026-08-16T10:00:00Z",
		},
	}
	es := httptest.NewServer(sensorRawSearchStub(t, docs, new(string)))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	reqs, ok := s.loadHTTPHoneypotRequests()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	req := reqs[0]
	if req.Method != "POST" || req.Path != "/wp-login.php" || req.Query != "action=login" {
		t.Fatalf("request line fields not read: %+v", req)
	}
	if req.Body != "log=admin&pwd=hunter2" {
		t.Fatalf("body not read: %+v", req)
	}
	// headerMap lowercases keys (HTTP headers are case-insensitive).
	if req.Headers["x-ja4"] != "t13d..." {
		t.Fatalf("headers not read/lowercased: %+v", req.Headers)
	}
	if req.Username != "admin" || req.Password != "hunter2" || req.AuthType != "form" {
		t.Fatalf("submitted credentials not read: %+v", req)
	}
	if req.Status != 200 || req.Category != "wordpress" {
		t.Fatalf("status/category not read: %+v", req)
	}
	if !req.Tarpitted || req.TarpitBytes != 4096 || req.TarpitMS != 1500 {
		t.Fatalf("tarpit fields not read: %+v", req)
	}
}

func TestSensorDetailDataDisabledWithoutES(t *testing.T) {
	s := &store{}
	page := s.sensorDetailData(httptest.NewRequest(http.MethodGet, "/sensors", nil))
	if page.Enabled {
		t.Fatal("expected Enabled=false with no ES client configured")
	}
	if page.Mailoney != nil || page.HTTPRequests != nil {
		t.Fatalf("expected no data queried without an ES client: %+v", page)
	}
}

func TestSensorDetailDataPopulatesBothSensors(t *testing.T) {
	docs := []map[string]any{
		{"sensor": "mailoney", "event": "login", "session_id": "sess-1", "username": "a", "password": "b", "timestamp": "2026-08-16T10:00:00Z"},
	}
	es := httptest.NewServer(sensorRawSearchStub(t, docs, new(string)))
	defer es.Close()

	s := &store{es: newESClient(es.URL, "")}
	page := s.sensorDetailData(httptest.NewRequest(http.MethodGet, "/sensors?foo=bar", nil))
	if !page.Enabled {
		t.Fatal("expected Enabled=true with an ES client configured")
	}
	if len(page.Mailoney) != 1 {
		t.Fatalf("expected 1 mailoney session (the stub answers every sensor query with the same docs), got %d", len(page.Mailoney))
	}
	// The stub ignores the term filter and answers every query with the
	// same docs, so the http-honeypot query also gets this one (mailoney-
	// shaped) doc back as a single, mostly-empty row -- the point here is
	// just that both queries ran and both fields got populated once ok=true.
	if len(page.HTTPRequests) != 1 {
		t.Fatalf("expected 1 http-honeypot row once ok=true, got %d", len(page.HTTPRequests))
	}
}
