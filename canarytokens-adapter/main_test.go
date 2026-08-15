package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBuildEvent_ParsesCanarytokensTimeFormat(t *testing.T) {
	p := alertPayload{
		Channel:      "HTTP",
		TokenType:    "web",
		SrcIP:        "203.0.113.5",
		Token:        "abc123",
		Time:         "2026-08-15 12:34:56 (UTC)",
		Memo:         "planted in cowrie fake home dir",
		ManageURL:    "https://canarytokens.internal.apiary/manage?token=abc123",
		PublicDomain: "canarytokens.internal.apiary",
	}
	ev := buildEvent(p, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))

	if ev["sensor"] != "canarytokens" {
		t.Errorf("sensor = %v, want canarytokens", ev["sensor"])
	}
	if ev["timestamp"] != "2026-08-15T12:34:56Z" {
		t.Errorf("timestamp = %v, want 2026-08-15T12:34:56Z", ev["timestamp"])
	}
	if ev["src_ip"] != "203.0.113.5" {
		t.Errorf("src_ip = %v", ev["src_ip"])
	}
	if ev["token_type"] != "web" {
		t.Errorf("token_type = %v", ev["token_type"])
	}
}

func TestBuildEvent_FallsBackToNowOnUnparseableTime(t *testing.T) {
	fallback := time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)
	p := alertPayload{Time: "not-a-real-timestamp"}
	ev := buildEvent(p, fallback)

	if ev["timestamp"] != "2026-08-15T09:00:00Z" {
		t.Errorf("timestamp = %v, want fallback 2026-08-15T09:00:00Z", ev["timestamp"])
	}
}

func TestWriteEvent_RejectsNonPost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	writeEvent(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestWriteEvent_RejectsMalformedJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	writeEvent(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestWriteEvent_WritesJSONLineToLogFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "canarytokens-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	logFile = f

	body := `{"channel":"HTTP","token_type":"web","src_ip":"198.51.100.9","token":"tok1","time":"2026-08-15 10:00:00 (UTC)","memo":"test","manage_url":"https://example.invalid/manage","public_domain":"example.invalid"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	writeEvent(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	written, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), `"sensor":"canarytokens"`) {
		t.Errorf("log line missing sensor field: %s", written)
	}
	if !strings.Contains(string(written), `"src_ip":"198.51.100.9"`) {
		t.Errorf("log line missing src_ip: %s", written)
	}
}
