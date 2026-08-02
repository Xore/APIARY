package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// Acknowledging one alert at a time is unworkable once a scan floods the
// board, but "all" has to mean all: list() only returns the newest 200, and a
// bulk action that silently stopped at the visible rows would leave older
// alerts open while telling the operator they were handled.
func TestAcknowledgeAllCoversRecordsThePageNeverShows(t *testing.T) {
	m := newAlertManager(filepath.Join(t.TempDir(), "alerts.json"), 0)
	for i := 0; i < 250; i++ {
		m.observe("key-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "message", "", true)
	}
	total := len(m.records)
	if total <= len(m.list()) {
		t.Fatalf("only %d records for %d listed: the test cannot prove the cap is crossed", total, len(m.list()))
	}

	if changed := m.acknowledgeAll(true); changed != total {
		t.Fatalf("acknowledgeAll changed %d of %d records", changed, total)
	}
	for _, r := range m.records {
		if !r.Acknowledged {
			t.Fatalf("record %q left open after acknowledging all", r.Key)
		}
	}

	// A second pass has nothing to do; reporting work that did not happen would
	// make the confirmation message a lie.
	if changed := m.acknowledgeAll(true); changed != 0 {
		t.Fatalf("re-acknowledging reported %d changes, want 0", changed)
	}
}

// The count comes back so the UI can report what the server did rather than
// what the page happened to be displaying.
func TestAlertsAPIBulkAcknowledge(t *testing.T) {
	s := &store{alerts: newAlertManager(filepath.Join(t.TempDir(), "alerts.json"), 0)}
	s.alerts.observe("one", "first", "", true)
	s.alerts.observe("two", "second", "", true)
	s.alerts.acknowledge("one", true)

	body := strings.NewReader("scope=all&ack=true")
	req := httptest.NewRequest(http.MethodPost, "/api/alerts", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.serveAlertsAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Changed int
		Alerts  []alertRecord
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Changed != 1 {
		t.Fatalf("changed=%d, want only the one alert that was still open", got.Changed)
	}
	if len(got.Alerts) != 2 {
		t.Fatalf("got %d alerts back, want the full refreshed list", len(got.Alerts))
	}
	for _, r := range got.Alerts {
		if !r.Acknowledged {
			t.Fatalf("alert %q still open in the response", r.Key)
		}
	}
}

// #248: campaign/OT/YARA/sandbox-risk alerts carry a drill-down Link to the
// events behind them; it should overwrite on each observation the same way
// Message already does, and stay empty for alert types with nothing to link
// to (pipeline-health alerts never pass a link).
func TestAlertLinkOverwritesOnEachObservation(t *testing.T) {
	m := newAlertManager(filepath.Join(t.TempDir(), "alerts.json"), 0)
	m.observe("campaign:203.0.113.0/24", "first sighting", "/events?cidr=203.0.113.0%2F24", true)
	if got := m.records["campaign:203.0.113.0/24"].Link; got != "/events?cidr=203.0.113.0%2F24" {
		t.Fatalf("Link = %q after first observe", got)
	}
	m.observe("campaign:203.0.113.0/24", "second sighting", "/events?cidr=203.0.113.0%2F24", true)
	if got, want := len(m.list()), 1; got != want {
		t.Fatalf("got %d records, want %d (re-observing must not duplicate)", got, want)
	}

	m.observe("stale:cowrie", "feed stale", "", true)
	if got := m.records["stale:cowrie"].Link; got != "" {
		t.Fatalf("pipeline-health alert got a non-empty Link: %q", got)
	}

	b, err := json.Marshal(m.records["stale:cowrie"])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "Link") {
		t.Fatalf("empty Link should be omitted from JSON, got: %s", b)
	}
}

// An empty key must not be read as "everything". A form that drops its key is
// a bug; treating it as a request to clear the whole board turns that bug into
// a silent loss of every open alert.
func TestAlertsAPIEmptyKeyIsNotBulk(t *testing.T) {
	s := &store{alerts: newAlertManager(filepath.Join(t.TempDir(), "alerts.json"), 0)}
	s.alerts.observe("one", "first", "", true)

	req := httptest.NewRequest(http.MethodPost, "/api/alerts", strings.NewReader("key=&ack=true"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.serveAlertsAPI(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 for an unknown key", rec.Code)
	}
	if s.alerts.records["one"].Acknowledged {
		t.Fatal("an empty key acknowledged an alert")
	}
}
