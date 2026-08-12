package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func seedAttacker(t *testing.T, es *esClient, row attackerRow) {
	t.Helper()
	body, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.docIndex(attackersIndex, row.ID, body, true, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func TestReadAttackersSortsByEventsDescending(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	seedAttacker(t, es, attackerRow{ID: "a", IPs: []string{"203.0.113.1"}, Events: 5})
	seedAttacker(t, es, attackerRow{ID: "b", IPs: []string{"203.0.113.2"}, Events: 50})

	rows, err := readAttackers(es)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].ID != "b" || rows[1].ID != "a" {
		t.Fatalf("expected b (50 events) before a (5 events), got %+v", rows)
	}
}

func TestReadAttackersSetsLink(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	seedAttacker(t, es, attackerRow{ID: "entity-1", IPs: []string{"203.0.113.1"}, Events: 1})

	rows, err := readAttackers(es)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Link != "/attackers?id=entity-1" {
		t.Fatalf("Link = %q", rows[0].Link)
	}
}

// #1268: RecordingsURL scopes /recordings to every one of the entity's
// member IPs via the shared ?ips= filter, so an operator can find this
// entity's TTY session recordings without hunting through /events.
func TestReadAttackersSetsRecordingsURL(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	seedAttacker(t, es, attackerRow{ID: "entity-1", IPs: []string{"203.0.113.1", "203.0.113.2"}, Events: 1})

	rows, err := readAttackers(es)
	if err != nil {
		t.Fatal(err)
	}
	want := "/recordings?ips=203.0.113.1&ips=203.0.113.2"
	if rows[0].RecordingsURL != want {
		t.Fatalf("RecordingsURL = %q, want %q", rows[0].RecordingsURL, want)
	}
}

func TestRecordingsURLForIPsEmptyForNoIPs(t *testing.T) {
	if got := recordingsURLForIPs(nil); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestAttackersDataCountsMultiIPEntities(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	seedAttacker(t, es, attackerRow{ID: "solo", IPs: []string{"203.0.113.1"}, Events: 1})
	seedAttacker(t, es, attackerRow{ID: "merged", IPs: []string{"203.0.113.2", "198.51.100.1"}, Events: 2})

	s := &store{es: es}
	req := httptest.NewRequest("GET", "/attackers", nil)
	page := s.attackersData(req)

	if page.Total != 2 {
		t.Fatalf("Total = %d, want 2", page.Total)
	}
	if page.MultiIPRows != 1 {
		t.Fatalf("MultiIPRows = %d, want 1", page.MultiIPRows)
	}
}

func TestAttackersDataSelectsByIDQueryParam(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	seedAttacker(t, es, attackerRow{ID: "target", IPs: []string{"203.0.113.1", "198.51.100.1"}, Events: 3})
	seedAttacker(t, es, attackerRow{ID: "other", IPs: []string{"203.0.113.2"}, Events: 1})

	s := &store{es: es}
	req := httptest.NewRequest("GET", "/attackers?id=target", nil)
	page := s.attackersData(req)

	if page.Selected == nil || page.Selected.ID != "target" {
		t.Fatalf("Selected = %+v", page.Selected)
	}
}

func TestAttackersDataNoSelectionWithoutIDParam(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	seedAttacker(t, es, attackerRow{ID: "target", IPs: []string{"203.0.113.1"}, Events: 1})

	s := &store{es: es}
	req := httptest.NewRequest("GET", "/attackers", nil)
	page := s.attackersData(req)

	if page.Selected != nil {
		t.Fatalf("expected no selection, got %+v", page.Selected)
	}
}

func TestAttackersDataNoESClientReturnsEmptyPage(t *testing.T) {
	s := &store{}
	req := httptest.NewRequest("GET", "/attackers", nil)
	page := s.attackersData(req)
	if page.Total != 0 || page.Rows != nil {
		t.Fatalf("expected an empty page without an ES client, got %+v", page)
	}
}
