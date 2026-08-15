package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestReadAttackersCarriesTechniques (#1260): attacker-identity-worker's
// own durable technique-coverage field round-trips through readAttackers
// unchanged, same as every other field this reader is a pure mirror of.
func TestReadAttackersCarriesTechniques(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")

	seedAttacker(t, es, attackerRow{ID: "entity-1", IPs: []string{"203.0.113.1"}, Events: 1, Techniques: []string{"T1059", "T1110"}})

	rows, err := readAttackers(es)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows[0].Techniques) != 2 || rows[0].Techniques[0] != "T1059" || rows[0].Techniques[1] != "T1110" {
		t.Fatalf("Techniques = %+v", rows[0].Techniques)
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

// TestAttackersShellRendersWithoutES covers #1327's shell+hydrate
// conversion: /attackers must render a 200 shell with no Elasticsearch
// client configured at all -- the old behavior synchronously called
// readAttackers() and would have rendered an empty table here; that read
// now happens only on the client's own follow-up fetch to the fragment
// route below. The shell must carry the fragment URL for
// hp-attackers-detail.js to hydrate from, and it must not leak table rows
// that would only be true for a real result.
func TestAttackersShellRendersWithoutES(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	mux := s.routes(tmpl)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/attackers", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a shell render (it fetches entities client-side)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-hp-attackers-fragment-url="/attackers/fragment"`) {
		t.Errorf("shell is missing the fragment URL hp-attackers-detail.js hydrates from, got: %s", body)
	}
	if strings.Contains(body, "attackers-body") {
		t.Error("shell must not render the body template's own define name as literal text")
	}
}

// TestAttackersShellPreservesSelectedIDInFragmentURL: an ?id= query
// param selects an entity's graph/fusion cards synchronously in the
// shell (attackersShell needs no ES read to know the id was requested),
// but the fragment URL the client hydrates from must carry that same id
// forward so the metadata grid and table it resolves stay in sync with
// which entity is selected.
func TestAttackersShellPreservesSelectedIDInFragmentURL(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	mux := s.routes(tmpl)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/attackers?id=entity-1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-hp-attackers-fragment-url="/attackers/fragment?id=entity-1"`) {
		t.Errorf("shell did not carry the selected id into the fragment URL, got: %s", body)
	}
	if !strings.Contains(body, "Entity entity-1") {
		t.Errorf("shell did not render the selected entity's graph card immediately, got: %s", body)
	}
}

// TestAttackersFragmentRoute covers the fragment route's own real-data
// path: it renders the resolved entity table (and, given a selected id,
// that entity's own metadata grid) from a real attackersData() result.
func TestAttackersFragmentRoute(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")
	seedAttacker(t, es, attackerRow{ID: "entity-1", IPs: []string{"203.0.113.1"}, Events: 7})

	s := &store{es: es}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	mux := s.routes(tmpl)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/attackers/fragment?id=entity-1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "entity-1") {
		t.Errorf("fragment missing the resolved entity, got: %s", body)
	}
	if !strings.Contains(body, ">7<") {
		t.Errorf("fragment missing the selected entity's own event count, got: %s", body)
	}
	if !strings.Contains(body, `id="attackers-selected-meta"`) || strings.Count(body, `class="card"`) < 9 {
		t.Errorf("fragment must render every selected identity category as a card, got: %s", body)
	}
	if !strings.Contains(body, "No credential pairs recorded for this identity.") ||
		!strings.Contains(body, "No fingerprints recorded for this identity.") ||
		!strings.Contains(body, "No payload hashes recorded for this identity.") {
		t.Errorf("fragment must keep empty evidence categories visible, got: %s", body)
	}
	if !strings.Contains(body, `<div class="card__scroll"><table class="data-table">`) {
		t.Errorf("identities table must be inside a bounded scroll region, got: %s", body)
	}
}

// #1444: populated evidence collections render as independent scrollable
// cards instead of one inline run that makes the complete page unbounded.
func TestAttackersFragmentRendersEvidenceInScrollableCards(t *testing.T) {
	memStore := newMemESDocStore()
	srv := httptest.NewServer(memStore.handler())
	defer srv.Close()
	es := newESClient(srv.URL, "")
	seedAttacker(t, es, attackerRow{
		ID:           "entity-evidence",
		IPs:          []string{"203.0.113.10", "203.0.113.11"},
		Fingerprints: []string{"SSH-2.0-libssh2"},
		Payloads:     []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Credentials:  []string{"root / password"},
		Sensors:      []string{"cowrie"},
		Events:       12,
		First:        "2026-08-14T10:00:00Z",
		Last:         "2026-08-15T10:00:00Z",
		Updated:      "2026-08-15T10:01:00Z",
		Verdicts:     []string{"malicious"},
		Techniques:   []string{"T1110"},
	})

	s := &store{es: es}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	mux := s.routes(tmpl)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/attackers/fragment?id=entity-evidence", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Member IPs (2)", "Credential pairs (1)", "root / password",
		"Fingerprints (1)", "SSH-2.0-libssh2", "Payload hashes (1)",
		"Ghidra verdicts (1)", "ATT&amp;CK techniques (1)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("fragment missing %q, got: %s", want, body)
		}
	}
	if got := strings.Count(body, `class="card__scroll"`); got < 7 {
		t.Errorf("scrollable collections plus identities table = %d, want at least 7", got)
	}
}
