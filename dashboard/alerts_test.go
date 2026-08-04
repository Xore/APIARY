package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// memESDocStore is a minimal in-memory stand-in for Elasticsearch's document
// CRUD API (GET/_doc, PUT/_doc with op_type=create or if_seq_no/
// if_primary_term, and a plain _search) -- just enough of the real
// contract for alertManager's docGet/docIndex/docSearchAll calls to
// round-trip against in a test, including the optimistic-concurrency
// version_conflict_engine_exception (409) both a losing create and a losing
// conditional update get in real Elasticsearch.
type memESDocStore struct {
	mu   sync.Mutex
	docs map[string]memESDoc // index+"/"+id -> doc
}

type memESDoc struct {
	seqNo, primaryTerm int64
	source             json.RawMessage
}

func newMemESDocStore() *memESDocStore { return &memESDocStore{docs: map[string]memESDoc{}} }

func (m *memESDocStore) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 3)
		if len(parts) < 2 {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		index := parts[0]
		w.Header().Set("Content-Type", "application/json")

		if len(parts) == 3 && parts[1] == "_doc" {
			id, err := url.PathUnescape(parts[2])
			if err != nil {
				http.Error(w, "bad id", http.StatusBadRequest)
				return
			}
			key := index + "/" + id
			m.mu.Lock()
			defer m.mu.Unlock()
			switch r.Method {
			case http.MethodGet:
				doc, ok := m.docs[key]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					fmt.Fprint(w, `{"found":false}`)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{
					"_id": id, "_seq_no": doc.seqNo, "_primary_term": doc.primaryTerm,
					"_source": json.RawMessage(doc.source), "found": true,
				})
			case http.MethodPut:
				body, _ := jsonRead(r)
				if r.URL.Query().Get("op_type") == "create" {
					if _, exists := m.docs[key]; exists {
						w.WriteHeader(http.StatusConflict)
						fmt.Fprint(w, `{"error":{"type":"version_conflict_engine_exception"}}`)
						return
					}
					m.docs[key] = memESDoc{seqNo: 0, primaryTerm: 1, source: body}
					w.WriteHeader(http.StatusCreated)
					fmt.Fprint(w, `{"result":"created"}`)
					return
				}
				wantSeq, wantTerm := r.URL.Query().Get("if_seq_no"), r.URL.Query().Get("if_primary_term")
				doc, exists := m.docs[key]
				if !exists || fmt.Sprint(doc.seqNo) != wantSeq || fmt.Sprint(doc.primaryTerm) != wantTerm {
					w.WriteHeader(http.StatusConflict)
					fmt.Fprint(w, `{"error":{"type":"version_conflict_engine_exception"}}`)
					return
				}
				m.docs[key] = memESDoc{seqNo: doc.seqNo + 1, primaryTerm: doc.primaryTerm, source: body}
				fmt.Fprint(w, `{"result":"updated"}`)
			default:
				http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
			}
			return
		}
		if len(parts) == 2 && parts[1] == "_search" {
			m.mu.Lock()
			defer m.mu.Unlock()
			type hit struct {
				ID          string          `json:"_id"`
				SeqNo       int64           `json:"_seq_no"`
				PrimaryTerm int64           `json:"_primary_term"`
				Source      json.RawMessage `json:"_source"`
			}
			var hits []hit
			prefix := index + "/"
			for key, doc := range m.docs {
				if !strings.HasPrefix(key, prefix) {
					continue
				}
				hits = append(hits, hit{ID: strings.TrimPrefix(key, prefix), SeqNo: doc.seqNo, PrimaryTerm: doc.primaryTerm, Source: doc.source})
			}
			json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
			return
		}
		http.Error(w, "not stubbed", http.StatusInternalServerError)
	}
}

func jsonRead(r *http.Request) (json.RawMessage, error) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

func newTestAlertManager(t *testing.T) *alertManager {
	t.Helper()
	store := newMemESDocStore()
	srv := httptest.NewServer(store.handler())
	t.Cleanup(srv.Close)
	es := newESClient(srv.URL, "")
	return newAlertManager(es, 0)
}

// Acknowledging one alert at a time is unworkable once a scan floods the
// board, but "all" has to mean all: list() only returns the newest 200, and a
// bulk action that silently stopped at the visible rows would leave older
// alerts open while telling the operator they were handled.
func TestAcknowledgeAllCoversRecordsThePageNeverShows(t *testing.T) {
	m := newTestAlertManager(t)
	for i := 0; i < 250; i++ {
		m.observe("key-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "message", "", true)
	}
	all := m.es
	hits, err := all.docSearchAll(alertIndex, 10000)
	if err != nil {
		t.Fatal(err)
	}
	total := len(hits)
	if total <= len(m.list()) {
		t.Fatalf("only %d records for %d listed: the test cannot prove the cap is crossed", total, len(m.list()))
	}

	if changed := m.acknowledgeAll(true); changed != total {
		t.Fatalf("acknowledgeAll changed %d of %d records", changed, total)
	}
	hits, err = all.docSearchAll(alertIndex, 10000)
	if err != nil {
		t.Fatal(err)
	}
	for _, hit := range hits {
		var r alertRecord
		if err := json.Unmarshal(hit.Source, &r); err != nil {
			t.Fatal(err)
		}
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
	s := &store{alerts: newTestAlertManager(t)}
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
	m := newTestAlertManager(t)
	m.observe("campaign:203.0.113.0/24", "first sighting", "/events?cidr=203.0.113.0%2F24", true)
	hit, found, err := m.es.docGet(alertIndex, "campaign:203.0.113.0/24")
	if err != nil || !found {
		t.Fatalf("docGet after first observe: found=%v err=%v", found, err)
	}
	var r alertRecord
	if err := json.Unmarshal(hit.Source, &r); err != nil {
		t.Fatal(err)
	}
	if r.Link != "/events?cidr=203.0.113.0%2F24" {
		t.Fatalf("Link = %q after first observe", r.Link)
	}
	m.observe("campaign:203.0.113.0/24", "second sighting", "/events?cidr=203.0.113.0%2F24", true)
	if got, want := len(m.list()), 1; got != want {
		t.Fatalf("got %d records, want %d (re-observing must not duplicate)", got, want)
	}

	m.observe("stale:cowrie", "feed stale", "", true)
	hit, found, err = m.es.docGet(alertIndex, "stale:cowrie")
	if err != nil || !found {
		t.Fatalf("docGet for stale:cowrie: found=%v err=%v", found, err)
	}
	// A fresh variable, not the campaign record reused above: json.Unmarshal
	// only overwrites fields present in the source, so reusing r would leave
	// its old Link value in place once this record's own Link is omitted.
	var stale alertRecord
	if err := json.Unmarshal(hit.Source, &stale); err != nil {
		t.Fatal(err)
	}
	if stale.Link != "" {
		t.Fatalf("pipeline-health alert got a non-empty Link: %q", stale.Link)
	}
	if strings.Contains(string(hit.Source), "Link") {
		t.Fatalf("empty Link should be omitted from JSON, got: %s", hit.Source)
	}
}

// An empty key must not be read as "everything". A form that drops its key is
// a bug; treating it as a request to clear the whole board turns that bug into
// a silent loss of every open alert.
func TestAlertsAPIEmptyKeyIsNotBulk(t *testing.T) {
	s := &store{alerts: newTestAlertManager(t)}
	s.alerts.observe("one", "first", "", true)

	req := httptest.NewRequest(http.MethodPost, "/api/alerts", strings.NewReader("key=&ack=true"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.serveAlertsAPI(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 for an unknown key", rec.Code)
	}
	hit, found, err := s.alerts.es.docGet(alertIndex, "one")
	if err != nil || !found {
		t.Fatalf("docGet for one: found=%v err=%v", found, err)
	}
	var r alertRecord
	if err := json.Unmarshal(hit.Source, &r); err != nil {
		t.Fatal(err)
	}
	if r.Acknowledged {
		t.Fatal("an empty key acknowledged an alert")
	}
}

// newAlertManager must return nil (alerting disabled, not a local-file
// fallback) when Elasticsearch is not configured -- every observe() call
// site across the codebase relies on this via `s.alerts == nil ||`.
func TestNewAlertManagerNilWithoutES(t *testing.T) {
	if m := newAlertManager(nil, 0); m != nil {
		t.Fatalf("expected nil alertManager without an ES client, got %+v", m)
	}
}

// #301: /alerts gains a filter bar (state, key-or-message substring) --
// filtering itself happens client-side in alerts.html against the always-
// unfiltered GET /api/alerts response (a shared endpoint other widgets also
// call, and already capped at 200 records), so what's tested on the Go side
// is the filter bar's own construction and the client-side wiring actually
// being present in the rendered page, not row-level filtering logic.

func TestAlertsStateIsAClosedTwoValueEnum(t *testing.T) {
	opts, ok := filterSelectOptions["state"]
	if !ok {
		t.Fatal(`filterSelectOptions["state"] is missing -- state should render as a <select>, not free text`)
	}
	got := map[string]bool{}
	for _, o := range opts {
		got[o.Value] = true
	}
	// alertRecord.Acknowledged is a bool -- exactly two real states, plus the
	// empty "any" value every other select field in this codebase uses.
	for _, want := range []string{"", "open", "acknowledged"} {
		if !got[want] {
			t.Errorf("state options missing %q: %+v", want, opts)
		}
	}
	if len(opts) != 3 {
		t.Errorf("state should have exactly 3 options (any/open/acknowledged), got %+v", opts)
	}
}

func TestAlertsFilterBarPreFillsFromRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/alerts?state=open&q=mirai", nil)
	bar := buildFilterBar(r, "/alerts", [2]string{"state", "State"}, [2]string{"q", "Key or message contains"})
	if bar.FilterAction != "/alerts" {
		t.Fatalf("FilterAction = %q, want /alerts", bar.FilterAction)
	}
	names := map[string]string{}
	kinds := map[string]string{}
	for _, f := range bar.FilterFields {
		names[f.Name], kinds[f.Name] = f.Value, f.Kind
	}
	if names["state"] != "open" || kinds["state"] != "select" {
		t.Errorf("state field not pre-filled as a select: %+v", bar.FilterFields)
	}
	if names["q"] != "mirai" {
		t.Errorf("q field not pre-filled: %+v", bar.FilterFields)
	}
}

// End-to-end through the real template: the filter bar disclosure renders
// with the state <select> pre-filled, and the page's own script carries the
// client-side filtering function that reads it back out of the URL.
func TestAlertsPageRendersFilterBarAndClientSideFilterWiring(t *testing.T) {
	funcs := templateFuncs(nil, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))
	r := httptest.NewRequest("GET", "/alerts?state=acknowledged", nil)
	data := alertsPageData{
		filterBar: buildFilterBar(r, "/alerts", [2]string{"state", "State"}, [2]string{"q", "Key or message contains"}),
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "alerts", &data); err != nil {
		t.Fatalf("alerts page does not render: %v", err)
	}
	html := out.String()

	if !strings.Contains(html, `<select name="state">`) {
		t.Error("state filter field did not render as a <select>")
	}
	if !strings.Contains(html, `value="acknowledged" selected`) {
		t.Errorf("state select is not pre-filled from the request: %s", html)
	}
	if !strings.Contains(html, "function alertMatchesFilter") {
		t.Error("client-side filter function is missing from the rendered page")
	}
	if !strings.Contains(html, "new URLSearchParams(location.search)") {
		t.Error("loadAlerts no longer reads the active filter from the URL")
	}
	// "acknowledge all" must stay scoped to the whole board, not the filtered
	// view -- renderAckAll must still be called with the unfiltered list.
	if !strings.Contains(html, "renderAckAll(all)") {
		t.Error("acknowledge-all count must be computed from the unfiltered alert list, not the filtered one")
	}
}
