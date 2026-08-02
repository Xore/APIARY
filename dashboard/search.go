package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The investigation command dock used to route client-side by guessing the
// shape of the query: anything hex-looking became a session id, anything long
// and hex became a payload hash. A guess that missed produced a bare 404. The
// dock now posts every query here instead. An exact hit on a known entity
// redirects straight to it; everything else is answered with grouped matches
// from every source the dashboard holds, so a query is never a dead end.

// searchGroupLimit bounds each group so one noisy category cannot bury the
// others. A group that has more offers a link to the unbounded view.
const searchGroupLimit = 8

type searchHit struct {
	Label  string // the matched value
	Detail string // why it matched / supporting context
	Count  int    // related events, where the group counts them
	URL    string
}

type searchGroup struct {
	Title   string
	Hint    string
	Hits    []searchHit
	More    int    // matches beyond searchGroupLimit
	MoreURL string // unbounded view for the remainder
}

type searchPage struct {
	pageMeta
	Generated time.Time
	Query     string
	Groups    []searchGroup
	Total     int
	Filters   []string
	filterBar
}

// searchRedirect resolves a query that unambiguously names one entity. The
// caller redirects rather than rendering a result page with a single row.
func (s *store) searchRedirect(query string) string {
	events := s.getEvents()
	lower := strings.ToLower(query)
	for _, e := range events {
		switch {
		case e.Session != "" && strings.EqualFold(e.Session, query):
			return "/sessions/" + url.PathEscape(e.Session)
		case e.Shasum != "" && strings.EqualFold(e.Shasum, query):
			return "/payload-analysis/" + url.PathEscape(e.Shasum)
		case e.SrcIP != "" && e.SrcIP == query:
			return "/investigate/ip/" + url.PathEscape(e.SrcIP)
		}
	}
	for _, run := range loadSandboxResults() {
		if strings.EqualFold(run.Job, query) {
			return "/sandbox/" + url.PathEscape(run.Job)
		}
	}
	if strings.HasPrefix(lower, "as") {
		if asn, err := strconv.ParseUint(strings.TrimPrefix(lower, "as"), 10, 32); err == nil {
			return eventsURL(url.Values{"asn": {strconv.FormatUint(asn, 10)}})
		}
	}
	return ""
}

// counter accumulates distinct matched values with their event counts and a
// short piece of supporting context.
type counter struct {
	order   []string
	counts  map[string]int
	details map[string]string
}

func newCounter() *counter {
	return &counter{counts: map[string]int{}, details: map[string]string{}}
}

func (c *counter) add(value, detail string) {
	if value == "" {
		return
	}
	if _, seen := c.counts[value]; !seen {
		c.order = append(c.order, value)
		c.details[value] = detail
	}
	c.counts[value]++
}

// group renders the accumulated values, most frequent first, capped to
// searchGroupLimit. link builds the target URL for one value.
func (c *counter) group(title, hint, moreURL string, link func(string) string) searchGroup {
	if len(c.order) == 0 {
		return searchGroup{}
	}
	values := append([]string(nil), c.order...)
	sort.SliceStable(values, func(i, j int) bool { return c.counts[values[i]] > c.counts[values[j]] })
	g := searchGroup{Title: title, Hint: hint}
	for _, value := range values {
		if len(g.Hits) == searchGroupLimit {
			g.More = len(values) - searchGroupLimit
			g.MoreURL = moreURL
			break
		}
		g.Hits = append(g.Hits, searchHit{Label: value, Detail: c.details[value], Count: c.counts[value], URL: link(value)})
	}
	return g
}

func (s *store) searchData(query string, f filter) searchPage {
	page := searchPage{Generated: time.Now(), Query: query, Filters: f.describe()}
	needle := strings.ToLower(strings.TrimSpace(query))
	if needle == "" {
		return page
	}

	sources, sessions, payloads := newCounter(), newCounter(), newCounter()
	commands, paths, credentials := newCounter(), newCounter(), newCounter()
	signatures, fingerprints, decoys := newCounter(), newCounter(), newCounter()
	matchingEvents := 0

	contains := func(value string) bool {
		return value != "" && strings.Contains(strings.ToLower(value), needle)
	}

	for _, e := range s.getEvents() {
		if !f.match(e) {
			continue
		}
		matched := false
		if contains(e.SrcIP) || contains(e.Org) || contains(e.Country) || contains(e.City) ||
			(e.ASN != 0 && strings.Contains("as"+strconv.FormatUint(uint64(e.ASN), 10), needle)) {
			location := strings.TrimSpace(strings.Join([]string{e.City, e.Country, e.Org}, " "))
			sources.add(e.SrcIP, location)
			matched = true
		}
		if contains(e.Session) {
			sessions.add(e.Session, e.SrcIP+" via "+e.Sensor)
			matched = true
		}
		if contains(e.Shasum) || contains(e.Download) {
			payloads.add(e.Shasum, e.Download)
			matched = true
		}
		if contains(e.Command) {
			commands.add(e.Command, e.Sensor)
			matched = true
		}
		if contains(e.Path) {
			paths.add(e.Path, e.Sensor)
			matched = true
		}
		if contains(e.User) || contains(e.Pass) {
			credentials.add(e.User+" / "+e.Pass, e.Sensor)
			matched = true
		}
		if contains(e.Alert) || contains(e.Category) {
			signatures.add(firstNonEmpty(e.Alert, e.Category), e.Category)
			matched = true
		}
		if contains(e.Fingerprint) || contains(e.ClientVer) {
			fingerprints.add(e.Fingerprint, firstNonEmpty(e.FingerKind, e.ClientVer))
			matched = true
		}
		if contains(e.Persona) || contains(e.Site) || contains(e.Asset) || contains(e.PersonaOrg) {
			decoys.add(e.Persona, strings.TrimSpace(e.Site+" "+e.Asset))
			matched = true
		}
		if matched || contains(e.Detail) {
			matchingEvents++
		}
	}

	freeText := eventsURL(url.Values{"q": {query}})
	groups := []searchGroup{
		sources.group("Attack sources", "Addresses, networks, and locations", eventsURL(url.Values{"q": {query}}),
			func(v string) string { return "/investigate/ip/" + url.PathEscape(v) }),
		sessions.group("Sessions", "Complete interactive replays", freeText,
			func(v string) string { return "/sessions/" + url.PathEscape(v) }),
		payloads.group("Captured payloads", "Downloaded artifacts and their analysis", "/payloads",
			func(v string) string { return "/payload-analysis/" + url.PathEscape(v) }),
		commands.group("Executed commands", "Commands attackers ran on a decoy", "/commands",
			func(v string) string { return eventsURL(url.Values{"cmd": {v}}) }),
		paths.group("Requested paths", "HTTP paths probed on web decoys", freeText,
			func(v string) string { return eventsURL(url.Values{"path": {v}}) }),
		credentials.group("Credentials", "Username and password pairs that were tried", freeText,
			func(v string) string { return eventsURL(url.Values{"cred": {v}}) }),
		signatures.group("Detections", "Sensor signatures and categories", "/alerts",
			func(v string) string { return eventsURL(url.Values{"sig": {v}}) }),
		fingerprints.group("Client fingerprints", "HASSH, JA3/JA4, and client banners", freeText,
			func(v string) string { return eventsURL(url.Values{"fingerprint": {v}}) }),
		decoys.group("Decoys", "Emulated personas, sites, and assets", freeText,
			func(v string) string { return eventsURL(url.Values{"persona": {v}}) }),
	}

	if runs := s.searchSandbox(needle); len(runs.Hits) > 0 {
		groups = append(groups, runs)
	}
	if analyses := s.searchGitHubAnalysis(needle); len(analyses.Hits) > 0 {
		groups = append(groups, analyses)
	}
	if matchingEvents > 0 {
		groups = append(groups, searchGroup{
			Title: "Events",
			Hint:  "Every normalized record mentioning this value",
			Hits: []searchHit{{
				Label:  strconv.Itoa(matchingEvents) + " matching events",
				Detail: "Open the event explorer filtered to this query",
				Count:  matchingEvents,
				URL:    freeText,
			}},
		})
	}

	for _, g := range groups {
		if len(g.Hits) > 0 {
			page.Groups = append(page.Groups, g)
			page.Total += len(g.Hits)
		}
	}
	return page
}

func (s *store) searchSandbox(needle string) searchGroup {
	runs := newCounter()
	for _, run := range loadSandboxResults() {
		haystack := strings.ToLower(strings.Join([]string{run.Job, run.SHA256, run.CaptureName, run.FileType, run.RiskLevel, run.Classification.Label}, " "))
		if strings.Contains(haystack, needle) {
			runs.add(run.Job, strings.TrimSpace(run.Classification.Label+" "+run.RiskLevel))
		}
	}
	return runs.group("Sandbox runs", "Completed dynamic analysis", "/sandbox",
		func(v string) string { return "/sandbox/" + url.PathEscape(v) })
}

func (s *store) searchGitHubAnalysis(needle string) searchGroup {
	rows := newCounter()
	for _, result := range loadGitHubAnalysisResults() {
		verdictLevel := ""
		if result.Verdict != nil {
			verdictLevel = result.Verdict.Level
		}
		haystack := strings.ToLower(strings.Join([]string{result.SHA256, result.Family, result.ExitStatus, verdictLevel}, " "))
		if strings.Contains(haystack, needle) {
			rows.add(result.SHA256, strings.TrimSpace(result.Family+" "+verdictLevel))
		}
	}
	return rows.group("GitHub analyses", "External scanner verdicts", "/github-analysis",
		func(v string) string { return "/github-analysis/" + url.PathEscape(v) })
}

// quickSearchLimit caps the command palette's live preview list. It is a
// preview, not the results page (that stays unbounded-per-group via
// serveSearch/searchGroupLimit) -- a handful of top matches is enough to
// decide whether to press Enter for the full grouped view or click straight
// through to one match.
const quickSearchLimit = 8

type quickSearchHit struct {
	Title string `json:"title"`
	Meta  string `json:"meta"`
	Group string `json:"group"`
	URL   string `json:"url"`
}

// quickSearchResults flattens searchData's groups in their existing priority
// order (Attack sources, Sessions, Payloads, ... -- the same order a query
// would already surface on the full results page) into one capped list for
// the command palette's live preview. An exact single-entity match (the same
// check serveSearch uses to redirect instead of rendering a results page) is
// always the first row, so a query that names one specific thing shows that
// thing first regardless of which group it would otherwise fall into.
// quickSearchResults feeds the topbar's typeahead popup, deliberately
// unfiltered (filter{}) -- it's a lightweight dropdown, not the full
// /search page, and #280's filter bar work is scoped to that page, not
// this popup.
func (s *store) quickSearchResults(query string) []quickSearchHit {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	var hits []quickSearchHit
	if target := s.searchRedirect(query); target != "" {
		hits = append(hits, quickSearchHit{Title: query, Meta: "Enter", Group: "Exact match", URL: target})
	}
	for _, group := range s.searchData(query, filter{}).Groups {
		for _, hit := range group.Hits {
			if len(hits) >= quickSearchLimit {
				return hits
			}
			hits = append(hits, quickSearchHit{Title: hit.Label, Meta: group.Title, Group: group.Title, URL: hit.URL})
		}
	}
	return hits
}

func (s *store) serveQuickSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	hits := s.quickSearchResults(r.URL.Query().Get("q"))
	if hits == nil {
		hits = []quickSearchHit{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"results": hits})
}

func (s *store) serveSearch(w http.ResponseWriter, r *http.Request, tmpl *template.Template) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		http.Redirect(w, r, "/events", http.StatusSeeOther)
		return
	}
	if target := s.searchRedirect(query); target != "" {
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	data := s.searchData(query, parseFilter(r))
	data.filterBar = buildFilterBar(r, "/search",
		[2]string{"sensor", "Sensor"}, [2]string{"country", "Country"}, [2]string{"since", "Since (e.g. 24h)"})
	renderPage(w, tmpl, "search", &data)
}
