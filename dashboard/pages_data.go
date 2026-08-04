package main

import (
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// payloadRow is one captured malware sample: its hash, where the attacker put
// it, and how many times it was seen. The hash links out to VirusTotal.
type payloadRow struct {
	Shasum   string
	Download string
	Count    int
	Link     string // /events?shasum=…
	VT       string // VirusTotal lookup URL
}

type kv struct {
	Key   string
	Count int
	Link  string `json:",omitempty"` // optional /events?… drill-down URL
	Title string `json:",omitempty"` // full value when Key is shortened for display
}

// mapPoint is one marker on the overview attack map: an accumulated city (or,
// when GeoIP only resolved to country level, a country), not a single IP.
// #228: ASN/org/provider/intel are deliberately absent -- those are per-IP
// attributes, and a cluster of many IPs behind one city marker will often mix
// several of each, so showing whichever happened to be counted would read as
// representative when it is really an arbitrary sample. That breakdown
// already exists properly as its own leaderboard (ASNs/Providers on the
// overview page); the map's job is geographic density, not attribution.
type mapPoint struct {
	Country string  `json:"country,omitempty"`
	City    string  `json:"city,omitempty"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Count   int     `json:"count"`
	IPCount int     `json:"ip_count"`
	Link    string  `json:"-"` // /events?city=&country= drill-down, shared by the SVG fallback and the GeoJSON API
	X       float64 `json:"-"`
	Y       float64 `json:"-"`
	R       int     `json:"-"`
}

// mapPointEventsURL is the drill-down target for a city (or, when GeoIP only
// resolved to country level, country) marker -- every event from that place,
// not one arbitrarily-chosen contributing IP. Shared by the server-rendered
// SVG fallback map (aggregate.go) and the Leaflet GeoJSON API (map_api.go)
// so the two never drift apart.
func mapPointEventsURL(city, country string) string {
	q := url.Values{"country": {country}}
	if city != "" {
		q.Set("city", city)
	}
	return eventsURL(q)
}

// eventsPage is the data for the /events drill-down view.
type eventsPage struct {
	pageMeta
	Generated time.Time
	Filters   []string
	Total     int
	Shown     int
	Offset    int
	From      int
	To        int
	Page      int
	Pages     int
	PerPage   int
	PrevURL   string
	NextURL   string
	RowsURL   string
	ExportURL string
	Chain     bool // single-IP view rendered chronologically as an attack chain
	IP        string
	Events    []storedEvent
	// FingerprintIPs (#278): the distinct source IPs behind the current
	// fingerprint filter, pre-checked to match includeIPs -- lets the page
	// offer a check/uncheck list to isolate one IP among many sharing the
	// same fingerprint. Nil unless a fingerprint filter is active and more
	// than one IP is behind it.
	FingerprintIPs []correlatedIP
	// FingerprintIPsQuery preserves every other active filter as hidden
	// form fields so applying an IP selection doesn't drop them (a GET
	// form submission replaces the whole query string with its own fields).
	FingerprintIPsQuery []queryPair
	// ResetIPsURL clears the includeIPs narrowing (back to every IP for
	// the current fingerprint); empty when no narrowing is active.
	ResetIPsURL string
	filterBar
}

// correlatedIP is one distinct source IP behind the current fingerprint (or,
// in future, another correlating field) match (#278).
type correlatedIP struct {
	IP      string
	Count   int
	Checked bool
}

type queryPair struct{ Key, Value string }

// fingerprintIPCorrelation returns the distinct source IPs behind the
// current fingerprint filter, evaluated against every filter except
// includeIPs itself -- so unchecking one IP doesn't also shrink the
// checklist down to just the IPs that remain checked. Nil when there's no
// fingerprint filter active, or only one IP is behind it (nothing to
// isolate).
func fingerprintIPCorrelation(events []storedEvent, f filter) []correlatedIP {
	if f.fingerprint == "" {
		return nil
	}
	base := f
	base.includeIPs = nil
	counts := map[string]int{}
	var order []string
	for _, e := range events {
		if e.SrcIP == "" || !base.match(e) {
			continue
		}
		if _, seen := counts[e.SrcIP]; !seen {
			order = append(order, e.SrcIP)
		}
		counts[e.SrcIP]++
	}
	if len(order) < 2 {
		return nil
	}
	sort.Slice(order, func(i, j int) bool {
		if counts[order[i]] != counts[order[j]] {
			return counts[order[i]] > counts[order[j]]
		}
		return order[i] < order[j]
	})
	checked := func(ip string) bool {
		return len(f.includeIPs) == 0 || slices.Contains(f.includeIPs, ip)
	}
	out := make([]correlatedIP, 0, len(order))
	for _, ip := range order {
		out = append(out, correlatedIP{IP: ip, Count: counts[ip], Checked: checked(ip)})
	}
	return out
}

type attackerPage struct {
	pageMeta
	Generated    time.Time
	IP           string
	Country      string
	ASN          uint
	Org          string
	Provider     string
	First        string
	FirstUTC     string
	Last         string
	LastUTC      string
	Total        int
	Sessions     int
	PayloadCount int
	Sensors      []kv
	Creds        []kv
	Commands     []kv
	Payloads     []kv
	Paths        []kv
	Alerts       []kv
	Fingerprints []kv
	Events       []storedEvent
	Techniques   []attackTechnique
	// Correlation is #354's "ask the backend for everything" answer --
	// Elasticsearch-backed, so it includes portbridge tunnel connections
	// (never visible here before) and history beyond the in-memory,
	// log-tail-bounded Events above. Advisory only: Available is false
	// (never blocks the page) whenever Elasticsearch is unconfigured or the
	// query fails.
	Correlation ipCorrelation
}

func (s *store) attackerData(ip string) (attackerPage, bool) {
	if _, err := netip.ParseAddr(ip); err != nil {
		return attackerPage{}, false
	}
	p := attackerPage{Generated: time.Now(), IP: ip}
	sensors, creds, commands := map[string]int{}, map[string]int{}, map[string]int{}
	payloads, paths, alerts := map[string]int{}, map[string]int{}, map[string]int{}
	fingerprints, fingerKinds := map[string]int{}, map[string]string{}
	sessions := map[string]bool{}
	for _, event := range s.getEvents() {
		if event.SrcIP != ip {
			continue
		}
		p.Events = append(p.Events, event)
		p.Total++
		if p.Last == "" {
			p.Last, p.LastUTC, p.Country, p.ASN, p.Org = event.Time, event.UTC, event.Country, event.ASN, event.Org
			p.Provider = firstNonEmpty(event.Intel, event.Provider)
		}
		p.First, p.FirstUTC = event.Time, event.UTC
		sensors[event.Sensor]++
		if event.Session != "" {
			sessions[event.Session] = true
		}
		if event.HasCredential {
			creds[event.User+" / "+event.Pass]++
		}
		if event.Command != "" {
			commands[event.Command]++
		}
		if event.Shasum != "" {
			payloads[event.Shasum]++
			p.PayloadCount++
		}
		if event.Path != "" {
			paths[event.Path]++
		}
		if event.Alert != "" {
			alerts[event.Alert]++
		}
		if event.Fingerprint != "" {
			fingerprints[event.Fingerprint]++
			if _, seen := fingerKinds[event.Fingerprint]; !seen {
				fingerKinds[event.Fingerprint] = firstNonEmpty(event.FingerKind, "fingerprint")
			}
		}
	}
	if p.Total == 0 {
		return p, false
	}
	for i, j := 0, len(p.Events)-1; i < j; i, j = i+1, j-1 {
		p.Events[i], p.Events[j] = p.Events[j], p.Events[i]
	}
	if len(p.Events) > 250 {
		p.Events = p.Events[len(p.Events)-250:]
	}
	p.Sessions = len(sessions)
	p.Sensors, p.Creds, p.Commands = topN(sensors, 20), topN(creds, 15), topN(commands, 15)
	p.Payloads, p.Paths, p.Alerts = topN(payloads, 15), topN(paths, 15), topN(alerts, 15)
	p.Fingerprints = topN(fingerprints, 15)
	for i := range p.Fingerprints {
		fp := p.Fingerprints[i].Key
		p.Fingerprints[i].Title = fp
		p.Fingerprints[i].Key = fingerKinds[fp] + ": " + fp
		p.Fingerprints[i].Link = eventsURL(url.Values{"fingerprint": {fp}})
	}
	p.Techniques = aggregateTechniques(p.Events)
	if s.es != nil {
		p.Correlation = s.es.correlateIP(ip, 100)
	}
	return p, true
}

// ipRow is one line of the /ips listing.
type ipRow struct {
	IP       string
	Country  string
	Count    int
	Logins   int
	Sensors  string
	Sessions int
	First    string
	FirstUTC string
	Last     string
	LastUTC  string
}

type ipsPage struct {
	pageMeta
	Generated time.Time
	Rows      []ipRow
	Total     int
	Filters   []string
	RowsURL   string
	filterBar
}

const defaultEventRows = 25

func (s *store) eventsData(r *http.Request) eventsPage {
	f := parseFilter(r)
	events := s.getEvents()
	total := 0
	for _, event := range events {
		if f.match(event) {
			total++
		}
	}
	chain := f.ip != ""
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 25 || perPage > 500 {
		perPage = defaultEventRows
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pages := max(1, (total+perPage-1)/perPage)
	if page > pages {
		page = pages
	}
	start := min(total, (page-1)*perPage)
	end := min(total, start+perPage)
	out := make([]storedEvent, 0, end-start)
	matched := 0
	appendWindow := func(event storedEvent) {
		if !f.match(event) {
			return
		}
		if matched >= start && matched < end {
			out = append(out, event)
		}
		matched++
	}
	if chain {
		// attack chain: oldest first, so the story reads top to bottom
		for i := len(events) - 1; i >= 0; i-- {
			appendWindow(events[i])
		}
	} else {
		for _, event := range events {
			appendWindow(event)
		}
	}
	pageURL := func(target int) string {
		q := r.URL.Query()
		q.Set("page", strconv.Itoa(target))
		q.Set("per_page", strconv.Itoa(perPage))
		return "/events?" + q.Encode()
	}
	prevURL, nextURL := "", ""
	if page > 1 {
		prevURL = pageURL(page - 1)
	}
	if page < pages {
		nextURL = pageURL(page + 1)
	}
	rowsQuery := r.URL.Query()
	rowsQuery.Del("page")
	rowsQuery.Del("per_page")
	rowsURL := "/api/event-rows"
	if encoded := rowsQuery.Encode(); encoded != "" {
		rowsURL += "?" + encoded
	}
	// ExportURL mirrors RowsURL's own "same filters, strip pagination" query
	// (a fresh r.URL.Query() call -- rowsQuery above is already mutated) so
	// /export/events.csv (investigate.go, already filters via parseFilter(r))
	// exports exactly the scope the page is showing, not page/per_page along
	// with it and not the unfiltered set (#59).
	exportQuery := r.URL.Query()
	exportQuery.Del("page")
	exportQuery.Del("per_page")
	exportURL := "/export/events.csv"
	if encoded := exportQuery.Encode(); encoded != "" {
		exportURL += "?" + encoded
	}
	// #278: hidden fields for the check/uncheck IP form so applying a
	// selection doesn't drop every other active filter -- a GET form
	// submission replaces the whole query string with just its own fields.
	ipsQuery := r.URL.Query()
	ipsQuery.Del("ips")
	ipsQuery.Del("page")
	ipsQuery.Del("per_page")
	var fingerprintIPsQuery []queryPair
	for key, values := range ipsQuery {
		for _, v := range values {
			fingerprintIPsQuery = append(fingerprintIPsQuery, queryPair{Key: key, Value: v})
		}
	}
	resetIPsURL := ""
	if len(f.includeIPs) > 0 {
		resetQuery := r.URL.Query()
		resetQuery.Del("ips")
		resetIPsURL = "/events"
		if encoded := resetQuery.Encode(); encoded != "" {
			resetIPsURL += "?" + encoded
		}
	}
	// #344: the Event Explorer had no interactive filter bar at all --
	// every filter had to be hand-typed into the URL. Reuses the same
	// shared filter-bar plumbing (buildFilterBar/{{template "filterbar"}})
	// Reports and GitHub analysis already have, rather than building
	// something page-specific.
	bar := buildFilterBar(r, "/events",
		[2]string{"sensor", "Sensor"}, [2]string{"proto", "Attack path"}, [2]string{"ip", "IP"},
		[2]string{"port", "Port"}, [2]string{"country", "Country"}, [2]string{"type", "Type"},
		[2]string{"since", "Since (e.g. 24h)"})
	return eventsPage{
		Generated:           time.Now(),
		Filters:             f.describe(),
		filterBar:           bar,
		Total:               total,
		Shown:               len(out),
		Offset:              start,
		From:                start + boolInt(total > 0),
		To:                  end,
		Page:                page,
		Pages:               pages,
		PerPage:             perPage,
		PrevURL:             prevURL,
		NextURL:             nextURL,
		RowsURL:             rowsURL,
		ExportURL:           exportURL,
		Chain:               chain,
		IP:                  f.ip,
		Events:              out,
		FingerprintIPs:      fingerprintIPCorrelation(events, f),
		FingerprintIPsQuery: fingerprintIPsQuery,
		ResetIPsURL:         resetIPsURL,
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// ipsData serves both /ips and /api/ip-rows. The 30s cache only ever holds
// the unfiltered view -- once a filter (#280) is active, results are
// request-specific, so those are always computed fresh instead of being
// cached under (and potentially served back for) a completely different
// query.
func (s *store) ipsData(r *http.Request) ipsPage {
	f := parseFilter(r)
	filters := f.describe()
	rowsQuery := r.URL.Query()
	rowsQuery.Del("offset")
	rowsURL := "/api/ip-rows"
	if encoded := rowsQuery.Encode(); encoded != "" {
		rowsURL += "?" + encoded
	}
	bar := buildFilterBar(r, "/ips",
		[2]string{"ip", "IP"}, [2]string{"cidr", "CIDR"}, [2]string{"sensor", "Sensor"},
		[2]string{"country", "Country"}, [2]string{"since", "Since (e.g. 24h)"})
	finish := func(page ipsPage) ipsPage {
		page.Filters, page.RowsURL = filters, rowsURL
		page.filterBar = bar
		return page
	}
	if len(filters) == 0 {
		s.ipsMu.Lock()
		defer s.ipsMu.Unlock()
		if !s.ipsCacheAt.IsZero() && time.Since(s.ipsCacheAt) < 30*time.Second {
			return finish(s.ipsCache)
		}
		s.ipsCache = s.buildIPsData(f)
		s.ipsCacheAt = time.Now()
		return finish(s.ipsCache)
	}
	return finish(s.buildIPsData(f))
}

func (s *store) buildIPsData(f filter) ipsPage {
	type agg struct {
		count, logins     int
		country           string
		sensors           map[string]bool
		sessions          map[string]bool
		first, last       string
		firstUTC, lastUTC string
	}
	m := map[string]*agg{}
	// events are newest-first: the first time we see an IP is its most recent
	// event, the last time is its oldest.
	for _, e := range s.getEvents() {
		if e.SrcIP == "" || !f.match(e) {
			continue
		}
		a := m[e.SrcIP]
		if a == nil {
			a = &agg{sensors: map[string]bool{}, sessions: map[string]bool{}}
			m[e.SrcIP] = a
		}
		a.count++
		if e.IsLogin {
			a.logins++
		}
		if e.Country != "" {
			a.country = e.Country
		}
		a.sensors[e.Sensor] = true
		if e.Session != "" {
			a.sessions[e.Session] = true
		}
		if e.Time != "" {
			if a.last == "" {
				a.last, a.lastUTC = e.Time, e.UTC
			}
			a.first, a.firstUTC = e.Time, e.UTC
		}
	}
	rows := make([]ipRow, 0, len(m))
	for ip, a := range m {
		var sensors []string
		for s := range a.sensors {
			sensors = append(sensors, s)
		}
		sort.Strings(sensors)
		rows = append(rows, ipRow{
			IP: ip, Country: a.country, Count: a.count, Logins: a.logins,
			Sensors: strings.Join(sensors, " "), Sessions: len(a.sessions),
			First: a.first, FirstUTC: a.firstUTC, Last: a.last, LastUTC: a.lastUTC,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].IP < rows[j].IP
	})
	return ipsPage{Generated: time.Now(), Rows: rows, Total: len(rows)}
}
