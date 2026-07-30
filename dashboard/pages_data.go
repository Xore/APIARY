package main

import (
	"net/http"
	"net/netip"
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

type mapPoint struct {
	IP       string  `json:"ip"`
	Country  string  `json:"country,omitempty"`
	City     string  `json:"city,omitempty"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	ASN      uint    `json:"asn,omitempty"`
	Org      string  `json:"organization,omitempty"`
	Provider string  `json:"provider_type,omitempty"`
	Intel    string  `json:"intel,omitempty"`
	Count    int     `json:"count"`
	X        float64 `json:"-"`
	Y        float64 `json:"-"`
	R        int     `json:"-"`
}

// eventsPage is the data for the /events drill-down view.
type eventsPage struct {
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
	Chain     bool // single-IP view rendered chronologically as an attack chain
	IP        string
	Events    []storedEvent
}

type attackerPage struct {
	Generated    time.Time
	IP           string
	Country      string
	ASN          uint
	Org          string
	Provider     string
	First        string
	Last         string
	Total        int
	Sessions     int
	PayloadCount int
	Sensors      []kv
	Creds        []kv
	Commands     []kv
	Payloads     []kv
	Paths        []kv
	Alerts       []kv
	Events       []storedEvent
	Techniques   []attackTechnique
}

func (s *store) attackerData(ip string) (attackerPage, bool) {
	if _, err := netip.ParseAddr(ip); err != nil {
		return attackerPage{}, false
	}
	p := attackerPage{Generated: time.Now(), IP: ip}
	sensors, creds, commands := map[string]int{}, map[string]int{}, map[string]int{}
	payloads, paths, alerts := map[string]int{}, map[string]int{}, map[string]int{}
	sessions := map[string]bool{}
	for _, event := range s.getEvents() {
		if event.SrcIP != ip {
			continue
		}
		p.Events = append(p.Events, event)
		p.Total++
		if p.Last == "" {
			p.Last, p.Country, p.ASN, p.Org = event.Time, event.Country, event.ASN, event.Org
			p.Provider = firstNonEmpty(event.Intel, event.Provider)
		}
		p.First = event.Time
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
	p.Techniques = aggregateTechniques(p.Events)
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
	Last     string
}

type ipsPage struct {
	Generated time.Time
	Rows      []ipRow
	Total     int
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
	return eventsPage{
		Generated: time.Now(),
		Filters:   f.describe(),
		Total:     total,
		Shown:     len(out),
		Offset:    start,
		From:      start + boolInt(total > 0),
		To:        end,
		Page:      page,
		Pages:     pages,
		PerPage:   perPage,
		PrevURL:   prevURL,
		NextURL:   nextURL,
		RowsURL:   rowsURL,
		Chain:     chain,
		IP:        f.ip,
		Events:    out,
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *store) ipsData() ipsPage {
	s.ipsMu.Lock()
	defer s.ipsMu.Unlock()
	if !s.ipsCacheAt.IsZero() && time.Since(s.ipsCacheAt) < 30*time.Second {
		return s.ipsCache
	}
	s.ipsCache = s.buildIPsData()
	s.ipsCacheAt = time.Now()
	return s.ipsCache
}

func (s *store) buildIPsData() ipsPage {
	type agg struct {
		count, logins int
		country       string
		sensors       map[string]bool
		sessions      map[string]bool
		first, last   string
	}
	m := map[string]*agg{}
	// events are newest-first: the first time we see an IP is its most recent
	// event, the last time is its oldest.
	for _, e := range s.getEvents() {
		if e.SrcIP == "" {
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
				a.last = e.Time
			}
			a.first = e.Time
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
			First: a.first, Last: a.last,
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
