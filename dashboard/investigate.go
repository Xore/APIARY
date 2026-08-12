package main

import (
	"encoding/csv"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type commandRow struct {
	Sensor   string
	Command  string
	Count    int
	Sources  string
	Sessions int
	First    string
	FirstUTC string
	Last     string
	LastUTC  string
	Link     string
}

type commandsPage struct {
	pageMeta
	Generated time.Time
	Rows      []commandRow
	Filters   []string
	filterBar
}

func (s *store) commandsData(r *http.Request) commandsPage {
	f := parseFilter(r)
	type agg struct {
		row      commandRow
		sources  map[string]bool
		sessions map[string]bool
		first    time.Time
		last     time.Time
	}
	groups := map[string]*agg{}
	for _, e := range s.getEvents() {
		// Trim before grouping: a command differing only in trailing
		// whitespace (seen live from real cowrie sessions) otherwise gets
		// its own row that's visually indistinguishable from the trimmed
		// one, reading as a dashboard bug rather than the attacker-supplied
		// data variance it actually is.
		command := strings.TrimSpace(e.Command)
		if command == "" || !f.match(e) {
			continue
		}
		key := e.Sensor + "\x00" + command
		a := groups[key]
		if a == nil {
			a = &agg{row: commandRow{Sensor: e.Sensor, Command: command}, sources: map[string]bool{}, sessions: map[string]bool{}}
			groups[key] = a
		}
		a.row.Count++
		a.sources[e.SrcIP], a.sessions[e.Session] = e.SrcIP != "", e.Session != ""
		if a.first.IsZero() || e.when.Before(a.first) {
			a.first = e.when
		}
		if e.when.After(a.last) {
			a.last = e.when
		}
	}
	rows := make([]commandRow, 0, len(groups))
	for _, a := range groups {
		a.row.Sources = sortedSet(a.sources, 6)
		a.row.Sessions = len(a.sessions)
		a.row.First, a.row.FirstUTC = a.first.Format("2006-01-02 15:04"), utcOrEmpty(a.first)
		a.row.Last, a.row.LastUTC = a.last.Format("2006-01-02 15:04"), utcOrEmpty(a.last)
		a.row.Link = eventsURL(url.Values{"sensor": {a.row.Sensor}, "cmd": {a.row.Command}})
		rows = append(rows, a.row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		// #40: Last is minute-granularity ("2006-01-02 15:04"), so a burst of
		// commands landing in the same minute -- routine under real attack
		// traffic -- ties here too. sort.Slice isn't stable and Go map
		// iteration order (groups above) is randomized per process, so
		// without a final tiebreaker two dashboard instances reading the
		// identical underlying events could render /commands in a different
		// row order. Sensor+Command is unique per row (it's the map key),
		// making this a genuine total order.
		if rows[i].Last != rows[j].Last {
			return rows[i].Last > rows[j].Last
		}
		if rows[i].Sensor != rows[j].Sensor {
			return rows[i].Sensor < rows[j].Sensor
		}
		return rows[i].Command < rows[j].Command
	})
	bar := buildFilterBar(r, "/commands",
		[2]string{"sensor", "Sensor"}, [2]string{"q", "Command contains"}, [2]string{"since", "Since (e.g. 24h)"})
	return commandsPage{Generated: time.Now(), Rows: rows, Filters: f.describe(), filterBar: bar}
}

func (s *store) exportEventsCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="honeypot-events.csv"`)
	c := csv.NewWriter(w)
	defer c.Flush()
	_ = c.Write([]string{"time", "sensor", "source_ip", "country", "city", "asn", "organization", "provider", "protocol", "port", "username", "password", "command", "path", "alert", "session", "payload_hash", "detail"})
	for _, e := range parseFilter(r).filtered(s.getEvents()) {
		_ = c.Write([]string{e.Time, e.Sensor, e.SrcIP, e.Country, e.City, strconv.FormatUint(uint64(e.ASN), 10), e.Org, firstNonEmpty(e.Intel, e.Provider), e.Proto, e.Port, e.User, e.Pass, e.Command, e.Path, e.Alert, e.Session, e.Shasum, e.Detail})
	}
}

func (s *store) exportCommandsCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="honeypot-commands.csv"`)
	c := csv.NewWriter(w)
	defer c.Flush()
	_ = c.Write([]string{"sensor", "command", "count", "sources", "sessions", "first", "last"})
	for _, row := range s.commandsData(r).Rows {
		_ = c.Write([]string{row.Sensor, row.Command, strconv.Itoa(row.Count), row.Sources, strconv.Itoa(row.Sessions), row.First, row.Last})
	}
}

// exportIPsCSV mirrors exportEventsCSV/exportCommandsCSV's own shape (#513):
// the same filtered scope the /ips page itself would show, never the
// unfiltered set (#59) -- and unlike the page's own rendering, never capped
// to the top 25 rows either, since an export exists precisely for the rows
// that don't fit on screen.
func (s *store) exportIPsCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="honeypot-attack-sources.csv"`)
	c := csv.NewWriter(w)
	defer c.Flush()
	_ = c.Write([]string{"ip", "country", "count", "logins", "sensors", "sessions", "first", "last"})
	for _, row := range s.buildIPsData(parseFilter(r)).Rows {
		_ = c.Write([]string{row.IP, row.Country, strconv.Itoa(row.Count), strconv.Itoa(row.Logins), row.Sensors, strconv.Itoa(row.Sessions), row.First, row.Last})
	}
}

// exportCampaignsCSV exports the same rows /campaigns' own full table
// renders (score/network/... every column campaignrows has, not the
// overview's decluttered summary from #478 -- this is the detail page's own
// export, scoped by whatever filter the request carries, same #59 rule as
// every other export here).
func (s *store) exportCampaignsCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="honeypot-campaigns.csv"`)
	c := csv.NewWriter(w)
	defer c.Flush()
	_ = c.Write([]string{"score", "network", "events", "ips", "sensors", "ports", "creds", "payloads", "alerts", "asns", "providers", "fingerprints", "sequence", "why_correlated", "first", "last"})
	for _, row := range s.campaignsData(r).Campaigns {
		_ = c.Write([]string{
			strconv.Itoa(row.Score), row.CIDR, strconv.Itoa(row.Events), strconv.Itoa(row.UniqueIPs),
			row.Sensors, row.Ports, strconv.Itoa(row.Creds), strconv.Itoa(row.Payloads), strconv.Itoa(row.Alerts),
			row.ASNs, row.Providers, strconv.Itoa(row.Fingerprints), row.Sequence, row.Explanation, row.First, row.Last,
		})
	}
}

// exportClustersCSV exports /clusters' own rows, same shape and filter
// scoping as the page -- including the post-aggregation ?kind= narrowing
// main.go's /clusters handler applies, since Kind only exists after
// clustersData's own aggregation and isn't part of the shared filter type
// clustersRequestFilter builds.
func (s *store) exportClustersCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="honeypot-clusters.csv"`)
	c := csv.NewWriter(w)
	defer c.Flush()
	_ = c.Write([]string{"kind", "value", "source_ips", "events", "coverage"})
	kind := r.URL.Query().Get("kind")
	for _, row := range s.clustersData(clustersRequestFilter(r)).Rows {
		if kind != "" && row.Kind != kind {
			continue
		}
		_ = c.Write([]string{row.Kind, row.Value, strconv.Itoa(row.Sources), strconv.Itoa(row.Events), row.Summary})
	}
}
