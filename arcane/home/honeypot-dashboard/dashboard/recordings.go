package main

import (
	"net/http"
	"net/url"
	"sort"
	"time"
)

// recordings.go (#1268): TTY session replays previously had no dedicated,
// browsable entry point at all -- storedEvent.TTYReplay (classify.go's
// cowrie.log.closed branch) only ever surfaced inline on that one event's
// own row inside /events or /sessions/<id>'s shared "everow" partial,
// buried among every other event. /recordings is the same shape every
// other listing page in this dashboard already has (commandsData,
// investigate.go), reading from the same in-memory s.getEvents() cache --
// no new ES query, no per-request slow work.

type recordingRow struct {
	Session, SrcIP, Country, Sensor string
	Time, TimeUTC                   string
	TTYReplay                       string
}

type recordingsPage struct {
	pageMeta
	Generated time.Time
	Rows      []recordingRow
	Filters   []string
	filterBar
}

func (s *store) recordingsData(r *http.Request) recordingsPage {
	f := parseFilter(r)
	var rows []recordingRow
	for _, e := range s.getEvents() {
		if e.TTYReplay == "" || !f.match(e) {
			continue
		}
		rows = append(rows, recordingRow{
			Session: e.Session, SrcIP: e.SrcIP, Country: e.Country, Sensor: e.Sensor,
			Time: e.Time, TimeUTC: e.UTC, TTYReplay: e.TTYReplay,
		})
	}
	// Newest first -- matches /events' own default order, and a fresh
	// recording is almost always the one an operator wants to check first.
	sort.Slice(rows, func(i, j int) bool { return rows[i].TimeUTC > rows[j].TimeUTC })
	bar := buildFilterBar(r, "/recordings",
		[2]string{"ip", "Source IP"}, [2]string{"country", "Country"}, [2]string{"since", "Since (e.g. 24h)"})
	return recordingsPage{Generated: time.Now(), Rows: rows, Filters: f.describe(), filterBar: bar}
}

// recordingsURLForIPs (#1268) links an attacker entity's own member IPs
// (attackers.go's attackerRow.RecordingsURL) to /recordings scoped to all
// of them via the shared ?ips= filter -- empty for a zero-IP entity, which
// shouldn't occur in practice but isn't this function's place to assume.
func recordingsURLForIPs(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	v := url.Values{}
	for _, ip := range ips {
		v.Add("ips", ip)
	}
	return "/recordings?" + v.Encode()
}
