package main

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

// campaignRow correlates related sources by routable network over a rolling
// seven-day window. It deliberately retains only counts and short summaries;
// the link opens the complete matching event chain.
type campaignRow struct {
	CIDR         string
	Score        int
	Events       int
	UniqueIPs    int
	Sensors      string
	Ports        string
	Creds        int
	Payloads     int
	Alerts       int
	ASNs         string
	Providers    string
	Fingerprints int
	Sequence     string
	First        string
	FirstUTC     string
	Last         string
	LastUTC      string
	Link         string
	Explanation  string
}

// campaignsPage is /campaigns' page data. Previously the route reused the
// whole periodic-snapshot `snapshot` struct (s.get()) just for its
// .Campaigns field, which meant it could only ever show the cached,
// unfiltered 7-day view computed on aggregate.go's own schedule. This gives
// it a dedicated data function instead (#280) that recomputes live from the
// current request's filter, same as ipsData/commandsData/clustersData.
type campaignsPage struct {
	pageMeta
	Generated time.Time
	Campaigns []campaignRow
	Filters   []string
	ExportURL string
	filterBar
}

func (s *store) campaignsData(r *http.Request) campaignsPage {
	f := parseFilter(r)
	bar := buildFilterBar(r, "/campaigns",
		[2]string{"cidr", "Network (CIDR)"}, [2]string{"asn", "ASN"}, [2]string{"sensor", "Sensor"},
		[2]string{"since", "Since (e.g. 24h)"})
	// #513/#59: exports exactly the current filtered scope, never the
	// unfiltered set.
	exportURL := "/export/campaigns.csv"
	if encoded := r.URL.Query().Encode(); encoded != "" {
		exportURL += "?" + encoded
	}

	// #307: the plain, unfiltered page visit -- overwhelmingly the common
	// case -- is answered from the already-fresh, already-paid-for
	// aggregate.go rebuild() snapshot (at most 15s stale) instead of
	// recomputing correlateCampaigns() over the full matching event set
	// again on every single request. Any active filter still needs a live
	// recompute, since the cached snapshot only ever holds the unfiltered
	// defaultCorrelationWindow view.
	if f.cidr == "" && f.asn == "" && f.sensor == "" && f.since.IsZero() {
		return campaignsPage{Generated: time.Now(), Campaigns: s.get().Campaigns, Filters: f.describe(), ExportURL: exportURL, filterBar: bar}
	}

	// Default matches aggregate.go's own periodic snapshot window; ?since=
	// overrides it, same meaning "since" already has everywhere else.
	since := time.Now().Add(-defaultCorrelationWindow)
	if !f.since.IsZero() {
		since = f.since
	}
	return campaignsPage{
		Generated: time.Now(),
		Campaigns: correlateCampaigns(f.filtered(s.getEvents()), since),
		Filters:   f.describe(),
		ExportURL: exportURL,
		filterBar: bar,
	}
}

// balancedRecent keeps global newest-first ordering while limiting how many
// rows one sensor may occupy. This is presentation-only: aggregates and the
// /events explorer still include every parsed event.
func balancedRecent(evs []storedEvent, limit, perSensor int) []storedEvent {
	if limit <= 0 || perSensor <= 0 {
		return nil
	}
	out := make([]storedEvent, 0, min(limit, len(evs)))
	counts := make(map[string]int)
	for _, ev := range evs {
		if isOverviewNoise(ev) {
			continue
		}
		if counts[ev.Sensor] >= perSensor {
			continue
		}
		out = append(out, ev)
		counts[ev.Sensor]++
		if len(out) == limit {
			break
		}
	}
	return out
}

// isOverviewNoise removes collection faults and internal-only traffic from the
// short live sample. The complete event explorer intentionally retains them.
func isOverviewNoise(ev storedEvent) bool {
	if ev.Sensor == "suricata" && isOperationalAlert(ev.Alert) {
		return true
	}
	if ev.SrcIP == tunnelPeerIP {
		return true
	}
	if addr, err := netip.ParseAddr(ev.SrcIP); err == nil && (addr.IsLoopback() || addr.IsLinkLocalUnicast()) {
		return true
	}
	return false
}

// dedupeKey removes duplicate representations of the same observation. This
// matters most for Dionaea, where log_json and log_incident both describe a
// connection. Rich payload/auth incidents retain their own detail and remain.
func dedupeKey(ev event) string {
	if ev.sensor == "" || ev.when.IsZero() {
		return ""
	}
	detail := ev.detail
	bucket := ev.when.UnixNano()
	if ev.sensor == "dionaea" && ev.shasum == "" && ev.user == "" && ev.pass == "" {
		if strings.HasPrefix(detail, "connection.") || strings.Contains(detail, "/") {
			detail = "connection"
			bucket = ev.when.Unix() / 3
		}
	}
	return fmt.Sprintf("%s|%s|%s|%s|%d|%s|%s", ev.sensor, ev.ip, ev.port, ev.proto, bucket, detail, ev.session)
}

func campaignCIDR(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return ""
	}
	a = a.Unmap()
	bits := 64
	if a.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(a, bits).Masked().String()
}

func sortedSet(m map[string]bool, limit int) string {
	items := make([]string, 0, len(m))
	for item := range m {
		if item != "" {
			items = append(items, item)
		}
	}
	sort.Strings(items)
	if len(items) > limit {
		items = append(items[:limit], fmt.Sprintf("+%d", len(items)-limit))
	}
	return strings.Join(items, " ")
}

func correlateCampaigns(evs []storedEvent, since time.Time) []campaignRow {
	type agg struct {
		events, alerts  int
		ips, sensors    map[string]bool
		ports, creds    map[string]bool
		payloads        map[string]bool
		asns, providers map[string]bool
		fingerprints    map[string]bool
		sequence        []string
		first, last     time.Time
	}
	groups := map[string]*agg{}
	for _, e := range evs {
		if e.when.IsZero() || e.when.Before(since) {
			continue
		}
		cidr := campaignCIDR(e.SrcIP)
		if cidr == "" {
			continue
		}
		a := groups[cidr]
		if a == nil {
			a = &agg{ips: map[string]bool{}, sensors: map[string]bool{}, ports: map[string]bool{}, creds: map[string]bool{}, payloads: map[string]bool{}, asns: map[string]bool{}, providers: map[string]bool{}, fingerprints: map[string]bool{}}
			groups[cidr] = a
		}
		a.events++
		a.ips[e.SrcIP], a.sensors[e.Sensor], a.ports[e.Port] = true, true, true
		if e.IsLogin && validCredentialPair(e.User, e.Pass) {
			a.creds[e.User+" / "+e.Pass] = true
		}
		if e.Shasum != "" {
			a.payloads[e.Shasum] = true
		}
		if e.Alert != "" {
			a.alerts++
		}
		if e.ASN != 0 {
			a.asns[fmt.Sprintf("AS%d", e.ASN)] = true
		}
		if p := firstNonEmpty(e.Intel, e.Provider); p != "" {
			a.providers[p] = true
		}
		if e.Fingerprint != "" {
			a.fingerprints[e.Fingerprint] = true
		}
		if len(a.sequence) < 8 && (len(a.sequence) == 0 || a.sequence[len(a.sequence)-1] != e.Sensor) {
			a.sequence = append(a.sequence, e.Sensor)
		}
		if a.first.IsZero() || e.when.Before(a.first) {
			a.first = e.when
		}
		if e.when.After(a.last) {
			a.last = e.when
		}
	}
	rows := make([]campaignRow, 0, len(groups))
	for cidr, a := range groups {
		score := min(100, min(a.events, 30)+len(a.sensors)*15+len(a.ips)*3+len(a.creds)*8+len(a.payloads)*20+min(a.alerts, 15)*2+len(a.fingerprints)*3+len(a.providers)*2)
		var why []string
		if len(a.sensors) > 1 {
			why = append(why, fmt.Sprintf("cross-sensor activity (%d)", len(a.sensors)))
		}
		if len(a.ips) > 1 {
			why = append(why, fmt.Sprintf("%d related source IPs", len(a.ips)))
		}
		if len(a.payloads) > 0 {
			why = append(why, fmt.Sprintf("%d shared payloads", len(a.payloads)))
		}
		if len(a.creds) > 0 {
			why = append(why, fmt.Sprintf("%d reused credentials", len(a.creds)))
		}
		if a.alerts > 0 {
			why = append(why, fmt.Sprintf("%d IDS alerts", a.alerts))
		}
		if len(a.fingerprints) > 0 {
			why = append(why, fmt.Sprintf("%d fingerprints", len(a.fingerprints)))
		}
		if len(why) == 0 {
			why = append(why, "repeated activity from one routable network")
		}
		rows = append(rows, campaignRow{
			CIDR: cidr, Score: score, Events: a.events, UniqueIPs: len(a.ips),
			Sensors: sortedSet(a.sensors, 6), Ports: sortedSet(a.ports, 8),
			Creds: len(a.creds), Payloads: len(a.payloads), Alerts: a.alerts,
			ASNs: sortedSet(a.asns, 4), Providers: sortedSet(a.providers, 4), Fingerprints: len(a.fingerprints),
			Sequence: strings.Join(a.sequence, " ← "),
			First:    a.first.Format("2006-01-02 15:04"), FirstUTC: utcOrEmpty(a.first),
			Last: a.last.Format("2006-01-02 15:04"), LastUTC: utcOrEmpty(a.last),
			Link:        eventsURL(url.Values{"cidr": {cidr}, "since": {"168h"}}),
			Explanation: strings.Join(why, "; "),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		if rows[i].Events != rows[j].Events {
			return rows[i].Events > rows[j].Events
		}
		return rows[i].CIDR < rows[j].CIDR
	})
	if len(rows) > 50 {
		rows = rows[:50]
	}
	return rows
}
