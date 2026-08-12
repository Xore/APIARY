package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// defaultCorrelationWindow bounds /campaigns and /clusters to a recent
// slice of history by default (#307) -- both pages correlate every matching
// event into per-key groups (per-CIDR for campaigns, per-fingerprint/
// payload/ASN/provider for clusters), which means an unbounded default
// walks the ENTIRE all-time event history on every page load. An operator
// who genuinely needs the full history can still widen it explicitly via
// ?since=. Shared by both so their defaults can't silently drift apart.
const defaultCorrelationWindow = 7 * 24 * time.Hour

// attackTechnique is a conservative, evidence-derived ATT&CK annotation. It
// describes behavior observed by a honeypot; it is not an attribution claim.
type attackTechnique struct {
	ID       string
	Name     string
	Domain   string
	Evidence string
	URL      string
	Count    int
}

func technique(id, name, domain, evidence string) attackTechnique {
	path := "techniques/" + strings.ReplaceAll(id, ".", "/")
	return attackTechnique{ID: id, Name: name, Domain: domain, Evidence: evidence, URL: "https://attack.mitre.org/" + path + "/"}
}

func techniquesForEvent(e storedEvent) []attackTechnique {
	text := strings.ToLower(strings.Join([]string{e.Command, e.Path, e.Alert, e.Detail}, " "))
	var out []attackTechnique
	if e.IsLogin || e.HasCredential {
		out = append(out, technique("T1110", "Brute Force", "Enterprise", "credential attempt"))
	}
	if e.Command != "" {
		id, name := "T1059", "Command and Scripting Interpreter"
		switch {
		case strings.Contains(text, "powershell") || strings.Contains(text, "pwsh"):
			id, name = "T1059.001", "PowerShell"
		case strings.Contains(text, "cmd.exe") || strings.Contains(text, "cmd /c"):
			id, name = "T1059.003", "Windows Command Shell"
		case strings.Contains(text, "/bin/sh") || strings.Contains(text, "bash") || strings.Contains(text, "wget") || strings.Contains(text, "curl"):
			id, name = "T1059.004", "Unix Shell"
		}
		out = append(out, technique(id, name, "Enterprise", "command captured"))
	}
	if e.Shasum != "" || e.Download != "" || strings.Contains(text, "wget") || strings.Contains(text, "curl") || strings.Contains(text, "invoke-webrequest") || strings.Contains(text, "downloadstring") {
		out = append(out, technique("T1105", "Ingress Tool Transfer", "Enterprise", "payload transfer or downloader"))
	}
	if e.Path != "" && (e.Alert != "" || strings.ContainsAny(e.Path, "?%") || strings.Contains(text, "../") || strings.Contains(text, "wp-") || strings.Contains(text, "php")) {
		out = append(out, technique("T1190", "Exploit Public-Facing Application", "Enterprise", "web exploit or probing evidence"))
	}
	if e.Fingerprint != "" && e.Command == "" && !e.IsLogin {
		out = append(out, technique("T1595", "Active Scanning", "Enterprise", "scanner/client fingerprint"))
	}
	ot := strings.ToLower(strings.Join([]string{e.Sensor, e.Proto, e.Asset, e.Alert, e.Detail}, " "))
	if strings.Contains(ot, "conpot") || strings.Contains(ot, "modbus") || strings.Contains(ot, "s7") || strings.Contains(ot, "iec104") || strings.Contains(ot, "dnp3") || strings.Contains(ot, "enip") {
		out = append(out, technique("T0886", "Remote Services", "ICS", "industrial protocol interaction"))
		if e.Alert != "" || e.Command != "" || strings.Contains(ot, "write") || strings.Contains(ot, "command") {
			out = append(out, technique("T1692.001", "Unauthorized Message: Command Message", "ICS", "control command or write attempt"))
		}
	}
	return uniqueTechniques(out)
}

func uniqueTechniques(in []attackTechnique) []attackTechnique {
	seen := map[string]bool{}
	out := make([]attackTechnique, 0, len(in))
	for _, item := range in {
		if seen[item.ID] {
			continue
		}
		seen[item.ID] = true
		out = append(out, item)
	}
	return out
}

func aggregateTechniques(events []storedEvent) []attackTechnique {
	rows := map[string]attackTechnique{}
	for _, event := range events {
		for _, item := range techniquesForEvent(event) {
			current := rows[item.ID]
			if current.ID == "" {
				current = item
			}
			current.Count++
			rows[item.ID] = current
		}
	}
	out := make([]attackTechnique, 0, len(rows))
	for _, row := range rows {
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].ID < out[j].ID
	})
	return out
}

type sessionPage struct {
	pageMeta
	Generated                                time.Time
	ID, IP, Country, First, Last             string
	FirstUTC, LastUTC                        string
	Total                                    int
	Sensors, Commands, Credentials, Payloads []kv
	Techniques                               []attackTechnique
	Events                                   []storedEvent
}

func (s *store) sessionData(id string) (sessionPage, bool) {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 256 {
		return sessionPage{}, false
	}
	p := sessionPage{Generated: time.Now(), ID: id}
	sensors, commands, creds, payloads := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	for _, event := range s.getEvents() {
		if event.Session != id {
			continue
		}
		p.Events = append(p.Events, event)
		p.Total++
		if p.Last == "" {
			p.Last, p.LastUTC, p.IP, p.Country = event.Time, event.UTC, event.SrcIP, event.Country
		}
		p.First, p.FirstUTC = event.Time, event.UTC
		sensors[event.Sensor]++
		if event.Command != "" {
			commands[event.Command]++
		}
		if event.HasCredential {
			creds[event.User+" / "+event.Pass]++
		}
		if event.Shasum != "" {
			payloads[event.Shasum]++
		}
	}
	if p.Total == 0 {
		return p, false
	}
	for i, j := 0, len(p.Events)-1; i < j; i, j = i+1, j-1 {
		p.Events[i], p.Events[j] = p.Events[j], p.Events[i]
	}
	p.Sensors, p.Commands, p.Credentials, p.Payloads = topN(sensors, 20), topN(commands, 30), topN(creds, 20), topN(payloads, 20)
	p.Techniques = aggregateTechniques(p.Events)
	return p, true
}

type clusterRow struct {
	Kind, Value, Summary, Link string
	Events, Sources            int
}

type clustersPage struct {
	pageMeta
	// Ready mirrors s.ready.Load() -- see eventsPage's own comment (#1142/#1155).
	Ready     bool
	Generated time.Time
	Rows      []clusterRow
	Filters   []string
	ExportURL string
	filterBar
}

// clustersRequestFilter builds the filter a live /clusters HTTP request
// should use (#307): same as parseFilter(r), except an absent ?since=
// defaults to defaultCorrelationWindow instead of leaving the correlation
// genuinely unbounded -- clustersData itself has no default at all (every
// other filter.match() caller either has one, like campaignsData, or is
// aggregate.go's own deliberately-unfiltered periodic snapshot call), so an
// ordinary page visit walked every event this dashboard has ever recorded.
// Kept separate from parseFilter/clustersData so that periodic snapshot
// call site (clustersData(filter{})) stays genuinely unfiltered.
func clustersRequestFilter(r *http.Request) filter {
	f := parseFilter(r)
	if f.since.IsZero() {
		f.since = time.Now().Add(-defaultCorrelationWindow)
	}
	return f
}

// clustersData takes a filter directly rather than *http.Request (unlike
// ipsData/commandsData) because it has a genuine non-HTTP caller --
// aggregate.go's periodic intelligence snapshot -- which has no request to
// parse and always wants the unfiltered view (filter{}).
func (s *store) clustersData(f filter) clustersPage {
	// #1222: unlike campaignsData, clustersData has never had a caching
	// fast path at all -- every /clusters visit (filtered or not)
	// recomputed from every matching raw event on every request. Prefer
	// correlator-worker's own attacker-clusters-v1 (#1219) for the default
	// view, falling back to the recompute below on any read failure (index
	// not created yet, ES unreachable, worker never deployed).
	if f.isDefaultCorrelationView() {
		if rows, ok := s.readClustersFromWorkerIndex(); ok {
			return clustersPage{Generated: time.Now(), Rows: rows, Filters: f.describe()}
		}
	}
	type agg struct {
		events       int
		ips, sensors map[string]bool
	}
	groups := map[string]*agg{}
	add := func(kind, value, ip, sensor string) {
		value = strings.TrimSpace(value)
		if value == "" || ip == "" {
			return
		}
		key := kind + "\x00" + value
		a := groups[key]
		if a == nil {
			a = &agg{ips: map[string]bool{}, sensors: map[string]bool{}}
			groups[key] = a
		}
		a.events++
		a.ips[ip] = true
		a.sensors[sensor] = true
	}
	for _, e := range s.getEvents() {
		if !f.match(e) {
			continue
		}
		add("Fingerprint", e.Fingerprint, e.SrcIP, e.Sensor)
		add("Payload", e.Shasum, e.SrcIP, e.Sensor)
		if e.ASN != 0 {
			add("Autonomous system", fmt.Sprintf("AS%d %s", e.ASN, e.Org), e.SrcIP, e.Sensor)
		}
		if provider := firstNonEmpty(e.Intel, e.Provider); provider != "" {
			add("Provider class", provider, e.SrcIP, e.Sensor)
		}
	}
	var rows []clusterRow
	for key, a := range groups {
		if len(a.ips) < 2 {
			continue
		}
		kind, value, _ := strings.Cut(key, "\x00")
		param := "q"
		switch kind {
		case "Fingerprint":
			param = "fingerprint"
		case "Payload":
			param = "shasum"
		case "Provider class":
			param = "provider"
		case "Autonomous system":
			param = "asn"
			if fields := strings.Fields(value); len(fields) > 0 {
				value = strings.TrimPrefix(fields[0], "AS")
			}
		}
		linkValue := value
		displayValue := strings.Split(key, "\x00")[1]
		rows = append(rows, clusterRow{Kind: kind, Value: displayValue, Events: a.events, Sources: len(a.ips), Summary: fmt.Sprintf("%d sensors: %s", len(a.sensors), sortedSet(a.sensors, 6)), Link: eventsURL(url.Values{param: {linkValue}})})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Sources != rows[j].Sources {
			return rows[i].Sources > rows[j].Sources
		}
		if rows[i].Events != rows[j].Events {
			return rows[i].Events > rows[j].Events
		}
		// #40: Sources and Events both tying is routine for the smaller
		// clusters -- without a final unique tiebreaker, sort.Slice's lack
		// of a stability guarantee plus Go's randomized map iteration order
		// (groups above) means two dashboard instances reading identical
		// underlying events could render this table in a different row
		// order. Kind+Value is the original map key, so it's unique.
		if rows[i].Kind != rows[j].Kind {
			return rows[i].Kind < rows[j].Kind
		}
		return rows[i].Value < rows[j].Value
	})
	if len(rows) > 250 {
		rows = rows[:250]
	}
	return clustersPage{Generated: time.Now(), Rows: rows, Filters: f.describe()}
}

const clustersIndex = "attacker-clusters-v1"

// clusterWorkerDoc mirrors correlator-worker/correlate.go's own
// clusterDoc field-for-field.
type clusterWorkerDoc struct {
	Kind    string   `json:"kind"`
	Value   string   `json:"value"`
	Events  int      `json:"events"`
	Sources int      `json:"sources"`
	Sensors []string `json:"sensors"`
}

// clusterWorkerKindLabels maps correlator-worker's own lowercase,
// single-word kind convention (fingerprint/payload/asn/provider -- see
// correlate.go's clusterDoc doc comment for why it deliberately doesn't
// match dashboard's display strings) back to the exact Title Case labels
// clusterRow.Kind has always used -- filters.go's own "kind" dropdown
// (?kind=) and main.go's /clusters handler both compare against these
// literal strings, so a worker-sourced row must carry the same ones a
// locally-computed row would.
var clusterWorkerKindLabels = map[string]string{
	"fingerprint": "Fingerprint",
	"payload":     "Payload",
	"asn":         "Autonomous system",
	"provider":    "Provider class",
}

// readClustersFromWorkerIndex reads correlator-worker's own
// attacker-clusters-v1 (#1219, #1222) instead of recomputing in-process.
func (s *store) readClustersFromWorkerIndex() ([]clusterRow, bool) {
	if s.es == nil {
		return nil, false
	}
	hits, err := s.es.docSearchAll(clustersIndex, 250)
	if err != nil || len(hits) == 0 {
		return nil, false
	}
	rows := make([]clusterRow, 0, len(hits))
	for _, hit := range hits {
		var doc clusterWorkerDoc
		if json.Unmarshal(hit.Source, &doc) != nil || doc.Value == "" {
			continue
		}
		kind, ok := clusterWorkerKindLabels[doc.Kind]
		if !ok {
			continue
		}
		param, linkValue := "q", doc.Value
		switch kind {
		case "Fingerprint":
			param = "fingerprint"
		case "Payload":
			param = "shasum"
		case "Provider class":
			param = "provider"
		case "Autonomous system":
			param = "asn"
			if fields := strings.Fields(doc.Value); len(fields) > 0 {
				linkValue = strings.TrimPrefix(fields[0], "AS")
			}
		}
		rows = append(rows, clusterRow{
			Kind: kind, Value: doc.Value, Events: doc.Events, Sources: doc.Sources,
			Summary: fmt.Sprintf("%d sensors: %s", len(doc.Sensors), strings.Join(doc.Sensors, " ")),
			Link:    eventsURL(url.Values{param: {linkValue}}),
		})
	}
	if len(rows) == 0 {
		return nil, false
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Sources != rows[j].Sources {
			return rows[i].Sources > rows[j].Sources
		}
		if rows[i].Events != rows[j].Events {
			return rows[i].Events > rows[j].Events
		}
		if rows[i].Kind != rows[j].Kind {
			return rows[i].Kind < rows[j].Kind
		}
		return rows[i].Value < rows[j].Value
	})
	return rows, true
}

// clusterIPs recomputes one specific cluster's member IP set by kind+value
// -- the same grouping clustersData uses, scoped to a single key instead of
// building all 250 rows at once. #354's "do this even for clusters": unlike
// clustersData's own rows (which keep only a *count* of member IPs, per
// clusterRow's doc comment), this is the one place that actually needs the
// full IP list, to hand to esClient.correlateIPs.
//
// Deliberately unfiltered by date/sensor/etc (unlike clustersData(f
// filter)): this recomputes "every IP this dashboard has ever seen sharing
// this fingerprint/payload/ASN/provider", not whatever time window happened
// to be active on the /clusters list view a user drilled in from -- a
// broader, more useful answer for "what does the backend know about this
// cluster overall", and it avoids threading filter state through yet
// another route.
func (s *store) clusterIPs(kind, value string) []string {
	ips := map[string]bool{}
	for _, e := range s.getEvents() {
		var k, v string
		switch kind {
		case "Fingerprint":
			k, v = "Fingerprint", e.Fingerprint
		case "Payload":
			k, v = "Payload", e.Shasum
		case "Autonomous system":
			if e.ASN != 0 {
				k, v = "Autonomous system", fmt.Sprintf("AS%d %s", e.ASN, e.Org)
			}
		case "Provider class":
			k, v = "Provider class", firstNonEmpty(e.Intel, e.Provider)
		}
		if k == kind && v == value && e.SrcIP != "" {
			ips[e.SrcIP] = true
		}
	}
	result := make([]string, 0, len(ips))
	for ip := range ips {
		result = append(result, ip)
	}
	return result
}

// clusterCorrelationPage is clusters' drill-down equivalent of campaigns'
// cidrCorrelationPage (dashboard/ip_correlation.go) -- the same backend
// query, scoped to a cluster's recomputed member IP set via Elasticsearch's
// terms matching instead of a CIDR range. Its own page for the same reason
// cidrCorrelationPage is its own page: querying eagerly for every row of
// the clusters list would be an Elasticsearch round-trip per displayed
// cluster (up to 250) on every page view.
type clusterCorrelationPage struct {
	pageMeta
	Generated   time.Time
	Kind, Value string
	IPCount     int
	Correlation ipCorrelation
}

func (s *store) clusterCorrelationData(kind, value string) (clusterCorrelationPage, bool) {
	ips := s.clusterIPs(kind, value)
	if len(ips) < 2 {
		// Matches clustersData's own "not a cluster" threshold -- a single
		// IP sharing a value with no one else isn't a cluster to correlate.
		return clusterCorrelationPage{}, false
	}
	p := clusterCorrelationPage{Generated: time.Now(), Kind: kind, Value: value, IPCount: len(ips)}
	if s.es != nil {
		p.Correlation = s.es.correlateIPs(ips, 200)
	}
	if !p.Correlation.Available {
		return p, false
	}
	return p, true
}
