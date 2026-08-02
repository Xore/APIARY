package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

// cidrCorrelationPage is campaigns' drill-down equivalent of attackerPage's
// Correlation field (#354: "do this even for attack campaigns") -- the same
// backend query, scoped to a whole CIDR via Elasticsearch's native ip-field
// range matching instead of one IP. Deliberately its own page rather than
// eagerly queried into every row of the campaigns list: that would be one
// Elasticsearch round-trip per displayed campaign (up to 50) on every page
// view, reintroducing the same class of N-queries-per-view cost #348/#352
// already had to fix elsewhere in this dashboard. This page only queries
// when a user actually drills into one campaign.
type cidrCorrelationPage struct {
	pageMeta
	Generated   time.Time
	CIDR        string
	Correlation ipCorrelation
}

func (s *store) cidrCorrelationData(cidr string) (cidrCorrelationPage, bool) {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return cidrCorrelationPage{}, false
	}
	p := cidrCorrelationPage{Generated: time.Now(), CIDR: cidr}
	if s.es != nil {
		p.Correlation = s.es.correlateCIDR(cidr, 200)
	}
	if !p.Correlation.Available {
		return p, false
	}
	return p, true
}

// correlatedRecord is one Elasticsearch hit normalized across the three
// index families (honeypot-v2-*, suricata-*, portbridge-v2-*) that all now
// share the same source.ip/event.sensor ECS envelope (#354). Summary is a
// best-effort one-line description built from whichever source-specific
// namespace the hit actually carries.
type correlatedRecord struct {
	Time     time.Time
	Sensor   string
	Category string
	Index    string
	Summary  string
	// Portbridge-specific fields, populated only when Sensor == "portbridge"
	// -- the whole reason this exists: this data has never been queryable
	// outside the current rebuild cycle's local-file join before #354.
	TunnelViaPort int
	TunnelTarget  string
	TunnelOS      string
}

// ipCorrelation is the aggregated "everything the backend knows about this
// IP" answer -- what attackerData (the existing /investigate/ip/{ip} page)
// could never show before #354, since it only ever read the in-memory,
// log-tail-bounded event snapshot.
type ipCorrelation struct {
	Available         bool // false when Elasticsearch is unconfigured or the query failed -- advisory only, never blocks the page
	Total             int
	Truncated         bool
	Sensors           []kv
	TunnelConnections int
	TunnelOSGuesses   []string
	Records           []correlatedRecord
}

const correlationIndices = "honeypot-v2-*,suricata-*,portbridge-v2-*"
const correlationRecordCap = 500

// esHitSource mirrors just the fields correlate cares about across every
// index family's document shape -- see analysis/elasticsearch-setup.sh's
// honeypot-events-v2/suricata-events/portbridge-events templates for the
// authoritative field list. Every field here already exists in at least one
// of the three templates; unknown fields are silently ignored by
// json.Unmarshal, so this does not need to enumerate everything.
type esHitSource struct {
	Timestamp string `json:"@timestamp"`
	Event     struct {
		Sensor   string `json:"sensor"`
		Category string `json:"category"`
	} `json:"event"`
	Destination struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"destination"`
	Network struct {
		Transport string `json:"transport"`
		Protocol  string `json:"protocol"`
	} `json:"network"`
	User struct {
		Name string `json:"name"`
	} `json:"user"`
	Process struct {
		CommandLine string `json:"command_line"`
	} `json:"process"`
	URL struct {
		Path string `json:"path"`
	} `json:"url"`
	Portbridge struct {
		OS      string `json:"os"`
		ViaPort int    `json:"via_port"`
		Target  string `json:"target"`
	} `json:"portbridge"`
	Suricata struct {
		Eve struct {
			EventType string `json:"event_type"`
			Alert     struct {
				Signature string `json:"signature"`
			} `json:"alert"`
		} `json:"eve"`
	} `json:"suricata"`
	Honeypot struct {
		Eventid string `json:"eventid"`
	} `json:"honeypot"`
}

type esSearchResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Index  string      `json:"_index"`
			Source esHitSource `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

func recordSummary(src esHitSource) string {
	switch {
	case src.Event.Sensor == "portbridge":
		parts := []string{"tunnel connect"}
		if src.Destination.Port > 0 {
			parts = append(parts, fmt.Sprintf("port %d", src.Destination.Port))
		}
		if src.Portbridge.OS != "" {
			parts = append(parts, "p0f: "+src.Portbridge.OS)
		}
		return strings.Join(parts, " · ")
	case src.Suricata.Eve.Alert.Signature != "":
		return "suricata alert: " + src.Suricata.Eve.Alert.Signature
	case src.Suricata.Eve.EventType != "":
		return "suricata " + src.Suricata.Eve.EventType
	case src.Honeypot.Eventid != "":
		return src.Honeypot.Eventid
	case src.Process.CommandLine != "":
		return "command: " + truncateString(src.Process.CommandLine, 120)
	case src.URL.Path != "":
		return "path: " + src.URL.Path
	case src.User.Name != "":
		return "session as " + src.User.Name
	default:
		return firstNonEmpty(src.Event.Category, "event")
	}
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// correlate runs one bounded Elasticsearch search across every index family
// that shares the geoip-honeypot pipeline's ECS envelope and returns
// normalized hits, newest first. query must already be a safe, fully-
// escaped Lucene query-string fragment -- callers build it from a validated
// IP/CIDR (see correlateIP/correlateCIDR), never from unvalidated input.
func (c *esClient) correlate(query string, limit int) ([]correlatedRecord, int, error) {
	if c == nil || c.base == "" {
		return nil, 0, fmt.Errorf("elasticsearch is not configured")
	}
	if limit <= 0 || limit > correlationRecordCap {
		limit = correlationRecordCap
	}
	path := fmt.Sprintf("/%s/_search?q=%s&size=%d&sort=@timestamp:desc", correlationIndices, url.QueryEscape(query), limit)
	body, err := c.request(path)
	if err != nil {
		return nil, 0, err
	}
	var resp esSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, err
	}
	records := make([]correlatedRecord, 0, len(resp.Hits.Hits))
	for _, hit := range resp.Hits.Hits {
		src := hit.Source
		ts, _ := time.Parse(time.RFC3339, src.Timestamp)
		record := correlatedRecord{
			Time: ts, Sensor: firstNonEmpty(src.Event.Sensor, "unknown"), Category: src.Event.Category,
			Index: hit.Index, Summary: recordSummary(src),
		}
		if src.Event.Sensor == "portbridge" {
			record.TunnelViaPort, record.TunnelTarget, record.TunnelOS = src.Portbridge.ViaPort, src.Portbridge.Target, src.Portbridge.OS
		}
		records = append(records, record)
	}
	return records, resp.Hits.Total.Value, nil
}

// summarizeCorrelation turns raw records into the aggregate view callers
// actually render -- sensor breakdown, tunnel-connection count, and the
// distinct p0f OS guesses portbridge contributed, which is genuinely new
// information no prior version of this dashboard could show at all.
func summarizeCorrelation(records []correlatedRecord, total int) ipCorrelation {
	sensors := map[string]int{}
	osSeen := map[string]bool{}
	result := ipCorrelation{Available: true, Total: total, Records: records, Truncated: total > len(records)}
	for _, record := range records {
		sensors[record.Sensor]++
		if record.Sensor == "portbridge" {
			result.TunnelConnections++
			if record.TunnelOS != "" && !osSeen[record.TunnelOS] {
				osSeen[record.TunnelOS] = true
				result.TunnelOSGuesses = append(result.TunnelOSGuesses, record.TunnelOS)
			}
		}
	}
	result.Sensors = topN(sensors, 10)
	sort.Strings(result.TunnelOSGuesses)
	return result
}

// correlateIP answers "everything the backend knows about this IP" -- the
// literal ask behind #354. ip must already be validated (net.ParseIP or
// netip.ParseAddr) by the caller; this re-validates defensively since a
// malformed value ending up in a Lucene query string is a query-injection
// surface, not just a correctness bug.
func (c *esClient) correlateIP(ip string, limit int) ipCorrelation {
	if net.ParseIP(ip) == nil {
		return ipCorrelation{}
	}
	records, total, err := c.correlate(fmt.Sprintf(`source.ip:"%s"`, ip), limit)
	if err != nil {
		return ipCorrelation{}
	}
	return summarizeCorrelation(records, total)
}

// correlateCIDR answers the same question for a whole campaign's CIDR at
// once (#354: "do this even for attack campaigns") -- Elasticsearch's ip
// field type natively supports CIDR range queries, so this is the same
// query shape as correlateIP with one different operand, not a separate
// aggregation pipeline. Intentionally NOT called eagerly for every row of a
// campaigns list (that would be an N-queries-per-page-view cost); callers
// should only invoke this for one campaign a user has drilled into.
func (c *esClient) correlateCIDR(cidr string, limit int) ipCorrelation {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return ipCorrelation{}
	}
	records, total, err := c.correlate(fmt.Sprintf(`source.ip:"%s"`, cidr), limit)
	if err != nil {
		return ipCorrelation{}
	}
	return summarizeCorrelation(records, total)
}

// correlateIPsCap bounds how many IPs correlateIPs will fold into one Lucene
// query string -- a cluster's member set is otherwise unbounded, and an
// oversized query string is a real failure mode (URL/query-length limits),
// not just a performance concern. #354's clusters correlation only ever
// needs "is there Elasticsearch history for this cluster's members", so
// silently capping to a bounded subset is an acceptable tradeoff.
const correlateIPsCap = 200

// correlateIPs answers #354's "do this even for clusters" ask: unlike
// campaigns' compact CIDRs, a cluster's member IPs (dashboard/intelligence.go's
// clustersData) can span many unrelated networks, so there is no single
// CIDR range query that covers them -- this is the terms-query variant of
// correlateIP/correlateCIDR instead, matching Elasticsearch's ip field type
// against any of a list of exact addresses. Same "one query per drill-in,
// never eager for a bulk list view" rule as correlateCIDR.
func (c *esClient) correlateIPs(ips []string, limit int) ipCorrelation {
	valid := make([]string, 0, len(ips))
	for _, ip := range ips {
		if net.ParseIP(ip) != nil {
			valid = append(valid, ip)
		}
	}
	if len(valid) == 0 {
		return ipCorrelation{}
	}
	if len(valid) > correlateIPsCap {
		valid = valid[:correlateIPsCap]
	}
	clauses := make([]string, len(valid))
	for i, ip := range valid {
		clauses[i] = fmt.Sprintf(`"%s"`, ip)
	}
	records, total, err := c.correlate("source.ip:("+strings.Join(clauses, " OR ")+")", limit)
	if err != nil {
		return ipCorrelation{}
	}
	return summarizeCorrelation(records, total)
}
