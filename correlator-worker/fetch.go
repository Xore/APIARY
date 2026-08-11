package main

// fetch.go -- reads recent events from honeypot-v2-* for correlate.go to
// group. Deliberately narrower than dashboard/classify.go's full per-sensor
// field mapping: reads only the already-ES-native fields (source.ip,
// event.sensor, destination.port, @timestamp) plus the canonical_* fields
// #1197 promotes at ingest time (honeypot.canonical_user/pass/shasum/
// fingerprint/fingerprint_kind) for the sensors #1197 currently covers
// (cowrie, dionaea, cisco-asa-honeypot). Every other sensor still
// contributes CIDR/sensor/IP grouping (campaigns' baseline signal) but not
// yet creds/payload/fingerprint signal -- the same "#1199 depends
// partially on #1197" gap #1204's gap analysis already flagged, closing
// automatically as #1197 covers more sensors.
//
// ASN grouping reads source.as.asn/source.as.organization_name, populated
// by the geoip-honeypot ingest pipeline (analysis/elasticsearch-setup.sh)
// -- if that pipeline's GeoLite2-ASN.mmdb isn't provisioned on a given
// deployment, these fields are simply absent and ASN clustering finds
// nothing, the same graceful-degrade-by-absence every other ES-native
// aggregate in this codebase already relies on.
//
// Scale: this fetches raw documents into memory and correlates in Go,
// the same approach dashboard/campaigns.go's correlateCampaigns and
// dashboard/intelligence.go's clustersData already use (the epic's own
// "logic ported from campaigns.go/intelligence.go rather than shared as a
// package" decision) -- not an Elasticsearch-native aggregation. That's
// fine at the volume a single HTTP request handles on demand; it does NOT
// scale to dashboard's own 7-day defaultCorrelationWindow as a
// continuously-refreshing background job at this deployment's real
// traffic (confirmed live during #1198/#1206: dionaea alone runs
// ~1.8M events/24h) -- 7 days would be tens of millions of documents,
// nowhere near esMaxPages*esPageSize. main.go's default CORRELATION_WINDOW
// is deliberately much shorter than dashboard's page default for exactly
// this reason; fetchRecentEvents logs if it hits the page cap so silent
// truncation is at least visible. Moving this to a real ES-native
// aggregation (a composite agg keyed by a runtime or ingest-time CIDR
// field) is the right fix for a deployment whose volume needs the full
// 7-day window continuously refreshed -- a distinct, larger follow-up.

import (
	"encoding/json"
	"log"
	"strconv"
	"time"
)

const (
	honeypotIndexPattern = "honeypot-v2-*"
	esPageSize           = 10000
	esMaxPages           = 50
)

// corrEvent is the subset of one honeypot-v2-* document this worker
// correlates on.
type corrEvent struct {
	When        time.Time
	SrcIP       string
	Sensor      string
	Port        string
	User, Pass  string
	Shasum      string
	Fingerprint string
	ASN         int64
	ASNOrg      string
}

// fetchRecentEvents pages through every honeypot-v2-* document at or after
// since, via PIT + search_after -- same pattern dashboard/events_es.go's
// loadSensorEventsES uses, ported here since this worker has no shared
// package with dashboard.
func fetchRecentEvents(es *esClient, since time.Time) ([]corrEvent, bool) {
	pitID, ok := es.openPointInTime(honeypotIndexPattern, "2m")
	if !ok {
		return nil, false
	}
	defer es.closePointInTime(pitID)

	var out []corrEvent
	var searchAfter []any
	for page := 0; page < esMaxPages; page++ {
		body := map[string]any{
			"size": esPageSize,
			"pit":  map[string]any{"id": pitID, "keep_alive": "2m"},
			"sort": []map[string]any{
				{"@timestamp": "asc"},
				{"_shard_doc": "asc"},
			},
			"query": map[string]any{
				"bool": map[string]any{
					"filter": []map[string]any{
						{"range": map[string]any{"@timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
						{"exists": map[string]any{"field": "source.ip"}},
					},
				},
			},
			"_source": []string{
				"@timestamp", "source.ip", "event.sensor", "destination.port",
				"honeypot.canonical_user", "honeypot.canonical_pass", "honeypot.canonical_shasum",
				"honeypot.canonical_fingerprint",
				"source.as.asn", "source.as.organization_name",
			},
		}
		if searchAfter != nil {
			body["search_after"] = searchAfter
		}
		reqBody, err := json.Marshal(body)
		if err != nil {
			break
		}
		b, err := es.searchBody("/_search", reqBody)
		if err != nil {
			break
		}
		var v struct {
			Hits struct {
				Hits []struct {
					Sort   []any `json:"sort"`
					Source struct {
						Timestamp string `json:"@timestamp"`
						Source    struct {
							IP string `json:"ip"`
							AS struct {
								ASN              int64  `json:"asn"`
								OrganizationName string `json:"organization_name"`
							} `json:"as"`
						} `json:"source"`
						Event struct {
							Sensor string `json:"sensor"`
						} `json:"event"`
						Destination struct {
							Port int `json:"port"`
						} `json:"destination"`
						Honeypot struct {
							CanonicalUser        string `json:"canonical_user"`
							CanonicalPass        string `json:"canonical_pass"`
							CanonicalShasum      string `json:"canonical_shasum"`
							CanonicalFingerprint string `json:"canonical_fingerprint"`
						} `json:"honeypot"`
					} `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if json.Unmarshal(b, &v) != nil || len(v.Hits.Hits) == 0 {
			break
		}
		for _, h := range v.Hits.Hits {
			when, _ := time.Parse(time.RFC3339, h.Source.Timestamp)
			ip := h.Source.Source.IP
			if ip == "" || ip == tunnelPeerIP {
				continue
			}
			port := ""
			if h.Source.Destination.Port != 0 {
				port = strconv.Itoa(h.Source.Destination.Port)
			}
			out = append(out, corrEvent{
				When: when, SrcIP: ip, Sensor: h.Source.Event.Sensor, Port: port,
				User: h.Source.Honeypot.CanonicalUser, Pass: h.Source.Honeypot.CanonicalPass,
				Shasum: h.Source.Honeypot.CanonicalShasum, Fingerprint: h.Source.Honeypot.CanonicalFingerprint,
				ASN: h.Source.Source.AS.ASN, ASNOrg: h.Source.Source.AS.OrganizationName,
			})
		}
		if len(v.Hits.Hits) < esPageSize {
			break
		}
		searchAfter = v.Hits.Hits[len(v.Hits.Hits)-1].Sort
		if page == esMaxPages-1 {
			log.Printf("correlator-worker: hit the %d-page cap (%d events) before exhausting the window since %s -- results this cycle are truncated to the oldest events in range, not the full window; narrow CORRELATION_WINDOW or raise esMaxPages",
				esMaxPages, esMaxPages*esPageSize, since.UTC().Format(time.RFC3339))
		}
	}
	return out, true
}

// tunnelPeerIP matches ip-enrichment-worker/dashboard's own constant --
// an event still carrying it means the via_port join hasn't resolved this
// connection yet (see #1198/#1206); it's never a real attacker, so it must
// never seed a campaign or cluster.
const tunnelPeerIP = "10.8.0.1"
