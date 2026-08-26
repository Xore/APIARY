package main

// fetch.go -- #1219: queries honeypot-v2-* and suricata-v2-alert-* via
// real Elasticsearch-native aggregations rather than paging raw documents
// into memory and grouping in Go (correlate.go's previous approach,
// removed by this change). That approach was fine for an on-demand HTTP
// request (the former Go dashboard's correlateCampaigns/clustersData
// worked that way until the dashboard's removal, #1659); it did not scale to a continuously-refreshing background
// job at this deployment's real volume -- confirmed live during #1198/
// #1206/#1199's own verification: dionaea alone runs ~1.8M events/24h, so
// a 7-day window is tens of millions of documents, nowhere near what
// esMaxPages*esPageSize (the old cap) could cover; it was hit on every
// cycle in steady-state production traffic. Verified this design directly
// against live production Elasticsearch (2026-08-12): the full campaign
// aggregation below, run over the real 7-day window, returned in ~6.7s.
//
// Campaign grouping uses Elasticsearch's own ip_prefix aggregation (source
// .ip is mapped as ES's native `ip` type) instead of a runtime/ingest-time
// CIDR field -- it buckets by network prefix directly, matching the former
// dashboard/campaigns.go's campaignCIDR() exactly (its rule lives on as
// backend-service/src/correlator.rs's campaign_cidr; /24 for IPv4, /64 for IPv6; two
// separate ip_prefix aggregations are needed since ES ties is_ipv6 and
// prefix_length to one aggregation instance, not detected per-document).
// A CIDR bucket's routability (excluding private/loopback/link-local/the
// tunnel peer address) is filtered in Go on the returned bucket keys
// (isRoutableNetwork below) rather than duplicated as query clauses --
// ES has no single "is this a private/global-unicast address" filter, and
// re-deriving that policy as CIDR exclusion clauses would be a second,
// driftable copy of net/netip's own classification the Go standard
// library already gets right.
//
// Credential pairs need a per-bucket sub-aggregation, not a plain field --
// no honeypot.* field stores "user / pass" as one value. A scripted terms
// aggregation on a small (size 50) set of the bucket's own top pairs does
// this without pulling documents: verified live that a flattened field's
// leaf value is reachable from Painless via doc['honeypot.canonical_user']
// exactly like a real keyword field. validCredentialPair (correlate.go)
// still runs in Go against just those <=50 returned pair strings, not
// every document, so its exact filtering behavior (matching dashboard's
// TopCreds semantics) is unchanged, just applied to a far smaller input.
//
// Cluster grouping (fingerprint/payload/asn/provider) is four sibling
// terms aggregations against the same honeypot-v2-* documents, each with
// a cardinality(source.ip) sub-aggregation so the existing >=2-unique-IP
// threshold (correlate.go) can still be applied -- min_doc_count: 2 on
// the outer terms bucket is a cheap pre-filter (necessary but not
// sufficient: 2 docs from the same single IP would pass it but must still
// be excluded), the real threshold check happens in Go against each
// bucket's own unique_ips value, unchanged from before this redesign.

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const honeypotIndexPattern = "honeypot-v2-*"

// campaignBucket is one ip_prefix aggregation bucket -- the aggregation
// equivalent of the old campaignAgg, before alert-count folding and
// scoring (see correlate.go's scoreCampaigns).
type campaignBucket struct {
	CIDR         string
	Events       int
	UniqueIPs    int
	Sensors      []string
	Ports        []string
	Creds        int
	Payloads     int
	Fingerprints int
	Providers    []string
	First, Last  string
}

// termsBucketAggs is the sub-aggregation shape shared by both the IPv4
// and IPv6 campaign aggregations below -- built once so the two ip_prefix
// aggregations (which must be issued as separate aggregation instances,
// see this file's header) don't carry two independently-drifting copies
// of the same sub-aggregation set.
func campaignSubAggs() map[string]any {
	return map[string]any{
		"unique_ips": map[string]any{"cardinality": map[string]any{"field": "source.ip"}},
		"sensors":    map[string]any{"terms": map[string]any{"field": "event.sensor", "size": 20}},
		"ports":      map[string]any{"terms": map[string]any{"field": "destination.port", "size": 20}},
		"cred_pairs": map[string]any{"terms": map[string]any{
			"size": 50,
			"script": map[string]any{
				"source": "def u = doc.containsKey(params.uf) && !doc[params.uf].empty ? doc[params.uf].value : ''; def p = doc.containsKey(params.pf) && !doc[params.pf].empty ? doc[params.pf].value : ''; return u + ' / ' + p;",
				"params": map[string]any{"uf": "honeypot.canonical_user", "pf": "honeypot.canonical_pass"},
			},
		}},
		"payloads":     map[string]any{"cardinality": map[string]any{"field": "honeypot.canonical_shasum"}},
		"fingerprints": map[string]any{"cardinality": map[string]any{"field": "honeypot.canonical_fingerprint"}},
		"providers":    map[string]any{"terms": map[string]any{"field": "source.as.type", "size": 10}},
		"first":        map[string]any{"min": map[string]any{"field": "@timestamp"}},
		"last":         map[string]any{"max": map[string]any{"field": "@timestamp"}},
	}
}

type aggTermsBucket struct {
	Key      any `json:"key"` // string for keyword fields, number for destination.port
	DocCount int `json:"doc_count"`
}

type aggTerms struct {
	Buckets []aggTermsBucket `json:"buckets"`
}

type campaignAggBucket struct {
	Key          string                  `json:"key"` // the masked network address, e.g. "203.0.113.0"
	PrefixLength int                     `json:"prefix_length"`
	DocCount     int                     `json:"doc_count"`
	UniqueIPs    struct{ Value float64 } `json:"unique_ips"`
	Sensors      aggTerms                `json:"sensors"`
	Ports        aggTerms                `json:"ports"`
	CredPairs    aggTerms                `json:"cred_pairs"`
	Payloads     struct{ Value float64 } `json:"payloads"`
	Fingerprints struct{ Value float64 } `json:"fingerprints"`
	Providers    aggTerms                `json:"providers"`
	First        struct {
		ValueAsString string `json:"value_as_string"`
	} `json:"first"`
	Last struct {
		ValueAsString string `json:"value_as_string"`
	} `json:"last"`
}

// isRoutableNetwork mirrors the former dashboard/campaigns.go's
// campaignCIDR's own filter (correlator.rs's is_routable_network is its
// live copy), applied here to an aggregation bucket's masked network address
// instead of a single member IP -- same policy (public, non-private,
// non-loopback, non-link-local), see this file's header for why it isn't
// duplicated as Elasticsearch query clauses instead.
func isRoutableNetwork(networkAddr string) bool {
	a, err := netip.ParseAddr(networkAddr)
	if err != nil {
		return false
	}
	return a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}

func stringTerms(t aggTerms, limit int) []string {
	out := make([]string, 0, len(t.Buckets))
	for _, b := range t.Buckets {
		if s, ok := b.Key.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func portTerms(t aggTerms) []string {
	out := make([]string, 0, len(t.Buckets))
	for _, b := range t.Buckets {
		switch v := b.Key.(type) {
		case float64:
			out = append(out, strconv.Itoa(int(v)))
		case string:
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// cutCredPair splits a "user / pass" cred_pairs bucket key (the exact
// separator campaignSubAggs' own script concatenates with) back into its
// two parts.
func cutCredPair(s string) (user, pass string, found bool) {
	return strings.Cut(s, " / ")
}

func toBucket(b campaignAggBucket) campaignBucket {
	creds := 0
	for _, pair := range b.CredPairs.Buckets {
		s, ok := pair.Key.(string)
		if !ok {
			continue
		}
		user, pass, found := cutCredPair(s)
		if found && validCredentialPair(user, pass) {
			creds++
		}
	}
	cidr := b.Key + "/" + strconv.Itoa(b.PrefixLength)
	return campaignBucket{
		CIDR: cidr, Events: b.DocCount, UniqueIPs: int(b.UniqueIPs.Value),
		Sensors: stringTerms(b.Sensors, 6), Ports: portTerms(b.Ports),
		Creds: creds, Payloads: int(b.Payloads.Value), Fingerprints: int(b.Fingerprints.Value),
		Providers: stringTerms(b.Providers, 4),
		First:     b.First.ValueAsString, Last: b.Last.ValueAsString,
	}
}

// fetchCampaignAggregates issues one Elasticsearch query with two sibling
// ip_prefix aggregations (IPv4 /24, IPv6 /64) covering the whole window
// in a single round trip, returning one campaignBucket per routable
// network that had at least 2 events. Scoring/alert-folding happens
// afterward in correlate.go's scoreCampaigns, kept a pure function over
// plain structs so it stays unit-testable without an HTTP mock.
func fetchCampaignAggregates(es *esClient, since time.Time) ([]campaignBucket, bool) {
	subAggs := campaignSubAggs()
	body := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []map[string]any{
					{"range": map[string]any{"@timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
					{"exists": map[string]any{"field": "source.ip"}},
				},
			},
		},
		"aggs": map[string]any{
			"cidrs_v4": map[string]any{
				"ip_prefix": map[string]any{"field": "source.ip", "prefix_length": 24, "is_ipv6": false, "min_doc_count": 2},
				"aggs":      subAggs,
			},
			"cidrs_v6": map[string]any{
				"ip_prefix": map[string]any{"field": "source.ip", "prefix_length": 64, "is_ipv6": true, "min_doc_count": 2},
				"aggs":      subAggs,
			},
		},
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, false
	}
	b, err := es.searchBody("/"+honeypotIndexPattern+"/_search", reqBody)
	if err != nil {
		return nil, false
	}
	var v struct {
		Aggregations struct {
			CidrsV4 struct {
				Buckets []campaignAggBucket `json:"buckets"`
			} `json:"cidrs_v4"`
			CidrsV6 struct {
				Buckets []campaignAggBucket `json:"buckets"`
			} `json:"cidrs_v6"`
		} `json:"aggregations"`
	}
	if json.Unmarshal(b, &v) != nil {
		return nil, false
	}
	var out []campaignBucket
	for _, raw := range append(v.Aggregations.CidrsV4.Buckets, v.Aggregations.CidrsV6.Buckets...) {
		if !isRoutableNetwork(raw.Key) {
			continue
		}
		out = append(out, toBucket(raw))
	}
	return out, true
}

// clusterAggBucket is one terms-aggregation bucket for fingerprint/
// payload/asn/provider grouping.
type clusterAggBucket struct {
	Key       any                     `json:"key"`
	DocCount  int                     `json:"doc_count"`
	UniqueIPs struct{ Value float64 } `json:"unique_ips"`
	Sensors   aggTerms                `json:"sensors"`
	Org       aggTerms                `json:"org,omitempty"`
}

// fetchClusterAggregates issues one query with four sibling terms
// aggregations (fingerprint/payload/asn/provider), returning one
// clusterBucket per value seen from at least 2 distinct source IPs --
// the same >=2-unique-IP threshold correlate.go's old Go-side grouping
// enforced, applied here against each bucket's own cardinality sub-agg
// (min_doc_count: 2 in the query is a cheap pre-filter only, not the
// real threshold -- see this file's header).
func fetchClusterAggregates(es *esClient, since time.Time) ([]clusterBucket, bool) {
	withUniqueIPsAndSensors := func(extra map[string]any) map[string]any {
		aggs := map[string]any{
			"unique_ips": map[string]any{"cardinality": map[string]any{"field": "source.ip"}},
			"sensors":    map[string]any{"terms": map[string]any{"field": "event.sensor", "size": 10}},
		}
		for k, v := range extra {
			aggs[k] = v
		}
		return aggs
	}
	body := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []map[string]any{
					{"range": map[string]any{"@timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
					{"exists": map[string]any{"field": "source.ip"}},
				},
			},
		},
		"aggs": map[string]any{
			"fingerprints": map[string]any{
				"terms": map[string]any{"field": "honeypot.canonical_fingerprint", "size": 250, "min_doc_count": 2},
				"aggs":  withUniqueIPsAndSensors(nil),
			},
			"payloads": map[string]any{
				"terms": map[string]any{"field": "honeypot.canonical_shasum", "size": 250, "min_doc_count": 2},
				"aggs":  withUniqueIPsAndSensors(nil),
			},
			"asns": map[string]any{
				"terms": map[string]any{"field": "source.as.asn", "size": 250, "min_doc_count": 2},
				"aggs":  withUniqueIPsAndSensors(map[string]any{"org": map[string]any{"terms": map[string]any{"field": "source.as.organization_name", "size": 1}}}),
			},
			"providers": map[string]any{
				"terms": map[string]any{"field": "source.as.type", "size": 250, "min_doc_count": 2},
				"aggs":  withUniqueIPsAndSensors(nil),
			},
		},
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, false
	}
	b, err := es.searchBody("/"+honeypotIndexPattern+"/_search", reqBody)
	if err != nil {
		return nil, false
	}
	var v struct {
		Aggregations struct {
			Fingerprints struct{ Buckets []clusterAggBucket } `json:"fingerprints"`
			Payloads     struct{ Buckets []clusterAggBucket } `json:"payloads"`
			Asns         struct{ Buckets []clusterAggBucket } `json:"asns"`
			Providers    struct{ Buckets []clusterAggBucket } `json:"providers"`
		} `json:"aggregations"`
	}
	if json.Unmarshal(b, &v) != nil {
		return nil, false
	}
	var out []clusterBucket
	add := func(kind string, buckets []clusterAggBucket, valueOf func(clusterAggBucket) string) {
		for _, raw := range buckets {
			if int(raw.UniqueIPs.Value) < 2 {
				continue
			}
			value := valueOf(raw)
			if value == "" {
				continue
			}
			out = append(out, clusterBucket{Kind: kind, Value: value, Events: raw.DocCount, UniqueIPs: int(raw.UniqueIPs.Value), Sensors: stringTerms(raw.Sensors, 6)})
		}
	}
	add("fingerprint", v.Aggregations.Fingerprints.Buckets, func(b clusterAggBucket) string { return anyToString(b.Key) })
	add("payload", v.Aggregations.Payloads.Buckets, func(b clusterAggBucket) string { return anyToString(b.Key) })
	add("asn", v.Aggregations.Asns.Buckets, func(b clusterAggBucket) string {
		asn := anyToString(b.Key)
		if asn == "" {
			return ""
		}
		org := ""
		if len(b.Org.Buckets) > 0 {
			org = anyToString(b.Org.Buckets[0].Key)
		}
		return "AS" + asn + " " + org
	})
	add("provider", v.Aggregations.Providers.Buckets, func(b clusterAggBucket) string { return anyToString(b.Key) })
	return out, true
}

func anyToString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.Itoa(int(t))
	default:
		return ""
	}
}

const suricataAlertIndexPattern = "suricata-v2-alert-*"

// alertBucketCap is the terms aggregation's size -- one bucket per
// distinct alerting source IP within the window. Generously above what
// this deployment's real Suricata alert volume produces; a truncated
// aggregation (Elasticsearch simply returns its top alertBucketCap IPs by
// doc count, not a random subset) degrades gracefully -- the
// highest-volume alerters, the ones that matter most for campaign
// scoring, are exactly the ones a truncated result still keeps.
const alertBucketCap = 10000

// fetchSuricataAlertCounts returns, for every source IP that triggered at
// least one Suricata alert at or after since, how many. An ES-native terms
// aggregation (size: 0, no hits) rather than a raw-document page-and-count
// -- only the per-IP count is ever used (scoreCampaigns folds it into
// whichever CIDR group each alerting IP's own campaignCIDR() belongs to,
// a pure Go computation independent of how the campaign buckets
// themselves were fetched), so there's no reason to pull the alert
// documents themselves into this worker's memory at all.
func fetchSuricataAlertCounts(es *esClient, since time.Time) (map[string]int, bool) {
	body := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []map[string]any{
					{"range": map[string]any{"@timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
					{"exists": map[string]any{"field": "source.ip"}},
				},
			},
		},
		"aggs": map[string]any{
			"by_ip": map[string]any{
				"terms": map[string]any{"field": "source.ip", "size": alertBucketCap},
			},
		},
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, false
	}
	status, b, err := es.doRequest(http.MethodPost, "/"+suricataAlertIndexPattern+"/_search", reqBody)
	if err != nil {
		return nil, false
	}
	if status == http.StatusNotFound {
		// No suricata-v2-alert-* index yet (no alerts ever shipped on this
		// deployment) is not a failure -- the honeypot-v2-* fetch above
		// already runs regardless, campaign scoring just gets a zero
		// alert count for every group, same as before this signal existed.
		return map[string]int{}, true
	}
	if status/100 != 2 {
		return nil, false
	}
	var v struct {
		Aggregations struct {
			ByIP struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"by_ip"`
		} `json:"aggregations"`
	}
	if json.Unmarshal(b, &v) != nil {
		return nil, false
	}
	counts := make(map[string]int, len(v.Aggregations.ByIP.Buckets))
	for _, bucket := range v.Aggregations.ByIP.Buckets {
		counts[bucket.Key] = bucket.DocCount
	}
	return counts, true
}

// tunnelPeerIP matches ip-enrichment-worker/dashboard's own constant.
// Kept even though isRoutableNetwork already excludes the whole 10.8.0.0/24
// network the tunnel peer lives in -- scoreCampaigns' alert-count folding
// (correlate.go) still needs it directly to skip an unresolved connection's
// synthetic address before computing its own campaignCIDR().
const tunnelPeerIP = "10.8.0.1"
