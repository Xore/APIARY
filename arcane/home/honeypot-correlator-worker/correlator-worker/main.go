// correlator-worker (#1199, part of the #1205 dashboard-aggregation
// epic): periodically recomputes campaign (CIDR-grouped) and attacker
// cluster (fingerprint/payload/ASN/provider-grouped) correlation over a
// rolling window of recent honeypot-v2-* events, writing the result to two
// flat, backend-computed Elasticsearch indices -- campaigns-v1 and
// attacker-clusters-v1 -- instead of every dashboard instance recomputing
// the same correlation in its own process on every rebuild cycle
// (dashboard/campaigns.go's correlateCampaigns, dashboard/intelligence.go's
// clustersData). Wiring the dashboard to read these instead of computing
// them itself is #1202, not this -- this worker only makes the data
// available, running alongside the dashboard's own existing computation
// for now, the same transition posture #1201's payload-inventory-worker
// took.
//
// #1219: the correlation itself runs as Elasticsearch-native aggregations
// (fetch.go), not a raw-document fetch-and-group-in-Go pass -- see that
// file's own doc comment for why, and correlate.go for the pure
// scoring/threshold logic that runs over the aggregation results.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"
)

const (
	campaignsIndex = "campaigns-v1"
	clustersIndex  = "attacker-clusters-v1"
)

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func getenvDuration(k string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func main() {
	esURL := getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
	// #1219: now the same 7-day default dashboard/intelligence.go's own
	// defaultCorrelationWindow uses -- the ES-native aggregation approach
	// (fetch.go) is what makes the full window affordable as a
	// continuously-refreshing background job; the previous 6h default was
	// a scale-driven compromise forced by the raw-document-fetch approach
	// this replaces. Verified live (2026-08-12): the full 7-day
	// aggregation completes in ~7s against this deployment's real volume.
	window := getenvDuration("CORRELATION_WINDOW", 7*24*time.Hour)
	interval := getenvDuration("RUN_INTERVAL", 15*time.Minute)

	es := newESClient(esURL)
	for {
		runCorrelation(es, window)
		time.Sleep(interval)
	}
}

func runCorrelation(es *esClient, window time.Duration) {
	start := time.Now()
	since := start.Add(-window)

	campaignBuckets, ok := fetchCampaignAggregates(es, since)
	if !ok {
		log.Printf("correlator-worker: fetching campaign aggregates failed, skipping this cycle")
		return
	}
	clusterBuckets, ok := fetchClusterAggregates(es, since)
	if !ok {
		log.Printf("correlator-worker: fetching cluster aggregates failed, skipping this cycle")
		return
	}
	// #1218: a failed alert-count fetch degrades this cycle's campaign
	// scoring (every group's alert term is just 0) rather than skipping
	// the whole cycle -- the honeypot-v2-* aggregations above are the
	// primary signal and already succeeded; losing the IDS-alert term for
	// one cycle isn't worth discarding it.
	alertCounts, ok := fetchSuricataAlertCounts(es, since)
	if !ok {
		log.Printf("correlator-worker: fetching suricata alert counts failed, scoring this cycle without them")
		alertCounts = nil
	}

	campaigns := scoreCampaigns(campaignBuckets, start, alertCounts)
	campaignIDs := make([]string, 0, len(campaigns))
	for _, c := range campaigns {
		id := c.CIDR
		campaignIDs = append(campaignIDs, id)
		body, err := json.Marshal(c)
		if err != nil {
			continue
		}
		if err := es.docIndex(campaignsIndex, id, body); err != nil {
			log.Printf("correlator-worker: index campaign %s: %v", id, err)
		}
	}
	if err := deleteByQueryExcept(es, campaignsIndex, campaignIDs); err != nil {
		log.Printf("correlator-worker: clean up stale campaigns: %v", err)
	}

	clusters := finalizeClusters(clusterBuckets, start)
	clusterIDs := make([]string, 0, len(clusters))
	for _, c := range clusters {
		id := clusterDocID(c.Kind, c.Value)
		clusterIDs = append(clusterIDs, id)
		body, err := json.Marshal(c)
		if err != nil {
			continue
		}
		if err := es.docIndex(clustersIndex, id, body); err != nil {
			log.Printf("correlator-worker: index cluster %s/%s: %v", c.Kind, c.Value, err)
		}
	}
	if err := deleteByQueryExcept(es, clustersIndex, clusterIDs); err != nil {
		log.Printf("correlator-worker: clean up stale clusters: %v", err)
	}

	log.Printf("correlator-worker: cycle complete: %d campaigns, %d clusters in %s",
		len(campaigns), len(clusters), time.Since(start).Round(time.Millisecond))
}

// clusterDocID hashes kind+value into a URL/ID-safe document ID -- cluster
// values (fingerprints, payload hashes, "AS1234 Some Org Name") carry
// arbitrary characters unsafe or awkward in a URL path, unlike campaigns'
// CIDR-shaped IDs.
func clusterDocID(kind, value string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + value))
	return hex.EncodeToString(sum[:])
}
