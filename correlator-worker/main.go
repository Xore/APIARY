// correlator-worker (#1199, part of the #1205 dashboard-aggregation
// epic): periodically recomputes campaign (CIDR-grouped) and attacker
// cluster (fingerprint/payload/ASN-grouped) correlation over a rolling
// window of recent honeypot-v2-* events, writing the result to two flat,
// backend-computed Elasticsearch indices -- campaigns-v1 and
// attacker-clusters-v1 -- instead of every dashboard instance recomputing
// the same correlation in its own process on every rebuild cycle
// (dashboard/campaigns.go's correlateCampaigns, dashboard/intelligence.go's
// clustersData). Wiring the dashboard to read these instead of computing
// them itself is #1202, not this -- this worker only makes the data
// available, running alongside the dashboard's own existing computation
// for now, the same transition posture #1201's payload-inventory-worker
// took.
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
	// Deliberately much shorter than dashboard/intelligence.go's own
	// defaultCorrelationWindow (7 days) -- that default is fine for an
	// on-demand HTTP request; it does not fit a continuously-refreshing
	// background job's raw-document-fetch pagination cap at this
	// deployment's real volume. See fetch.go's own doc comment for the
	// full reasoning and the scale follow-up this implies.
	window := getenvDuration("CORRELATION_WINDOW", 6*time.Hour)
	interval := getenvDuration("RUN_INTERVAL", 15*time.Minute)

	es := newESClient(esURL)
	for {
		runCorrelation(es, window)
		time.Sleep(interval)
	}
}

func runCorrelation(es *esClient, window time.Duration) {
	start := time.Now()
	events, ok := fetchRecentEvents(es, start.Add(-window))
	if !ok {
		log.Printf("correlator-worker: fetching recent events failed, skipping this cycle")
		return
	}

	campaigns := correlateCampaigns(events, start)
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

	clusters := correlateClusters(events, start)
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

	log.Printf("correlator-worker: cycle complete: %d events, %d campaigns, %d clusters in %s",
		len(events), len(campaigns), len(clusters), time.Since(start).Round(time.Millisecond))
}

// clusterDocID hashes kind+value into a URL/ID-safe document ID -- cluster
// values (fingerprints, payload hashes, "AS1234 Some Org Name") carry
// arbitrary characters unsafe or awkward in a URL path, unlike campaigns'
// CIDR-shaped IDs.
func clusterDocID(kind, value string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + value))
	return hex.EncodeToString(sum[:])
}
