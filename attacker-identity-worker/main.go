// attacker-identity-worker (#1200, part of the #1205 dashboard-
// aggregation epic): the missing piece #1204's gap analysis called out --
// no durable, entity-resolved attacker identity anywhere in this
// codebase. Merges IPs sharing 2+ strong signals (fingerprint, payload
// SHA-256, credential pair) into persistent entities in attackers-v1,
// joined against ghidra-analysis-v1's malware-family verdicts. See
// identity.go's own package-level doc comment for the merge algorithm and
// verdicts.go's for the analysis join. Depends on #1199 (correlator-worker)
// only in the sense of running alongside it and sharing the same
// event-fetch scope/limits, not on its output directly -- this worker
// reads honeypot-v2-* itself.
package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"
)

const (
	attackersIndex  = "attackers-v1"
	maxExistingLoad = 20000
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
	// Deliberately short, same reasoning as correlator-worker's own
	// CORRELATION_WINDOW -- this is how far back each CYCLE looks for new
	// evidence, not how long an identity persists (identities in
	// attackers-v1 are permanent once created; see identity.go).
	window := getenvDuration("EVIDENCE_WINDOW", 6*time.Hour)
	interval := getenvDuration("RUN_INTERVAL", 15*time.Minute)

	es := newESClient(esURL)
	for {
		runCycle(es, window)
		time.Sleep(interval)
	}
}

func runCycle(es *esClient, window time.Duration) {
	start := time.Now()

	events, ok := fetchRecentEvents(es, start.Add(-window))
	if !ok {
		log.Printf("attacker-identity-worker: fetching recent events failed, skipping this cycle")
		return
	}
	observations := buildIPObservations(events)

	existingDocs, ok := docScrollAll[entity](es, attackersIndex, maxExistingLoad)
	if !ok {
		log.Printf("attacker-identity-worker: loading existing entities failed, skipping this cycle")
		return
	}
	if len(existingDocs) == maxExistingLoad {
		log.Printf("attacker-identity-worker: existing entity population hit the %d-doc load cap -- merge candidates beyond this cap won't be considered this cycle", maxExistingLoad)
	}
	existing := make([]*entity, len(existingDocs))
	for i := range existingDocs {
		e := existingDocs[i]
		existing[i] = &e
	}

	changed, absorbed := resolveIdentities(existing, observations)

	for _, e := range changed {
		e.Updated = start.UTC().Format(time.RFC3339)
		attachVerdicts(es, e)
		body, err := json.Marshal(e)
		if err != nil {
			continue
		}
		if err := es.docIndex(attackersIndex, e.ID, body); err != nil {
			log.Printf("attacker-identity-worker: index entity %s: %v", e.ID, err)
		}
	}
	for _, id := range absorbed {
		if err := es.docDelete(attackersIndex, id); err != nil {
			log.Printf("attacker-identity-worker: delete absorbed entity %s: %v", id, err)
		}
	}

	log.Printf("attacker-identity-worker: cycle complete: %d events, %d IPs observed, %d entities updated, %d absorbed, %d existing loaded, in %s",
		len(events), len(observations), len(changed), len(absorbed), len(existingDocs), time.Since(start).Round(time.Millisecond))
}
