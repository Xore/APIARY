// payload-inventory-worker (#1201, part of the #1205 dashboard-aggregation
// epic): moves the payload inventory's write side -- discovering and
// classifying every captured file under a set of capture directories --
// off dashboard/payloads_data.go's scanPayloads (a per-dashboard-instance
// disk walk gated on that instance mounting PAYLOAD_DIRS) into one
// standalone worker, matching the pattern ghidra-worker/es-results-importer
// already established for other analysis pipelines: one process writes,
// every dashboard instance reads the same Elasticsearch documents. See
// scan.go's own doc comment for exactly what moved and what didn't.
package main

import (
	"log"
	"os"
	"strings"
	"time"
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
	interval := getenvDuration("SCAN_INTERVAL", 5*time.Minute)

	var dirs []string
	seen := map[string]bool{}
	for _, d := range strings.Split(os.Getenv("PAYLOAD_DIRS"), ",") {
		d = strings.TrimSpace(d)
		if d == "" || seen[d] {
			continue
		}
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			dirs = append(dirs, d)
			seen[d] = true
			log.Printf("payload-inventory-worker: capture source enabled: %s", d)
		} else {
			log.Printf("payload-inventory-worker: %s: not a directory, skipping", d)
		}
	}
	if len(dirs) == 0 {
		log.Fatal("payload-inventory-worker: no valid PAYLOAD_DIRS entries, nothing to scan")
	}

	es := newESClient(esURL)
	for {
		runScan(es, dirs)
		time.Sleep(interval)
	}
}

func runScan(es *esClient, dirs []string) {
	start := time.Now()
	files, paths := scanDirs(dirs)
	failures := indexPayloadInventory(es, files)
	for _, file := range files {
		if path, ok := paths[file.Hash]; ok {
			if err := mirrorPayloadBytes(es, file.Hash, path, file.Size); err != nil {
				failures++
			}
		}
	}
	if failures > 0 {
		log.Printf("payload-inventory-worker: scan complete WITH %d elasticsearch failure(s): %d unique files in %s", failures, len(files), time.Since(start).Round(time.Millisecond))
		return
	}
	log.Printf("payload-inventory-worker: scan complete: %d unique files in %s", len(files), time.Since(start).Round(time.Millisecond))
}
