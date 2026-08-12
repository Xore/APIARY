package main

import (
	"encoding/json"
	"net/http"
)

// scanner_fingerprints.go (#1275): suricata-v2-ssh-*/suricata-v2-tls-*
// capture a connection-level fingerprint for EVERY wire-level connection,
// including pure scanners that connect and disconnect without cowrie/
// dionaea ever completing a session. classify.go's suricata branch already
// reads tls.ja4/ssh.client.software_version into ev.fingerprint, but only
// for event_type=="alert" -- the much larger population of plain ssh/tls
// event-type records (everything that triggered no IDS signature, i.e.
// most scanner traffic) is skipped there entirely (ev.skip=true, same
// "would swamp the per-event table" reasoning netflow's own records get).
// This bypasses that per-event pipeline the same way netflow_volume.go and
// dionaea_cve_chart.go do: a live ES terms aggregation directly against
// the wire-level index, independent of whether any connection ever
// produced an alert.
//
// suricata-v2-tls-* mixes genuine attacker connections with this
// deployment's OWN legitimate HTTPS traffic (Traefik-fronted operator
// subdomains -- auth., dashboard, monitoring, admin tooling -- confirmed
// live: one sample was a Cloudflare-range IP hitting the dashboard's own
// SNI). Confirmed live that dest_port 443 alone accounts for ~10,800 of
// ~11,900 sampled TLS docs and is dominated by exactly those operator
// hostnames, while the honeypot's own decoy TLS-adjacent ports (8443,
// 4443, 3389, 44818/EtherNet-IP, 2404/IEC-104, etc.) carry the real
// scanner traffic -- excluding dest_port 443 is a simpler, more durable
// filter than maintaining a Cloudflare CIDR allowlist (the issue's other
// proposed option) and was confirmed to cleanly separate the two
// populations. suricata-v2-ssh-* needs no such filter: port 22 is a
// honeypot-only port, this deployment exposes no legitimate SSH service.
//
// JA4 alone (not falling back to JA3 the way classify.go's alert-path
// fingerprint reader does) is enough for this chart: confirmed live that
// zero non-443 TLS docs in the current index lack tls.ja4.
const scannerFingerprintWindow = "now-7d"

const tlsFingerprintQuery = `{
  "size": 0,
  "query": {
    "bool": {
      "filter": [{"range": {"@timestamp": {"gte": "` + scannerFingerprintWindow + `"}}}],
      "must_not": [{"term": {"suricata.eve.dest_port": 443}}]
    }
  },
  "aggs": {"ja4": {"terms": {"field": "suricata.eve.tls.ja4.keyword", "size": 15}}}
}`

const sshFingerprintQuery = `{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "` + scannerFingerprintWindow + `"}}},
  "aggs": {"software": {"terms": {"field": "suricata.eve.ssh.client.software_version.keyword", "size": 15}}}
}`

type scannerFingerprintResponse struct {
	Aggregations map[string]struct {
		Buckets []struct {
			Key      string `json:"key"`
			DocCount int    `json:"doc_count"`
		} `json:"buckets"`
	} `json:"aggregations"`
}

// scannerFingerprintBar is the {categories, values} bar shape
// hp-kill-chain.js's generic initBar already consumes (#1294/#1276).
type scannerFingerprintBar struct {
	Categories []string `json:"categories"`
	Values     []int    `json:"values"`
}

// fetchScannerFingerprints runs query against index and reshapes the named
// aggregation's buckets into a bar. aggName lets one function serve both
// endpoints below without duplicating the ES round trip/reshape logic.
func (s *store) fetchScannerFingerprints(index, aggName string, query []byte) (scannerFingerprintBar, bool) {
	if s.es == nil {
		return scannerFingerprintBar{}, false
	}
	b, err := s.es.searchBody("/"+index+"/_search", query)
	if err != nil {
		return scannerFingerprintBar{}, false
	}
	var resp scannerFingerprintResponse
	if json.Unmarshal(b, &resp) != nil {
		return scannerFingerprintBar{}, false
	}
	agg, ok := resp.Aggregations[aggName]
	if !ok {
		return scannerFingerprintBar{}, false
	}
	out := scannerFingerprintBar{
		Categories: make([]string, 0, len(agg.Buckets)),
		Values:     make([]int, 0, len(agg.Buckets)),
	}
	for _, b := range agg.Buckets {
		out.Categories = append(out.Categories, b.Key)
		out.Values = append(out.Values, b.DocCount)
	}
	return out, true
}

func (s *store) serveTLSFingerprints(w http.ResponseWriter, r *http.Request) {
	bar, ok := s.fetchScannerFingerprints("suricata-v2-tls-*", "ja4", []byte(tlsFingerprintQuery))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		http.Error(w, "TLS fingerprint data unavailable", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(bar)
}

func (s *store) serveSSHFingerprints(w http.ResponseWriter, r *http.Request) {
	bar, ok := s.fetchScannerFingerprints("suricata-v2-ssh-*", "software", []byte(sshFingerprintQuery))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		http.Error(w, "SSH client fingerprint data unavailable", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(bar)
}
