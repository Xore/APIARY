package main

import (
	"encoding/json"
	"net/http"
)

// osDistributionPoint is one ECharts pie-series data point -- {name, value}
// is ECharts' own native shape for pie chart data, so the JS side
// (hp-kill-chain.js's generic initPie, shared with the kill-chain page's
// own charts) passes this straight through with no reshaping.
type osDistributionPoint struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// serveOSDistribution answers /api/os-distribution (#1277): p0f's own OS
// guess (classify.go's buildViaMap, folded into aggregate.go's rebuild()
// as a "p0f OS"-kind fingerprint) previously only ever showed mixed into
// the generic Fingerprints leaderboard alongside JA3/JA4/User-Agent/
// SSH-client identities -- this reads the same already-computed snapshot
// field aggregate.go's rebuild() populates, no new aggregation pass.
func (s *store) serveOSDistribution(w http.ResponseWriter, r *http.Request) {
	snap := s.get()
	points := make([]osDistributionPoint, 0, len(snap.OSDistribution))
	for _, row := range snap.OSDistribution {
		points = append(points, osDistributionPoint{Name: row.Key, Value: row.Count})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(points)
}
