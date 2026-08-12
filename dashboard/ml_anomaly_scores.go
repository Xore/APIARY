package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"
)

// #1284: /ml-anomalies already surfaces CompositeScore/ModelScores per
// anomaly, but only as small inline text in a table row -- three numbers
// read one row at a time hides the genuinely interesting "which detector
// actually caught this" signal (model agreement/disagreement across many
// anomalies). This reshapes the SAME in-memory mlAnomalyStore snapshot
// (already polled from Elasticsearch on the existing 1-minute ticker, see
// ml_anomalies.go's own transport-decision comment) into one scatter
// series per model plus a composite series -- no new ES query.
//
// Reuses ml_backlog.go's mlBacklogSeries/mlBacklogPoint shape (name +
// [{time, value}]): a scatter series here is structurally identical to a
// line series there, a named list of time+value points. Only the
// frontend's render function (hp-kill-chain.js's new initScatter, vs.
// initLine) differs.
func (s *store) fetchMLAnomalyScores() []mlBacklogSeries {
	if s.mlAnomalies == nil {
		return []mlBacklogSeries{}
	}
	items := s.mlAnomalies.snapshot()

	// Model names come from the data itself, not a hardcoded enum (unlike
	// ml_anomalies.html's table, which spells out isolation_forest/lstm_ae/
	// hbos by name) -- so a future model addition to ml-worker's
	// write_anomaly() shows up here with no dashboard code change.
	modelNames := map[string]bool{}
	for _, a := range items {
		for name := range a.ModelScores {
			modelNames[name] = true
		}
	}
	names := make([]string, 0, len(modelNames)+1)
	for name := range modelNames {
		names = append(names, name)
	}
	sort.Strings(names)
	names = append(names, "composite")

	series := make([]mlBacklogSeries, 0, len(names))
	for _, name := range names {
		points := make([]mlBacklogPoint, 0, len(items))
		for _, a := range items {
			t, err := time.Parse(time.RFC3339, a.Timestamp)
			if err != nil {
				continue
			}
			value, ok := a.CompositeScore, true
			if name != "composite" {
				value, ok = a.ModelScores[name]
			}
			if !ok {
				continue
			}
			points = append(points, mlBacklogPoint{Time: t.UTC().Format(time.RFC3339), Value: value})
		}
		series = append(series, mlBacklogSeries{Name: name, Points: points})
	}
	return series
}

// serveMLAnomalyScores answers /api/ml-anomaly-scores (#1284). Unlike
// ml_backlog.go/netflow_volume.go's live-ES-query endpoints, this reads an
// already-in-memory cache that has no separate "unavailable" state --
// s.mlAnomalies being nil (not yet initialized) or genuinely empty (no
// anomalies scored yet) both mean "nothing to chart yet", not a query
// failure, so this always responds 200 with a (possibly empty) array.
func (s *store) serveMLAnomalyScores(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(s.fetchMLAnomalyScores())
}
