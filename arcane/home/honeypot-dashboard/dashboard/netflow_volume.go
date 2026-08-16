package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// #1278: suricata-v2-netflow-* (~1.9M docs across a 4-day sample, the
// single largest unused index by volume, confirmed live) carries real
// traffic-volume metrics -- byte/packet counts per flow -- that no other
// index in this stack has. classify.go correctly skips every netflow
// record for the per-event table (ev.skip=true; it would swamp it), but
// that also means there was previously no view of actual traffic volume
// anywhere: the activity heatmap counts discrete events, so a large
// download/exfil spike looks identical to a single probe. Both fields are
// plain typed `long` in the live mapping (confirmed directly, unlike
// honeypot-v2-*/dionaea-incidents' flattened payload fields), so this is a
// live ES date_histogram+sum aggregation -- matching es_aggregate.go's
// established pattern -- not an in-process accumulation.
//
// Field path is suricata.eve.netflow.bytes/pkts, NOT the top-level
// netflow.bytes/pkts a raw Suricata eve.json sample would suggest --
// confirmed live that Filebeat's ingest pipeline nests every Suricata
// event under suricata.eve.*. A sum aggregation on a nonexistent field
// path fails silently (returns 0.0, no error), which is exactly what an
// earlier version of this query did before checking a real document.
const netflowVolumeWindow = "now-7d"

const netflowBytesQuery = `{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "` + netflowVolumeWindow + `"}}},
  "aggs": {
    "hourly": {
      "date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0},
      "aggs": {"total": {"sum": {"field": "suricata.eve.netflow.bytes"}}}
    }
  }
}`

const netflowPacketsQuery = `{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "` + netflowVolumeWindow + `"}}},
  "aggs": {
    "hourly": {
      "date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0},
      "aggs": {"total": {"sum": {"field": "suricata.eve.netflow.pkts"}}}
    }
  }
}`

type netflowVolumeResponse struct {
	Aggregations struct {
		Hourly struct {
			Buckets []struct {
				KeyAsString string `json:"key_as_string"`
				Total       struct {
					Value float64 `json:"value"`
				} `json:"total"`
			} `json:"buckets"`
		} `json:"hourly"`
	} `json:"aggregations"`
}

// fetchNetflowVolume runs query against suricata-v2-netflow-* and reshapes
// the single date_histogram+sum result into the same
// []mlBacklogSeries{{name, points}} shape ml_backlog.go already produces,
// so the frontend's existing generic initLine chart function needs no
// netflow-specific code. Elasticsearch's sum aggregation returns 0 (not
// null) for an empty bucket, unlike avg (see fetchMLBacklogTrend's
// null-skipping) -- every hourly bucket in range is a real point here.
func (s *store) fetchNetflowVolume(query []byte, seriesName string) ([]mlBacklogSeries, bool) {
	if s.es == nil {
		return nil, false
	}
	b, err := s.es.searchBody("/suricata-v2-netflow-*/_search", query)
	if err != nil {
		return nil, false
	}
	var resp netflowVolumeResponse
	if json.Unmarshal(b, &resp) != nil {
		return nil, false
	}
	points := make([]mlBacklogPoint, 0, len(resp.Aggregations.Hourly.Buckets))
	for _, hb := range resp.Aggregations.Hourly.Buckets {
		t, err := time.Parse(time.RFC3339, hb.KeyAsString)
		if err != nil {
			continue
		}
		points = append(points, mlBacklogPoint{Time: t.UTC().Format(time.RFC3339), Value: hb.Total.Value})
	}
	return []mlBacklogSeries{{Name: seriesName, Points: points}}, true
}

// serveNetflowBytes answers /api/netflow-bytes (#1278).
func (s *store) serveNetflowBytes(w http.ResponseWriter, r *http.Request) {
	series, ok := s.fetchNetflowVolume([]byte(netflowBytesQuery), "bytes")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		http.Error(w, "netflow byte volume unavailable", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(series)
}

// serveNetflowPackets answers /api/netflow-packets (#1278).
func (s *store) serveNetflowPackets(w http.ResponseWriter, r *http.Request) {
	series, ok := s.fetchNetflowVolume([]byte(netflowPacketsQuery), "packets")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		http.Error(w, "netflow packet volume unavailable", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(series)
}
