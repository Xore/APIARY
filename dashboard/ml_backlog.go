package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// #1283: ml-worker-metrics already writes a dedicated backlog-tracking
// document on every check cycle -- {"kind": "backlog", "source_index":
// "honeypot-v2-*"|"suricata-v2-*", "backlog_count": N, "@timestamp": ...} --
// confirmed live against the production index (plain typed mapping, not
// flattened, unlike honeypot-v2-*/dionaea-incidents' own payload fields), so
// this is a pure live-ES-aggregation read via es_aggregate.go's established
// pattern (fetchSensorHeatmap's terms+nested-date_histogram shape), not a
// new in-process accumulation.
const mlBacklogWindow = "now-7d"

const mlBacklogQuery = `{
  "size": 0,
  "query": {"bool": {"filter": [
    {"term": {"kind": "backlog"}},
    {"range": {"@timestamp": {"gte": "` + mlBacklogWindow + `"}}}
  ]}},
  "aggs": {
    "sources": {
      "terms": {"field": "source_index", "size": 10},
      "aggs": {
        "hourly": {
          "date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0},
          "aggs": {"avg_backlog": {"avg": {"field": "backlog_count"}}}
        }
      }
    }
  }
}`

type mlBacklogResponse struct {
	Aggregations struct {
		Sources struct {
			Buckets []struct {
				Key    string `json:"key"`
				Hourly struct {
					Buckets []struct {
						KeyAsString string `json:"key_as_string"`
						AvgBacklog  struct {
							Value *float64 `json:"value"`
						} `json:"avg_backlog"`
					} `json:"buckets"`
				} `json:"hourly"`
			} `json:"buckets"`
		} `json:"sources"`
	} `json:"aggregations"`
}

// mlBacklogPoint is one hourly sample on the backlog trend chart. Value is
// an average, not a sum: backlog_count is a point-in-time gauge (queue
// depth at the moment ml-worker checked), so averaging samples within an
// hour is the right reduction -- summing would make the chart meaningless.
type mlBacklogPoint struct {
	Time  string  `json:"time"`
	Value float64 `json:"value"`
}

type mlBacklogSeries struct {
	Name   string           `json:"name"`
	Points []mlBacklogPoint `json:"points"`
}

// fetchMLBacklogTrend queries ml-worker-metrics for the backlog_count trend
// per source_index over mlBacklogWindow. A query or decode failure returns
// (nil, false); the caller responds 503 rather than showing an empty chart
// as if the backlog were genuinely zero.
func (s *store) fetchMLBacklogTrend() ([]mlBacklogSeries, bool) {
	if s.es == nil {
		return nil, false
	}
	b, err := s.es.searchBody("/ml-worker-metrics/_search", []byte(mlBacklogQuery))
	if err != nil {
		return nil, false
	}
	var resp mlBacklogResponse
	if json.Unmarshal(b, &resp) != nil {
		return nil, false
	}
	series := make([]mlBacklogSeries, 0, len(resp.Aggregations.Sources.Buckets))
	for _, sb := range resp.Aggregations.Sources.Buckets {
		points := make([]mlBacklogPoint, 0, len(sb.Hourly.Buckets))
		for _, hb := range sb.Hourly.Buckets {
			if hb.AvgBacklog.Value == nil {
				continue
			}
			t, err := time.Parse(time.RFC3339, hb.KeyAsString)
			if err != nil {
				continue
			}
			points = append(points, mlBacklogPoint{Time: t.UTC().Format(time.RFC3339), Value: *hb.AvgBacklog.Value})
		}
		series = append(series, mlBacklogSeries{Name: sb.Key, Points: points})
	}
	return series, true
}

// serveMLBacklog answers /api/ml-backlog (#1283).
func (s *store) serveMLBacklog(w http.ResponseWriter, r *http.Request) {
	series, ok := s.fetchMLBacklogTrend()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		http.Error(w, "ml backlog trend unavailable", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(series)
}
