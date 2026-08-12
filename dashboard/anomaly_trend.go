package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"
)

// anomaly_trend.go (#1279): suricata-v2-anomaly-* events are NOT skipped by
// classify.go the way flow/dns/netflow/stats records are (classify.go's own
// #616 comment: genuinely low-volume, confirmed live ~50/hour vs. 5700+/hour
// for netflow in the same window) -- they already reach storedEvent via the
// normal per-request in-memory cache s.getEvents() everywhere else already
// uses, so this needs no new ES query, unlike netflow_volume.go/
// dionaea_cve_chart.go/scanner_fingerprints.go's live-aggregation approach
// for genuinely high-volume signals. Protocol-conformance violations are,
// by definition, traffic that doesn't conform to the protocol it claims to
// be -- often indicative of scanning tools or deliberate IDS-evasion
// attempts -- so a trend view (is evasion-style traffic increasing,
// decreasing, spiking?) is legible in a way scrolling /events rows isn't.

// anomalyTrendHourFormat truncates to the hour, matching aggregate.go's own
// SensorHeatmap bucketing granularity for "activity over time" views.
const anomalyTrendHourFormat = "2006-01-02T15:00:00Z"

// anomalyTrend groups s.getEvents()'s already-cached storedEvents by
// AnomalyAppProto (the protocol the violating traffic claimed to be) into
// hourly buckets, reusing mlBacklogSeries/mlBacklogPoint (#1283) -- the
// same {name, points: [{time, value}]} shape hp-kill-chain.js's generic
// initLine chart function already consumes, so this needs no new frontend
// chart type. Events with no AnomalyAppProto (a small minority -- some
// anomaly types are link-layer, not tied to one app protocol) are grouped
// under "(none)" rather than dropped, so the total count of anomaly events
// shown always matches what /events?cat=anomaly would return.
func (s *store) anomalyTrend() []mlBacklogSeries {
	type key struct {
		proto string
		hour  string
	}
	counts := map[key]int{}
	protos := map[string]bool{}
	for _, ev := range s.getEvents() {
		if ev.Category != "anomaly" {
			continue
		}
		proto := ev.AnomalyAppProto
		if proto == "" {
			proto = "(none)"
		}
		protos[proto] = true
		hour := ev.when.UTC().Truncate(time.Hour).Format(anomalyTrendHourFormat)
		counts[key{proto, hour}]++
	}

	protoNames := make([]string, 0, len(protos))
	for p := range protos {
		protoNames = append(protoNames, p)
	}
	// #40: sorted, not map iteration order, so two dashboard instances (or
	// two requests to the same one) render the same series order.
	sort.Strings(protoNames)

	series := make([]mlBacklogSeries, 0, len(protoNames))
	for _, proto := range protoNames {
		hours := map[string]bool{}
		for k := range counts {
			if k.proto == proto {
				hours[k.hour] = true
			}
		}
		hourList := make([]string, 0, len(hours))
		for h := range hours {
			hourList = append(hourList, h)
		}
		sort.Strings(hourList)
		points := make([]mlBacklogPoint, 0, len(hourList))
		for _, h := range hourList {
			points = append(points, mlBacklogPoint{Time: h, Value: float64(counts[key{proto, h}])})
		}
		series = append(series, mlBacklogSeries{Name: proto, Points: points})
	}
	return series
}

// serveAnomalyTrend answers /api/anomaly-trend (#1279).
func (s *store) serveAnomalyTrend(w http.ResponseWriter, r *http.Request) {
	series := s.anomalyTrend()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(series)
}
