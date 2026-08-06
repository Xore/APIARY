package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

// #39 (design decided under #37): sensor counts, the activity heatmap, and
// the attack map are cheap, fast-changing, and already sit on ECS fields the
// existing geoip-honeypot ingest pipeline promotes (network.protocol,
// destination.port, source.ip, source.geo.*, source.as.*, event.sensor,
// url.path) -- exactly the shape Elasticsearch's own aggregation framework
// is built for. Querying it live, instead of accumulating the same numbers
// in-process from every event read on every rebuild cycle, is what makes
// two dashboard instances reading the same ES store return identical
// numbers with no per-instance state of their own.
//
// Deliberately NOT moved here, and still computed the old way in
// aggregate.go: TopCreds, TopCommands, Fingerprints, Alerts/AlertCats,
// Providers, Clients, Payloads' Download field, Campaigns, and Clusters.
// Every one of those depends on classify()'s per-sensor, per-eventid
// normalization (which raw field holds a command, which of several raw
// field names carries a fingerprint, how a payload hash's companion
// download path is chosen) that has no single ECS-promoted field to query
// -- replicating that heterogeneity in a second, Elasticsearch-side
// language (Painless, for a scripted aggregation) would be exactly the kind
// of two-implementations-drift risk #38's own design rejected for the
// via_port join. They stay in-process until/unless a future pass gives them
// real ingest-time promotion first.
//
// esOverviewWindow bounds every aggregation below to the same 48h window
// aggregate.go's own Total/Last24h/Previous24h/Change24h always meant in
// practice: even before this change, "Total" was never a true lifetime
// count (bounded by tailCap's local-file byte cap, or the 10000-document
// cap on esOnlySensors' own reads) -- an explicit 48h window is a more
// honest description of the same thing, not a narrower one.
const esOverviewWindow = "now-48h"

// esOverviewWindowDuration mirrors esOverviewWindow as a time.Duration for
// Go-side comparisons (see #469's haveFullBaseline check in aggregate.go) --
// kept as a separate constant rather than parsed from the string above so a
// future change to the query's date-math literal doesn't silently desync
// the two without a compile-time reminder to update both.
const esOverviewWindowDuration = 48 * time.Hour

// esOverviewAggQuery is a fixed JSON literal: every "now" reference is
// resolved by Elasticsearch itself (date math in the query), so no
// per-request templating is needed on the Go side. Validated directly
// against the production cluster before being wired in here -- every field
// referenced is confirmed to exist and aggregate correctly, not assumed
// from the index template alone.
const esOverviewAggQuery = `{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "` + esOverviewWindow + `"}}},
  "aggs": {
    "last24h": {"filter": {"range": {"@timestamp": {"gte": "now-24h"}}}},
    "previous24h": {"filter": {"range": {"@timestamp": {"gte": "` + esOverviewWindow + `", "lt": "now-24h"}}}},
    "unattributed": {"filter": {"term": {"source.ip": "10.8.0.1"}}},
    "unique_ips": {"cardinality": {"field": "source.ip"}},
    "earliest": {"global": {}, "aggs": {"min_ts": {"min": {"field": "@timestamp"}}}},
    "sensors": {
      "terms": {"field": "event.sensor", "size": 50},
      "aggs": {"last_seen": {"max": {"field": "@timestamp"}}}
    },
    "protocols": {"terms": {"field": "network.protocol", "size": 30}},
    "ports": {"terms": {"field": "destination.port", "size": 15}},
    "countries": {"terms": {"field": "source.geo.country_iso_code", "size": 12}},
    "asns": {
      "terms": {"field": "source.as.asn", "size": 12},
      "aggs": {"org": {"terms": {"field": "source.as.organization_name", "size": 1}}}
    },
    "top_ips": {"terms": {"field": "source.ip", "size": 15}},
    "paths": {"terms": {"field": "url.path", "size": 15}},
    "heatmap": {
      "filter": {"range": {"@timestamp": {"gte": "now-24h"}}},
      "aggs": {
        "sensors": {
          "terms": {"field": "event.sensor", "size": 50, "order": {"_count": "desc"}},
          "aggs": {
            "hourly": {
              "date_histogram": {
                "field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0,
                "extended_bounds": {"min": "now-23h/h", "max": "now/h"}
              }
            }
          }
        }
      }
    },
    "points": {
      "filter": {"exists": {"field": "source.geo.location"}},
      "aggs": {
        "by_place": {
          "multi_terms": {
            "terms": [{"field": "source.geo.city_name"}, {"field": "source.geo.country_iso_code"}],
            "size": 500
          },
          "aggs": {
            "centroid": {"geo_centroid": {"field": "source.geo.location"}},
            "unique_ips": {"cardinality": {"field": "source.ip"}}
          }
        }
      }
    }
  }
}`

type esFilterAgg struct {
	DocCount int `json:"doc_count"`
}

type esValueAgg struct {
	Value float64 `json:"value"`
}

type esBucket struct {
	Key      json.RawMessage `json:"key"`
	DocCount int             `json:"doc_count"`
}

// bucketKeyString reads a terms-agg bucket key regardless of whether
// Elasticsearch encoded it as a JSON string (keyword fields) or a number
// (long/integer fields like destination.port and source.as.asn).
func bucketKeyString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var f float64
	if json.Unmarshal(raw, &f) == nil {
		return formatAggNumber(f)
	}
	return ""
}

func formatAggNumber(f float64) string {
	if f == float64(int64(f)) {
		return itoa64(int64(f))
	}
	b, _ := json.Marshal(f)
	return string(b)
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

type esSensorBucket struct {
	Key      string `json:"key"`
	DocCount int    `json:"doc_count"`
	LastSeen struct {
		ValueAsString string `json:"value_as_string"`
	} `json:"last_seen"`
}

type esASNBucket struct {
	Key      json.RawMessage `json:"key"`
	DocCount int             `json:"doc_count"`
	Org      struct {
		Buckets []esBucket `json:"buckets"`
	} `json:"org"`
}

type esHeatmapSensorBucket struct {
	Key    string `json:"key"`
	Hourly struct {
		Buckets []struct {
			KeyAsString string `json:"key_as_string"`
			DocCount    int    `json:"doc_count"`
		} `json:"buckets"`
	} `json:"hourly"`
}

type esPlaceBucket struct {
	Key      []string `json:"key"`
	DocCount int      `json:"doc_count"`
	Centroid struct {
		Location struct {
			Lat float64 `json:"lat"`
			Lon float64 `json:"lon"`
		} `json:"location"`
	} `json:"centroid"`
	UniqueIPs esValueAgg `json:"unique_ips"`
}

type esOverviewAggResponse struct {
	Aggregations struct {
		Last24h      esFilterAgg `json:"last24h"`
		Previous24h  esFilterAgg `json:"previous24h"`
		Unattributed esFilterAgg `json:"unattributed"`
		UniqueIPs    esValueAgg  `json:"unique_ips"`
		Earliest     struct {
			MinTS struct {
				ValueAsString string `json:"value_as_string"`
			} `json:"min_ts"`
		} `json:"earliest"`
		Sensors struct {
			Buckets []esSensorBucket `json:"buckets"`
		} `json:"sensors"`
		Protocols struct {
			Buckets []esBucket `json:"buckets"`
		} `json:"protocols"`
		Ports struct {
			Buckets []esBucket `json:"buckets"`
		} `json:"ports"`
		Countries struct {
			Buckets []esBucket `json:"buckets"`
		} `json:"countries"`
		ASNs struct {
			Buckets []esASNBucket `json:"buckets"`
		} `json:"asns"`
		TopIPs struct {
			Buckets []esBucket `json:"buckets"`
		} `json:"top_ips"`
		Paths struct {
			Buckets []esBucket `json:"buckets"`
		} `json:"paths"`
		Heatmap struct {
			Sensors struct {
				Buckets []esHeatmapSensorBucket `json:"buckets"`
			} `json:"sensors"`
		} `json:"heatmap"`
		Points struct {
			ByPlace struct {
				Buckets []esPlaceBucket `json:"buckets"`
			} `json:"by_place"`
		} `json:"points"`
	} `json:"aggregations"`
}

// esOverview is everything rebuild() needs from Elasticsearch to build the
// overview page's counts, top-N tables, heatmap, and map without any
// per-event in-process accumulation. now is passed in (rather than read via
// time.Now() here) purely so buildSensorHeatmap's own hour-labeling and this
// query's "now-23h/h" window agree on what "now" means for one rebuild
// cycle -- both already had that property before this change.
type esOverview struct {
	Total, Last24h, Previous24h, Unattributed  int
	UniqueIPs                                  int
	EarliestSeen                               time.Time
	SensorCounts                               map[string]int
	SensorLastSeen                             map[string]time.Time
	Protocols, Ports, Countries, TopIPs, Paths []kv
	ASNs                                       []kv
	MapPoints                                  []mapPoint
	SensorHeatmap                              []heatmapRow
}

// fetchESOverview queries and parses the compound aggregation. A query or
// decode failure returns (nil, false); the caller falls back to the
// in-process computation for this cycle rather than showing a blank
// overview page.
func (s *store) fetchESOverview(now time.Time) (*esOverview, bool) {
	if s.es == nil {
		return nil, false
	}
	b, err := s.es.searchBody("/honeypot-v2-*/_search", []byte(esOverviewAggQuery))
	if err != nil {
		return nil, false
	}
	var resp esOverviewAggResponse
	if json.Unmarshal(b, &resp) != nil {
		return nil, false
	}
	agg := resp.Aggregations

	out := &esOverview{
		Last24h:      agg.Last24h.DocCount,
		Previous24h:  agg.Previous24h.DocCount,
		Unattributed: agg.Unattributed.DocCount,
		UniqueIPs:    int(agg.UniqueIPs.Value),
	}
	out.Total = out.Last24h + out.Previous24h
	if t, err := time.Parse(time.RFC3339, agg.Earliest.MinTS.ValueAsString); err == nil {
		out.EarliestSeen = t
	}

	out.SensorCounts = make(map[string]int, len(agg.Sensors.Buckets))
	out.SensorLastSeen = make(map[string]time.Time, len(agg.Sensors.Buckets))
	for _, b := range agg.Sensors.Buckets {
		out.SensorCounts[b.Key] = b.DocCount
		if t, err := time.Parse(time.RFC3339, b.LastSeen.ValueAsString); err == nil {
			out.SensorLastSeen[b.Key] = t
		}
	}

	// normalizeProtocol collapses implementation-specific service names
	// (smbd->smb, mongod->mongodb, ...) the same way the in-process path
	// already did -- network.protocol carries the raw, un-collapsed value,
	// so buckets that normalize to the same name are merged here rather
	// than showing as separate rows.
	protoCounts := map[string]int{}
	for _, b := range agg.Protocols.Buckets {
		protoCounts[normalizeProtocol(bucketKeyString(b.Key))] += b.DocCount
	}
	out.Protocols = topN(protoCounts, 12)

	for _, b := range agg.Ports.Buckets {
		out.Ports = append(out.Ports, kv{Key: bucketKeyString(b.Key), Count: b.DocCount})
	}
	for _, b := range agg.Countries.Buckets {
		out.Countries = append(out.Countries, kv{Key: bucketKeyString(b.Key), Count: b.DocCount})
	}
	for _, b := range agg.TopIPs.Buckets {
		out.TopIPs = append(out.TopIPs, kv{Key: bucketKeyString(b.Key), Count: b.DocCount})
	}
	for _, b := range agg.Paths.Buckets {
		out.Paths = append(out.Paths, kv{Key: bucketKeyString(b.Key), Count: b.DocCount})
	}
	for _, b := range agg.ASNs.Buckets {
		org := ""
		if len(b.Org.Buckets) > 0 {
			org = bucketKeyString(b.Org.Buckets[0].Key)
		}
		out.ASNs = append(out.ASNs, kv{Key: "AS" + bucketKeyString(b.Key) + " " + org, Count: b.DocCount})
	}

	for _, sb := range agg.Heatmap.Sensors.Buckets {
		cells := make([]heatmapCell, 0, len(sb.Hourly.Buckets))
		for _, hb := range sb.Hourly.Buckets {
			t, _ := time.Parse(time.RFC3339, hb.KeyAsString)
			cells = append(cells, heatmapCell{Label: t.Local().Format("15") + ":00", Count: hb.DocCount})
		}
		out.SensorHeatmap = append(out.SensorHeatmap, heatmapRow{Sensor: sb.Key, Cells: cells})
	}
	quantizeHeatmap(out.SensorHeatmap)

	for _, pb := range agg.Points.ByPlace.Buckets {
		city, country := "", ""
		if len(pb.Key) > 0 {
			city = pb.Key[0]
		}
		if len(pb.Key) > 1 {
			country = pb.Key[1]
		}
		out.MapPoints = append(out.MapPoints, mapPoint{
			Country: country, City: city,
			Lat: pb.Centroid.Location.Lat, Lon: pb.Centroid.Location.Lon,
			Count: pb.DocCount, IPCount: int(pb.UniqueIPs.Value),
		})
	}

	return out, true
}

// quantizeHeatmap fills in each cell's Pct the same way buildSensorHeatmap
// (aggregate.go) already did: a single global scale (the busiest cell across
// every row), not per-row, so a quiet sensor's own peak hour never reads as
// visually "hot" as the noisiest sensor's.
func quantizeHeatmap(rows []heatmapRow) {
	maxCell := 1
	for _, row := range rows {
		for _, c := range row.Cells {
			if c.Count > maxCell {
				maxCell = c.Count
			}
		}
	}
	for r := range rows {
		for c := range rows[r].Cells {
			count := rows[r].Cells[c].Count
			var pct int
			switch {
			case count <= 0:
				pct = 0
			case count*4 <= maxCell:
				pct = 25
			case count*4 <= maxCell*2:
				pct = 50
			case count*4 <= maxCell*3:
				pct = 75
			default:
				pct = 100
			}
			rows[r].Cells[c].Pct = pct
		}
	}
}

// esSingleSensorHeatmapQuery is the request body for fetchSensorHeatmap,
// built via json.Marshal (not string concatenation) since, unlike
// esOverviewAggQuery, sensor here comes from a user-controlled query
// parameter (the overview page's heatmap sensor picker, #41) -- this is the
// same "never string-format attacker-controlled input into a query" rule
// every other Elasticsearch call in this file already gets for free by
// having no dynamic input at all.
type esSingleSensorHeatmapQuery struct {
	Size  int `json:"size"`
	Query struct {
		Bool struct {
			Filter []map[string]any `json:"filter"`
		} `json:"bool"`
	} `json:"query"`
	Aggs struct {
		Hourly struct {
			DateHistogram struct {
				Field          string         `json:"field"`
				FixedInterval  string         `json:"fixed_interval"`
				MinDocCount    int            `json:"min_doc_count"`
				ExtendedBounds map[string]any `json:"extended_bounds"`
			} `json:"date_histogram"`
		} `json:"hourly"`
	} `json:"aggs"`
}

func buildSingleSensorHeatmapQuery(sensor string) []byte {
	var q esSingleSensorHeatmapQuery
	q.Size = 0
	q.Query.Bool.Filter = []map[string]any{
		{"range": map[string]any{"@timestamp": map[string]any{"gte": "now-24h"}}},
		{"term": map[string]any{"event.sensor": sensor}},
	}
	q.Aggs.Hourly.DateHistogram.Field = "@timestamp"
	q.Aggs.Hourly.DateHistogram.FixedInterval = "1h"
	q.Aggs.Hourly.DateHistogram.MinDocCount = 0
	q.Aggs.Hourly.DateHistogram.ExtendedBounds = map[string]any{"min": "now-23h/h", "max": "now/h"}
	b, _ := json.Marshal(q)
	return b
}

type esSingleSensorHeatmapResponse struct {
	Aggregations struct {
		Hourly struct {
			Buckets []struct {
				KeyAsString string `json:"key_as_string"`
				DocCount    int    `json:"doc_count"`
			} `json:"buckets"`
		} `json:"hourly"`
	} `json:"aggregations"`
}

// fetchSensorHeatmap (#41) is the single-sensor counterpart to
// fetchESOverview's own heatmap sub-aggregation: that one caps results to
// the busiest sensorHeatmapRows sensors so the default overview stays
// readable, which is exactly what makes a specific, possibly-quiet
// sensor's own full 24h activity invisible there. This queries one sensor
// alone, with no top-N cap, quantized against its own max (quantizeHeatmap
// naturally does this correctly for a single-row input).
func (s *store) fetchSensorHeatmap(sensor string, now time.Time) ([]heatmapCell, bool) {
	if s.es == nil || sensor == "" {
		return nil, false
	}
	b, err := s.es.searchBody("/honeypot-v2-*/_search", buildSingleSensorHeatmapQuery(sensor))
	if err != nil {
		return nil, false
	}
	var resp esSingleSensorHeatmapResponse
	if json.Unmarshal(b, &resp) != nil {
		return nil, false
	}
	cells := make([]heatmapCell, 0, len(resp.Aggregations.Hourly.Buckets))
	for _, hb := range resp.Aggregations.Hourly.Buckets {
		t, _ := time.Parse(time.RFC3339, hb.KeyAsString)
		cells = append(cells, heatmapCell{Label: t.Local().Format("15") + ":00", Count: hb.DocCount})
	}
	row := []heatmapRow{{Sensor: sensor, Cells: cells}}
	quantizeHeatmap(row)
	return row[0].Cells, true
}

// serveHeatmap backs the overview page's per-sensor picker (#41 item 1): the
// default "all sensors" view stays the pre-existing top-N snapshot field
// (fetchESOverview already caps and quantizes it once per rebuild), while a
// specific sensor is fetched live via fetchSensorHeatmap so a quiet sensor
// that never makes the top-N cut is still visible. suricata and portbridge
// are rejected here for the same reason rebuild() skips them for the main
// event read (#41): they ship to their own suricata-*/portbridge-v2-*
// indices, not honeypot-v2-*, so a query for them here would always,
// silently return zero -- indistinguishable from "quiet".
func (s *store) serveHeatmap(w http.ResponseWriter, r *http.Request) {
	sensor := r.URL.Query().Get("sensor")
	w.Header().Set("Content-Type", "application/json")
	if sensor == "" || sensor == "all" {
		snap := s.get()
		json.NewEncoder(w).Encode(map[string]any{"sensor": "", "rows": snap.SensorHeatmap})
		return
	}
	if sensor == "suricata" || sensor == "portbridge" {
		http.Error(w, "sensor not queryable via this endpoint", http.StatusBadRequest)
		return
	}
	cells, ok := s.fetchSensorHeatmap(sensor, time.Now())
	if !ok {
		http.Error(w, "heatmap unavailable", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"sensor": sensor, "rows": []heatmapRow{{Sensor: sensor, Cells: cells}}})
}

// esSingleSensorVectorsQuery is the request body for fetchSensorAttackVectors
// -- built via json.Marshal for the same reason esSingleSensorHeatmapQuery
// is: sensor is a user-controlled query parameter (#471's per-sensor
// "attack vectors" panel), so it must never be string-formatted into the
// query body.
type esSingleSensorVectorsQuery struct {
	Size  int `json:"size"`
	Query struct {
		Bool struct {
			Filter []map[string]any `json:"filter"`
		} `json:"bool"`
	} `json:"query"`
	Aggs struct {
		Ports struct {
			Terms struct {
				Field string `json:"field"`
				Size  int    `json:"size"`
			} `json:"terms"`
		} `json:"ports"`
		Protocols struct {
			Terms struct {
				Field string `json:"field"`
				Size  int    `json:"size"`
			} `json:"terms"`
		} `json:"protocols"`
	} `json:"aggs"`
}

func buildSingleSensorVectorsQuery(sensor string) []byte {
	var q esSingleSensorVectorsQuery
	q.Size = 0
	q.Query.Bool.Filter = []map[string]any{
		{"range": map[string]any{"@timestamp": map[string]any{"gte": "now-24h"}}},
		{"term": map[string]any{"event.sensor": sensor}},
	}
	q.Aggs.Ports.Terms.Field = "destination.port"
	q.Aggs.Ports.Terms.Size = 15
	q.Aggs.Protocols.Terms.Field = "network.protocol"
	q.Aggs.Protocols.Terms.Size = 15
	b, _ := json.Marshal(q)
	return b
}

type esSingleSensorVectorsResponse struct {
	Aggregations struct {
		Ports struct {
			Buckets []esBucket `json:"buckets"`
		} `json:"ports"`
		Protocols struct {
			Buckets []esBucket `json:"buckets"`
		} `json:"protocols"`
	} `json:"aggregations"`
}

// fetchSensorAttackVectors (#471) answers "which ports/services did this
// sensor actually get hit on in the last 24h" -- new surface area beyond
// fetchSensorHeatmap's event-volume-over-time view, queried the same way
// (one sensor, no top-N cap since a single sensor's own port/protocol
// spread is already small).
func (s *store) fetchSensorAttackVectors(sensor string, now time.Time) (ports, protocols []kv, ok bool) {
	if s.es == nil || sensor == "" {
		return nil, nil, false
	}
	b, err := s.es.searchBody("/honeypot-v2-*/_search", buildSingleSensorVectorsQuery(sensor))
	if err != nil {
		return nil, nil, false
	}
	var resp esSingleSensorVectorsResponse
	if json.Unmarshal(b, &resp) != nil {
		return nil, nil, false
	}
	for _, bucket := range resp.Aggregations.Ports.Buckets {
		ports = append(ports, kv{Key: bucketKeyString(bucket.Key), Count: bucket.DocCount, Link: eventsURL(url.Values{"sensor": {sensor}, "port": {bucketKeyString(bucket.Key)}})})
	}
	protoCounts := map[string]int{}
	for _, bucket := range resp.Aggregations.Protocols.Buckets {
		protoCounts[normalizeProtocol(bucketKeyString(bucket.Key))] += bucket.DocCount
	}
	for _, row := range topN(protoCounts, len(protoCounts)) {
		protocols = append(protocols, kv{Key: row.Key, Count: row.Count, Link: eventsURL(url.Values{"sensor": {sensor}, "proto": {row.Key}})})
	}
	return ports, protocols, true
}

// serveAttackVectors backs the overview page's per-sensor "attack vectors"
// companion panel (#471): which ports/services a specific sensor actually
// saw traffic on in the last 24h, alongside (not instead of) the existing
// hourly heatmap. suricata/portbridge are rejected for the same reason
// serveHeatmap already rejects them -- they ship to their own indices, not
// honeypot-v2-*, so a query here would always, silently return empty.
func (s *store) serveAttackVectors(w http.ResponseWriter, r *http.Request) {
	sensor := r.URL.Query().Get("sensor")
	w.Header().Set("Content-Type", "application/json")
	if sensor == "" || sensor == "suricata" || sensor == "portbridge" {
		http.Error(w, "a specific sensor is required", http.StatusBadRequest)
		return
	}
	ports, protocols, ok := s.fetchSensorAttackVectors(sensor, time.Now())
	if !ok {
		http.Error(w, "attack vectors unavailable", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"sensor": sensor, "ports": ports, "protocols": protocols})
}
