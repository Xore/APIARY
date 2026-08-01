package main

// ml_anomalies.go delivers ml-worker's scored anomalies (ml-anomalies ES
// index, docs/ml-worker-plan.md §7) to the dashboard (#64).
//
// Transport decision: Elasticsearch polling on the dashboard's existing
// 1-minute ES ticker (main.go), the same cadence esClient.refresh() already
// runs on. No Redis, no new SSE endpoint -- ml-gpu-coordinated-roadmap.md §1
// decision 1 and docs/ml-worker-plan.md §10 are explicit that a broker is
// only justified once polling is measured and shown insufficient, which has
// not happened. Anomalies land in the same in-memory cache pattern every
// other cheap, read-mostly dataset here already uses (payloadCache,
// ipsCache) -- capped at mlAnomalyCacheCap, since this dashboard is
// memory-bounded on purpose (#64's own constraint).

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// mlAnomaly mirrors the document ml-worker's write_anomaly() (worker.py)
// actually writes to the ml-anomalies index -- field names and shapes are
// intentionally identical, not reinterpreted, so this struct is a direct
// contract with that file rather than an independent guess.
type mlAnomaly struct {
	Timestamp      string             `json:"@timestamp"`
	SourceEventID  string             `json:"source_event_id"`
	SourceIndex    string             `json:"source_index"`
	SrcIP          string             `json:"src_ip"`
	SrcCountry     string             `json:"src_country"`
	CompositeScore float64            `json:"composite_score"`
	Severity       string             `json:"severity"`
	ModelScores    map[string]float64 `json:"model_scores"`
	Explanation    string             `json:"explanation"`
	EventType      string             `json:"event_type"`
	DstPort        int                `json:"dst_port"`
	Proto          string             `json:"proto"`
}

// SourceLink pivots from an anomaly back to the exact honeypot event that
// produced it (#173, ml-gpu-coordinated-roadmap.md Milestone E bullet 3:
// "link to immutable source identity"). SourceEventID is a raw
// Elasticsearch document _id, not one of the dashboard's own normalized
// event filters (filters.go's `filter` has no id/event_id field, and the
// bounded in-memory events cache isn't guaranteed to still hold an old
// event by the time its anomaly is viewed) -- so this goes through
// /history's existing raw-query-string search instead of /events, the
// same "direct Elasticsearch-document-style link" /history already
// provides. _index is included alongside _id: source_event_id is only
// unique within its own source index (write_anomaly()'s own anomaly_doc_id
// comment notes honeypot-v2-*/suricata-v2-* auto-generated IDs are not
// guaranteed disjoint from each other), so the query pins both.
func (a mlAnomaly) SourceLink() string {
	if a.SourceEventID == "" || a.SourceIndex == "" {
		return ""
	}
	q := `_id:"` + a.SourceEventID + `" AND _index:"` + a.SourceIndex + `"`
	return "/history?" + url.Values{"q": {q}}.Encode()
}

// mlAnomalyCacheCap bounds the in-memory cache -- a stated worst case, same
// reasoning as ml-worker's own MAX_TRAIN_SAMPLES (#62)/MAX_TRAIN_WINDOWS
// (#63): the dashboard is memory-capped on purpose, and an unbounded cache
// fed by an external, attacker-influenced signal (composite_score reacts to
// attacker behavior) is exactly the kind of growth that must be capped by
// construction, not by assumption.
const mlAnomalyCacheCap = 200

type mlAnomalyStore struct {
	mu    sync.RWMutex
	items []mlAnomaly // ascending by @timestamp, capped to the newest mlAnomalyCacheCap
	since string      // last-seen @timestamp; next poll's lower bound
}

func (c *mlAnomalyStore) checkpoint() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.since
}

// absorb appends newly-polled anomalies (already ascending by @timestamp)
// and trims to the cap. Safe to call with an empty slice (no-op).
func (c *mlAnomalyStore) absorb(items []mlAnomaly) {
	if len(items) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = append(c.items, items...)
	if len(c.items) > mlAnomalyCacheCap {
		c.items = c.items[len(c.items)-mlAnomalyCacheCap:]
	}
	c.since = items[len(items)-1].Timestamp
}

func (c *mlAnomalyStore) snapshot() []mlAnomaly {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]mlAnomaly, len(c.items))
	copy(out, c.items)
	return out
}

// refreshMLAnomalies polls ml-anomalies for documents newer than the last
// seen checkpoint. Best-effort: a failed or empty poll leaves the cache and
// checkpoint untouched, and the next tick (main.go's existing 1-minute ES
// ticker) retries -- matching esClient.refresh()'s own error handling, no
// new failure mode introduced.
func (s *store) refreshMLAnomalies() {
	if s.es == nil || s.mlAnomalies == nil {
		return
	}
	path := "/ml-anomalies/_search?size=" + strconv.Itoa(mlAnomalyCacheCap) + "&sort=%40timestamp%3Aasc"
	if since := s.mlAnomalies.checkpoint(); since != "" {
		path += "&q=" + url.QueryEscape("@timestamp:{"+since+" TO *]")
	}
	b, err := s.es.request(path)
	if err != nil {
		return
	}
	var resp struct {
		Hits struct {
			Hits []struct {
				Source mlAnomaly `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if json.Unmarshal(b, &resp) != nil {
		return
	}
	items := make([]mlAnomaly, len(resp.Hits.Hits))
	for i, h := range resp.Hits.Hits {
		items[i] = h.Source
	}
	s.mlAnomalies.absorb(items)
}

// serveMLAnomaliesAPI implements GET /api/ml/anomalies from
// docs/ml-worker-plan.md §8: limit (default 50, capped at the cache size),
// severity, and since (RFC3339) filters over the cached, already-polled
// set -- never a live Elasticsearch call on the request path, so this
// endpoint's cost is bounded by mlAnomalyCacheCap regardless of query
// params.
func (s *store) serveMLAnomaliesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.mlAnomalies == nil {
		json.NewEncoder(w).Encode([]mlAnomaly{})
		return
	}
	items := s.mlAnomalies.snapshot()
	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	since := strings.TrimSpace(r.URL.Query().Get("since"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > mlAnomalyCacheCap {
		limit = 50
	}
	filtered := make([]mlAnomaly, 0, len(items))
	for _, item := range items {
		if severity != "" && item.Severity != severity {
			continue
		}
		if since != "" && item.Timestamp <= since {
			continue
		}
		filtered = append(filtered, item)
	}
	// Newest first for the API and the page -- an operator scanning either
	// wants the most recent anomaly on top, not buried after 200 older ones.
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Timestamp > filtered[j].Timestamp })
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	json.NewEncoder(w).Encode(filtered)
}

// mlAnomalyStats is GET /api/ml/stats's response shape (docs/ml-worker-plan.md §8).
type mlAnomalyStats struct {
	Total24h   int64 `json:"total_anomalies_24h"`
	BySeverity []kv  `json:"by_severity"`
	TopSrcIPs  []kv  `json:"top_src_ips"`
}

func mlAnomalyStatsFrom(items []mlAnomaly, now time.Time) mlAnomalyStats {
	stats := mlAnomalyStats{}
	bySeverity := map[string]int{}
	byIP := map[string]int{}
	cutoff := now.Add(-24 * time.Hour)
	for _, item := range items {
		ts, err := time.Parse(time.RFC3339, item.Timestamp)
		if err != nil || ts.Before(cutoff) {
			continue
		}
		stats.Total24h++
		bySeverity[item.Severity]++
		if item.SrcIP != "" {
			byIP[item.SrcIP]++
		}
	}
	for _, severity := range []string{"critical", "high", "medium", "low"} {
		if n := bySeverity[severity]; n > 0 {
			stats.BySeverity = append(stats.BySeverity, kv{Key: severity, Count: n})
		}
	}
	for ip, n := range byIP {
		stats.TopSrcIPs = append(stats.TopSrcIPs, kv{Key: ip, Count: n, Link: "/events?ip=" + url.QueryEscape(ip)})
	}
	sort.Slice(stats.TopSrcIPs, func(i, j int) bool {
		if stats.TopSrcIPs[i].Count != stats.TopSrcIPs[j].Count {
			return stats.TopSrcIPs[i].Count > stats.TopSrcIPs[j].Count
		}
		return stats.TopSrcIPs[i].Key < stats.TopSrcIPs[j].Key
	})
	if len(stats.TopSrcIPs) > 10 {
		stats.TopSrcIPs = stats.TopSrcIPs[:10]
	}
	return stats
}

func (s *store) serveMLStatsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var items []mlAnomaly
	if s.mlAnomalies != nil {
		items = s.mlAnomalies.snapshot()
	}
	json.NewEncoder(w).Encode(mlAnomalyStatsFrom(items, time.Now().UTC()))
}

// mlAnomaliesPage is /ml-anomalies' page data -- server-rendered from the
// cache on each request, like /source-health and /dead-letters (no live
// client-side polling; a page reload shows the current cache, consistent
// with the rest of this diagnostics group).
type mlAnomaliesPage struct {
	pageMeta
	Generated time.Time
	Enabled   bool
	Anomalies []mlAnomaly
	Stats     mlAnomalyStats
}

func (s *store) mlAnomaliesData() mlAnomaliesPage {
	page := mlAnomaliesPage{Generated: time.Now(), Enabled: s.es != nil}
	if s.mlAnomalies == nil {
		return page
	}
	items := s.mlAnomalies.snapshot()
	page.Stats = mlAnomalyStatsFrom(items, time.Now().UTC())
	sort.Slice(items, func(i, j int) bool { return items[i].Timestamp > items[j].Timestamp })
	page.Anomalies = items
	return page
}
