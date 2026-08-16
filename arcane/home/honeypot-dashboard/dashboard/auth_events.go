package main

// auth_events.go delivers auth-events-worker's Keycloak/gateway
// authentication-failure telemetry (#1066, #981 follow-up) to the
// dashboard.
//
// Transport decision: Elasticsearch polling on the dashboard's existing
// 1-minute ES ticker (main.go), same as ml-anomalies (ml_anomalies.go's own
// package comment) -- no new broker, same reasoning.

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

// authFailureEvent mirrors the document auth-events-worker's redact()
// (worker.py) actually writes to the auth-failure-events index -- field
// names and shapes are intentionally identical, not reinterpreted, same
// discipline as mlAnomaly's own comment on ml-worker's write_anomaly().
type authFailureEvent struct {
	Timestamp string            `json:"@timestamp"`
	EventID   string            `json:"event_id"`
	Type      string            `json:"type"`
	Realm     string            `json:"realm"`
	ClientID  string            `json:"client_id"`
	UserID    string            `json:"user_id"`
	IPAddress string            `json:"ip_address"`
	Error     string            `json:"error"`
	Details   map[string]string `json:"details"`
}

// authEventCacheCap bounds the in-memory cache -- same reasoning as
// mlAnomalyCacheCap (#64): this dashboard is memory-bounded on purpose, and
// an unbounded cache fed by an external, attacker-influenced signal (a
// credential-stuffing burst inflates this exactly like attacker behavior
// inflates anomaly scores) must be capped by construction.
const authEventCacheCap = 500

type authEventStore struct {
	mu    sync.RWMutex
	items []authFailureEvent // ascending by @timestamp, capped to the newest authEventCacheCap
	since string             // last-seen @timestamp; next poll's lower bound
}

func (c *authEventStore) checkpoint() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.since
}

func (c *authEventStore) absorb(items []authFailureEvent) {
	if len(items) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = append(c.items, items...)
	if len(c.items) > authEventCacheCap {
		c.items = c.items[len(c.items)-authEventCacheCap:]
	}
	c.since = items[len(items)-1].Timestamp
}

func (c *authEventStore) snapshot() []authFailureEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]authFailureEvent, len(c.items))
	copy(out, c.items)
	return out
}

// refreshAuthEvents polls auth-failure-events for documents newer than the
// last seen checkpoint. Best-effort, same error handling as
// refreshMLAnomalies: a failed or empty poll leaves the cache untouched and
// the next tick retries.
func (s *store) refreshAuthEvents() {
	if s.es == nil || s.authEvents == nil {
		return
	}
	path := "/auth-failure-events/_search?size=" + strconv.Itoa(authEventCacheCap) + "&sort=%40timestamp%3Aasc"
	if since := s.authEvents.checkpoint(); since != "" {
		path += "&q=" + url.QueryEscape("@timestamp:{"+since+" TO *]")
	}
	b, err := s.es.request(path)
	if err != nil {
		return
	}
	var resp struct {
		Hits struct {
			Hits []struct {
				Source authFailureEvent `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if json.Unmarshal(b, &resp) != nil {
		return
	}
	items := make([]authFailureEvent, len(resp.Hits.Hits))
	for i, h := range resp.Hits.Hits {
		items[i] = h.Source
	}
	s.authEvents.absorb(items)
}

// authEventFilter holds /auth-events' query parameters, mirroring
// mlAnomalyFilter's shape (ml_anomalies.go).
type authEventFilter struct {
	clientID, errorType, ipAddress, since string
}

func parseAuthEventFilter(r *http.Request) authEventFilter {
	v := r.URL.Query()
	return authEventFilter{
		clientID:  strings.TrimSpace(v.Get("client")),
		errorType: strings.TrimSpace(v.Get("error")),
		ipAddress: strings.TrimSpace(v.Get("ip")),
		since:     strings.TrimSpace(v.Get("since")),
	}
}

func (f authEventFilter) match(e authFailureEvent) bool {
	if f.clientID != "" && e.ClientID != f.clientID {
		return false
	}
	if f.errorType != "" && e.Error != f.errorType {
		return false
	}
	if f.ipAddress != "" && e.IPAddress != f.ipAddress {
		return false
	}
	if f.since != "" && e.Timestamp <= f.since {
		return false
	}
	return true
}

func (f authEventFilter) describe() []string {
	var out []string
	add := func(k, v string) {
		if v != "" {
			out = append(out, k+" = "+v)
		}
	}
	add("client", f.clientID)
	add("error", f.errorType)
	add("ip", f.ipAddress)
	add("since", f.since)
	return out
}

// authEventStats is /auth-events' summary panel, mirroring
// mlAnomalyStatsFrom's shape (ml_anomalies.go).
type authEventStats struct {
	Total24h  int64 `json:"total_24h"`
	ByClient  []kv  `json:"by_client"`
	TopSrcIPs []kv  `json:"top_src_ips"`
}

func authEventStatsFrom(items []authFailureEvent, now time.Time) authEventStats {
	stats := authEventStats{}
	byClient := map[string]int{}
	byIP := map[string]int{}
	cutoff := now.Add(-24 * time.Hour)
	for _, item := range items {
		ts, err := time.Parse(time.RFC3339, item.Timestamp)
		if err != nil || ts.Before(cutoff) {
			continue
		}
		stats.Total24h++
		if item.ClientID != "" {
			byClient[item.ClientID]++
		}
		if item.IPAddress != "" {
			byIP[item.IPAddress]++
		}
	}
	for client, n := range byClient {
		stats.ByClient = append(stats.ByClient, kv{Key: client, Count: n, Link: "/auth-events?client=" + url.QueryEscape(client)})
	}
	sort.Slice(stats.ByClient, func(i, j int) bool {
		if stats.ByClient[i].Count != stats.ByClient[j].Count {
			return stats.ByClient[i].Count > stats.ByClient[j].Count
		}
		return stats.ByClient[i].Key < stats.ByClient[j].Key
	})
	for ip, n := range byIP {
		stats.TopSrcIPs = append(stats.TopSrcIPs, kv{Key: ip, Count: n, Link: "/auth-events?ip=" + url.QueryEscape(ip)})
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

func (s *store) serveAuthEventsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.authEvents == nil {
		json.NewEncoder(w).Encode([]authFailureEvent{})
		return
	}
	items := s.authEvents.snapshot()
	f := parseAuthEventFilter(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > authEventCacheCap {
		limit = 100
	}
	filtered := make([]authFailureEvent, 0, len(items))
	for _, item := range items {
		if f.match(item) {
			filtered = append(filtered, item)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Timestamp > filtered[j].Timestamp })
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	json.NewEncoder(w).Encode(filtered)
}

// authEventsPage is /auth-events' page data -- server-rendered from the
// cache on each request, same pattern as mlAnomaliesPage.
type authEventsPage struct {
	pageMeta
	Generated time.Time
	Enabled   bool
	Events    []authFailureEvent
	Stats     authEventStats
	Filters   []string
	filterBar
}

// Skeleton-sweep audit (#1157 follow-up): this handler was checked against
// the site-wide instant-render sweep and needs no change. It only reads
// s.authEvents.snapshot() -- an in-memory, mutex-protected slice -- with no
// ES/file I/O in the per-request path; the real ES fetch (refreshAuthEvents)
// runs on a background ticker AND once synchronously in main() before
// http.ListenAndServe, so unlike the rebuild()-backed listing pages #1155
// fixed there is no cold-start window where a request can observe a
// not-yet-populated cache. No Ready/Loading gate or skeleton is warranted.
func (s *store) authEventsData(r *http.Request) authEventsPage {
	f := parseAuthEventFilter(r)
	bar := buildFilterBar(r, "/auth-events",
		[2]string{"client", "Client"}, [2]string{"error", "Error"}, [2]string{"ip", "Source IP"})
	page := authEventsPage{Generated: time.Now(), Enabled: s.es != nil, Filters: f.describe(), filterBar: bar}
	if s.authEvents == nil {
		return page
	}
	items := s.authEvents.snapshot()
	filtered := make([]authFailureEvent, 0, len(items))
	for _, item := range items {
		if f.match(item) {
			filtered = append(filtered, item)
		}
	}
	page.Stats = authEventStatsFrom(filtered, time.Now().UTC())
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Timestamp > filtered[j].Timestamp })
	page.Events = filtered
	return page
}
