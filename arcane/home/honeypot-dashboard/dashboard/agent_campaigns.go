package main

// agent_campaigns.go delivers agent-intrusion-worker's correlated,
// deterministically-scored campaign verdicts (agent-intrusion-campaigns ES
// index, analysis/agent-intrusion-corpus/worker.py) to the dashboard --
// #154 phase 5's own "operator evidence" requirement: for each escalated
// campaign, which events triggered which rule, the trust boundary crossed,
// decoded-artifact hashes, and links back to the raw source event. No
// narrative/LLM text is rendered here at all -- everything on this page
// comes from criticality_rules.py's deterministic matches, so there is no
// untrusted free-text model output to guard against in the first place
// (contrast llm_analysis.go, which does carry that concern).
//
// Transport/caching follow ml_anomalies.go's own established pattern
// exactly (ES polling on the dashboard's existing 1-minute ticker,
// in-memory cache, no new SSE/Redis path) with one deliberate difference:
// campaign documents are upserted in place by worker.py (same campaign_id
// re-written on every poll cycle a campaign is still active), not
// append-only like ml-anomalies' one-document-per-anomaly shape -- so this
// store's cache is keyed by campaign_id and absorb() replaces, not appends.

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

// decodeStep mirrors decode_correlate.DecodeStep exactly, as serialized by
// worker.py's build_campaign_verdict (dataclasses.asdict) -- #154 phase 5's
// own "decoded-artifact hashes" requirement.
type decodeStep struct {
	Transform    string `json:"transform"`
	InputSHA256  string `json:"input_sha256"`
	OutputSHA256 string `json:"output_sha256"`
	OutputLen    int    `json:"output_len"`
}

// campaignMatchedRule mirrors one entry of worker.py's own matched_rules
// list -- field names and shapes intentionally identical, a direct
// contract with that file rather than an independent guess (same posture
// as mlAnomaly's own doc comment in ml_anomalies.go).
type campaignMatchedRule struct {
	Rule          string       `json:"rule"`
	Reason        string       `json:"reason"`
	TrustBoundary string       `json:"trust_boundary"`
	DecodeChain   []decodeStep `json:"decode_chain"`
}

// FinalArtifactHash returns the sha256 of the last layer bounded_decode
// peeled off (empty if this rule never decoded anything) -- the one hash
// an operator actually wants at a glance: the artifact as it existed right
// before whatever happened next, not every intermediate layer.
func (m campaignMatchedRule) FinalArtifactHash() string {
	if len(m.DecodeChain) == 0 {
		return ""
	}
	return m.DecodeChain[len(m.DecodeChain)-1].OutputSHA256
}

// TransformPath renders the decode chain as "base64 -> gzip -> base64", the
// same transform-only summary the template would otherwise need a loop
// index/arithmetic helper to build.
func (m campaignMatchedRule) TransformPath() string {
	transforms := make([]string, len(m.DecodeChain))
	for i, step := range m.DecodeChain {
		transforms[i] = step.Transform
	}
	return strings.Join(transforms, " → ")
}

// campaignEvent mirrors one entry of worker.py's own "events" list.
type campaignEvent struct {
	EventID      string                `json:"event_id"`
	SourceIndex  string                `json:"source_index"`
	Timestamp    string                `json:"timestamp"`
	MatchedRules []campaignMatchedRule `json:"matched_rules"`
}

// SourceLink pivots from a campaign member event back to the raw sensor
// document that produced it -- #154 phase 5's own "links back to raw
// evidence" requirement, identical reasoning and shape to mlAnomaly's own
// SourceLink in ml_anomalies.go (a raw Elasticsearch _id is only unique
// within its own source index, so both are pinned together).
func (e campaignEvent) SourceLink() string {
	if e.EventID == "" || e.SourceIndex == "" {
		return ""
	}
	q := `_id:"` + e.EventID + `" AND _index:"` + e.SourceIndex + `"`
	return "/history?" + url.Values{"q": {q}}.Encode()
}

// agentCampaign mirrors the document worker.py's build_campaign_verdict()
// writes to the agent-intrusion-campaigns index.
type agentCampaign struct {
	Timestamp              string          `json:"@timestamp"`
	CampaignID             string          `json:"campaign_id"`
	Start                  string          `json:"start"`
	End                    string          `json:"end"`
	Severity               string          `json:"severity"`
	MatchedCategories      []string        `json:"matched_categories"`
	CorrelationIdentifiers []string        `json:"correlation_identifiers"`
	EventCount             int             `json:"event_count"`
	Events                 []campaignEvent `json:"events"`
}

// IdentifierLinks pairs each correlation identifier with a best-effort
// drill-down URL, for the page to render as a chip -- "ip:"/"session:" pivot
// straight into the existing event filters; "channel:" (a value recovered
// from free text, not an indexed field) falls back to /history's raw query
// search, the same fallback mlAnomaly.SourceLink already relies on for a
// comparable reason.
func (c agentCampaign) IdentifierLinks() []kv {
	out := make([]kv, 0, len(c.CorrelationIdentifiers))
	for _, id := range c.CorrelationIdentifiers {
		kind, value, ok := strings.Cut(id, ":")
		if !ok {
			out = append(out, kv{Key: id})
			continue
		}
		switch kind {
		case "ip":
			out = append(out, kv{Key: id, Link: "/events?ip=" + url.QueryEscape(value)})
		case "session":
			out = append(out, kv{Key: id, Link: "/events?session=" + url.QueryEscape(value)})
		case "channel":
			out = append(out, kv{Key: id, Link: "/history?" + url.Values{"q": {value}}.Encode()})
		default:
			out = append(out, kv{Key: id})
		}
	}
	return out
}

// agentCampaignCacheCap bounds the in-memory cache -- same reasoning as
// mlAnomalyCacheCap: the dashboard is memory-capped on purpose, and this
// cache is fed by an external, attacker-influenced signal.
const agentCampaignCacheCap = 200

type agentCampaignStore struct {
	mu    sync.RWMutex
	items map[string]agentCampaign // keyed by campaign_id -- see package comment on why this upserts rather than appends
	since string                   // last-seen @timestamp; next poll's lower bound
}

func (c *agentCampaignStore) checkpoint() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.since
}

// absorb upserts newly-polled campaign verdicts (already ascending by
// @timestamp) by campaign_id, then trims to the cap by evicting the
// least-recently-written campaigns first -- a still-active campaign gets
// its @timestamp refreshed every cycle it's re-evaluated, so eviction by
// @timestamp naturally keeps stale/resolved campaigns from crowding out
// active ones. Safe to call with an empty slice (no-op).
func (c *agentCampaignStore) absorb(items []agentCampaign) {
	if len(items) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		c.items = map[string]agentCampaign{}
	}
	for _, it := range items {
		c.items[it.CampaignID] = it
	}
	if len(c.items) > agentCampaignCacheCap {
		all := make([]agentCampaign, 0, len(c.items))
		for _, v := range c.items {
			all = append(all, v)
		}
		sort.Slice(all, func(i, j int) bool { return all[i].Timestamp < all[j].Timestamp })
		for _, stale := range all[:len(all)-agentCampaignCacheCap] {
			delete(c.items, stale.CampaignID)
		}
	}
	c.since = items[len(items)-1].Timestamp
}

func (c *agentCampaignStore) snapshot() []agentCampaign {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]agentCampaign, 0, len(c.items))
	for _, v := range c.items {
		out = append(out, v)
	}
	return out
}

// refreshAgentCampaigns polls agent-intrusion-campaigns for documents newer
// than the last seen checkpoint. Best-effort, identical error posture to
// refreshMLAnomalies: a failed or empty poll leaves the cache and
// checkpoint untouched, retried on the next tick.
func (s *store) refreshAgentCampaigns() {
	if s.es == nil || s.agentCampaigns == nil {
		return
	}
	path := "/agent-intrusion-campaigns/_search?size=" + strconv.Itoa(agentCampaignCacheCap) + "&sort=%40timestamp%3Aasc"
	if since := s.agentCampaigns.checkpoint(); since != "" {
		path += "&q=" + url.QueryEscape("@timestamp:{"+since+" TO *]")
	}
	b, err := s.es.request(path)
	if err != nil {
		return
	}
	var resp struct {
		Hits struct {
			Hits []struct {
				Source agentCampaign `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if json.Unmarshal(b, &resp) != nil {
		return
	}
	items := make([]agentCampaign, len(resp.Hits.Hits))
	for i, h := range resp.Hits.Hits {
		items[i] = h.Source
	}
	s.agentCampaigns.absorb(items)
}

// agentCampaignFilter holds the /agent-campaigns and /api/agent-campaigns
// query parameters -- deliberately narrower than mlAnomalyFilter, since a
// campaign is a richer, multi-event object with no single src_ip/proto/etc.
// of its own to filter on the way one anomaly document has.
type agentCampaignFilter struct {
	severity, category, identifier string
}

func parseAgentCampaignFilter(r *http.Request) agentCampaignFilter {
	v := r.URL.Query()
	return agentCampaignFilter{
		severity:   strings.TrimSpace(v.Get("severity")),
		category:   strings.TrimSpace(v.Get("category")),
		identifier: strings.TrimSpace(v.Get("id")),
	}
}

func (f agentCampaignFilter) match(c agentCampaign) bool {
	if f.severity != "" && c.Severity != f.severity {
		return false
	}
	if f.category != "" {
		found := false
		for _, cat := range c.MatchedCategories {
			if cat == f.category {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.identifier != "" {
		found := false
		for _, id := range c.CorrelationIdentifiers {
			if strings.Contains(id, f.identifier) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (f agentCampaignFilter) describe() []string {
	var out []string
	add := func(k, v string) {
		if v != "" {
			out = append(out, k+" = "+v)
		}
	}
	add("severity", f.severity)
	add("category", f.category)
	add("identifier", f.identifier)
	return out
}

// serveAgentCampaignsAPI implements GET /api/agent-campaigns: limit
// (default 50, capped at the cache size) plus every agentCampaignFilter
// field, over the cached, already-polled set -- same "never a live
// Elasticsearch call on the request path" cost bound as
// serveMLAnomaliesAPI.
func (s *store) serveAgentCampaignsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.agentCampaigns == nil {
		json.NewEncoder(w).Encode([]agentCampaign{})
		return
	}
	items := s.agentCampaigns.snapshot()
	f := parseAgentCampaignFilter(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > agentCampaignCacheCap {
		limit = 50
	}
	filtered := make([]agentCampaign, 0, len(items))
	for _, item := range items {
		if f.match(item) {
			filtered = append(filtered, item)
		}
	}
	// Newest first -- an operator scanning wants the most recently
	// (re-)evaluated campaign on top, matching serveMLAnomaliesAPI.
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Timestamp > filtered[j].Timestamp })
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	json.NewEncoder(w).Encode(filtered)
}

// agentCampaignsPage is /agent-campaigns' page data -- server-rendered from
// the cache on each request, like /ml-anomalies (no live client-side
// polling; a page reload shows the current cache).
type agentCampaignsPage struct {
	pageMeta
	Generated  time.Time
	Enabled    bool
	Campaigns  []agentCampaign
	CountByCat []kv
	Filters    []string
	filterBar
}

// agentCampaignsData has no per-request slow call to gate with a skeleton
// (#1157-sweep audit): it only parses the query string and reads
// s.agentCampaigns.snapshot(), an in-memory copy of a <=agentCampaignCacheCap
// cache that refreshAgentCampaigns populates synchronously before
// srv.ListenAndServe() (main.go) and thereafter only from the background
// 1-minute ticker -- never from this handler. Unlike /ml-anomalies, there is
// no ack-join or any other side call here to worry about.
func (s *store) agentCampaignsData(r *http.Request) agentCampaignsPage {
	f := parseAgentCampaignFilter(r)
	bar := buildFilterBar(r, "/agent-campaigns",
		[2]string{"severity", "Severity"}, [2]string{"category", "Category"}, [2]string{"id", "Identifier contains"})
	page := agentCampaignsPage{Generated: time.Now(), Enabled: s.es != nil, Filters: f.describe(), filterBar: bar}
	if s.agentCampaigns == nil {
		return page
	}
	items := s.agentCampaigns.snapshot()
	filtered := make([]agentCampaign, 0, len(items))
	byCat := map[string]int{}
	for _, item := range items {
		if !f.match(item) {
			continue
		}
		filtered = append(filtered, item)
		for _, cat := range item.MatchedCategories {
			byCat[cat]++
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Timestamp > filtered[j].Timestamp })
	page.Campaigns = filtered
	for cat, n := range byCat {
		page.CountByCat = append(page.CountByCat, kv{Key: cat, Count: n, Link: "/agent-campaigns?category=" + url.QueryEscape(cat)})
	}
	sort.Slice(page.CountByCat, func(i, j int) bool {
		if page.CountByCat[i].Count != page.CountByCat[j].Count {
			return page.CountByCat[i].Count > page.CountByCat[j].Count
		}
		return page.CountByCat[i].Key < page.CountByCat[j].Key
	})
	return page
}
