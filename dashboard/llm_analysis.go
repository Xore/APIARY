package main

// llm_analysis.go delivers llm-worker's guarded model output (llm-analysis
// ES index, docs/gpu-llm-analysis-worker.md §10, llm-worker/worker.py's
// ANALYSIS_INDEX) to the dashboard (#150). #66 builds the worker and its
// Elasticsearch output; #83 gates real-model canary runs; neither owns this
// delivery layer.
//
// Transport decision: Elasticsearch polling on the same 1-minute ES ticker
// mlAnomalies already uses (main.go), not a new SSE/Redis path -- matching
// #150's own scope note ("Use Elasticsearch polling first; any SSE/Redis
// wake-up path remains optional and non-authoritative") and mlAnomalies'
// precedent (#64) for the identical decision.
//
// Everything this endpoint returns is guarded, attacker-influenced model
// output (llm-worker/worker.py's own sanitize_text() already strips control
// characters and truncates before the model ever sees it, but the model's
// own summary/behaviors/etc. text is still free-form and must never be
// trusted as markup). json.Marshal's default SetEscapeHTML(true) already
// backslash-escapes <, >, and & in every string field this encodes, and the
// page (llm_analysis.html) renders every field through Go's html/template,
// which HTML-escapes on top of that -- two independent layers, neither
// dependent on the other holding.
import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// llmAnalysisDoc mirrors llm-worker/worker.py's base_document()/
// analysis_mapping() field-for-field -- not reinterpreted, the same
// direct-contract approach mlAnomaly already takes toward ml-worker's
// write_anomaly(). Every doc_type ("session", "payload", "report", "error")
// shares this one flat shape; annotation fields simply stay empty for
// doc_types that never populate them (e.g. Error is empty on every doc_type
// except "error").
type llmAnalysisDoc struct {
	Timestamp          string   `json:"@timestamp"`
	AnalysisID         string   `json:"analysis_id"`
	DocType            string   `json:"doc_type"`
	SourceIndex        string   `json:"source_index"`
	SourceID           string   `json:"source_id"`
	SessionID          string   `json:"session_id"`
	SrcIP              string   `json:"src_ip"`
	PayloadSHA256      string   `json:"payload_sha256"`
	Model              string   `json:"model"`
	ModelDigest        string   `json:"model_digest"`
	WorkerVersion      string   `json:"worker_version"`
	SchemaVersion      string   `json:"schema_version"`
	PromptVersion      string   `json:"prompt_version"`
	Summary            string   `json:"summary"`
	Intent             string   `json:"intent"`
	Language           string   `json:"language"`
	Behaviors          []string `json:"behaviors"`
	MitreAttack        []string `json:"mitre_attack"`
	IOCs               []string `json:"iocs"`
	Severity           string   `json:"severity"`
	ModelSeverity      string   `json:"model_severity"`
	Confidence         string   `json:"confidence"`
	Highlights         []string `json:"highlights"`
	Trends             []string `json:"trends"`
	RecommendedChecks  []string `json:"recommended_checks"`
	DeterministicFlags []string `json:"deterministic_flags"`
	PromptTruncated    bool     `json:"prompt_truncated"`
	AnalysisMs         int      `json:"analysis_ms"`
	DoneReason         string   `json:"done_reason"`
	ErrorCode          string   `json:"error_code"`
	Error              string   `json:"error"`
	Attempt            int      `json:"attempt"`
}

// AIGenerated is always true -- a fixed field, not a stored one, so a
// template or API consumer can label every row without also having to know
// this whole index only ever holds model output (#150's "label every
// rendered item as AI-generated" requirement, made structural rather than
// left to the caller to remember).
func (d llmAnalysisDoc) AIGenerated() bool { return true }

// EvidenceLink pivots from an analysis document back to the honeypot
// activity it was generated from, mirroring mlAnomaly.SourceLink()'s same
// reasoning (#173): a session analysis links to every event in that
// session, a payload analysis links to the payload's own entry, and a
// report (an aggregate over many sessions/payloads, no single source
// document) has no single evidence link.
func (d llmAnalysisDoc) EvidenceLink() string {
	switch d.DocType {
	case "session":
		if d.SessionID == "" {
			return ""
		}
		q := `honeypot.session:"` + d.SessionID + `"`
		return "/history?" + url.Values{"q": {q}}.Encode()
	case "payload":
		if d.PayloadSHA256 == "" {
			return ""
		}
		return "/payloads?q=" + url.QueryEscape(d.PayloadSHA256)
	default:
		return ""
	}
}

// llmAnalysisCacheCap bounds the in-memory cache, same reasoning as
// mlAnomalyCacheCap: the dashboard is memory-bounded on purpose, and this
// index is fed by an external, unbounded-cardinality producer (llm-worker
// runs continuously against live attacker sessions).
const llmAnalysisCacheCap = 200

type llmAnalysisStore struct {
	mu    sync.RWMutex
	items []llmAnalysisDoc // ascending by @timestamp, capped to the newest llmAnalysisCacheCap
	since string           // last-seen @timestamp; next poll's lower bound
}

func (c *llmAnalysisStore) checkpoint() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.since
}

func (c *llmAnalysisStore) absorb(items []llmAnalysisDoc) {
	if len(items) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = append(c.items, items...)
	if len(c.items) > llmAnalysisCacheCap {
		c.items = c.items[len(c.items)-llmAnalysisCacheCap:]
	}
	c.since = items[len(items)-1].Timestamp
}

func (c *llmAnalysisStore) snapshot() []llmAnalysisDoc {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]llmAnalysisDoc, len(c.items))
	copy(out, c.items)
	return out
}

// refreshLLMAnalysis polls llm-analysis for documents newer than the last
// seen checkpoint. Best-effort, mirroring refreshMLAnomalies exactly: a
// failed poll (including a missing index -- the worker may not have run
// yet, or #150's dashboard support may be deployed ahead of #66's worker)
// leaves the cache and checkpoint untouched; the next tick retries. A
// document that fails to unmarshal (malformed/unexpected shape) is skipped
// individually rather than discarding the whole poll.
func (s *store) refreshLLMAnalysis() {
	if s.es == nil || s.llmAnalysis == nil {
		return
	}
	path := "/llm-analysis/_search?size=" + strconv.Itoa(llmAnalysisCacheCap) + "&sort=%40timestamp%3Aasc"
	if since := s.llmAnalysis.checkpoint(); since != "" {
		path += "&q=" + url.QueryEscape("@timestamp:{"+since+" TO *]")
	}
	b, err := s.es.request(path)
	if err != nil {
		return
	}
	var resp struct {
		Hits struct {
			Hits []struct {
				Source json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if json.Unmarshal(b, &resp) != nil {
		return
	}
	items := make([]llmAnalysisDoc, 0, len(resp.Hits.Hits))
	for _, h := range resp.Hits.Hits {
		var doc llmAnalysisDoc
		if json.Unmarshal(h.Source, &doc) != nil {
			continue
		}
		items = append(items, doc)
	}
	s.llmAnalysis.absorb(items)
}

// llmAnalysisFilter holds the /llm-analysis page's and /api/llm/analysis
// endpoint's query parameters, mirroring mlAnomalyFilter's shape (#280-style:
// all set fields must match, AND).
type llmAnalysisFilter struct {
	docType, severity, since string
}

func parseLLMAnalysisFilter(r *http.Request) llmAnalysisFilter {
	v := r.URL.Query()
	return llmAnalysisFilter{
		docType:  strings.TrimSpace(v.Get("doc_type")),
		severity: strings.TrimSpace(v.Get("severity")),
		since:    strings.TrimSpace(v.Get("since")),
	}
}

func (f llmAnalysisFilter) match(d llmAnalysisDoc) bool {
	if f.docType != "" && d.DocType != f.docType {
		return false
	}
	if f.severity != "" && d.Severity != f.severity {
		return false
	}
	if f.since != "" && d.Timestamp <= f.since {
		return false
	}
	return true
}

func (f llmAnalysisFilter) describe() []string {
	var out []string
	add := func(k, v string) {
		if v != "" {
			out = append(out, k+" = "+v)
		}
	}
	add("doc_type", f.docType)
	add("severity", f.severity)
	if f.since != "" {
		out = append(out, "since = "+f.since)
	}
	return out
}

// serveLLMAnalysisAPI implements GET /api/llm/analysis: doc_type/severity/since
// filters plus limit (default 50, capped at the cache size), over the
// cached, already-polled set -- never a live Elasticsearch call on the
// request path, mirroring serveMLAnomaliesAPI exactly.
func (s *store) serveLLMAnalysisAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.llmAnalysis == nil {
		json.NewEncoder(w).Encode([]llmAnalysisDoc{})
		return
	}
	items := s.llmAnalysis.snapshot()
	f := parseLLMAnalysisFilter(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > llmAnalysisCacheCap {
		limit = 50
	}
	filtered := make([]llmAnalysisDoc, 0, len(items))
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

// llmAnalysisPage is /llm-analysis's page data -- server-rendered from the
// cache on each request, same "no client-side polling, a reload shows the
// current cache" posture as /ml-anomalies.
type llmAnalysisPage struct {
	pageMeta
	Generated time.Time
	Enabled   bool
	Docs      []llmAnalysisDoc
	Filters   []string
	filterBar
}

func (s *store) llmAnalysisData(r *http.Request) llmAnalysisPage {
	f := parseLLMAnalysisFilter(r)
	bar := buildFilterBar(r, "/llm-analysis",
		[2]string{"doc_type", "Type"}, [2]string{"severity", "Severity"})
	page := llmAnalysisPage{Generated: time.Now(), Enabled: s.es != nil, Filters: f.describe(), filterBar: bar}
	if s.llmAnalysis == nil {
		return page
	}
	items := s.llmAnalysis.snapshot()
	filtered := make([]llmAnalysisDoc, 0, len(items))
	for _, item := range items {
		if f.match(item) {
			filtered = append(filtered, item)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Timestamp > filtered[j].Timestamp })
	page.Docs = filtered
	return page
}

// llmAnalysisAlerts appends alerts for llm-worker's own analysis failures
// and for session/payload analyses the model itself scored high/critical,
// riding the same s.alerts sink as ghidraAlerts/githubAnalysisAlerts
// (dashboard/store.go) -- no new transport. Threat model research (#154,
// docs/agent-intrusion-threat-model.md item 9) found llm-analysis severity
// was reachable only by browsing /llm-analysis, never wired into the alert
// sink at all; this closes that gap.
//
// Severity here is a model judgment, not a deterministic signal -- the same
// posture ghidraAlerts already takes toward Ghidra's own AI triage risk
// level, and the same reasoning docs/gpu-llm-analysis-worker.md §10 already
// states for phase 2 ("treat model output as advisory; deterministic rules
// own... critical alert gates"): this alert surfaces the model's judgment
// for a human to review, it does not act on it, and the message itself says
// so, the same way ghidraAlerts' own comment explains why hiding that would
// be worse than not alerting at all.
//
// "report" doc_type is deliberately excluded -- an aggregate over many
// sessions/payloads, not evidence of a single actor's behavior, and
// EvidenceLink() already treats it the same way (no single source document).
func llmAnalysisAlerts(s *store, messages *[]string, markOnly bool) {
	if s.llmAnalysis == nil {
		// Elasticsearch not configured, or llm-worker's dashboard support
		// (#150) deployed ahead of #66's worker -- alerting about a subsystem
		// that was never wired up is pure noise, same reasoning as
		// ghidraAlerts'/githubAnalysisAlerts' own Configured checks.
		return
	}

	emit := func(key, message, link string) {
		if s.alerts == nil || s.alerts.observe(key, message, link, markOnly) {
			if !markOnly {
				*messages = append(*messages, message)
			}
		}
	}

	alertSeverities := map[string]bool{}
	for _, level := range strings.Split(getenv("LLM_ANALYSIS_ALERT_SEVERITIES", "high,critical"), ",") {
		if level = strings.ToLower(strings.TrimSpace(level)); level != "" {
			alertSeverities[level] = true
		}
	}

	for _, doc := range s.llmAnalysis.snapshot() {
		if doc.AnalysisID == "" {
			continue
		}
		if doc.DocType == "error" {
			emit("llm-analysis:error:"+doc.AnalysisID, fmt.Sprintf(
				"llm-analysis failed: analysis_id=%s code=%s error=%s", doc.AnalysisID, doc.ErrorCode, doc.Error), "")
			continue
		}
		if doc.DocType != "session" && doc.DocType != "payload" {
			continue
		}
		if !alertSeverities[strings.ToLower(strings.TrimSpace(doc.Severity))] {
			continue
		}
		emit("llm-analysis:flagged:"+doc.AnalysisID, fmt.Sprintf(
			"llm-analysis flagged %s: analysis_id=%s AI-guessed severity=%s (UNVERIFIED, model=%s) intent=%s",
			doc.DocType, doc.AnalysisID, doc.Severity, doc.Model, doc.Intent), doc.EvidenceLink())
	}
}
