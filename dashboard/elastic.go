package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type esSource struct {
	Name  string
	Count int64
	Link  string
}

type esStatus struct {
	Enabled           bool
	State             string
	Documents         int64
	DeadLetters       int64
	RecentDeadLetters int64
	FilebeatState     string
	FilebeatAcked     int64
	FilebeatFailed    int64
	FilebeatDropped   int64
	FilebeatActive    int64
	LastIngest        string
	LastIngestAge     string
	IngestState       string
	Checked           string
	Error             string `json:",omitempty"`
	Sources           []esSource
}

type esClient struct {
	base         string
	filebeatBase string
	http         *http.Client
	mu           sync.RWMutex
	stat         esStatus
}

func newESClient(base, filebeatBase string) *esClient {
	return &esClient{base: strings.TrimRight(base, "/"), filebeatBase: strings.TrimRight(filebeatBase, "/"), http: &http.Client{Timeout: 8 * time.Second}, stat: esStatus{Enabled: base != ""}}
}

func (c *esClient) get() esStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stat
}

func (c *esClient) request(path string) ([]byte, error) {
	r, err := c.http.Get(c.base + path)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if r.StatusCode/100 != 2 {
		return nil, fmt.Errorf("Elasticsearch %s: %s", r.Status, strings.TrimSpace(string(b)))
	}
	return b, nil
}

// requestMethod is request's mutating counterpart (POST/DELETE/...), used
// only by purgeDeadLetters today. Kept separate from request rather than
// generalizing it: every other Elasticsearch call in this file is
// deliberately read-only, and a shared helper that silently accepted any
// method would make that no longer obvious from the call site.
func (c *esClient) requestMethod(method, path string) ([]byte, error) {
	req, err := http.NewRequest(method, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if r.StatusCode/100 != 2 {
		return nil, fmt.Errorf("Elasticsearch %s: %s", r.Status, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func (c *esClient) count(index, query string) (int64, error) {
	path := "/" + index + "/_count"
	if query != "" {
		path += "?q=" + url.QueryEscape(query)
	}
	b, err := c.request(path)
	if err != nil {
		return 0, err
	}
	var v struct {
		Count int64 `json:"count"`
	}
	err = json.Unmarshal(b, &v)
	return v.Count, err
}

func (c *esClient) refresh() {
	st := esStatus{Enabled: true, Checked: time.Now().Format("2006-01-02 15:04:05 MST")}
	if b, err := c.request("/_cluster/health?filter_path=status"); err == nil {
		var h struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(b, &h)
		st.State = h.Status
	} else {
		st.Error = err.Error()
		c.set(st)
		return
	}
	st.Documents, _ = c.count("honeypot-v2-*,suricata-*", "")
	st.DeadLetters, _ = c.count("dead-letter-honeypot*", "")
	st.RecentDeadLetters, _ = c.count("dead-letter-honeypot*", "@timestamp:[now-24h TO now]")
	c.refreshFilebeat(&st)
	if b, err := c.request("/honeypot-v2-*,suricata-*/_search?size=1&sort=%40timestamp%3Adesc&filter_path=hits.hits._source.%40timestamp"); err == nil {
		var v struct {
			Hits struct {
				Hits []struct {
					Source map[string]any `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if json.Unmarshal(b, &v) == nil && len(v.Hits.Hits) > 0 {
			st.LastIngest = fmt.Sprint(v.Hits.Hits[0].Source["@timestamp"])
			if parsed, err := time.Parse(time.RFC3339Nano, st.LastIngest); err == nil {
				age := time.Since(parsed)
				if age < 0 {
					age = 0
				}
				st.LastIngestAge = age.Round(time.Second).String()
				st.IngestState = "healthy"
				if age > 15*time.Minute {
					st.IngestState = "stale"
				} else if age > 2*time.Minute {
					st.IngestState = "delayed"
				}
			}
		}
	}
	queries := []struct{ name, index, query string }{
		{"cowrie", "honeypot-v2-*", "honeypot.eventid:cowrie.*"}, {"multipot", "honeypot-v2-*", "event.sensor:multipot"},
		{"http", "honeypot-v2-*", "event.sensor:http-honeypot"}, {"api-honeypot", "honeypot-v2-*", "event.sensor:api-honeypot"},
		{"dionaea", "honeypot-v2-*", "log.file.path:*dionaea*"}, {"conpot", "honeypot-v2-*", "event.sensor:conpot"},
		{"conpot-s7-1200", "honeypot-v2-*", "event.sensor:conpot-s7-1200"}, {"conpot-s7-1500", "honeypot-v2-*", "event.sensor:conpot-s7-1500"},
		{"conpot-iec104", "honeypot-v2-*", "event.sensor:conpot-iec104"}, {"conpot-guardian", "honeypot-v2-*", "event.sensor:conpot-guardian"},
		{"conpot-kamstrup", "honeypot-v2-*", "event.sensor:conpot-kamstrup"}, {"tanner", "honeypot-v2-*", "log.file.path:*tanner*"},
		{"dicompot", "honeypot-v2-*", "event.sensor:dicompot"},
		{"dns-honeypot", "honeypot-v2-*", "event.sensor:dns-honeypot"},
		{"suricata", "suricata-*", ""},
	}
	for _, q := range queries {
		if n, err := c.count(q.index, q.query); err == nil {
			historyQuery := q.query
			if historyQuery == "" {
				historyQuery = "_index:" + q.index
			}
			st.Sources = append(st.Sources, esSource{Name: q.name, Count: n, Link: "/history?q=" + url.QueryEscape(historyQuery)})
		}
	}
	c.set(st)
}

func (c *esClient) deadLetters(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	path := fmt.Sprintf("/dead-letter-honeypot*/_search?size=%d&sort=%%40timestamp%%3Adesc", limit)
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		path += "&q=" + url.QueryEscape(q)
	}
	b, err := c.request(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

// purgeDeadLetters deletes dead-letter documents matching the same `q`
// Lucene query-string param /dead-letters' own search box already uses --
// the operator purges exactly the scope they were just looking at, never a
// silently broader one (#59, same "filtered scope, not the unfiltered set"
// rule the export modal enforces). An empty query is accepted (purges every
// retained dead letter) but is never the default the client sends without
// the operator explicitly clearing the search box first -- the confirmation
// modal states the scope in words either way.
func (c *esClient) purgeDeadLetters(w http.ResponseWriter, r *http.Request) {
	path := "/dead-letter-honeypot*/_delete_by_query?conflicts=proceed"
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		path += "&q=" + url.QueryEscape(q)
	}
	b, err := c.requestMethod(http.MethodPost, path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	var result struct {
		Deleted int64 `json:"deleted"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		http.Error(w, "purge ran but the response could not be parsed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"deleted": result.Deleted})
}

func (c *esClient) refreshFilebeat(st *esStatus) {
	if c.filebeatBase == "" {
		return
	}
	r, err := c.http.Get(c.filebeatBase + "/stats")
	if err != nil {
		st.FilebeatState = "unreachable"
		return
	}
	defer r.Body.Close()
	if r.StatusCode/100 != 2 {
		st.FilebeatState = r.Status
		return
	}
	var v struct {
		Libbeat struct {
			Output struct {
				Events struct{ Acked, Failed, Dropped, Active int64 } `json:"events"`
			} `json:"output"`
		} `json:"libbeat"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&v) == nil {
		st.FilebeatState = "healthy"
		st.FilebeatAcked, st.FilebeatFailed = v.Libbeat.Output.Events.Acked, v.Libbeat.Output.Events.Failed
		st.FilebeatDropped, st.FilebeatActive = v.Libbeat.Output.Events.Dropped, v.Libbeat.Output.Events.Active
	}
}

func (c *esClient) set(st esStatus) {
	c.mu.Lock()
	c.stat = st
	c.mu.Unlock()
}

// searchNamespace runs a bounded _search against index and returns each
// hit's `field` sub-document, still JSON-encoded. #384: the four
// #383-mirrored result indices (ghidra/sandbox/github-analysis/workbench)
// store the producer's original, unmodified result JSON under a
// source-namespaced field (see analysis/es-results-importer/importer.py's
// build_document) -- so a caller can unmarshal the returned bytes straight
// into the same struct it already unmarshals the local JSON file into,
// with no separate ES-specific schema to maintain.
//
// size is capped at Elasticsearch's default index.max_result_window
// (10000): these are analysis-result indices, not the high-volume event
// stream, so an unpaged single page comfortably covers realistic corpus
// sizes today. Revisit with search_after/scroll if that stops being true.
func (c *esClient) searchNamespace(index, field string, size int) ([]json.RawMessage, error) {
	if size <= 0 || size > 10000 {
		size = 10000
	}
	b, err := c.request(fmt.Sprintf("/%s/_search?size=%d", index, size))
	if err != nil {
		return nil, err
	}
	var v struct {
		Hits struct {
			Hits []struct {
				Source map[string]json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	out := make([]json.RawMessage, 0, len(v.Hits.Hits))
	for _, h := range v.Hits.Hits {
		if raw, ok := h.Source[field]; ok {
			out = append(out, raw)
		}
	}
	return out, nil
}

func (c *esClient) history(w http.ResponseWriter, r *http.Request, attachment bool) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	index := "honeypot-v2-*,suricata-*"
	path := fmt.Sprintf("/%s/_search?size=%d&sort=%%40timestamp%%3Adesc", index, limit)
	if q != "" {
		path += "&q=" + url.QueryEscape(q)
	}
	b, err := c.request(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if attachment {
		w.Header().Set("Content-Disposition", `attachment; filename="honeypot-history.json"`)
	}
	w.Write(b)
}
