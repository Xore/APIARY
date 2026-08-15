package main

import (
	"bytes"
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
	// FilebeatDecodeFailures (#1298): filebeat-* is Filebeat's own default
	// fallback index for lines its json.decode processor couldn't parse at
	// all -- a distinct, earlier failure layer from dead-letter-honeypot*
	// (which only ever holds documents Elasticsearch itself rejected after
	// Filebeat successfully decoded and shipped them). No dashboard code
	// path read this index before; a corrupted Suricata eve.json write
	// (crash, disk pressure, a rotation race) landed here completely
	// invisibly.
	FilebeatDecodeFailures int64
	FilebeatState          string
	FilebeatAcked          int64
	FilebeatFailed         int64
	FilebeatDropped        int64
	FilebeatActive         int64
	LastIngest             string
	LastIngestAge          string
	IngestState            string
	Checked                string
	Error                  string `json:",omitempty"`
	Sources                []esSource
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

// esResponseBodyCap bounds every Elasticsearch response this client reads.
// esResultsClient (elastic search results, a separate *esClient instance)
// uses the same cap via this same helper.
const esResponseBodyCap = 16 << 20 // 16MiB

// readCappedBody reads up to esResponseBodyCap bytes from r and errors
// instead of silently truncating when the real response is larger (#1233).
// The four call sites below used to feed io.LimitReader's silently-cut-off
// bytes straight to json.Unmarshal, surfacing a confusing "unterminated
// string" parse error with no indication the response was ever truncated
// -- deadLetters()/history() in particular return full raw documents
// rather than a paginated/summarized view, so a real ES response can
// exceed this cap. Reads one byte past the cap (not the whole oversized
// body) to tell "exactly at the cap" apart from "larger than the cap".
func readCappedBody(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, esResponseBodyCap+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > esResponseBodyCap {
		return nil, fmt.Errorf("Elasticsearch response exceeds the %d byte cap -- narrow the query and try again", esResponseBodyCap)
	}
	return b, nil
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
	b, err := readCappedBody(r.Body)
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
	b, err := readCappedBody(r.Body)
	if err != nil {
		return nil, err
	}
	if r.StatusCode/100 != 2 {
		return nil, fmt.Errorf("Elasticsearch %s: %s", r.Status, strings.TrimSpace(string(b)))
	}
	return b, nil
}

// searchBody POSTs a JSON request body to path (an Elasticsearch _search
// endpoint with an aggregation query) and returns the raw response.
// request/requestMethod are both bodyless; every other caller in this file
// is a plain GET or a no-body mutation, so this stays its own method rather
// than generalizing requestMethod to also carry a body every other caller
// would have to pass nil for.
func (c *esClient) searchBody(path string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	b, err := readCappedBody(r.Body)
	if err != nil {
		return nil, err
	}
	if r.StatusCode/100 != 2 {
		return nil, fmt.Errorf("Elasticsearch %s: %s", r.Status, strings.TrimSpace(string(b)))
	}
	return b, nil
}

// doRequest is the one place in this file that returns a raw status code
// alongside the body -- every other helper here treats a non-2xx response as
// a plain error, which is right for read-only queries but wrong for the
// dashboard-owned write paths below (docGet/docIndex): a 404 on docGet is
// "no record yet", not a failure, and a 409 on docIndex is a concurrent
// writer to retry against, not a failure either. Callers that only need
// "did this succeed" can still treat status/100 != 2 as an error themselves.
func (c *esClient) doRequest(method, path string, body []byte) (status int, respBody []byte, err error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	r, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer r.Body.Close()
	b, err := readCappedBody(r.Body)
	if err != nil {
		return 0, nil, err
	}
	return r.StatusCode, b, nil
}

// openPointInTime opens a point-in-time context against indexPattern,
// returning its ID for use in a subsequent search's "pit" field (see
// loadSensorEventsES). Elasticsearch requires a PIT to sort by _shard_doc --
// the modern, always-available search_after tie-breaker, needed since this
// deployment's Elasticsearch version rejects sorting by _id outright (see
// loadSensorEventsES's own comment for the full story).
func (c *esClient) openPointInTime(indexPattern, keepAlive string) (id string, ok bool) {
	status, b, err := c.doRequest(http.MethodPost, "/"+indexPattern+"/_pit?keep_alive="+url.QueryEscape(keepAlive), nil)
	if err != nil || status/100 != 2 {
		return "", false
	}
	var v struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(b, &v) != nil || v.ID == "" {
		return "", false
	}
	return v.ID, true
}

// closePointInTime releases a PIT opened by openPointInTime. Best-effort:
// an idle PIT also expires on its own keep_alive, so a failure here (the
// caller already got what it needed from the PIT) is not worth surfacing.
func (c *esClient) closePointInTime(id string) {
	if id == "" {
		return
	}
	body, err := json.Marshal(map[string]string{"id": id})
	if err != nil {
		return
	}
	_, _, _ = c.doRequest(http.MethodDelete, "/_pit", body)
}

// esDocHit is one search hit carrying the concurrency-control fields
// (SeqNo/PrimaryTerm) docIndex needs for a compare-and-swap update, alongside
// the document ID and its raw _source.
type esDocHit struct {
	ID          string
	Source      json.RawMessage
	SeqNo       int64
	PrimaryTerm int64
}

// docGet fetches one document by ID for a dashboard-owned index (state this
// process itself writes, e.g. dashboard-alert-state-v1 -- not the sensor
// telemetry indices every other method in this file only ever reads).
// found=false, err=nil on a 404: "no record yet" is the expected first call
// for a new key, not a failure.
func (c *esClient) docGet(index, id string) (hit esDocHit, found bool, err error) {
	status, body, err := c.doRequest(http.MethodGet, "/"+index+"/_doc/"+url.PathEscape(id), nil)
	if err != nil {
		return esDocHit{}, false, err
	}
	if status == http.StatusNotFound {
		return esDocHit{}, false, nil
	}
	if status/100 != 2 {
		return esDocHit{}, false, fmt.Errorf("Elasticsearch GET %s: status %d: %s", index, status, strings.TrimSpace(string(body)))
	}
	var v struct {
		ID          string          `json:"_id"`
		SeqNo       int64           `json:"_seq_no"`
		PrimaryTerm int64           `json:"_primary_term"`
		Source      json.RawMessage `json:"_source"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return esDocHit{}, false, err
	}
	return esDocHit{ID: v.ID, Source: v.Source, SeqNo: v.SeqNo, PrimaryTerm: v.PrimaryTerm}, true, nil
}

// errESConflict is returned by docIndex when the compare-and-swap lost a
// race to a concurrent writer (Elasticsearch's 409 version_conflict_engine_
// exception) -- the caller's own retry loop re-fetches and reapplies rather
// than treating this as a hard failure.
var errESConflict = fmt.Errorf("elasticsearch: concurrent write conflict")

// docIndex writes doc as document id in a dashboard-owned index.
// create=true uses Elasticsearch's op_type=create (fails if the ID already
// exists -- for the first write of a brand new key, where there is no prior
// seq_no/primary_term to condition on). create=false conditions the write on
// seqNo/primaryTerm (from a prior docGet), returning errESConflict if
// another writer updated the document in between -- the same optimistic-
// concurrency shape Elasticsearch's own docs recommend for read-modify-write
// without a distributed lock.
// docIndexMaxBytes guards every dashboard-owned write in this file against
// ever accidentally embedding a large blob (a raw payload sample, a full PDF
// report) in a normal Elasticsearch document: dashboard-owned indices are
// small bookkeeping/cache records (alert state, static-analysis summaries),
// never a store for the multi-hundred-megabyte binaries this stack captures.
// Elasticsearch's own default HTTP body ceiling is ~100MB, and a document
// anywhere near that is already a known anti-pattern (bloats the index,
// costs heap on merge/reindex) well before hitting it -- this stays well
// under both, and any caller that would exceed it needs a different storage
// design (a capped/truncated summary, or a real blob store), not a bigger
// limit here.
const docIndexMaxBytes = 2 << 20 // 2MB

func (c *esClient) docIndex(index, id string, doc []byte, create bool, seqNo, primaryTerm int64) error {
	return c.docIndexSized(index, id, doc, docIndexMaxBytes, create, seqNo, primaryTerm)
}

// docIndexSized is docIndex with an explicit, caller-chosen size cap instead
// of the default docIndexMaxBytes -- an opt-in escape hatch for the rare
// dashboard-owned document that is legitimately larger than a bookkeeping
// record (e.g. #475's generated PDF reports, base64-encoded), never a way to
// silently bypass the guard: every caller still states its own ceiling
// explicitly at the call site rather than passing no limit at all.
func (c *esClient) docIndexSized(index, id string, doc []byte, maxBytes int, create bool, seqNo, primaryTerm int64) error {
	return c.docIndexSizedRefreshed(index, id, doc, maxBytes, create, seqNo, primaryTerm, false)
}

// docIndexWaitForRefresh is docIndex with Elasticsearch's own refresh=
// wait_for write parameter (#920): the call does not return until the write
// is visible to a subsequent _search against the same index, at the cost of
// extra per-write latency (bounded by the index's own refresh_interval,
// default ~1s). Opt-in per call site for the specific writes whose very next
// read -- in the same request, or an immediate same-session follow-up --
// must see them (workbench_es.go's saveRecipe/createOrReuseRun, #920's
// audit found both could otherwise read stale state through docSearchAll
// and, in saveRecipe's case, spuriously reject a non-conflicting save).
// Not the default on docIndex: most dashboard-owned writes here are
// fire-and-forget with no such requirement, and paying wait_for's latency on
// every one of them would be wasteful.
func (c *esClient) docIndexWaitForRefresh(index, id string, doc []byte, create bool, seqNo, primaryTerm int64) error {
	return c.docIndexSizedRefreshed(index, id, doc, docIndexMaxBytes, create, seqNo, primaryTerm, true)
}

func (c *esClient) docIndexSizedRefreshed(index, id string, doc []byte, maxBytes int, create bool, seqNo, primaryTerm int64, waitForRefresh bool) error {
	if len(doc) > maxBytes {
		return fmt.Errorf("elasticsearch: document for %s/%s is %d bytes, over the %d-byte cap for this index", index, id, len(doc), maxBytes)
	}
	path := "/" + index + "/_doc/" + url.PathEscape(id)
	if create {
		path += "?op_type=create"
	} else {
		path += fmt.Sprintf("?if_seq_no=%d&if_primary_term=%d", seqNo, primaryTerm)
	}
	if waitForRefresh {
		path += "&refresh=wait_for"
	}
	status, body, err := c.doRequest(http.MethodPut, path, doc)
	if err != nil {
		return err
	}
	if status == http.StatusConflict {
		return errESConflict
	}
	if status/100 != 2 {
		return fmt.Errorf("Elasticsearch PUT %s: status %d: %s", index, status, strings.TrimSpace(string(body)))
	}
	return nil
}

// docDelete removes one document from a dashboard-owned index. A 404 (doc
// doesn't exist) is treated as success -- deleting something already gone
// is the desired end state, not a failure to report.
func (c *esClient) docDelete(index, id string) error {
	status, body, err := c.doRequest(http.MethodDelete, "/"+index+"/_doc/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status/100 != 2 {
		return fmt.Errorf("Elasticsearch DELETE %s: status %d: %s", index, status, strings.TrimSpace(string(body)))
	}
	return nil
}

// docSearchAll returns every document in a dashboard-owned index (capped at
// Elasticsearch's default index.max_result_window, same ceiling and
// reasoning as searchNamespace: this is dashboard-generated bookkeeping, not
// the high-volume event stream), each carrying the concurrency-control
// fields a caller needs to condition its own docIndex update on.
//
// #498: a dashboard-owned index is created lazily on first write (via its
// matching index template, auto_create_index), so "no run/recipe has ever
// been created yet" is a completely normal state in which the index simply
// doesn't exist -- confirmed live: the Workbench's very first run submission
// failed outright with "index_not_found_exception" from countRuns' own call
// here, before createOrReuseRun's own docIndex ever got a chance to create
// it. A missing index and an empty index mean the same thing to every caller
// of this function (countRuns, listRuns*), so treat 404 the same way docGet
// already treats a missing single document: zero hits, not an error.
func (c *esClient) docSearchAll(index string, size int) ([]esDocHit, error) {
	return c.docSearchAllExcluding(index, size)
}

// docSearchAllExcluding is docSearchAll's counterpart for callers that only
// need a subset of each document's fields (#1341): an ES `_source_excludes`
// filter means the excluded field's bytes are never sent over the wire or
// unmarshaled, instead of being fetched and discarded -- the difference
// that matters when a document can embed a large blob (a generated
// report's base64 PDF, for one) that most callers don't need at all.
func (c *esClient) docSearchAllExcluding(index string, size int, excludeFields ...string) ([]esDocHit, error) {
	if size <= 0 || size > 10000 {
		size = 10000
	}
	path := fmt.Sprintf("/%s/_search?size=%d", index, size)
	if len(excludeFields) > 0 {
		path += "&_source_excludes=" + url.QueryEscape(strings.Join(excludeFields, ","))
	}
	status, body, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("Elasticsearch GET %s: status %d: %s", index, status, strings.TrimSpace(string(body)))
	}
	b := body
	var v struct {
		Hits struct {
			Hits []struct {
				ID          string          `json:"_id"`
				SeqNo       int64           `json:"_seq_no"`
				PrimaryTerm int64           `json:"_primary_term"`
				Source      json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	out := make([]esDocHit, 0, len(v.Hits.Hits))
	for _, h := range v.Hits.Hits {
		out = append(out, esDocHit{ID: h.ID, Source: h.Source, SeqNo: h.SeqNo, PrimaryTerm: h.PrimaryTerm})
	}
	return out, nil
}

// docListIDs returns just the _id of every document in index, with
// "_source": false so this stays cheap regardless of how large individual
// stored documents are -- unlike docSearchAll, which always pulls full
// document bodies over the wire. Built for #638/#763: ghidra-report-
// artifacts-v1 stores base64-encoded HTML reports and SVG call graphs with
// no retention cap bounding how many accumulate, so checking "does an
// artifact exist for this sha256" for every row of a results table must
// not mean fetching every stored artifact's full payload just to answer a
// yes/no question.
func (c *esClient) docListIDs(index string, size int) ([]string, error) {
	if size <= 0 || size > 10000 {
		size = 10000
	}
	status, body, err := c.doRequest(http.MethodPost, fmt.Sprintf("/%s/_search?size=%d", index, size), []byte(`{"_source":false}`))
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("Elasticsearch POST %s: status %d: %s", index, status, strings.TrimSpace(string(body)))
	}
	var v struct {
		Hits struct {
			Hits []struct {
				ID string `json:"_id"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(v.Hits.Hits))
	for _, h := range v.Hits.Hits {
		ids = append(ids, h.ID)
	}
	return ids, nil
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
	st.FilebeatDecodeFailures, _ = c.count("filebeat-*", "")
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
		{"citrix-honeypot", "honeypot-v2-*", "event.sensor:citrix-honeypot"},
		{"cisco-asa-honeypot", "honeypot-v2-*", "event.sensor:cisco-asa-honeypot"},
		{"rdp-honeypot", "honeypot-v2-*", "event.sensor:rdp-honeypot"},
		{"beelzebub", "honeypot-v2-*", "event.sensor:beelzebub"},
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
	if !requireAdmin(w, r) {
		return
	}
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

// searchNamespacePageSize/searchNamespaceMaxPages bound searchNamespace's
// own pagination (#1156) the same way esEventsPageSize/esEventsMaxPages
// bound loadSensorEventsES's -- a smaller per-page size than that one
// (these aren't the high-volume event stream) but the same safety-valve
// shape: stop after a bounded number of pages rather than looping forever
// against a corpus that somehow never stops growing mid-fetch.
const searchNamespacePageSize = 1000
const searchNamespaceMaxPages = 50

// searchNamespace runs a fully paginated _search against index and returns
// every hit's `field` sub-document, still JSON-encoded. #384: the
// #383-mirrored result indices (ghidra/sandbox/github-analysis/cape/
// revdeck) store the producer's original, unmodified result JSON under a
// source-namespaced field (see analysis/es-results-importer/importer.py's
// build_document) -- so a caller can unmarshal the returned bytes straight
// into the same struct it already unmarshals the local JSON file into,
// with no separate ES-specific schema to maintain.
//
// #1156: this used to be a single bounded request capped at 10000 (this
// deployment's index.max_result_window), silently missing anything past
// that ceiling and just as importantly always paying for the full 10000
// -document scan on every listing-page load regardless of true corpus
// size. Paginates via PIT + search_after now instead, the same mechanism
// loadSensorEventsES already established in this codebase for the same
// max_result_window problem on the honeypot-v2-* event stream (see that
// function's own comment for why _shard_doc is the tie-breaker and why a
// PIT is required to use it at all on this Elasticsearch version). Sorted
// by @timestamp -- build_document sets it from completed_at/updated_at/
// requested_at, so this naturally returns newest-first, and every one of
// these five indices already promotes @timestamp as a real, sortable
// field regardless of what's inside their own flattened namespace.
func (c *esClient) searchNamespace(index, field string) ([]json.RawMessage, error) {
	pitID, ok := c.openPointInTime(index, "1m")
	if !ok {
		return nil, fmt.Errorf("could not open a point-in-time against %s", index)
	}
	defer c.closePointInTime(pitID)

	var out []json.RawMessage
	var searchAfter []any
	for page := 0; page < searchNamespaceMaxPages; page++ {
		body := map[string]any{
			"size": searchNamespacePageSize,
			"pit":  map[string]any{"id": pitID, "keep_alive": "1m"},
			"sort": []map[string]any{
				{"@timestamp": "desc"},
				{"_shard_doc": "desc"},
			},
		}
		if searchAfter != nil {
			body["search_after"] = searchAfter
		}
		reqBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		b, err := c.searchBody("/_search", reqBody)
		if err != nil {
			if page == 0 {
				return nil, err
			}
			break // later page failed -- keep what earlier pages already returned
		}
		var v struct {
			Hits struct {
				Hits []struct {
					Sort   []any                      `json:"sort"`
					Source map[string]json.RawMessage `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			if page == 0 {
				return nil, err
			}
			break
		}
		if len(v.Hits.Hits) == 0 {
			break
		}
		for _, h := range v.Hits.Hits {
			if raw, ok := h.Source[field]; ok {
				out = append(out, raw)
			}
		}
		if len(v.Hits.Hits) < searchNamespacePageSize {
			break // last page
		}
		searchAfter = v.Hits.Hits[len(v.Hits.Hits)-1].Sort
	}
	return out, nil
}

// searchNamespaceByHash is searchNamespace scoped server-side to one hash,
// instead of fetching the whole index and scanning every document in Go:
// found live (#1142) that ghidraData/githubAnalysisData/matchingSandboxRuns
// and others all called the unscoped, whole-index searchNamespace just to
// find the one (or few) result(s) for a single hash -- genuinely slow
// (up to 10000 documents fetched and unmarshaled) for what a single scoped
// query answers directly. Uses file.hash.sha256, the keyword field
// elasticsearch-setup.sh promotes on every analysis-result index
// specifically for this kind of cross-index, single-hash correlation (the
// same field correlate's own sighting-history search already keys on) --
// not the importer's own "<label>:<sha256>" document _id convention,
// which would work for a direct docGet on the sha256-keyed indices
// (ghidra/github-analysis/revdeck) but not on sandbox's job-keyed one,
// and would couple this dashboard to an internal detail of a different
// program (analysis/es-results-importer) that has no reason to hold
// stable for callers outside its own bulk-overwrite bookkeeping.
func (c *esClient) searchNamespaceByHash(index, field, sha256 string, size int) ([]json.RawMessage, error) {
	if c == nil || c.base == "" {
		return nil, fmt.Errorf("elasticsearch is not configured")
	}
	if !hashName.MatchString(sha256) {
		return nil, fmt.Errorf("invalid hash")
	}
	if size <= 0 || size > 10000 {
		size = 50
	}
	reqBody, err := json.Marshal(map[string]any{
		"query": map[string]any{"term": map[string]any{"file.hash.sha256": sha256}},
		"size":  size,
	})
	if err != nil {
		return nil, err
	}
	status, b, err := c.doRequest(http.MethodPost, fmt.Sprintf("/%s/_search", index), reqBody)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("Elasticsearch POST %s: status %d: %s", index, status, strings.TrimSpace(string(b)))
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

// searchNamespaceLimit is searchNamespace bounded to the newest `limit`
// documents via a single request -- no PIT, no search_after loop. #1156
// fixed searchNamespace's own silent truncation past 10000 documents by
// paginating through the whole namespace, but a caller that only ever
// displays a top-N slice of a listing (githubAnalysisData's list branch,
// via refreshGithubAnalysisCacheAsync) has no reason to pay for that walk:
// paginating up to searchNamespaceMaxPages*searchNamespacePageSize
// documents just to keep the newest few hundred is exactly the unbounded-
// fetch cost #1156 flagged, merely moved off the request path instead of
// actually bounded. Sorted by @timestamp desc, same as searchNamespace, so
// "newest limit documents" is really what comes back.
func (c *esClient) searchNamespaceLimit(index, field string, limit int) ([]json.RawMessage, error) {
	if c == nil || c.base == "" {
		return nil, fmt.Errorf("elasticsearch is not configured")
	}
	if limit <= 0 || limit > 10000 {
		limit = 500
	}
	reqBody, err := json.Marshal(map[string]any{
		"size": limit,
		"sort": []map[string]any{{"@timestamp": "desc"}},
	})
	if err != nil {
		return nil, err
	}
	status, b, err := c.doRequest(http.MethodPost, fmt.Sprintf("/%s/_search", index), reqBody)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("Elasticsearch POST %s: status %d: %s", index, status, strings.TrimSpace(string(b)))
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

// esStorageStats is the brief cluster/storage summary the admin settings
// modal's Elasticsearch pane shows (#647): a metric-grid glance, not a
// dashboard of its own -- deep exploration already exists via the
// Elasticsearch history pane and Kibana. Read-only, same as history/
// deadLetters above.
type esStorageStats struct {
	ClusterStatus  string `json:"cluster_status"`
	DataNodes      int    `json:"data_nodes"`
	IndexCount     int    `json:"index_count"`
	DocCount       int64  `json:"doc_count"`
	StoreSizeBytes int64  `json:"store_size_bytes"`
}

func (c *esClient) storageStats() (esStorageStats, error) {
	var out esStorageStats

	health, err := c.request("/_cluster/health")
	if err != nil {
		return out, err
	}
	var h struct {
		Status          string `json:"status"`
		NumberDataNodes int    `json:"number_of_data_nodes"`
	}
	if err := json.Unmarshal(health, &h); err != nil {
		return out, fmt.Errorf("parse cluster health: %w", err)
	}
	out.ClusterStatus = h.Status
	out.DataNodes = h.NumberDataNodes

	stats, err := c.request("/_stats/store,docs")
	if err != nil {
		return out, err
	}
	var s struct {
		Indices map[string]json.RawMessage `json:"indices"`
		All     struct {
			Total struct {
				Docs struct {
					Count int64 `json:"count"`
				} `json:"docs"`
				Store struct {
					SizeInBytes int64 `json:"size_in_bytes"`
				} `json:"store"`
			} `json:"total"`
		} `json:"_all"`
	}
	if err := json.Unmarshal(stats, &s); err != nil {
		return out, fmt.Errorf("parse index stats: %w", err)
	}
	out.IndexCount = len(s.Indices)
	out.DocCount = s.All.Total.Docs.Count
	out.StoreSizeBytes = s.All.Total.Store.SizeInBytes
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
