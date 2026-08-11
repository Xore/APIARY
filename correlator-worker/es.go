package main

// es.go -- a minimal Elasticsearch client for this worker's two needs:
// paginated read of honeypot-v2-* (ported from dashboard/events_es.go's
// PIT + search_after pattern, the same one classify.go's buildViaMap and
// es_aggregate.go all use) and idempotent upsert + full-replace write of
// its own two output indices. Not shared as a package with dashboard or
// the other workers -- same module-boundary trade-off ip-enrichment-worker
// and payload-inventory-worker already made.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type esClient struct {
	base string
	http *http.Client
}

func newESClient(base string) *esClient {
	return &esClient{base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 30 * time.Second}}
}

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
	b, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		return 0, nil, err
	}
	return r.StatusCode, b, nil
}

// openPointInTime / closePointInTime -- ported from dashboard/elastic.go
// of the same name. See loadSensorEventsES's own doc comment there for why
// a PIT is required at all (sorting by _shard_doc, the modern
// search_after tie-breaker, needs one).
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

func (c *esClient) closePointInTime(id string) {
	if id == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"id": id})
	_, _, _ = c.doRequest(http.MethodDelete, "/_pit", body)
}

func (c *esClient) searchBody(path string, body []byte) ([]byte, error) {
	status, b, err := c.doRequest(http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("elasticsearch POST %s: status %d: %s", path, status, strings.TrimSpace(string(b)))
	}
	return b, nil
}

// docIndex writes doc as document id, unconditioned (see
// payload-inventory-worker/es.go's own docIndex comment for why this
// worker doesn't need optimistic-concurrency CAS: it's the sole writer of
// campaigns-v1/attacker-clusters-v1).
func (c *esClient) docIndex(index, id string, doc []byte) error {
	status, body, err := c.doRequest(http.MethodPut, "/"+index+"/_doc/"+url.PathEscape(id), doc)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return fmt.Errorf("elasticsearch PUT %s/%s: status %d: %s", index, id, status, strings.TrimSpace(string(body)))
	}
	return nil
}

// deleteByQueryExcept removes every document from index whose _id isn't in
// keep -- ported as a "match_all minus explicit ids" query rather than a
// full index delete-and-recreate, so a concurrent reader (the dashboard,
// once #1202 wires it to read this index) never sees the index
// transiently empty mid-refresh. A missing index (first run, nothing to
// clean up yet) is not an error.
func deleteByQueryExcept(es *esClient, index string, keep []string) error {
	mustNot := make([]map[string]any, 0, len(keep))
	for _, id := range keep {
		mustNot = append(mustNot, map[string]any{"ids": map[string]any{"values": []string{id}}})
	}
	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{"must_not": mustNot},
		},
	}
	body, err := json.Marshal(query)
	if err != nil {
		return err
	}
	status, respBody, err := es.doRequest(http.MethodPost, "/"+index+"/_delete_by_query?conflicts=proceed", body)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil // index doesn't exist yet -- nothing to clean up
	}
	if status/100 != 2 {
		return fmt.Errorf("elasticsearch delete_by_query %s: status %d: %s", index, status, strings.TrimSpace(string(respBody)))
	}
	return nil
}
