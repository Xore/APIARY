package main

// es.go -- minimal Elasticsearch client, same shape as correlator-worker's
// own es.go (paginated PIT search + docIndex/docGet/docDelete), not shared
// as a package -- same module-boundary trade-off every worker in this repo
// already makes.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

// docGet fetches one document by ID. found=false, err=nil on a 404.
func (c *esClient) docGet(index, id string) (source json.RawMessage, found bool, err error) {
	status, b, err := c.doRequest(http.MethodGet, "/"+index+"/_doc/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, false, err
	}
	if status == http.StatusNotFound {
		return nil, false, nil
	}
	if status/100 != 2 {
		return nil, false, fmt.Errorf("elasticsearch GET %s/%s: status %d", index, id, status)
	}
	var v struct {
		Source json.RawMessage `json:"_source"`
	}
	if json.Unmarshal(b, &v) != nil {
		return nil, false, nil
	}
	return v.Source, true, nil
}

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

// docDelete removes one document -- used when two existing attacker
// entities merge into one and the absorbed entity's own document must not
// linger as a stale duplicate. A 404 (already gone) is not an error.
func (c *esClient) docDelete(index, id string) error {
	status, body, err := c.doRequest(http.MethodDelete, "/"+index+"/_doc/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status/100 != 2 {
		return fmt.Errorf("elasticsearch DELETE %s/%s: status %d: %s", index, id, status, strings.TrimSpace(string(body)))
	}
	return nil
}

// docScrollAll returns every document in index up to limit -- used to load
// the existing attackers-v1 population each cycle. Plain PIT + search_after,
// same pattern as fetch.go's event fetch.
func docScrollAll[T any](es *esClient, index string, limit int) ([]T, bool) {
	// A PIT open on an index that doesn't exist yet returns 404 -- the
	// expected state before this worker's very first successful write
	// (attackers-v1 is created lazily on first docIndex, same as every
	// other dashboard-owned index in this codebase). That's "zero existing
	// entities", not a failure: treating it as ok=false would make the
	// worker unable to ever bootstrap itself past its first cycle.
	status, _, err := es.doRequest(http.MethodHead, "/"+index, nil)
	if err == nil && status == http.StatusNotFound {
		return nil, true
	}

	pitID, ok := es.openPointInTime(index, "1m")
	if !ok {
		return nil, false
	}
	defer es.closePointInTime(pitID)

	var out []T
	var searchAfter []any
	for len(out) < limit {
		size := 10000
		if remaining := limit - len(out); remaining < size {
			size = remaining
		}
		body := map[string]any{
			"size": size,
			"pit":  map[string]any{"id": pitID, "keep_alive": "1m"},
			"sort": []map[string]any{{"_shard_doc": "asc"}},
		}
		if searchAfter != nil {
			body["search_after"] = searchAfter
		}
		reqBody, err := json.Marshal(body)
		if err != nil {
			break
		}
		b, err := es.searchBody("/_search", reqBody)
		if err != nil {
			return out, false
		}
		var v struct {
			Hits struct {
				Hits []struct {
					Sort   []any `json:"sort"`
					Source T     `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		// An unmarshal error means this page's response is unparseable --
		// not "no more results". Treating the two the same silently
		// truncates the existing-entity population and reports a complete,
		// successful load: on the next cycle, resolveIdentities can't find
		// the un-loaded entities' IPs and forks their identity into a
		// brand-new entity instead of merging into the real one.
		if err := json.Unmarshal(b, &v); err != nil {
			log.Printf("attacker-identity-worker: docScrollAll %s: unmarshal search response: %v", index, err)
			return out, false
		}
		if len(v.Hits.Hits) == 0 {
			break
		}
		for _, h := range v.Hits.Hits {
			out = append(out, h.Source)
		}
		if len(v.Hits.Hits) < size {
			break
		}
		searchAfter = v.Hits.Hits[len(v.Hits.Hits)-1].Sort
	}
	return out, true
}
