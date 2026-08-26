package main

// es.go -- a minimal Elasticsearch client, ported from the shape of
// dashboard/elastic.go's docGet/docIndex/doRequest (same request/response
// contract, same optimistic-concurrency use of seq_no/primary_term) but
// not shared as a package: this worker and dashboard are separate Go
// modules with no shared package today, the same boundary
// ip-enrichment-worker's own viamap.go/enrich.go already established for
// porting the former Go dashboard's classify.go via_port join (that join
// now lives in backend-service/src/ip_enrichment/viamap.rs).

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

type esDocHit struct {
	Source      json.RawMessage
	SeqNo       int64
	PrimaryTerm int64
}

// docGet fetches one document by ID. found=false, err=nil on a 404: "no
// record yet" is the expected first call for a new key, not a failure.
func (c *esClient) docGet(index, id string) (hit esDocHit, found bool, err error) {
	status, body, err := c.doRequest(http.MethodGet, "/"+index+"/_doc/"+url.PathEscape(id), nil)
	if err != nil {
		return esDocHit{}, false, err
	}
	if status == http.StatusNotFound {
		return esDocHit{}, false, nil
	}
	if status/100 != 2 {
		return esDocHit{}, false, fmt.Errorf("elasticsearch GET %s: status %d: %s", index, status, strings.TrimSpace(string(body)))
	}
	var v struct {
		SeqNo       int64           `json:"_seq_no"`
		PrimaryTerm int64           `json:"_primary_term"`
		Source      json.RawMessage `json:"_source"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return esDocHit{}, false, err
	}
	return esDocHit{Source: v.Source, SeqNo: v.SeqNo, PrimaryTerm: v.PrimaryTerm}, true, nil
}

// docExists checks whether a document exists via HEAD, without
// transferring its _source -- #1221: mirrorPayloadBytes used to call the
// full docGet just to decide "already indexed, skip", which for this
// index means fetching the base64-encoded payload body itself (up to
// payloadBytesMaxBytes, ~43MB) on every already-mirrored file, every
// scan cycle. Confirmed live: a full re-scan of an already-fully-mirrored
// 590-file/2.9GB capture set took ~5m35s per cycle, almost entirely spent
// on this. HEAD returns just a status code, no body at all.
func (c *esClient) docExists(index, id string) (bool, error) {
	status, _, err := c.doRequest(http.MethodHead, "/"+index+"/_doc/"+url.PathEscape(id), nil)
	if err != nil {
		return false, err
	}
	if status == http.StatusNotFound {
		return false, nil
	}
	if status/100 != 2 {
		return false, fmt.Errorf("elasticsearch HEAD %s/%s: status %d", index, id, status)
	}
	return true, nil
}

// docIndex writes doc as document id. create=true uses op_type=create (the
// only mode this worker needs -- every write here follows a docGet that
// already told us whether the document exists, and on the "exists but
// differs" path we still just want last-write-wins, not a CAS failure
// against a concurrent scan of the same file from another host).
func (c *esClient) docIndex(index, id string, doc []byte, create bool) error {
	path := "/" + index + "/_doc/" + url.PathEscape(id)
	if create {
		path += "?op_type=create"
	}
	status, body, err := c.doRequest(http.MethodPut, path, doc)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return fmt.Errorf("elasticsearch PUT %s: status %d: %s", index, status, strings.TrimSpace(string(body)))
	}
	return nil
}
