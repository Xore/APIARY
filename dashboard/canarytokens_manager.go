package main

// canarytokens_manager.go -- #1487: dashboard-owned record of every
// canarytoken created through Settings > Canarytokens, so an operator can
// revisit/re-download an artifact without canarytokens' own (WireGuard-
// internal-only) management UI. Direct structural copy of ipBlockManager
// (dashboard/ip_block.go, #914): a dedicated Elasticsearch index, the same
// docGet/docIndex/errESConflict optimistic-concurrency retry loop, keyed by
// the canarytoken value itself (already a stable, unique ID).

import (
	"encoding/json"
	"sort"
	"time"
)

const canarytokensRecordIndex = "dashboard-canarytokens-v1"

// canarytokensRecord is the Elasticsearch-persisted shape, so every field
// here (including AuthToken) round-trips through save()/get()/list() --
// json:"-" would silently drop a field from storage, not just from an HTTP
// response. AuthToken is the canarytokens platform's own management/
// download credential for this specific token, equivalent to a password:
// it must never be marshaled into a response this package sends to a
// browser. That guarantee lives in canarytokens_api.go instead, which
// always projects this struct into a redacted response type
// (canarytokensListItem/canarytokensCreateResponse) rather than encoding it
// directly -- never relax that and encode a canarytokensRecord straight to
// an http.ResponseWriter.
type canarytokensRecord struct {
	ID           string    `json:"id"`
	TokenType    string    `json:"token_type"`
	Memo         string    `json:"memo"`
	TokenURL     string    `json:"token_url,omitempty"`
	Hostname     string    `json:"hostname,omitempty"`
	FilenameHint string    `json:"filename_hint,omitempty"`
	AuthToken    string    `json:"auth_token"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

type canarytokensManager struct {
	es *esClient
}

// newCanarytokensManager returns nil when es is nil (Elasticsearch not
// configured) -- every call site already treats a nil manager as "history
// unavailable"; creation itself still works (the record is best-effort
// bookkeeping, not load-bearing for the canarytokens platform itself).
func newCanarytokensManager(es *esClient) *canarytokensManager {
	if es == nil {
		return nil
	}
	return &canarytokensManager{es: es}
}

const canarytokensWriteRetries = 5

func (m *canarytokensManager) save(r canarytokensRecord) bool {
	if m == nil {
		return false
	}
	for attempt := 0; attempt < canarytokensWriteRetries; attempt++ {
		hit, found, err := m.es.docGet(canarytokensRecordIndex, r.ID)
		seqNo, primaryTerm := int64(0), int64(0)
		if err == nil && found {
			seqNo, primaryTerm = hit.SeqNo, hit.PrimaryTerm
		}
		body, err := json.Marshal(r)
		if err != nil {
			return false
		}
		err = m.es.docIndex(canarytokensRecordIndex, r.ID, body, !found, seqNo, primaryTerm)
		if err == nil {
			return true
		}
		if err != errESConflict {
			return false
		}
	}
	return false
}

func (m *canarytokensManager) get(id string) (canarytokensRecord, bool) {
	if m == nil {
		return canarytokensRecord{}, false
	}
	hit, found, err := m.es.docGet(canarytokensRecordIndex, id)
	if err != nil || !found {
		return canarytokensRecord{}, false
	}
	var r canarytokensRecord
	if json.Unmarshal(hit.Source, &r) != nil {
		return canarytokensRecord{}, false
	}
	return r, true
}

// list returns every created token record, newest first, for the Settings
// pane's history table. A non-nil error means the query itself failed
// (transport/ES error) -- distinct from a nil slice with a nil error, which
// means no tokens have been created yet (mirrors ipBlockManager.blockedIPs'
// own outage-vs-empty distinction, #1342).
func (m *canarytokensManager) list() ([]canarytokensRecord, error) {
	if m == nil {
		return nil, nil
	}
	hits, err := m.es.docSearchAll(canarytokensRecordIndex, 1000)
	if err != nil {
		return nil, err
	}
	out := make([]canarytokensRecord, 0, len(hits))
	for _, hit := range hits {
		var r canarytokensRecord
		if json.Unmarshal(hit.Source, &r) == nil {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
