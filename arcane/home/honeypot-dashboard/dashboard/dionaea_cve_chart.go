package main

import (
	"encoding/json"
	"net/http"
)

// dionaea_cve_chart.go (#1276): dionaea-incidents-v1-* (2.9M+ docs/day)
// carries a human-readable exploit name and, where known, the real CVE ID
// on every exploit-attempt incident -- classify.go's dionaea-incident
// branch now surfaces both in ev.detail, but that only helps an operator
// reading one event at a time. This adds a "top exploited CVEs/named
// incidents" ranking, live off the same index.
//
// data is mapped `flattened` (same as honeypot-v2-*'s own payload fields),
// but unlike a stats/sum aggregation (which fails outright on a flattened
// field, per #1294's own finding for honeypot._keyed), a terms aggregation
// on a flattened leaf works fine -- confirmed live. The one real gotcha:
// the field is queried as data.name directly, NOT data.name.keyword --
// flattened leaves have no .keyword sub-field, appending one silently
// matches nothing rather than erroring (this is exactly the trap #1276's
// own issue text hit while scoping this).
const dionaeaCVEWindow = "now-7d"

const dionaeaCVEQuery = `{
  "size": 0,
  "query": {"range": {"timestamp": {"gte": "` + dionaeaCVEWindow + `"}}},
  "aggs": {
    "names": {
      "terms": {"field": "data.name", "size": 15},
      "aggs": {"cve": {"terms": {"field": "data.cve", "size": 1}}}
    }
  }
}`

type dionaeaCVEResponse struct {
	Aggregations struct {
		Names struct {
			Buckets []struct {
				Key      string `json:"key"`
				DocCount int    `json:"doc_count"`
				CVE      struct {
					Buckets []struct {
						Key string `json:"key"`
					} `json:"buckets"`
				} `json:"cve"`
			} `json:"buckets"`
		} `json:"names"`
	} `json:"aggregations"`
}

// dionaeaCVEBar is one ECharts bar-series category: the exploit name (plus
// its CVE range, when known) as the label, incident count as the value --
// hp-kill-chain.js's generic initBar consumes {categories, values} the
// same shape endlessh_stats.go's histogram already established (#1294).
type dionaeaCVEBar struct {
	Categories []string `json:"categories"`
	Values     []int    `json:"values"`
}

// fetchDionaeaCVEs runs the live terms aggregation and reshapes it into
// dionaeaCVEBar, labeling each bucket with its exploit name plus CVE range
// when the sub-aggregation found one (most incident kinds -- bind/connect/
// login attempts with no known exploit mapping -- carry no data.cve at
// all, so a bucket without a CVE bucket just keeps the bare name).
func (s *store) fetchDionaeaCVEs() (dionaeaCVEBar, bool) {
	if s.es == nil {
		return dionaeaCVEBar{}, false
	}
	b, err := s.es.searchBody("/dionaea-incidents-v1-*/_search", []byte(dionaeaCVEQuery))
	if err != nil {
		return dionaeaCVEBar{}, false
	}
	var resp dionaeaCVEResponse
	if json.Unmarshal(b, &resp) != nil {
		return dionaeaCVEBar{}, false
	}
	out := dionaeaCVEBar{
		Categories: make([]string, 0, len(resp.Aggregations.Names.Buckets)),
		Values:     make([]int, 0, len(resp.Aggregations.Names.Buckets)),
	}
	for _, nb := range resp.Aggregations.Names.Buckets {
		label := nb.Key
		if len(nb.CVE.Buckets) > 0 {
			label += " (" + nb.CVE.Buckets[0].Key + ")"
		}
		out.Categories = append(out.Categories, label)
		out.Values = append(out.Values, nb.DocCount)
	}
	return out, true
}

// serveDionaeaCVEs answers /api/dionaea-cves (#1276).
func (s *store) serveDionaeaCVEs(w http.ResponseWriter, r *http.Request) {
	bar, ok := s.fetchDionaeaCVEs()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		http.Error(w, "dionaea exploit taxonomy unavailable", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(bar)
}
