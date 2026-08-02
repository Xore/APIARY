package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// filterValuesLimit bounds one /api/filter-values response the same way
// searchGroupLimit bounds quick-search groups (search.go) -- large enough
// that ordinary filtering feels complete, small enough that one very common
// value (e.g. a sensor with a million events) can't make the response itself
// slow or huge.
const filterValuesLimit = 20

// filterValueOption is one suggestion returned by /api/filter-values. Value
// is what gets written into the filter field and must match exactly what
// filter.match() (filters.go) compares against for that field -- e.g. ASN's
// Value is "AS64500", matching f.asn's own "AS" prefix handling, not the
// bare number. Label is what the dropdown displays, identical to Value
// except where Value alone would be meaningless to a human (ASN again: a
// bare "AS64500" says nothing without the organisation name).
type filterValueOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// filterValueFields says how to read one distinct-value field off a
// storedEvent, keyed by the same query-param name the shared filter-bar
// (filters.go's buildFilterBar) and reports.html's scope panel both already
// use for it (#303). One definition shared by every autocomplete-eligible
// field on the dashboard, not a bespoke lookup per page. A blank returned
// value is treated as "this event has nothing for this field" and excluded.
var filterValueFields = map[string]func(storedEvent) (value, label string){
	"sensor":  func(e storedEvent) (string, string) { return e.Sensor, e.Sensor },
	"country": func(e storedEvent) (string, string) { return e.Country, e.Country },
	"ip":      func(e storedEvent) (string, string) { return e.SrcIP, e.SrcIP },
	"port":    func(e storedEvent) (string, string) { return e.Port, e.Port },
	"sig": func(e storedEvent) (string, string) {
		if e.Alert == "" {
			return "", ""
		}
		return e.Alert, e.Alert
	},
	"asn": func(e storedEvent) (string, string) {
		if e.ASN == 0 {
			return "", ""
		}
		value := "AS" + strconv.FormatUint(uint64(e.ASN), 10)
		if e.Org == "" {
			return value, value
		}
		return value, value + " — " + e.Org
	},
}

// distinctFilterValues ranks every distinct value a field has actually taken
// across evs (most frequent first, same tie-break as topN), folds in
// expected sensors that have zero events yet (mirroring sensorRows in
// aggregate.go -- a configured-but-silent sensor should still be pickable),
// filters by a case-insensitive substring query, and caps the result.
func distinctFilterValues(evs []storedEvent, expected []string, field, query string, limit int) []filterValueOption {
	extract, ok := filterValueFields[field]
	if !ok {
		return nil
	}
	counts := map[string]int{}
	labels := map[string]string{}
	for _, e := range evs {
		value, label := extract(e)
		if value == "" {
			continue
		}
		counts[value]++
		labels[value] = label
	}
	if field == "sensor" {
		for _, name := range expected {
			if _, ok := counts[name]; !ok {
				counts[name] = 0
				labels[name] = name
			}
		}
	}

	query = strings.ToLower(strings.TrimSpace(query))
	ranked := topN(counts, len(counts))
	out := make([]filterValueOption, 0, limit)
	for _, row := range ranked {
		if query != "" && !strings.Contains(strings.ToLower(row.Key), query) {
			continue
		}
		out = append(out, filterValueOption{Value: row.Key, Label: labels[row.Key], Count: row.Count})
		if len(out) >= limit {
			break
		}
	}
	return out
}

// serveFilterValues backs the shared autocomplete widget (hp-app.js,
// [data-hp-filter-field]) for every applicable filter across the dashboard
// -- the six filter-bar pages and reports.html's scope panel alike (#303),
// one endpoint instead of a bespoke lookup per form.
func (s *store) serveFilterValues(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	field := r.URL.Query().Get("field")
	if _, ok := filterValueFields[field]; !ok {
		http.Error(w, "unknown field", http.StatusBadRequest)
		return
	}
	values := distinctFilterValues(s.getEvents(), s.expected, field, r.URL.Query().Get("q"), filterValuesLimit)
	if values == nil {
		values = []filterValueOption{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"values": values})
}
