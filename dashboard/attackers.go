package main

// attackers.go -- #1203 (part of the #1205 epic): the dashboard's read side
// for attackers-v1 (#1200's attacker-identity-worker). A pure ES reader,
// same shape as readPayloadInventory (#1201/#1202) -- no in-process
// correlation happens here, attacker-identity-worker already did that work
// and this only renders what it wrote.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"time"
)

const attackersIndex = "attackers-v1"

// attackerRow mirrors attacker-identity-worker/identity.go's entity JSON
// shape field-for-field -- deliberately reusing the wire shape rather than
// inventing a parallel one, same convention payloads_data.go's
// capturedFile already follows for payload-inventory-worker's documents.
type attackerRow struct {
	ID           string   `json:"id"`
	IPs          []string `json:"ips"`
	Fingerprints []string `json:"fingerprints"`
	Payloads     []string `json:"payloads"`
	Credentials  []string `json:"credentials"`
	Sensors      []string `json:"sensors"`
	Events       int      `json:"events"`
	First        string   `json:"first"`
	Last         string   `json:"last"`
	Updated      string   `json:"updated"`
	Verdicts     []string `json:"verdicts,omitempty"`
	// Techniques (#1260) is attacker-identity-worker's own durable MITRE
	// ATT&CK technique-coverage document for this entity -- the union of
	// every canonical_attck_techniques (#1261) ID any member IP's events
	// have carried. Bare technique IDs, not the richer attackTechnique
	// (ID/Name/Domain/Evidence) intelligence.go's own per-event
	// aggregateTechniques produces -- see attckTechniqueURL's own comment
	// for why attackers.html links these without that extra data.
	Techniques []string `json:"techniques,omitempty"`

	// Link is computed at read time, not stored -- selecting an entity
	// shows its graph on the same page (see attackers.html's "graph"
	// section).
	Link string `json:"-"`
	// RecordingsURL (#1268) points at /recordings scoped to every one of
	// this entity's member IPs via the shared ?ips= filter (filters.go's
	// includeIPs) -- same mechanism /events already uses to isolate a
	// fingerprint/cluster pivot down to specific source IPs.
	RecordingsURL string `json:"-"`
}

type attackersPage struct {
	pageMeta
	Ready       bool
	Generated   time.Time
	Rows        []attackerRow
	Total       int
	MultiIPRows int // entities with >1 member IP -- the "real merges" count
	Selected    *attackerRow
}

// readAttackers loads every attackers-v1 document -- same docSearchAll(...,
// 10000) cap readPayloadInventory uses, comfortably above this deployment's
// current few-hundred-entity population (see #1200's own PR for live
// counts). A future deployment large enough to need pagination here is the
// same scale problem #1201/#1202's own docs already flag for payload
// inventory, not something new to this file.
func readAttackers(es *esClient) ([]attackerRow, error) {
	hits, err := es.docSearchAll(attackersIndex, 10000)
	if err != nil {
		return nil, err
	}
	rows := make([]attackerRow, 0, len(hits))
	for _, hit := range hits {
		var row attackerRow
		if json.Unmarshal(hit.Source, &row) != nil {
			continue
		}
		row.Link = "/attackers?id=" + url.QueryEscape(row.ID)
		row.RecordingsURL = recordingsURLForIPs(row.IPs)
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Events != rows[j].Events {
			return rows[i].Events > rows[j].Events
		}
		return rows[i].ID < rows[j].ID
	})
	return rows, nil
}

// attackersShell (#1327 shell+hydrate conversion) is the synchronous half
// of "GET /attackers": everything the initial page render needs is the
// optional selected-entity id, taken straight from the request's own
// query string and never read from Elasticsearch. The real content --
// attackers-v1's full, unbounded doc listing readAttackers below actually
// resolves -- is rendered by the "attackers-body" template against a real
// attackersData() result, executed only by the new "GET
// /attackers/fragment" route on the client's own follow-up request;
// hp-attackers-detail.js fetches that fragment once on page load to
// replace the shell's skeleton placeholder. Mirrors ghidra.go's
// ghidraDetailShell -- see that function's own comment for the general
// reasoning. Selected is set to a bare stub carrying only the id so the
// entity graph/fusion cards (each already an independent client-side
// fetch against /api/attacker-graph and /api/attacker-fusion, unaffected
// by this change) can render immediately instead of waiting on the
// fragment too.
func attackersShell(r *http.Request) attackersPage {
	p := attackersPage{Generated: time.Now()}
	if id := r.URL.Query().Get("id"); id != "" {
		p.Selected = &attackerRow{ID: id}
	}
	return p
}

func (s *store) attackersData(r *http.Request) attackersPage {
	p := attackersPage{Generated: time.Now(), Ready: s.ready.Load()}
	if s.es == nil {
		return p
	}
	rows, err := readAttackers(s.es)
	if err != nil {
		return p
	}
	p.Rows = rows
	p.Total = len(rows)
	for _, row := range rows {
		if len(row.IPs) > 1 {
			p.MultiIPRows++
		}
	}
	if id := r.URL.Query().Get("id"); id != "" {
		for i := range rows {
			if rows[i].ID == id {
				p.Selected = &rows[i]
				break
			}
		}
	}
	return p
}

// serveAttackerGraph is /api/attacker-graph -- hp-attackers.js fetches this
// once on page load (the same fetch-then-render split /api/map-points'
// Leaflet consumer uses) and feeds the result straight into Cytoscape's
// elements list. Re-reads attackers-v1 rather than reusing attackersData's
// Selected (that's computed per-request from the page handler, not cached
// anywhere this handler could reach) -- readAttackers' own doc comment
// already accepts this cost at the current few-hundred-entity scale.
func (s *store) serveAttackerGraph(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" || s.es == nil {
		http.NotFound(w, r)
		return
	}
	rows, err := readAttackers(s.es)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	for i := range rows {
		if rows[i].ID != id {
			continue
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(buildAttackerGraph(&rows[i]))
		return
	}
	http.NotFound(w, r)
}
