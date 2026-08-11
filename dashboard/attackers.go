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

	// Link is computed at read time, not stored -- selecting an entity
	// shows its graph on the same page (see attackers.html's "graph"
	// section).
	Link string `json:"-"`
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
