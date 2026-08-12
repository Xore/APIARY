package main

// kill_chain.go -- #1224 (#1205 epic phase 2): the three visualizations
// #1203's own scope note deferred -- kill-chain Sankey, campaign timeline,
// ATT&CK coverage grid -- hosted together on a new /kill-chain page.
//
// ECharts (vendored, see assets.go) is the library choice the epic's own
// "decided up front" section deferred to whichever PR needed one first --
// picked over Cytoscape.js (#1203's own choice) because these three need a
// heatmap, a Gantt-style timeline, and a Sankey flow diagram, none of
// which a node-link graph library draws, and ECharts covers all three
// natively in one vendored dependency.
//
// Each chart is served by its own /api/... endpoint (JSON, fetched client-
// side by hp-kill-chain.js) rather than embedded in the page render --
// same fetch-then-render split /attackers' Cytoscape graph and the
// overview map both already use, so a slow chart never blocks the page
// shell, and none of the three recomputes on aggregate.go's own periodic
// snapshot cycle for a route that may go unvisited for a while.

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"
)

// killChainTactics is the canonical MITRE ATT&CK kill-chain order for
// every tactic techniqueTactic below maps to -- both the ATT&CK grid's
// column order and the Sankey's own stage sequence use this, so a group
// (session or IP) observed under two different tactics always flows in a
// consistent direction regardless of the actual event order within it.
var killChainTactics = []string{
	"Reconnaissance", "Initial Access", "Execution", "Credential Access",
	"Lateral Movement", "Command and Control", "Impair Process Control",
}

// techniqueTactic maps each attackTechnique.ID intelligence.go's own
// techniquesForEvent can produce to its real MITRE ATT&CK tactic --
// standard, publicly documented mappings (attack.mitre.org), not derived
// from this dashboard's own data. A technique ID with no entry here is
// skipped by every consumer below rather than guessed at.
var techniqueTactic = map[string]string{
	"T1595":     "Reconnaissance",
	"T1190":     "Initial Access",
	"T1059":     "Execution",
	"T1059.001": "Execution",
	"T1059.003": "Execution",
	"T1059.004": "Execution",
	"T1110":     "Credential Access",
	"T0886":     "Lateral Movement",
	"T1105":     "Command and Control",
	"T1692.001": "Impair Process Control",
}

func tacticIndex(tactic string) int {
	for i, t := range killChainTactics {
		if t == tactic {
			return i
		}
	}
	return -1
}

type killChainPage struct {
	pageMeta
	Ready     bool
	Generated time.Time
}

func (s *store) killChainData() killChainPage {
	return killChainPage{Generated: time.Now(), Ready: s.ready.Load()}
}

// --- ATT&CK coverage grid -------------------------------------------------

type attckCell struct {
	TacticIdx    int `json:"tactic_idx"`
	TechniqueIdx int `json:"technique_idx"`
	Count        int `json:"count"`
}

// attckGrid is an ECharts heatmap's own data shape: fixed tactic columns
// (killChainTactics), one row per technique actually observed (not the
// ~200 real ATT&CK techniques -- a honeypot's own coverage is always a
// small, specific subset, and a near-empty 200-row grid would bury the
// real signal), one cell per (tactic, technique) pair that has a nonzero
// count.
type attckGrid struct {
	Tactics    []string    `json:"tactics"`
	Techniques []string    `json:"techniques"`
	Cells      []attckCell `json:"cells"`
}

func buildAttckGrid(rows []attackTechnique) attckGrid {
	g := attckGrid{Tactics: killChainTactics}
	sorted := append([]attackTechnique(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool {
		ti, tj := tacticIndex(techniqueTactic[sorted[i].ID]), tacticIndex(techniqueTactic[sorted[j].ID])
		if ti != tj {
			return ti < tj
		}
		return sorted[i].ID < sorted[j].ID
	})
	for _, t := range sorted {
		ti := tacticIndex(techniqueTactic[t.ID])
		if ti < 0 {
			continue // no known tactic mapping -- skip rather than guess
		}
		g.Techniques = append(g.Techniques, t.ID+" "+t.Name)
		g.Cells = append(g.Cells, attckCell{TacticIdx: ti, TechniqueIdx: len(g.Techniques) - 1, Count: t.Count})
	}
	return g
}

func (s *store) serveAttckCoverage(w http.ResponseWriter, r *http.Request) {
	grid := buildAttckGrid(aggregateTechniques(s.getEvents()))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(grid)
}

// --- Campaign timeline -----------------------------------------------------

// timelineRow is one campaign's own Gantt-style bar: StartMS/EndMS as
// epoch milliseconds (parsed here, once, server-side) rather than handing
// the client campaignRow's own display-formatted First/Last strings to
// parse -- ECharts' own bar-with-invisible-base Gantt idiom needs numeric
// offsets, and parsing dates in JS is exactly the kind of thing this
// codebase already avoids (see every data-hp-utc twin elsewhere).
type timelineRow struct {
	CIDR    string `json:"cidr"`
	StartMS int64  `json:"start_ms"`
	EndMS   int64  `json:"end_ms"`
	Score   int    `json:"score"`
	Events  int    `json:"events"`
}

func buildCampaignTimeline(rows []campaignRow) []timelineRow {
	out := make([]timelineRow, 0, len(rows))
	for _, r := range rows {
		start, err1 := time.Parse(time.RFC3339, r.FirstUTC)
		end, err2 := time.Parse(time.RFC3339, r.LastUTC)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, timelineRow{CIDR: r.CIDR, StartMS: start.UnixMilli(), EndMS: end.UnixMilli(), Score: r.Score, Events: r.Events})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartMS < out[j].StartMS })
	return out
}

func (s *store) serveCampaignTimeline(w http.ResponseWriter, r *http.Request) {
	rows := buildCampaignTimeline(s.campaignsData(r).Campaigns)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(rows)
}

// --- Kill-chain Sankey -------------------------------------------------

type sankeyNode struct {
	Name string `json:"name"`
}

type sankeyLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Value  int    `json:"value"`
}

type sankeyData struct {
	Nodes []sankeyNode `json:"nodes"`
	Links []sankeyLink `json:"links"`
}

// buildKillChainSankey groups events by session (or, for the many sensors
// that never carry one -- e.g. dionaea -- by source IP as the next-best
// proxy for "one attacker's own activity") and, for each group, flows one
// unit between every pair of consecutive tactics in killChainTactics
// order that group's own events actually touched. This is a coarser
// signal than a true per-event chronological chain (two tactics observed
// in the same group flow in canonical kill-chain order, not necessarily
// the order they actually happened in), but it's an honest aggregate over
// what a group's traffic covered, and does not need per-event
// timestamps finer than what already backs the rest of this dashboard.
func buildKillChainSankey(events []storedEvent) sankeyData {
	groups := map[string]map[string]bool{}
	for _, e := range events {
		key := e.Session
		if key == "" {
			key = e.SrcIP
		}
		if key == "" {
			continue
		}
		for _, t := range techniquesForEvent(e) {
			tactic := techniqueTactic[t.ID]
			if tactic == "" {
				continue
			}
			if groups[key] == nil {
				groups[key] = map[string]bool{}
			}
			groups[key][tactic] = true
		}
	}
	type flowKey struct{ from, to string }
	flows := map[flowKey]int{}
	touchedTactics := map[string]bool{}
	for _, tactics := range groups {
		var touched []string
		for t := range tactics {
			touched = append(touched, t)
			touchedTactics[t] = true
		}
		sort.Slice(touched, func(i, j int) bool { return tacticIndex(touched[i]) < tacticIndex(touched[j]) })
		for i := 0; i+1 < len(touched); i++ {
			flows[flowKey{touched[i], touched[i+1]}]++
		}
	}
	var data sankeyData
	for _, tactic := range killChainTactics {
		if touchedTactics[tactic] {
			data.Nodes = append(data.Nodes, sankeyNode{Name: tactic})
		}
	}
	for key, count := range flows {
		data.Links = append(data.Links, sankeyLink{Source: key.from, Target: key.to, Value: count})
	}
	sort.Slice(data.Links, func(i, j int) bool {
		if data.Links[i].Source != data.Links[j].Source {
			return tacticIndex(data.Links[i].Source) < tacticIndex(data.Links[j].Source)
		}
		return tacticIndex(data.Links[i].Target) < tacticIndex(data.Links[j].Target)
	})
	return data
}

func (s *store) serveKillChainSankey(w http.ResponseWriter, r *http.Request) {
	data := buildKillChainSankey(s.getEvents())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(data)
}
