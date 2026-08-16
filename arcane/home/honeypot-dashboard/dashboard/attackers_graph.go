package main

// attackers_graph.go -- #1203's "attacker graph" visualization: one
// selected attacker entity's member IPs around a central entity node.
// Originally a hand-rolled radial SVG (no charting library, matching the
// epic's "dashboard is otherwise deliberately dependency-free" note);
// reworked to Cytoscape.js (vendored, see assets.go's own doc comment)
// once the epic owner explicitly authorized graph libraries -- this file
// now only shapes the node/edge data serveAttackerGraph (attackers.go)
// returns as JSON, layout and rendering both happen client-side in
// static/hp-attackers.js.

import "strconv"

// graphMaxNodes caps how many member IPs get their own node -- past this,
// even Cytoscape's force layout stops being readable at a normal card
// width. The largest entity observed live during #1200's own verification
// had 13 IPs, comfortably under this cap; an entity that exceeds it
// (#1200's merge algorithm has no upper bound on entity size) shows its
// highest-traffic IPs plus a single "+N more" node rather than silently
// dropping the rest. Raised from the original hand-rolled SVG's cap now
// that pan/zoom/drag make a denser graph still usable.
const graphMaxNodes = 60

const (
	graphKindHub      = "hub"
	graphKindSpoke    = "spoke"
	graphKindOverflow = "overflow"
)

type graphNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
}

type graphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// attackerGraph is served as-is (json.Marshal) by /api/attacker-graph;
// hp-attackers.js feeds it straight into cytoscape's elements list.
type attackerGraph struct {
	Nodes []graphNode `json:"nodes"`
	Edges []graphEdge `json:"edges"`
}

func buildAttackerGraph(row *attackerRow) attackerGraph {
	hubID := "hub:" + row.ID
	g := attackerGraph{
		Nodes: []graphNode{{ID: hubID, Label: shortAttackerID(row.ID), Kind: graphKindHub}},
	}
	ips := row.IPs
	overflow := 0
	if len(ips) > graphMaxNodes {
		overflow = len(ips) - (graphMaxNodes - 1)
		ips = ips[:graphMaxNodes-1]
	}
	for _, ip := range ips {
		// IPs are unique per entity (attacker-identity-worker/identity.go's
		// signalSet dedupes), so the IP itself is a stable, collision-free
		// node id.
		g.Nodes = append(g.Nodes, graphNode{ID: ip, Label: ip, Kind: graphKindSpoke})
		g.Edges = append(g.Edges, graphEdge{Source: hubID, Target: ip})
	}
	if overflow > 0 {
		overflowID := "overflow:" + row.ID
		g.Nodes = append(g.Nodes, graphNode{ID: overflowID, Label: "+" + strconv.Itoa(overflow), Kind: graphKindOverflow})
		g.Edges = append(g.Edges, graphEdge{Source: hubID, Target: overflowID})
	}
	return g
}

// shortAttackerID trims the entity ID (a 32-char sha256 prefix, see
// attacker-identity-worker/identity.go's newEntityID) to a label short
// enough to fit inside the hub node.
func shortAttackerID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
