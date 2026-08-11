package main

// attackers_graph.go -- #1203's "attacker graph" visualization: a radial
// layout of one selected attacker entity's member IPs around a central
// entity node. Plain computed SVG coordinates, no charting library and no
// client-side JS -- consistent with the dashboard's existing map rendering
// (aggregate.go's own MapPoints, also a fixed-radius SVG marker) and the
// epic's "dashboard is otherwise deliberately dependency-free" note, for a
// graph this simple (one hub, up to graphMaxNodes spokes) a library would
// be more machinery than the picture needs. A richer force-directed graph
// (many entities, edges between entities that share a weaker signal) is
// explicit follow-up, not attempted here -- see this file's own doc
// comment on graphMaxNodes for the scale this trades away.

import (
	"math"
	"strconv"
)

// graphMaxNodes caps how many member IPs get their own spoke -- past this,
// the labels overlap and the picture stops being readable regardless of
// viewBox size. The largest entity observed live during #1200's own
// verification had 13 IPs, comfortably under this cap; an entity that
// exceeds it (#1200's merge algorithm has no upper bound on entity size)
// shows its highest-traffic IPs plus a "+N more" node rather than silently
// dropping the rest.
const graphMaxNodes = 24

type graphNode struct {
	Label      string
	X, Y       float64
	IsCenter   bool
	IsOverflow bool
}

type graphEdge struct {
	X1, Y1, X2, Y2 float64
}

// attackerGraph is attackers.html's own render input: a hub node (the
// entity itself) plus one spoke node per member IP (capped at
// graphMaxNodes), arranged evenly around a circle, with a straight edge
// from the hub to each spoke.
type attackerGraph struct {
	Nodes []graphNode
	Edges []graphEdge
}

const (
	graphViewBox   = 520
	graphCenter    = graphViewBox / 2
	graphRadius    = 200
	graphHubRadius = 28
)

func buildAttackerGraph(row *attackerRow) attackerGraph {
	g := attackerGraph{
		Nodes: []graphNode{{Label: shortAttackerID(row.ID), X: graphCenter, Y: graphCenter, IsCenter: true}},
	}
	ips := row.IPs
	overflow := 0
	if len(ips) > graphMaxNodes {
		overflow = len(ips) - (graphMaxNodes - 1)
		ips = ips[:graphMaxNodes-1]
	}
	total := len(ips)
	if overflow > 0 {
		total++
	}
	for i, ip := range ips {
		angle := 2 * math.Pi * float64(i) / float64(total)
		x := graphCenter + graphRadius*math.Cos(angle)
		y := graphCenter + graphRadius*math.Sin(angle)
		g.Nodes = append(g.Nodes, graphNode{Label: ip, X: x, Y: y})
		g.Edges = append(g.Edges, graphEdge{X1: graphCenter, Y1: graphCenter, X2: x, Y2: y})
	}
	if overflow > 0 {
		angle := 2 * math.Pi * float64(total-1) / float64(total)
		x := graphCenter + graphRadius*math.Cos(angle)
		y := graphCenter + graphRadius*math.Sin(angle)
		g.Nodes = append(g.Nodes, graphNode{Label: "+" + strconv.Itoa(overflow), X: x, Y: y, IsOverflow: true})
		g.Edges = append(g.Edges, graphEdge{X1: graphCenter, Y1: graphCenter, X2: x, Y2: y})
	}
	return g
}

// shortAttackerID trims the entity ID (a 32-char sha256 prefix, see
// attacker-identity-worker/identity.go's newEntityID) to a label short
// enough to fit inside the hub circle.
func shortAttackerID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
