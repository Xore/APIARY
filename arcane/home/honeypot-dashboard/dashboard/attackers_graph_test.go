package main

import (
	"strconv"
	"testing"
)

func TestBuildAttackerGraphOneHubPerIP(t *testing.T) {
	row := &attackerRow{ID: "abcdef1234567890", IPs: []string{"203.0.113.1", "198.51.100.1"}}
	g := buildAttackerGraph(row)

	if len(g.Nodes) != 3 { // hub + 2 IPs
		t.Fatalf("expected 3 nodes (hub + 2 IPs), got %d: %+v", len(g.Nodes), g.Nodes)
	}
	if g.Nodes[0].Kind != graphKindHub {
		t.Fatalf("expected the first node to be the hub, got %+v", g.Nodes[0])
	}
	if len(g.Edges) != 2 {
		t.Fatalf("expected one edge per IP node, got %d", len(g.Edges))
	}
	for _, e := range g.Edges {
		if e.Source != g.Nodes[0].ID {
			t.Fatalf("expected every edge to originate at the hub id %q, got %+v", g.Nodes[0].ID, e)
		}
	}
}

func TestBuildAttackerGraphHubLabelIsShortID(t *testing.T) {
	row := &attackerRow{ID: "abcdef1234567890", IPs: []string{"203.0.113.1"}}
	g := buildAttackerGraph(row)
	if g.Nodes[0].Label != "abcdef12" {
		t.Fatalf("hub label = %q, want the first 8 chars of the ID", g.Nodes[0].Label)
	}
}

func TestBuildAttackerGraphSpokeIDsAreTheIPs(t *testing.T) {
	row := &attackerRow{ID: "entity", IPs: []string{"203.0.113.1", "198.51.100.1"}}
	g := buildAttackerGraph(row)
	got := map[string]bool{}
	for _, n := range g.Nodes {
		if n.Kind == graphKindSpoke {
			got[n.ID] = true
		}
	}
	for _, ip := range row.IPs {
		if !got[ip] {
			t.Fatalf("expected a spoke node with id %q, got nodes %+v", ip, g.Nodes)
		}
	}
}

func TestBuildAttackerGraphCapsNodesWithOverflowMarker(t *testing.T) {
	ips := make([]string, graphMaxNodes+20)
	for i := range ips {
		ips[i] = "203.0.113." + strconv.Itoa(i%254+1)
	}
	row := &attackerRow{ID: "entity", IPs: ips}
	g := buildAttackerGraph(row)

	if len(g.Nodes) != graphMaxNodes+1 { // hub + graphMaxNodes (last one is the overflow marker)
		t.Fatalf("expected %d nodes (hub + cap), got %d", graphMaxNodes+1, len(g.Nodes))
	}
	last := g.Nodes[len(g.Nodes)-1]
	if last.Kind != graphKindOverflow {
		t.Fatalf("expected the last node to be the overflow marker, got %+v", last)
	}
	wantOverflow := len(ips) - (graphMaxNodes - 1)
	if last.Label != "+"+strconv.Itoa(wantOverflow) {
		t.Fatalf("overflow label = %q, want +%d", last.Label, wantOverflow)
	}
}

func TestBuildAttackerGraphNoOverflowUnderCap(t *testing.T) {
	row := &attackerRow{ID: "entity", IPs: []string{"203.0.113.1", "203.0.113.2"}}
	g := buildAttackerGraph(row)
	for _, n := range g.Nodes {
		if n.Kind == graphKindOverflow {
			t.Fatalf("did not expect an overflow node under the cap: %+v", g.Nodes)
		}
	}
}
