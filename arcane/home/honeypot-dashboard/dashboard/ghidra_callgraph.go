package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ghidra_callgraph.go -- #1287: an interactive complement to the static
// graphviz call graph ghidra.html's own "Call graph" card already embeds
// as an <img> (see ghidra.go's attachGhidraCallGraph). That SVG stays --
// it's a plain, script-free rendering an operator can always fall back
// to, matching this dashboard's general convention -- but the underlying
// per-function cross-reference data (ghidraFunction.Callers/Callees,
// #1167) already reaches the frontend structurally and only ever gets
// rendered as flat text lines inside each function's evidence body. This
// shapes that same data into the same graphNode/graphEdge wire format
// attackers_graph.go already established for /api/attacker-graph, so
// hp-ghidra-callgraph.js can feed it straight into Cytoscape.js the same
// way hp-attackers.js does.
//
// Untrusted-label safety: Cytoscape.js renders node/edge labels to an
// HTML5 <canvas> via its own style pipeline ("label": "data(label)" in
// both hp-attackers.js and hp-ghidra-callgraph.js) -- canvas text drawing
// (fillText) takes a JS string and paints glyphs; it has no HTML parser
// in the path at all, so a function named e.g. "<img onerror=...>" from
// hp-attackers.js's own existing production usage cannot execute
// anything, and the ATT&CK issue explicitly calling for this to be
// confirmed rather than assumed. This is the same property the static
// SVG's own image-embedding relied on, just via a different rendering
// backend.
const ghidraCallGraphMaxNodes = 200

const (
	ghidraNodeKindFunction = "function" // has its own Callers/Callees data (the worker's deep-dive budget covered it)
	ghidraNodeKindLeaf     = "leaf"     // referenced only, from some deepened function's own xref list
)

// ghidraCallGraph is served as-is (json.Marshal) by /api/ghidra-callgraph/
// {sha}; hp-ghidra-callgraph.js feeds it straight into Cytoscape's
// elements list, the same shape attackerGraph already is for
// /api/attacker-graph.
type ghidraCallGraph struct {
	Nodes []graphNode `json:"nodes"`
	Edges []graphEdge `json:"edges"`
	// Truncated (#1287) says whether ghidraCallGraphMaxNodes cut this
	// graph off before every deepened function's own edges were
	// included -- the existing static SVG has the same "assembled from
	// the largest functions outward" truncation (ghidra.html's own note
	// on CallGraphURL), this is the interactive graph's equivalent.
	Truncated bool `json:"truncated"`
}

// buildGhidraCallGraph shapes a result's Functions into a call graph.
// Only functions the worker's deep-dive budget actually covered
// (len(Callers)+len(Callees) > 0) contribute edges -- there is no xref
// data for any other function to graph. Their callers/callees become
// leaf nodes even when a caller/callee is itself a deepened function
// elsewhere in the same list (resolved via the byAddr/deepened lookups
// below, not the add-order of any one edge) so a function's kind never
// depends on which of its neighbors happened to be visited first.
func buildGhidraCallGraph(functions []ghidraFunction) ghidraCallGraph {
	byAddr := make(map[string]ghidraFunction, len(functions))
	deepened := map[string]bool{}
	for _, f := range functions {
		if f.Address == "" {
			continue
		}
		byAddr[f.Address] = f
		if len(f.Callers) > 0 || len(f.Callees) > 0 {
			deepened[f.Address] = true
		}
	}

	var g ghidraCallGraph
	nodeSeen := map[string]bool{}
	addNode := func(addr, fallbackName string) {
		if addr == "" || nodeSeen[addr] {
			return
		}
		if len(g.Nodes) >= ghidraCallGraphMaxNodes {
			g.Truncated = true
			return
		}
		nodeSeen[addr] = true
		label := fallbackName
		if f, ok := byAddr[addr]; ok && f.Name != "" {
			label = f.Name
		}
		if label == "" {
			label = addr
		}
		kind := ghidraNodeKindLeaf
		if deepened[addr] {
			kind = ghidraNodeKindFunction
		}
		g.Nodes = append(g.Nodes, graphNode{ID: addr, Label: label, Kind: kind})
	}
	edgeSeen := map[[2]string]bool{}
	addEdge := func(from, to string) {
		if from == "" || to == "" || from == to || !nodeSeen[from] || !nodeSeen[to] {
			return
		}
		key := [2]string{from, to}
		if edgeSeen[key] {
			return
		}
		edgeSeen[key] = true
		g.Edges = append(g.Edges, graphEdge{Source: from, Target: to})
	}

	for _, f := range functions {
		if !deepened[f.Address] {
			continue
		}
		addNode(f.Address, f.Name)
		for _, c := range f.Callers {
			addNode(c.Addr, c.Name)
			addEdge(c.Addr, f.Address)
		}
		for _, c := range f.Callees {
			addNode(c.Addr, c.Name)
			addEdge(f.Address, c.Addr)
		}
	}
	return g
}

// serveGhidraInteractiveCallGraph answers /api/ghidra-callgraph/{sha} --
// hp-ghidra-callgraph.js's own fetch-then-render split, same convention
// serveAttackerGraph (attackers.go) already established.
func (s *store) serveGhidraInteractiveCallGraph(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha")
	if !hashName.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	data, err := s.ghidraData(strings.ToLower(sha), "")
	if err != nil || data.Detail == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(buildGhidraCallGraph(data.Detail.Functions))
}
