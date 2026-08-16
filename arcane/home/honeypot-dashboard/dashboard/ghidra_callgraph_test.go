package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildGhidraCallGraphOnlyGraphsDeepenedFunctions(t *testing.T) {
	functions := []ghidraFunction{
		{Address: "0x401000", Name: "main"}, // no Callers/Callees -- not deepened, contributes nothing
	}
	g := buildGhidraCallGraph(functions)
	if len(g.Nodes) != 0 || len(g.Edges) != 0 {
		t.Fatalf("expected an empty graph with no deepened functions, got %+v", g)
	}
}

func TestBuildGhidraCallGraphAddsCallerAndCalleeEdges(t *testing.T) {
	functions := []ghidraFunction{
		{
			Address: "0x401000", Name: "sub_401000",
			Callers: []ghidraXref{{Addr: "0x400f00", Name: "start"}},
			Callees: []ghidraXref{{Addr: "0x401100", Name: "sub_401100"}},
		},
	}
	g := buildGhidraCallGraph(functions)
	if len(g.Nodes) != 3 {
		t.Fatalf("expected 3 nodes (function + caller + callee), got %+v", g.Nodes)
	}
	wantEdges := map[[2]string]bool{
		{"0x400f00", "0x401000"}: true, // caller -> function
		{"0x401000", "0x401100"}: true, // function -> callee
	}
	if len(g.Edges) != len(wantEdges) {
		t.Fatalf("got %d edges, want %d: %+v", len(g.Edges), len(wantEdges), g.Edges)
	}
	for _, e := range g.Edges {
		if !wantEdges[[2]string{e.Source, e.Target}] {
			t.Fatalf("unexpected edge %+v", e)
		}
	}
}

// TestBuildGhidraCallGraphClassifiesReferencedFunctionCorrectly: a
// function referenced only as another function's caller/callee, but
// which is ALSO its own deepened entry elsewhere in the same list, must
// be classified as "function" (not "leaf") regardless of which edge
// reached it first -- see buildGhidraCallGraph's own comment on why this
// is resolved via the deepened/byAddr lookups rather than add-order.
func TestBuildGhidraCallGraphClassifiesReferencedFunctionCorrectly(t *testing.T) {
	functions := []ghidraFunction{
		{
			Address: "0x401000", Name: "a",
			Callees: []ghidraXref{{Addr: "0x402000", Name: "b"}},
		},
		{
			Address: "0x402000", Name: "b",
			Callers: []ghidraXref{{Addr: "0x401000", Name: "a"}},
		},
	}
	g := buildGhidraCallGraph(functions)
	kinds := map[string]string{}
	for _, n := range g.Nodes {
		kinds[n.ID] = n.Kind
	}
	if kinds["0x402000"] != ghidraNodeKindFunction {
		t.Fatalf("expected 0x402000 classified as %q (it has its own Callers), got %q", ghidraNodeKindFunction, kinds["0x402000"])
	}
	// Only one edge should exist between them, not a duplicate from each
	// function's own side of the same relationship.
	if len(g.Edges) != 1 {
		t.Fatalf("expected exactly 1 deduplicated edge, got %+v", g.Edges)
	}
}

func TestBuildGhidraCallGraphLeafNodeFallsBackToXrefName(t *testing.T) {
	functions := []ghidraFunction{
		{
			Address: "0x401000", Name: "sub_401000",
			Callees: []ghidraXref{{Addr: "0x403000", Name: "memcpy"}},
		},
	}
	g := buildGhidraCallGraph(functions)
	var leaf *graphNode
	for i := range g.Nodes {
		if g.Nodes[i].ID == "0x403000" {
			leaf = &g.Nodes[i]
		}
	}
	if leaf == nil || leaf.Label != "memcpy" || leaf.Kind != ghidraNodeKindLeaf {
		t.Fatalf("expected a leaf node labeled memcpy, got %+v", leaf)
	}
}

func TestBuildGhidraCallGraphTruncatesAtNodeCap(t *testing.T) {
	var functions []ghidraFunction
	for i := 0; i < ghidraCallGraphMaxNodes+10; i++ {
		addr := "0x" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))
		functions = append(functions, ghidraFunction{
			Address: addr, Name: addr,
			Callees: []ghidraXref{{Addr: addr + "c", Name: addr + "c"}},
		})
	}
	g := buildGhidraCallGraph(functions)
	if len(g.Nodes) != ghidraCallGraphMaxNodes {
		t.Fatalf("expected exactly the cap (%d) nodes, got %d", ghidraCallGraphMaxNodes, len(g.Nodes))
	}
	if !g.Truncated {
		t.Fatal("expected Truncated=true once the cap is hit")
	}
}

func TestServeGhidraCallGraphRejectsInvalidHash(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	mux := s.routes(tmpl)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ghidra-callgraph/not-a-hash", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an invalid hash", rec.Code)
	}
}

func TestServeGhidraCallGraphReturnsGraphForKnownResult(t *testing.T) {
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "exit_status": "success",
		"functions": []any{map[string]any{
			"address": "0x401000", "name": "main",
			"callers": []any{map[string]any{"addr": "0x400f00", "name": "start"}},
		}},
	})
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	mux := s.routes(tmpl)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ghidra-callgraph/"+shaA, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var g ghidraCallGraph
	if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(g.Nodes) != 2 || len(g.Edges) != 1 {
		t.Fatalf("got %+v", g)
	}
}

func TestServeGhidraCallGraphUnknownHash404s(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	mux := s.routes(tmpl)

	unknown := "b" + shaA[1:]
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ghidra-callgraph/"+unknown, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unknown hash", rec.Code)
	}
}
