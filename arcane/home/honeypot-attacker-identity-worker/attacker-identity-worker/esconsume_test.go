package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// The canonical Python suite analysis/es-consume/tests/test_es_consume.py
// asserts the same three layers on its side; keep the two files' coverage
// recognisably mirrored so an edit to one flags the other in review.

func loadFixtureCases(t *testing.T) []fixtureCase {
	t.Helper()
	path, err := findESConsumeFixture()
	if err != nil {
		t.Fatalf("shared parity fixtures unavailable: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Cases []fixtureCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(doc.Cases) == 0 {
		t.Fatalf("%s declares no cases -- the cross-language contract is empty", path)
	}
	return doc.Cases
}

// TestParityFixtures drives this Go engine through the SAME hand-computed
// fixture stream as es_consume.py (#1971): same pages in -> identical
// consumed-event sequence, ok flag, and resulting checkpoint out. Any
// language drift on the #168/#188/#190 semantics fails here AND there.
func TestParityFixtures(t *testing.T) {
	for _, c := range loadFixtureCases(t) {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			warned := ""
			ids, ok, final := c.run(func(m string) { warned = m })

			if !reflect.DeepEqual(ids, c.ExpectedConsumedIDs) {
				t.Errorf("consumed event sequence:\n got  %v\n want %v", ids, c.ExpectedConsumedIDs)
			}
			if ok != c.ExpectedOK {
				t.Errorf("ok flag: got %v, want %v (last warning: %q)", ok, c.ExpectedOK, warned)
			}
			if !reflect.DeepEqual(final, c.ExpectedFinalCheckpoint) {
				t.Errorf("resulting checkpoint:\n got  %+v\n want %+v", final, c.ExpectedFinalCheckpoint)
			}
		})
	}
}

func TestBuildSinceQueryShape(t *testing.T) {
	q := BuildSinceQuery("2026-08-01T10:00:00Z", 123)
	rng, ok := q["query"].(map[string]any)["range"].(map[string]any)["@timestamp"].(map[string]any)
	if !ok {
		t.Fatal("query.range.@timestamp missing")
	}
	if _, hasGt := rng["gt"]; hasGt {
		t.Error("exclusive gt boundary present -- that is exactly the #168 sibling-drop bug")
	}
	if rng["gte"] != "2026-08-01T10:00:00Z" {
		t.Errorf("gte since mangled: %v", rng["gte"])
	}
	wantSort := []map[string]any{{"@timestamp": map[string]any{"order": "asc"}}}
	if !reflect.DeepEqual(q["sort"], wantSort) {
		t.Errorf("ascending @timestamp sort required for every partial-scroll safety argument, got %v", q["sort"])
	}
	if q["size"] != 123 {
		t.Errorf("page size ignored: %v", q["size"])
	}
}

func TestAdvanceCheckpointEmptyBatchReturnsCallerCheckpoint(t *testing.T) {
	previous := &ConsumeCheckpoint{LastTimestamp: "2026-08-01T10:00:00Z", SeenIDs: []string{"k"}}
	if got := AdvanceCheckpoint(nil, previous); got != previous {
		t.Error("an empty consumed batch must return the caller's own checkpoint object")
	}
}

// Engine-contract mirror of the Python suite: clear_scroll failing must not
// be reported as a fully successful poll (the except block wraps ALL
// injected calls on the Python side too).
func TestFetchEventsSinceClearScrollFailureIsNotSuccess(t *testing.T) {
	served := false
	transport := consumeScrollTransport{
		Search: func(map[string]any) (scrollResponse, error) {
			served = true
			r := scrollResponse{ScrollID: "s0"}
			r.Hits.Hits = []ConsumeHit{{ID: "only"}}
			return r, nil
		},
		ScrollNext: func(string) (scrollResponse, error) {
			return scrollResponse{ScrollID: "s1"}, nil // zero hits -> clean exhaustion
		},
		ClearScroll: func(string) error {
			return os.ErrPermission
		},
	}
	events, ok := FetchEventsSince(transport, "1970-01-01T00:00:00Z", 10, 0,
		map[string]bool{}, func(string) {})
	if !served || len(events) != 1 {
		t.Fatalf("unexpected transport state: served=%v events=%d", served, len(events))
	}
	if ok {
		t.Fatal("a failed clear_scroll must not surface as a successful poll")
	}
}

func TestFindESConsumeFixtureResolvesFromSourceTree(t *testing.T) {
	if _, err := findESConsumeFixture(); err != nil {
		t.Skipf("canonical tree not present next to this checkout (%v)", err)
	}
}
