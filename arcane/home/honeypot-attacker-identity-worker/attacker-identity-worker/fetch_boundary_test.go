package main

// #1971 first-migration-step audit: does attacker-identity-worker's fetch
// share ml-worker's pre-#168 defect class -- dropping (or duplicating)
// equal-timestamp siblings at a consume boundary?
//
// Verdict, proven by the characterization tests below plus the existing
// failure-path coverage in fetch_test.go: VERIFIED-CORRECT. This worker is a
// windowed-refetch consumer (docs/ES-CONSUME-PATTERNS.md pattern 2), not an
// incremental-checkpoint one, so the #168 failure mode has no foothold:
//
//   - The boundary moves with wall clock (`runCycle` fetches now-EVIDENCE_WINDOW,
//     main.go) and nothing is persisted between cycles -- there is no advancing
//     watermark that can leave an equal-timestamp sibling behind, and every
//     cycle re-reads its whole window gte-inclusively.
//   - Within a cycle, ordering is the PIT sort tuple [@timestamp asc,
//     _shard_doc asc] (fetch.go) and search_after resumes from that FULL
//     tuple, so pagination cannot drop or duplicate a hit even when many
//     documents share one exact @timestamp (_shard_doc is unique per PIT).
//   - Re-consuming overlapping windows across cycles cannot duplicate output:
//     observations fold set-wise into entities keyed by newEntityID() and
//     written by deterministic-ID upsert (es.docIndex(attackersIndex, e.ID)),
//     the pattern-2 analogue of #168's deterministic anomaly doc IDs.
//
// These tests pin all three properties against httptest ES stand-ins, in the
// style of fetch_test.go's own silent-truncation regressions (#1344), so a
// future edit that scalar-watermarks this worker or trims _shard_doc from
// the resume tuple fails here loudly.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const boundaryTS = "2026-08-01T10:00:05Z"

func mustBoundaryTime(t *testing.T) time.Time {
	t.Helper()
	when, err := time.Parse(time.RFC3339, boundaryTS)
	if err != nil {
		t.Fatalf("boundary timestamp: %v", err)
	}
	return when
}

// esPITStub serves two scripted pages for /_search and echoes the request
// bodies so tests can inspect the search_after continuation tuples.
func esPITStub(t *testing.T, pages [][]map[string]any, requests *[]json.RawMessage) *httptest.Server {
	t.Helper()
	page := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/honeypot-v2-*/_pit":
			w.Write([]byte(`{"id":"pit-boundary"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/_pit":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/_search":
			*requests = append(*requests, body)
			if page >= len(pages) {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"_scroll_id": "unused-pit",
				"hits":       map[string]any{"hits": pages[page]},
			})
			page++
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
}

func equalTSHit(id, ip string, tsMillis int64, shardDoc int) map[string]any {
	return map[string]any{
		"_id": id,
		"_source": map[string]any{
			"@timestamp": boundaryTS,
			"source":     map[string]any{"ip": ip},
			"event":      map[string]any{"sensor": "cowrie"},
		},
		"sort": []any{tsMillis, shardDoc},
	}
}

func ipsInOrder(events []corrEvent) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.SrcIP
	}
	return out
}

func assertStringSlice(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %v (%d), want %v (%d)", label, got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", label, got, want)
		}
	}
}

// TestEqualTimestampSiblingsAllConsumedFromOnePage pins within-page total
// order: five documents sharing one exact @timestamp on a single page must
// each arrive exactly once, in served order.
func TestEqualTimestampSiblingsAllConsumedFromOnePage(t *testing.T) {
	var requests []json.RawMessage
	srv := esPITStub(t, [][]map[string]any{{
		equalTSHit("s1", "10.0.0.1", 1754035205000, 11),
		equalTSHit("s2", "10.0.0.2", 1754035205000, 12),
		equalTSHit("s3", "10.0.0.3", 1754035205000, 13),
		equalTSHit("s4", "10.0.0.4", 1754035205000, 14),
		equalTSHit("s5", "10.0.0.5", 1754035205000, 15),
	}}, &requests)
	defer srv.Close()

	events, ok := fetchRecentEvents(newESClient(srv.URL), mustBoundaryTime(t).Add(-time.Hour))
	if !ok {
		t.Fatal("fetch reported failure")
	}
	assertStringSlice(t, "equal-timestamp siblings consumed exactly once, in order",
		ipsInOrder(events), []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"})
}

// TestEqualTimestampGroupStraddlingPagesKeepsTotalOrder pins the #1971/#168
// concern at the pagination seam itself: the timestamp group is split by the
// page boundary and resumed via search_after, so if the worker ever resumed
// from a scalar watermark (last @timestamp only, the pre-#168 dashboard bug
// class) or dropped _shard_doc from the tuple, x3/x4 would be skipped until
// some later window happened to re-cover them.
func TestEqualTimestampGroupStraddlingPagesKeepsTotalOrder(t *testing.T) {
	const ms = int64(1754035205000)
	// Page 1 must be exactly esPageSize hits -- fetchRecentEvents treats any
	// shorter page as end-of-stream (the ES convention it relies on), so a
	// continuation only happens across a full page in production too.
	full := make([]map[string]any, 0, esPageSize)
	for i := 0; i < esPageSize; i++ {
		full = append(full, equalTSHit(
			fmt.Sprintf("f%d", i),
			fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255),
			ms, i))
	}
	page2 := []map[string]any{
		equalTSHit("x3", "10.200.200.3", ms, esPageSize),        // same timestamp, next shard_doc
		equalTSHit("x4", "10.200.200.9", ms+1000, esPageSize+1), // later ts ends the shared group
	}

	var requests []json.RawMessage
	srv := esPITStub(t, [][]map[string]any{full, page2}, &requests)
	defer srv.Close()

	events, ok := fetchRecentEvents(newESClient(srv.URL), mustBoundaryTime(t).Add(-time.Hour))
	if !ok {
		t.Fatal("fetch reported failure")
	}

	if len(events) != esPageSize+len(page2) {
		t.Fatalf("equal-timestamp group split by the page seam lost events: got %d, want %d",
			len(events), esPageSize+len(page2))
	}
	got := ipsInOrder(events)
	checks := []struct {
		at int
		ip string
	}{
		{0, "10.0.0.0"}, {1, "10.0.0.1"}, {esPageSize - 1, fmt.Sprintf("10.%d.%d.%d",
			(esPageSize-1)>>16&255, (esPageSize-1)>>8&255, (esPageSize-1)&255)},
		{esPageSize, "10.200.200.3"}, {esPageSize + 1, "10.200.200.9"},
	}
	for _, c := range checks {
		if got[c.at] != c.ip {
			t.Errorf("position %d: got %s, want %s -- total order broke at the page seam", c.at, got[c.at], c.ip)
		}
	}

	if len(requests) != 2 {
		t.Fatalf("expected exactly 2 search pages, got %d", len(requests))
	}
	var first, second struct {
		SearchAfter []any            `json:"search_after"`
		Sort        []map[string]any `json:"sort"`
	}
	if err := json.Unmarshal(requests[0], &first); err != nil {
		t.Fatalf("decode page-1 request: %v", err)
	}
	if first.SearchAfter != nil {
		t.Errorf("first page must not carry search_after, got %v", first.SearchAfter)
	}
	if err := json.Unmarshal(requests[1], &second); err != nil {
		t.Fatalf("decode page-2 request: %v", err)
	}
	if len(second.SearchAfter) != 2 || second.SearchAfter[0] != float64(ms) ||
		second.SearchAfter[1] != float64(esPageSize-1) {
		t.Errorf("page 2 must resume from the FULL sort tuple [ts,_shard_doc] of the last prior hit, got %v",
			second.SearchAfter)
	}
	if len(second.Sort) != 2 || second.Sort[1]["_shard_doc"] != "asc" {
		t.Errorf("_shard_doc tiebreaker missing from the sort tuple -- equal-timestamp resume becomes ambiguous, got %v",
			second.Sort)
	}
}

// TestOverlappingRefetchCannotForkIdenticalInput pins why across-cycle
// overlap (windowed refetch re-consuming the same events every cycle) is
// safe here: identical observation batches resolve to the identical entity
// population, and those entities are written under their own deterministic
// ID (newEntityID -> docIndex(e.ID)), so a refetched cycle overwrites rather
// than duplicates -- the pattern-2 counterpart of #168's idempotent writes.
func TestOverlappingRefetchCannotForkIdenticalInput(t *testing.T) {
	const fingerprint = "deadbeefcafebabe1122334455667788"
	events := func() []corrEvent {
		ts := mustBoundaryTime(t)
		return []corrEvent{
			{When: ts, SrcIP: "10.9.9.1", Sensor: "cowrie", Fingerprint: fingerprint},
			{When: ts.Add(time.Second), SrcIP: "10.9.9.1", Sensor: "cowrie",
				User: "root", Pass: "toor"},
		}
	}

	runOnce := func() []string {
		observations := buildIPObservations(events())
		changed, absorbed := resolveIdentities(nil, observations)
		if len(absorbed) != 0 {
			t.Fatalf("fresh cycle absorbed unexpectedly: %v", absorbed)
		}
		ids := make([]string, 0, len(changed))
		for _, e := range changed {
			ids = append(ids, e.ID)
		}
		return ids // resolveIdentities sorts by ID before returning
	}

	first, second := runOnce(), runOnce()
	if len(first) == 0 {
		t.Fatal("no entities resolved from a two-signal observation")
	}
	assertStringSlice(t, "entity population deterministic across identical refetch cycles",
		second, first)
}
