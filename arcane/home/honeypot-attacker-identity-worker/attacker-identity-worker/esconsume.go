package main

// esconsume.go -- Go reference implementation of the repo's shared
// incremental-checkpoint ES consume pattern (#1971), the behavioural twin of
// the canonical stdlib-only Python module analysis/es-consume/es_consume.py.
// It lives in this module (not a shared workspace -- every worker here is a
// separate module by stack boundary, see runloop.go's duplication note) so
// that `go test ./...` compiles and exercises it in CI today, making future
// adoption a copy-plus-wiring instead of a port.
//
// This worker itself deliberately does NOT consume through it: its fetch is
// a wall-clock windowed refetch (EVIDENCE_WINDOW re-scanned gte-inclusively
// every cycle, merged into deterministic-ID upserts), which is pattern 2 --
// docs/ES-CONSUME-PATTERNS.md names each consumer's pattern and why. Pattern
// 1 applies when a consumer protects persisted position across cycles;
// correlator-worker or payload-inventory-worker would adopt THIS file if
// they ever grew such state, exactly as ml-worker adopted the Python half.
//
// Behavioural parity with the Python engine is asserted against a shared,
// hand-computed fixture stream (same stream in -> same consumed-set and
// checkpoint out in both languages): esconsume_test.go drives this code
// through analysis/es-consume/fixtures/es-consume-parity.json, whose exact
// expectations were written from docs and issue history, not generated from
// either implementation. Stdlib-only by the gpu_queue.py discipline so the
// file stays vendorable into any Go module without dependency-budget review.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ConsumeCheckpoint is the total-order position tuple (#168): last processed
// timestamp plus the document IDs already processed AT that timestamp. Field
// names match the Python module's dict keys because the parity fixtures
// embed these objects verbatim.
type ConsumeCheckpoint struct {
	LastTimestamp string   `json:"last_timestamp"`
	SeenIDs       []string `json:"seen_ids"`
}

// ConsumeHit is the slice of an ES hit the pattern cares about: identity
// (for boundary exclusion and seen_ids bookkeeping) and sort timestamp.
type ConsumeHit struct {
	ID string `json:"_id"`
	// RawSource keeps only @timestamp; the engine never inspects payload.
	RawSource struct {
		Timestamp string `json:"@timestamp"`
	} `json:"_source"`
}

func (h ConsumeHit) timestamp() string { return h.RawSource.Timestamp }

// scrollResponse mirrors elasticsearch-py's response envelope, the transport
// dialect both engines speak: {"_scroll_id": "...", "hits": {"hits": [...]}}.
type scrollResponse struct {
	ScrollID string `json:"_scroll_id"`
	Hits     struct {
		Hits []ConsumeHit `json:"hits"`
	} `json:"hits"`
}

// consumeScrollTransport injects the ES calls, mirroring
// es_consume.fetch_events_since's three-callable seam. ClearScroll can fail
// like any other call: per the Python engine's contract a cleanup-phase
// error still reports (events, false), never a silent full success.
type consumeScrollTransport struct {
	Search      func(query map[string]any) (scrollResponse, error)
	ScrollNext  func(scrollID string) (scrollResponse, error)
	ClearScroll func(scrollID string) error
}

// BuildSinceQuery is the incremental poll's body: inclusive gte (never gt --
// exclusive boundaries are what dropped equal-timestamp siblings pre-#168),
// ascending @timestamp sort (every downstream safety argument rests on it),
// one bounded page. Kept next to the engine so the two cannot drift; the
// JSON shape is identical to es_consume.build_since_query's output.
func BuildSinceQuery(since string, pageSize int) map[string]any {
	return map[string]any{
		"query": map[string]any{
			"range": map[string]any{
				"@timestamp": map[string]any{"gte": since},
			},
		},
		"sort": []map[string]any{
			{"@timestamp": map[string]any{"order": "asc"}},
		},
		"size": pageSize,
	}
}

// AdvanceCheckpoint computes the next position tuple (#168) from a consumed
// batch (ascending by @timestamp) and the checkpoint it was fetched against.
// Only IDs at the NEW maximum timestamp survive: everything strictly earlier
// can never be requeried once the checkpoint moves past it, so SeenIDs stays
// bounded by one timestamp's collision count. Replacement, not append; an
// empty batch returns `previous` unchanged.
func AdvanceCheckpoint(events []ConsumeHit, previous *ConsumeCheckpoint) *ConsumeCheckpoint {
	if len(events) == 0 {
		return previous
	}
	maxTs := ""
	for _, e := range events {
		if ts := e.timestamp(); ts > maxTs {
			maxTs = ts
		}
	}
	if maxTs == "" {
		return previous
	}
	var seen []string
	for _, e := range events {
		if e.timestamp() == maxTs {
			seen = append(seen, e.ID)
		}
	}
	return &ConsumeCheckpoint{LastTimestamp: maxTs, SeenIDs: seen}
}

// FetchEventsSince scrolls events at or after `since` (inclusive) through the
// injected transport. Returns (events, ok); ok=false means a transport call
// failed -- distinct from a successful empty poll (#188). A scroll failing
// partway still returns what was already read with ok=false, which is safe
// to checkpoint per AdvanceCheckpoint's ordering argument. maxTotal truncates
// to the EARLIEST prefix, keeping the capped batch contiguous. Like the
// Python engine, the failure return wraps every injected call --
// ClearScroll's error included -- so a broken cleanup never reads as a fully
// successful poll.
func FetchEventsSince(transport consumeScrollTransport, since string, pageSize int,
	maxTotal int, excludeIDs map[string]bool, warn func(string)) ([]ConsumeHit, bool) {

	exclude := excludeIDs
	if exclude == nil {
		exclude = map[string]bool{}
	}
	var events []ConsumeHit
	resp, err := transport.Search(BuildSinceQuery(since, pageSize))
	scrollID := resp.ScrollID
	hits := resp.Hits.Hits
	for {
		if err != nil {
			if warn != nil {
				warn(err.Error())
			}
			return events, false
		}
		if len(hits) == 0 {
			break
		}
		for _, hit := range hits {
			if exclude[hit.ID] {
				continue
			}
			events = append(events, hit)
		}
		if maxTotal > 0 && len(events) >= maxTotal {
			events = events[:maxTotal]
			break
		}
		resp, err = transport.ScrollNext(scrollID)
		scrollID = resp.ScrollID
		hits = resp.Hits.Hits
		continue
	}
	if transport.ClearScroll != nil {
		if cerr := transport.ClearScroll(scrollID); cerr != nil {
			if warn != nil {
				warn(cerr.Error())
			}
			return events, false
		}
	}
	return events, true
}

// --- fixture plumbing shared with the canonical Python suite ---------------

// findESConsumeFixture locates analysis/es-consume/fixtures/
// es-consume-parity.json by walking upward from this source file, so tests
// run regardless of working directory and no copy of the fixture exists
// (nothing can drift; there is one file).
func findESConsumeFixture() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("runtime.Caller could not resolve this source file")
	}
	dir := filepath.Dir(thisFile)
	for {
		candidate := filepath.Join(dir, "analysis", "es-consume", "fixtures", "es-consume-parity.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("analysis/es-consume/fixtures/es-consume-parity.json not found above %s",
				filepath.Dir(thisFile))
		}
		dir = parent
	}
}

type fixturePage struct {
	OK    bool         `json:"ok"`
	Error string       `json:"error"`
	Hits  []ConsumeHit `json:"hits"`
}

type fixtureCase struct {
	Name              string            `json:"name"`
	InitialCheckpoint ConsumeCheckpoint `json:"initial_checkpoint"`
	MaxTotal          *int              `json:"max_total"`
	Pages             []fixturePage     `json:"pages"`

	ExpectedOK              bool              `json:"expected_ok"`
	ExpectedConsumedIDs     []string          `json:"expected_consumed_ids"`
	ExpectedFinalCheckpoint ConsumeCheckpoint `json:"expected_final_checkpoint"`
}

func (c fixtureCase) run(warn func(string)) ([]string, bool, ConsumeCheckpoint) {
	state := -1

	fail := func(page fixturePage) (scrollResponse, error) {
		if !page.OK {
			return scrollResponse{}, errors.New(page.Error)
		}
		state++
		r := scrollResponse{ScrollID: fmt.Sprintf("scroll-%d", state)}
		r.Hits.Hits = page.Hits
		return r, nil
	}

	transport := consumeScrollTransport{
		Search: func(map[string]any) (scrollResponse, error) {
			state = -1
			return fail(c.Pages[0])
		},
		ScrollNext: func(string) (scrollResponse, error) {
			return fail(c.Pages[state+1])
		},
		ClearScroll: func(string) error { return nil },
	}

	maxTotal := 0
	if c.MaxTotal != nil {
		maxTotal = *c.MaxTotal
	}

	events, ok := FetchEventsSince(transport, c.InitialCheckpoint.LastTimestamp,
		500, maxTotal, setOf(c.InitialCheckpoint.SeenIDs), warn)
	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	final := AdvanceCheckpoint(events, &c.InitialCheckpoint)
	if final == nil {
		final = &ConsumeCheckpoint{}
	}
	return ids, ok, *final
}

func setOf(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}
