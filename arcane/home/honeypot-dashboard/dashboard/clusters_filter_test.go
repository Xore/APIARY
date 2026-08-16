package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

// #280: /clusters gained the same query-string filtering /events already
// had. clustersData takes a filter directly (not *http.Request) because
// aggregate.go's periodic intelligence snapshot calls it with no request at
// all -- that call site must stay unfiltered.

func TestClustersDataAppliesFilter(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "8.8.8.8", Sensor: "cowrie", Fingerprint: "shared-hassh"},
		{SrcIP: "8.8.4.4", Sensor: "cowrie", Fingerprint: "shared-hassh"},
		{SrcIP: "9.9.9.9", Sensor: "dionaea", Fingerprint: "shared-hassh"},
	}}
	all := s.clustersData(filter{})
	if len(all.Rows) != 1 || all.Rows[0].Sources != 3 {
		t.Fatalf("expected one 3-source cluster unfiltered, got %+v", all.Rows)
	}

	narrowed := s.clustersData(parseFilter(httptest.NewRequest("GET", "/clusters?sensor=cowrie", nil)))
	if len(narrowed.Rows) != 1 || narrowed.Rows[0].Sources != 2 {
		t.Fatalf("sensor filter did not narrow the cluster to 2 sources, got %+v", narrowed.Rows)
	}
	if len(narrowed.Filters) != 1 || narrowed.Filters[0] != "sensor = cowrie" {
		t.Fatalf("expected a sensor filter chip, got %+v", narrowed.Filters)
	}
}

// TestClustersDataOrderIsDeterministicOnFullTie (#40): clustersData's sort
// used to compare only Sources then Events, with no further tiebreaker --
// two small clusters tying on both (routine: most clusters are small) left
// their relative order to sort.Slice's lack of a stability guarantee and
// Go's per-process randomized map iteration order (groups is a map), so two
// dashboard instances reading byte-identical underlying events could render
// /clusters in a different row order. Runs over many fresh stores (each
// rebuilds its map from scratch) and requires every run to agree.
func TestClustersDataOrderIsDeterministicOnFullTie(t *testing.T) {
	events := []storedEvent{
		{SrcIP: "8.8.8.8", Sensor: "cowrie", Fingerprint: "aaa-tied-hassh"},
		{SrcIP: "8.8.4.4", Sensor: "cowrie", Fingerprint: "aaa-tied-hassh"},
		{SrcIP: "9.9.9.9", Sensor: "cowrie", Fingerprint: "zzz-tied-hassh"},
		{SrcIP: "9.9.9.8", Sensor: "cowrie", Fingerprint: "zzz-tied-hassh"},
	}
	var want []string
	for i := 0; i < 20; i++ {
		s := &store{events: append([]storedEvent(nil), events...)}
		page := s.clustersData(filter{})
		got := make([]string, len(page.Rows))
		for j, r := range page.Rows {
			got[j] = r.Value
		}
		if want == nil {
			want = got
			continue
		}
		if len(got) != len(want) {
			t.Fatalf("run %d: row count changed: got %v, want %v", i, got, want)
		}
		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("run %d: order is not deterministic across runs: got %v, want %v", i, got, want)
			}
		}
	}
}

func TestClustersDataUnfilteredCallSiteStaysUnfiltered(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "8.8.8.8", Sensor: "cowrie", Fingerprint: "shared-hassh"},
		{SrcIP: "8.8.4.4", Sensor: "dionaea", Fingerprint: "shared-hassh"},
	}}
	// Mirrors aggregate.go's periodic-snapshot call site exactly: filter{}.
	page := s.clustersData(filter{})
	if len(page.Rows) != 1 || page.Rows[0].Sources != 2 {
		t.Fatalf("expected the background snapshot path to see every source, got %+v", page.Rows)
	}
}

// #307: an ordinary /clusters visit (no ?since=) used to correlate every
// event this dashboard has ever recorded, unbounded -- clustersRequestFilter
// is what the /clusters HTTP handler now uses instead of a bare
// parseFilter(r), defaulting to defaultCorrelationWindow.
func TestClustersRequestFilterDefaultsToTheCorrelationWindow(t *testing.T) {
	r := httptest.NewRequest("GET", "/clusters", nil)
	f := clustersRequestFilter(r)
	if f.since.IsZero() {
		t.Fatalf("expected a default since bound, got the zero value (unbounded)")
	}
	wantAround := time.Now().Add(-defaultCorrelationWindow)
	if diff := f.since.Sub(wantAround); diff < -time.Minute || diff > time.Minute {
		t.Fatalf("f.since = %v, want approximately %v (defaultCorrelationWindow ago)", f.since, wantAround)
	}
}

func TestClustersRequestFilterRespectsAnExplicitSince(t *testing.T) {
	r := httptest.NewRequest("GET", "/clusters?since=1h", nil)
	f := clustersRequestFilter(r)
	wantAround := time.Now().Add(-time.Hour)
	if diff := f.since.Sub(wantAround); diff < -time.Minute || diff > time.Minute {
		t.Fatalf("an explicit ?since=1h must not be overridden by the default window, got f.since = %v", f.since)
	}
}

func TestClustersHandlerDefaultWindowExcludesOldEvents(t *testing.T) {
	now := time.Now()
	s := &store{events: []storedEvent{
		{when: now.Add(-defaultCorrelationWindow - time.Hour), SrcIP: "8.8.8.8", Sensor: "cowrie", Fingerprint: "old-hassh"},
		{when: now.Add(-defaultCorrelationWindow - time.Hour), SrcIP: "8.8.4.4", Sensor: "cowrie", Fingerprint: "old-hassh"},
	}}
	unbounded := s.clustersData(filter{})
	if len(unbounded.Rows) != 1 {
		t.Fatalf("sanity check failed: filter{} should still see the old cluster, got %+v", unbounded.Rows)
	}

	bounded := s.clustersData(clustersRequestFilter(httptest.NewRequest("GET", "/clusters", nil)))
	if len(bounded.Rows) != 0 {
		t.Fatalf("the default correlation window should exclude events older than it, got %+v", bounded.Rows)
	}
}
