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
