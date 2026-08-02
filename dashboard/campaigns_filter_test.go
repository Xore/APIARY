package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

// #280: /campaigns gained its own dedicated data function instead of
// reusing the whole periodic-snapshot struct (s.get()) just for its
// .Campaigns field -- campaignsData recomputes live from the request's
// filter, same as ipsData/commandsData/clustersData. #307 later made the
// fully-unfiltered case read s.snap.Campaigns directly (already fresh from
// aggregate.go's own rebuild() cycle in production) instead of recomputing
// -- these tests populate s.snap by hand, standing in for the rebuild()
// call a real server always makes before serving any request.

func TestCampaignsDataAppliesFilter(t *testing.T) {
	now := time.Now()
	s := &store{events: []storedEvent{
		{when: now, SrcIP: "8.8.8.8", Sensor: "cowrie", Port: "22"},
		{when: now, SrcIP: "8.8.8.9", Sensor: "dionaea", Port: "445"},
	}}
	s.snap.Campaigns = correlateCampaigns(s.events, now.Add(-defaultCorrelationWindow))
	all := s.campaignsData(httptest.NewRequest("GET", "/campaigns", nil))
	if len(all.Campaigns) != 1 || all.Campaigns[0].Events != 2 || all.Campaigns[0].UniqueIPs != 2 {
		t.Fatalf("expected one 2-event campaign unfiltered, got %+v", all.Campaigns)
	}

	narrowed := s.campaignsData(httptest.NewRequest("GET", "/campaigns?sensor=cowrie", nil))
	if len(narrowed.Campaigns) != 1 || narrowed.Campaigns[0].Events != 1 || narrowed.Campaigns[0].UniqueIPs != 1 {
		t.Fatalf("sensor filter did not narrow the campaign, got %+v", narrowed.Campaigns)
	}
	if len(narrowed.Filters) != 1 || narrowed.Filters[0] != "sensor = cowrie" {
		t.Fatalf("expected a sensor filter chip, got %+v", narrowed.Filters)
	}
}

func TestCampaignsDataSinceOverridesDefaultSevenDayWindow(t *testing.T) {
	now := time.Now()
	s := &store{events: []storedEvent{
		{when: now.Add(-8 * 24 * time.Hour), SrcIP: "8.8.8.8", Sensor: "cowrie", Port: "22"},
		{when: now.Add(-8 * 24 * time.Hour), SrcIP: "8.8.8.9", Sensor: "cowrie", Port: "22"},
	}}
	s.snap.Campaigns = correlateCampaigns(s.events, now.Add(-defaultCorrelationWindow))
	def := s.campaignsData(httptest.NewRequest("GET", "/campaigns", nil))
	if len(def.Campaigns) != 0 {
		t.Fatalf("expected the default 7-day window to exclude 8-day-old events, got %+v", def.Campaigns)
	}

	widened := s.campaignsData(httptest.NewRequest("GET", "/campaigns?since=240h", nil))
	if len(widened.Campaigns) != 1 || widened.Campaigns[0].Events != 2 {
		t.Fatalf("since=240h should have widened the window to include both events, got %+v", widened.Campaigns)
	}
}

// #307: a plain, unfiltered /campaigns visit reads s.snap.Campaigns
// (whatever aggregate.go's rebuild() last computed) instead of recomputing
// correlateCampaigns() again -- proven directly by making the cached
// snapshot say something DIFFERENT from what a live recompute over
// s.events would produce, so a pass here can't be an accident of both
// paths happening to agree.
func TestCampaignsDataUnfilteredReadsTheCachedSnapshotNotALiveRecompute(t *testing.T) {
	now := time.Now()
	s := &store{events: []storedEvent{
		{when: now, SrcIP: "8.8.8.8", Sensor: "cowrie", Port: "22"},
		{when: now, SrcIP: "8.8.8.9", Sensor: "dionaea", Port: "445"},
	}}
	stale := []campaignRow{{CIDR: "203.0.113.0/24", Events: 999, UniqueIPs: 42}}
	s.snap.Campaigns = stale

	got := s.campaignsData(httptest.NewRequest("GET", "/campaigns", nil))
	if len(got.Campaigns) != 1 || got.Campaigns[0].Events != 999 {
		t.Fatalf("expected the unfiltered view to be exactly s.snap.Campaigns, got %+v", got.Campaigns)
	}
}

// Any active filter still needs a live recompute -- the cached snapshot
// only ever holds the unfiltered defaultCorrelationWindow view, so it can't
// answer a narrowed request.
func TestCampaignsDataFilteredIgnoresTheCachedSnapshot(t *testing.T) {
	now := time.Now()
	s := &store{events: []storedEvent{
		{when: now, SrcIP: "8.8.8.8", Sensor: "cowrie", Port: "22"},
	}}
	s.snap.Campaigns = []campaignRow{{CIDR: "203.0.113.0/24", Events: 999, UniqueIPs: 42}}

	got := s.campaignsData(httptest.NewRequest("GET", "/campaigns?sensor=cowrie", nil))
	if len(got.Campaigns) != 1 || got.Campaigns[0].Events != 1 {
		t.Fatalf("a filtered request must recompute live, not read the stale cached snapshot, got %+v", got.Campaigns)
	}
}
