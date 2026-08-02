package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

// #280: /campaigns gained its own dedicated data function instead of
// reusing the whole periodic-snapshot struct (s.get()) just for its
// .Campaigns field -- campaignsData recomputes live from the request's
// filter, same as ipsData/commandsData/clustersData.

func TestCampaignsDataAppliesFilter(t *testing.T) {
	now := time.Now()
	s := &store{events: []storedEvent{
		{when: now, SrcIP: "8.8.8.8", Sensor: "cowrie", Port: "22"},
		{when: now, SrcIP: "8.8.8.9", Sensor: "dionaea", Port: "445"},
	}}
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
	def := s.campaignsData(httptest.NewRequest("GET", "/campaigns", nil))
	if len(def.Campaigns) != 0 {
		t.Fatalf("expected the default 7-day window to exclude 8-day-old events, got %+v", def.Campaigns)
	}

	widened := s.campaignsData(httptest.NewRequest("GET", "/campaigns?since=240h", nil))
	if len(widened.Campaigns) != 1 || widened.Campaigns[0].Events != 2 {
		t.Fatalf("since=240h should have widened the window to include both events, got %+v", widened.Campaigns)
	}
}
