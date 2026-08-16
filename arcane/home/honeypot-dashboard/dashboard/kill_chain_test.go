package main

import (
	"testing"
	"time"
)

func TestTacticIndexOrdersCanonically(t *testing.T) {
	if tacticIndex("Reconnaissance") != 0 {
		t.Fatalf("expected Reconnaissance first, got index %d", tacticIndex("Reconnaissance"))
	}
	if tacticIndex("Impair Process Control") != len(killChainTactics)-1 {
		t.Fatalf("expected Impair Process Control last, got index %d", tacticIndex("Impair Process Control"))
	}
	if tacticIndex("not-a-real-tactic") != -1 {
		t.Fatal("expected -1 for an unknown tactic")
	}
}

func TestBuildAttckGridOrdersByTacticThenID(t *testing.T) {
	rows := []attackTechnique{
		{ID: "T1105", Name: "Ingress Tool Transfer", Count: 3}, // Command and Control
		{ID: "T1595", Name: "Active Scanning", Count: 10},      // Reconnaissance
		{ID: "T1059.001", Name: "PowerShell", Count: 2},        // Execution
		{ID: "T9999", Name: "Unmapped technique", Count: 99},   // no known tactic -- must be skipped
	}
	g := buildAttckGrid(rows)
	if len(g.Techniques) != 3 {
		t.Fatalf("expected 3 mapped techniques (unmapped one skipped), got %d: %+v", len(g.Techniques), g.Techniques)
	}
	if g.Techniques[0] != "T1595 Active Scanning" {
		t.Fatalf("expected Reconnaissance technique first, got %+v", g.Techniques)
	}
	if g.Cells[0].TacticIdx != tacticIndex("Reconnaissance") || g.Cells[0].Count != 10 {
		t.Fatalf("got %+v", g.Cells[0])
	}
	if len(g.Tactics) != len(killChainTactics) {
		t.Fatalf("expected the full canonical tactic list regardless of coverage, got %+v", g.Tactics)
	}
}

func TestBuildCampaignTimelineParsesUTCTimestampsAndSorts(t *testing.T) {
	rows := []campaignRow{
		{CIDR: "198.51.100.0/24", FirstUTC: "2026-08-10T00:00:00Z", LastUTC: "2026-08-10T01:00:00Z", Score: 10, Events: 2},
		{CIDR: "203.0.113.0/24", FirstUTC: "2026-08-05T00:00:00Z", LastUTC: "2026-08-05T02:00:00Z", Score: 50, Events: 9},
		{CIDR: "bad", FirstUTC: "not-a-time", LastUTC: "2026-08-05T02:00:00Z"}, // must be dropped, not crash
	}
	out := buildCampaignTimeline(rows)
	if len(out) != 2 {
		t.Fatalf("expected 2 valid rows (the unparseable one dropped), got %d: %+v", len(out), out)
	}
	if out[0].CIDR != "203.0.113.0/24" {
		t.Fatalf("expected the earlier campaign first, got %+v", out)
	}
	wantStart, _ := time.Parse(time.RFC3339, "2026-08-05T00:00:00Z")
	if out[0].StartMS != wantStart.UnixMilli() {
		t.Fatalf("StartMS = %d, want %d", out[0].StartMS, wantStart.UnixMilli())
	}
}

func TestBuildKillChainSankeyFlowsInCanonicalOrder(t *testing.T) {
	now := time.Now()
	events := []storedEvent{
		// One session touching both scanning (Reconnaissance) and a login
		// attempt (Credential Access) -- must flow Reconnaissance -> Credential Access
		// regardless of which event came first in the slice.
		{Session: "sess-1", Sensor: "cowrie", IsLogin: true, User: "root", Pass: "toor", when: now},
		{Session: "sess-1", Sensor: "suricata", Fingerprint: "scanner-ua", when: now},
	}
	data := buildKillChainSankey(events)
	if len(data.Links) == 0 {
		t.Fatalf("expected at least one flow link, got none: %+v", data)
	}
	for _, l := range data.Links {
		if tacticIndex(l.Source) > tacticIndex(l.Target) {
			t.Fatalf("flow %+v goes backwards in kill-chain order", l)
		}
	}
}

func TestBuildKillChainSankeyGroupsBySrcIPWhenNoSession(t *testing.T) {
	now := time.Now()
	events := []storedEvent{
		{SrcIP: "203.0.113.1", Sensor: "cowrie", IsLogin: true, User: "root", Pass: "toor", when: now},
	}
	data := buildKillChainSankey(events)
	if len(data.Nodes) == 0 {
		t.Fatalf("expected at least one tactic node from a sessionless event grouped by SrcIP, got %+v", data)
	}
}

func TestBuildKillChainSankeySkipsEventsWithNoIdentity(t *testing.T) {
	events := []storedEvent{{Sensor: "cowrie", IsLogin: true, User: "root", Pass: "toor", when: time.Now()}}
	data := buildKillChainSankey(events)
	if len(data.Nodes) != 0 || len(data.Links) != 0 {
		t.Fatalf("expected no nodes/links for an event with neither Session nor SrcIP, got %+v", data)
	}
}
