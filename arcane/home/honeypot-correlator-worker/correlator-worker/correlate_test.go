package main

import (
	"strings"
	"testing"
	"time"
)

func TestCampaignCIDRMasksPublicIPv4To24(t *testing.T) {
	if got := campaignCIDR("203.0.113.42"); got != "203.0.113.0/24" {
		t.Fatalf("got %q", got)
	}
}

func TestCampaignCIDRRejectsPrivateAndLoopback(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "not-an-ip", ""} {
		if got := campaignCIDR(ip); got != "" {
			t.Errorf("campaignCIDR(%q) = %q, want empty", ip, got)
		}
	}
}

func TestScoreCampaignsComputesFormula(t *testing.T) {
	now := time.Now()
	buckets := []campaignBucket{
		{CIDR: "203.0.113.0/24", Events: 2, UniqueIPs: 2, Sensors: []string{"cowrie", "dionaea"}, Creds: 1, Payloads: 1},
	}
	docs := scoreCampaigns(buckets, now, nil)
	if len(docs) != 1 {
		t.Fatalf("expected 1 campaign, got %d: %+v", len(docs), docs)
	}
	// cross-sensor (2 sensors) + 2 unique IPs + 1 cred + 1 payload
	// = min(2,30) + 2*15 + 2*3 + 1*8 + 1*20 = 2+30+6+8+20 = 66
	if docs[0].Score != 66 {
		t.Fatalf("score = %d, want 66", docs[0].Score)
	}
}

func TestScoreCampaignsCapsAtFifty(t *testing.T) {
	now := time.Now()
	var buckets []campaignBucket
	for i := 0; i < 60; i++ {
		buckets = append(buckets, campaignBucket{CIDR: "203.0.113.0/24", Events: i})
	}
	docs := scoreCampaigns(buckets, now, nil)
	if len(docs) != 50 {
		t.Fatalf("expected the top-50 cap to apply, got %d", len(docs))
	}
}

func TestScoreCampaignsSortsByScoreThenEventsThenCIDR(t *testing.T) {
	now := time.Now()
	buckets := []campaignBucket{
		{CIDR: "198.51.100.0/24", Events: 5},
		{CIDR: "203.0.113.0/24", Events: 5, Creds: 3}, // higher score, same events
	}
	docs := scoreCampaigns(buckets, now, nil)
	if docs[0].CIDR != "203.0.113.0/24" {
		t.Fatalf("expected the higher-scoring campaign first, got %+v", docs)
	}
}

func TestScoreCampaignsFoldsAlertCountsByCIDRNotLeakingAcrossGroups(t *testing.T) {
	now := time.Now()
	buckets := []campaignBucket{
		{CIDR: "203.0.113.0/24", Events: 1},
		{CIDR: "198.51.100.0/24", Events: 1},
	}
	alertCounts := map[string]int{"203.0.113.1": 3, "203.0.113.2": 2, "198.51.100.1": 100}
	docs := scoreCampaigns(buckets, now, alertCounts)
	byCIDR := map[string]campaignDoc{}
	for _, d := range docs {
		byCIDR[d.CIDR] = d
	}
	if byCIDR["203.0.113.0/24"].Alerts != 5 {
		t.Fatalf("expected 5 alerts (3+2) folded into 203.0.113.0/24, got %+v", byCIDR["203.0.113.0/24"])
	}
	if byCIDR["198.51.100.0/24"].Alerts != 100 {
		t.Fatalf("expected 100 alerts folded into 198.51.100.0/24, got %+v", byCIDR["198.51.100.0/24"])
	}
}

func TestScoreCampaignsIgnoresTunnelPeerAndUnroutableAlertIPs(t *testing.T) {
	now := time.Now()
	buckets := []campaignBucket{{CIDR: "203.0.113.0/24", Events: 1}}
	alertCounts := map[string]int{tunnelPeerIP: 999, "10.0.0.5": 999}
	docs := scoreCampaigns(buckets, now, alertCounts)
	if docs[0].Alerts != 0 {
		t.Fatalf("expected 0 alerts (tunnel peer / private IP must not count), got %d", docs[0].Alerts)
	}
}

func TestScoreCampaignsExplanationCoversEveryReason(t *testing.T) {
	now := time.Now()
	buckets := []campaignBucket{{
		CIDR: "203.0.113.0/24", Events: 1, UniqueIPs: 2, Sensors: []string{"cowrie", "dionaea"},
		Creds: 1, Payloads: 1, Fingerprints: 1,
	}}
	docs := scoreCampaigns(buckets, now, map[string]int{"203.0.113.1": 4})
	e := docs[0].Explanation
	for _, want := range []string{"cross-sensor", "related source IPs", "shared payloads", "reused credentials", "IDS alerts", "fingerprints"} {
		if !strings.Contains(e, want) {
			t.Errorf("explanation %q missing %q", e, want)
		}
	}
}

func TestScoreCampaignsFallbackExplanationWhenNoSignals(t *testing.T) {
	now := time.Now()
	buckets := []campaignBucket{{CIDR: "203.0.113.0/24", Events: 1}}
	docs := scoreCampaigns(buckets, now, nil)
	if docs[0].Explanation != "repeated activity from one routable network" {
		t.Fatalf("got %q", docs[0].Explanation)
	}
}

func TestFinalizeClustersSortsBySourcesThenEventsThenKindThenValue(t *testing.T) {
	now := time.Now()
	buckets := []clusterBucket{
		{Kind: "payload", Value: "hash1", Events: 5, UniqueIPs: 2},
		{Kind: "fingerprint", Value: "fp1", Events: 5, UniqueIPs: 3},
	}
	docs := finalizeClusters(buckets, now)
	if docs[0].Kind != "fingerprint" || docs[0].Sources != 3 {
		t.Fatalf("expected the higher-Sources cluster first, got %+v", docs)
	}
}

func TestFinalizeClustersCapsAtTwoFifty(t *testing.T) {
	now := time.Now()
	var buckets []clusterBucket
	for i := 0; i < 260; i++ {
		buckets = append(buckets, clusterBucket{Kind: "fingerprint", Value: "fp", UniqueIPs: 2})
	}
	docs := finalizeClusters(buckets, now)
	if len(docs) != 250 {
		t.Fatalf("expected the top-250 cap to apply, got %d", len(docs))
	}
}

func TestValidCredentialPairMatchesDashboardBehavior(t *testing.T) {
	cases := []struct {
		user, pass string
		want       bool
	}{
		{"", "", false},
		{"root", "toor", true},
		{"root", "; /bin/busybox", false},
		{"root ; rm -rf /", "x", false},
		{"root", "powershell -enc ...", false},
	}
	for _, tc := range cases {
		if got := validCredentialPair(tc.user, tc.pass); got != tc.want {
			t.Errorf("validCredentialPair(%q, %q) = %v, want %v", tc.user, tc.pass, got, tc.want)
		}
	}
}
