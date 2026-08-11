package main

import (
	"strconv"
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

func TestCorrelateCampaignsGroupsByCIDRAndScores(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	evs := []corrEvent{
		{When: now.Add(-1 * time.Hour), SrcIP: "203.0.113.1", Sensor: "cowrie", Port: "22", User: "root", Pass: "toor"},
		{When: now.Add(-2 * time.Hour), SrcIP: "203.0.113.2", Sensor: "dionaea", Port: "445", Shasum: "abc123"},
		{When: now, SrcIP: "198.51.100.1", Sensor: "cowrie", Port: "22"},
	}
	docs := correlateCampaigns(evs, now)
	if len(docs) != 2 {
		t.Fatalf("expected 2 campaign groups, got %d: %+v", len(docs), docs)
	}
	var found *campaignDoc
	for i := range docs {
		if docs[i].CIDR == "203.0.113.0/24" {
			found = &docs[i]
		}
	}
	if found == nil {
		t.Fatal("expected a 203.0.113.0/24 campaign")
	}
	if found.Events != 2 || found.UniqueIPs != 2 {
		t.Fatalf("got %+v", found)
	}
	if found.Creds != 1 {
		t.Fatalf("expected 1 credential pair counted, got %+v", found)
	}
	if found.Payloads != 1 {
		t.Fatalf("expected 1 payload counted, got %+v", found)
	}
	// cross-sensor (2 sensors: cowrie+dionaea) + 2 unique IPs + 1 cred + 1 payload
	// = min(2,30) + 2*15 + 2*3 + 1*8 + 1*20 + 0*3 = 2+30+6+8+20 = 66
	if found.Score != 66 {
		t.Fatalf("score = %d, want 66", found.Score)
	}
}

func TestCorrelateCampaignsExcludesInvalidCredentialPairs(t *testing.T) {
	now := time.Now()
	evs := []corrEvent{
		{When: now, SrcIP: "203.0.113.1", Sensor: "cowrie", User: "root", Pass: "; /bin/busybox"},
	}
	docs := correlateCampaigns(evs, now)
	if len(docs) != 1 || docs[0].Creds != 0 {
		t.Fatalf("expected the invalid credential pair to be excluded: %+v", docs)
	}
}

func TestCorrelateCampaignsCapsAtFifty(t *testing.T) {
	now := time.Now()
	var evs []corrEvent
	for i := 0; i < 60; i++ {
		evs = append(evs, corrEvent{When: now, SrcIP: "203.0." + strconv.Itoa(i) + ".1", Sensor: "cowrie"})
	}
	docs := correlateCampaigns(evs, now)
	if len(docs) != 50 {
		t.Fatalf("expected the top-50 cap to apply, got %d", len(docs))
	}
}

func TestCorrelateClustersRequiresAtLeastTwoSourceIPs(t *testing.T) {
	now := time.Now()
	evs := []corrEvent{
		{When: now, SrcIP: "203.0.113.1", Sensor: "cowrie", Fingerprint: "shared-fp"},
	}
	docs := correlateClusters(evs, now)
	if len(docs) != 0 {
		t.Fatalf("a fingerprint seen from only 1 IP must not form a cluster: %+v", docs)
	}
}

func TestCorrelateClustersGroupsByFingerprintPayloadASN(t *testing.T) {
	now := time.Now()
	evs := []corrEvent{
		{When: now, SrcIP: "203.0.113.1", Sensor: "cowrie", Fingerprint: "shared-fp"},
		{When: now, SrcIP: "198.51.100.1", Sensor: "dionaea", Fingerprint: "shared-fp"},
		{When: now, SrcIP: "203.0.113.1", Sensor: "cowrie", Shasum: "same-hash"},
		{When: now, SrcIP: "198.51.100.2", Sensor: "cowrie", Shasum: "same-hash"},
		{When: now, SrcIP: "203.0.113.1", Sensor: "cowrie", ASN: 64512, ASNOrg: "Example ISP"},
		{When: now, SrcIP: "198.51.100.3", Sensor: "cowrie", ASN: 64512, ASNOrg: "Example ISP"},
	}
	docs := correlateClusters(evs, now)
	kinds := map[string]bool{}
	for _, d := range docs {
		kinds[d.Kind] = true
		if d.Sources < 2 {
			t.Errorf("cluster %+v has fewer than 2 sources", d)
		}
	}
	for _, want := range []string{"fingerprint", "payload", "asn"} {
		if !kinds[want] {
			t.Errorf("expected a %q cluster, got %+v", want, docs)
		}
	}
}

func TestCorrelateClustersASNValueIncludesOrgName(t *testing.T) {
	now := time.Now()
	evs := []corrEvent{
		{When: now, SrcIP: "203.0.113.1", Sensor: "cowrie", ASN: 64512, ASNOrg: "Example ISP"},
		{When: now, SrcIP: "198.51.100.1", Sensor: "cowrie", ASN: 64512, ASNOrg: "Example ISP"},
	}
	docs := correlateClusters(evs, now)
	if len(docs) != 1 || docs[0].Value != "AS64512 Example ISP" {
		t.Fatalf("got %+v", docs)
	}
}
