package main

// correlate.go -- scoring/threshold logic over fetch.go's aggregation
// results (campaignBucket/clusterBucket), matching dashboard/campaigns.go's
// correlateCampaigns and dashboard/intelligence.go's clustersData exactly
// (same 100-point score cap, same >=2-unique-IP cluster threshold) so
// campaigns-v1/attacker-clusters-v1 read the same as the in-process
// versions they're meant to replace (#1202, not this). #1219 moved the
// grouping itself from a raw-document Go loop to real Elasticsearch
// aggregations (see fetch.go); this file is now pure functions over
// already-aggregated structs, kept that way deliberately so the scoring
// formula/threshold/explanation-string logic stays unit-testable without
// an HTTP mock, only fetch.go's parsing layer needs one.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

func validCredentialPair(user, pass string) bool {
	if user == "" && pass == "" || len(user) > 128 || len(pass) > 512 {
		return false
	}
	for _, value := range []string{user, pass} {
		lower := strings.ToLower(value)
		if strings.ContainsAny(value, "\x00\r\n") || strings.Contains(lower, `\x00`) || strings.Contains(lower, `\u0000`) {
			return false
		}
	}
	if strings.ContainsAny(user, " \t/;|&<>") {
		return false
	}
	lowerPass := strings.ToLower(strings.TrimSpace(pass))
	for _, marker := range []string{"/bin/", "busybox", "linuxshell", "powershell", "cmd.exe"} {
		if strings.Contains(lowerPass, marker) {
			return false
		}
	}
	return true
}

// campaignCIDR mirrors dashboard/campaigns.go's function of the same
// name -- still needed here (not just in fetch.go's isRoutableNetwork) to
// bucket fetchSuricataAlertCounts' flat per-IP result back into whichever
// CIDR group each alerting IP belongs to, since the aggregation-based
// campaign fetch no longer carries a per-group member-IP list to look
// alert counts up against directly.
func campaignCIDR(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return ""
	}
	a = a.Unmap()
	bits := 64
	if a.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(a, bits).Masked().String()
}

// campaignDoc is one campaigns-v1 document -- field names match
// dashboard/campaigns.go's campaignRow where the same signal exists here.
type campaignDoc struct {
	CIDR         string   `json:"cidr"`
	Score        int      `json:"score"`
	Events       int      `json:"events"`
	UniqueIPs    int      `json:"unique_ips"`
	Sensors      []string `json:"sensors"`
	Ports        []string `json:"ports"`
	Creds        int      `json:"creds"`
	Payloads     int      `json:"payloads"`
	Alerts       int      `json:"alerts"`
	Providers    []string `json:"providers"`
	Fingerprints int      `json:"fingerprints"`
	First        string   `json:"first"`
	Last         string   `json:"last"`
	Generated    string   `json:"generated"`
	Explanation  string   `json:"explanation"`
}

// alertCountsByCIDR re-buckets fetchSuricataAlertCounts' flat per-IP
// result by campaignCIDR(ip) -- a pure, cheap Go computation, so alert
// folding needs no changes to fetchSuricataAlertCounts itself and no
// per-group member-IP list from the campaign aggregation.
func alertCountsByCIDR(alertCounts map[string]int) map[string]int {
	out := map[string]int{}
	for ip, count := range alertCounts {
		if ip == tunnelPeerIP {
			continue
		}
		cidr := campaignCIDR(ip)
		if cidr == "" {
			continue
		}
		out[cidr] += count
	}
	return out
}

// scoreCampaigns mirrors dashboard/campaigns.go's correlateCampaigns:
// same score formula, same top-50 cap. alertCounts is
// fetchSuricataAlertCounts' own per-source-IP result (nil/empty is fine --
// every group's alert term is just 0).
func scoreCampaigns(buckets []campaignBucket, now time.Time, alertCounts map[string]int) []campaignDoc {
	byCIDR := alertCountsByCIDR(alertCounts)
	docs := make([]campaignDoc, 0, len(buckets))
	for _, b := range buckets {
		alerts := byCIDR[b.CIDR]
		score := min(100, min(b.Events, 30)+len(b.Sensors)*15+b.UniqueIPs*3+b.Creds*8+b.Payloads*20+min(alerts, 15)*2+b.Fingerprints*3+len(b.Providers)*2)
		var why []string
		if len(b.Sensors) > 1 {
			why = append(why, fmt.Sprintf("cross-sensor activity (%d)", len(b.Sensors)))
		}
		if b.UniqueIPs > 1 {
			why = append(why, fmt.Sprintf("%d related source IPs", b.UniqueIPs))
		}
		if b.Payloads > 0 {
			why = append(why, fmt.Sprintf("%d shared payloads", b.Payloads))
		}
		if b.Creds > 0 {
			why = append(why, fmt.Sprintf("%d reused credentials", b.Creds))
		}
		if alerts > 0 {
			why = append(why, fmt.Sprintf("%d IDS alerts", alerts))
		}
		if b.Fingerprints > 0 {
			why = append(why, fmt.Sprintf("%d fingerprints", b.Fingerprints))
		}
		if len(why) == 0 {
			why = append(why, "repeated activity from one routable network")
		}
		docs = append(docs, campaignDoc{
			CIDR: b.CIDR, Score: score, Events: b.Events, UniqueIPs: b.UniqueIPs,
			Sensors: b.Sensors, Ports: b.Ports,
			Creds: b.Creds, Payloads: b.Payloads, Alerts: alerts,
			Providers: b.Providers, Fingerprints: b.Fingerprints,
			First: b.First, Last: b.Last,
			Generated:   now.UTC().Format(time.RFC3339),
			Explanation: strings.Join(why, "; "),
		})
	}
	sort.Slice(docs, func(i, j int) bool {
		if docs[i].Score != docs[j].Score {
			return docs[i].Score > docs[j].Score
		}
		if docs[i].Events != docs[j].Events {
			return docs[i].Events > docs[j].Events
		}
		return docs[i].CIDR < docs[j].CIDR
	})
	if len(docs) > 50 {
		docs = docs[:50]
	}
	return docs
}

// clusterDoc is one attacker-clusters-v1 document -- mirrors dashboard/
// intelligence.go's clusterRow's four grouping kinds (Fingerprint/Payload/
// Autonomous system/Provider class), lowercased (kind/asn/provider, not
// "Autonomous system"/"Provider class") matching this worker's own
// existing "fingerprint"/"payload" convention rather than dashboard's
// display-string labels.
type clusterDoc struct {
	Kind      string   `json:"kind"`
	Value     string   `json:"value"`
	Events    int      `json:"events"`
	Sources   int      `json:"sources"`
	Sensors   []string `json:"sensors"`
	Generated string   `json:"generated"`
}

// clusterBucket is one fetchClusterAggregates result -- the >=2-unique-IP
// threshold is already applied by fetch.go, so finalizeClusters only
// needs to shape the final doc, sort, and cap.
type clusterBucket struct {
	Kind      string
	Value     string
	Events    int
	UniqueIPs int
	Sensors   []string
}

// finalizeClusters mirrors dashboard/intelligence.go's clustersData: same
// top-250 cap (the >=2-unique-IP threshold itself is enforced by
// fetch.go's fetchClusterAggregates, against each bucket's own
// cardinality sub-aggregation).
func finalizeClusters(buckets []clusterBucket, now time.Time) []clusterDoc {
	docs := make([]clusterDoc, 0, len(buckets))
	for _, b := range buckets {
		docs = append(docs, clusterDoc{
			Kind: b.Kind, Value: b.Value, Events: b.Events, Sources: b.UniqueIPs,
			Sensors: b.Sensors, Generated: now.UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(docs, func(i, j int) bool {
		if docs[i].Sources != docs[j].Sources {
			return docs[i].Sources > docs[j].Sources
		}
		if docs[i].Events != docs[j].Events {
			return docs[i].Events > docs[j].Events
		}
		if docs[i].Kind != docs[j].Kind {
			return docs[i].Kind < docs[j].Kind
		}
		return docs[i].Value < docs[j].Value
	})
	if len(docs) > 250 {
		docs = docs[:250]
	}
	return docs
}
