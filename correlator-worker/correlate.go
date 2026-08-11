package main

// correlate.go -- ports dashboard/campaigns.go's correlateCampaigns and
// dashboard/intelligence.go's clustersData grouping logic against
// corrEvent instead of storedEvent. Scoring/threshold constants match the
// dashboard originals exactly (same 100-point cap, same >=2-IP cluster
// threshold) so campaigns-v1/attacker-clusters-v1 read the same as the
// in-process versions they're meant to replace (#1202, not this).
//
// #1218 added Providers grouping/scoring and alert counts, both via
// ES-native signals rather than duplicating dashboard's own
// geoInfo/threat-intel lookup (a genuinely dashboard-instance-local
// subsystem this worker still has no access to) -- see fetch.go's own doc
// comment for exactly which fields/queries back each one, and campaignDoc/
// clusterDoc below for the remaining, narrower gap against dashboard's
// exact Provider field.

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

// campaignCIDR mirrors dashboard/campaigns.go's function of the same name.
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

func sortedSet(m map[string]bool, limit int) string {
	items := make([]string, 0, len(m))
	for item := range m {
		if item != "" {
			items = append(items, item)
		}
	}
	sort.Strings(items)
	if len(items) > limit {
		items = append(items[:limit], fmt.Sprintf("+%d", len(items)-limit))
	}
	return strings.Join(items, " ")
}

// campaignDoc is one campaigns-v1 document -- field names match
// dashboard/campaigns.go's campaignRow where the same signal exists here.
// Alerts/Providers were previously omitted (see #1218); both are now
// populated from the ES-native signals fetch.go's own doc comment
// describes -- Alerts from a real suricata-v2-alert-* count, Providers
// from source.as.type (a narrower signal than dashboard's own Provider
// field, which also folds in a local-only threat-intel CIDR list this
// worker has no access to -- see fetch.go).
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

type campaignAgg struct {
	events       int
	ips, sensors map[string]bool
	ports, creds map[string]bool
	payloads     map[string]bool
	providers    map[string]bool
	fingerprints map[string]bool
	first, last  time.Time
}

// correlateCampaigns mirrors dashboard/campaigns.go's correlateCampaigns:
// same CIDR grouping, same score formula, same top-50 cap. alertCounts is
// fetchSuricataAlertCounts' own per-source-IP result (nil/empty is fine --
// every group's alert term is just 0, same as before #1218); a group's
// total is the sum over its own member IPs, computed once per group after
// the main pass below (an alert count is per-IP, not per-event, so it
// can't be accumulated inside the per-event loop without double-counting
// every IP's count once per event it appears in).
func correlateCampaigns(evs []corrEvent, now time.Time, alertCounts map[string]int) []campaignDoc {
	groups := map[string]*campaignAgg{}
	for _, e := range evs {
		cidr := campaignCIDR(e.SrcIP)
		if cidr == "" {
			continue
		}
		a := groups[cidr]
		if a == nil {
			a = &campaignAgg{ips: map[string]bool{}, sensors: map[string]bool{}, ports: map[string]bool{}, creds: map[string]bool{}, payloads: map[string]bool{}, providers: map[string]bool{}, fingerprints: map[string]bool{}}
			groups[cidr] = a
		}
		a.events++
		a.ips[e.SrcIP], a.sensors[e.Sensor], a.ports[e.Port] = true, true, true
		if validCredentialPair(e.User, e.Pass) {
			a.creds[e.User+" / "+e.Pass] = true
		}
		if e.Shasum != "" {
			a.payloads[e.Shasum] = true
		}
		if e.Provider != "" {
			a.providers[e.Provider] = true
		}
		if e.Fingerprint != "" {
			a.fingerprints[e.Fingerprint] = true
		}
		if a.first.IsZero() || e.When.Before(a.first) {
			a.first = e.When
		}
		if e.When.After(a.last) {
			a.last = e.When
		}
	}

	docs := make([]campaignDoc, 0, len(groups))
	for cidr, a := range groups {
		alerts := 0
		for ip := range a.ips {
			alerts += alertCounts[ip]
		}
		score := min(100, min(a.events, 30)+len(a.sensors)*15+len(a.ips)*3+len(a.creds)*8+len(a.payloads)*20+min(alerts, 15)*2+len(a.fingerprints)*3+len(a.providers)*2)
		var why []string
		if len(a.sensors) > 1 {
			why = append(why, fmt.Sprintf("cross-sensor activity (%d)", len(a.sensors)))
		}
		if len(a.ips) > 1 {
			why = append(why, fmt.Sprintf("%d related source IPs", len(a.ips)))
		}
		if len(a.payloads) > 0 {
			why = append(why, fmt.Sprintf("%d shared payloads", len(a.payloads)))
		}
		if len(a.creds) > 0 {
			why = append(why, fmt.Sprintf("%d reused credentials", len(a.creds)))
		}
		if alerts > 0 {
			why = append(why, fmt.Sprintf("%d IDS alerts", alerts))
		}
		if len(a.fingerprints) > 0 {
			why = append(why, fmt.Sprintf("%d fingerprints", len(a.fingerprints)))
		}
		if len(why) == 0 {
			why = append(why, "repeated activity from one routable network")
		}
		docs = append(docs, campaignDoc{
			CIDR: cidr, Score: score, Events: a.events, UniqueIPs: len(a.ips),
			Sensors: setSlice(a.sensors), Ports: setSlice(a.ports),
			Creds: len(a.creds), Payloads: len(a.payloads), Alerts: alerts,
			Providers: setSlice(a.providers), Fingerprints: len(a.fingerprints),
			First: a.first.UTC().Format(time.RFC3339), Last: a.last.UTC().Format(time.RFC3339),
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

func setSlice(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
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

type clusterAgg struct {
	events       int
	ips, sensors map[string]bool
}

// correlateClusters mirrors dashboard/intelligence.go's clustersData: same
// >=2-unique-IP threshold to count as a cluster at all, same top-250 cap.
func correlateClusters(evs []corrEvent, now time.Time) []clusterDoc {
	groups := map[string]*clusterAgg{}
	add := func(kind, value, ip, sensor string) {
		value = strings.TrimSpace(value)
		if value == "" || ip == "" {
			return
		}
		key := kind + "\x00" + value
		a := groups[key]
		if a == nil {
			a = &clusterAgg{ips: map[string]bool{}, sensors: map[string]bool{}}
			groups[key] = a
		}
		a.events++
		a.ips[ip] = true
		a.sensors[sensor] = true
	}
	for _, e := range evs {
		add("fingerprint", e.Fingerprint, e.SrcIP, e.Sensor)
		add("payload", e.Shasum, e.SrcIP, e.Sensor)
		if e.ASN != 0 {
			add("asn", fmt.Sprintf("AS%d %s", e.ASN, e.ASNOrg), e.SrcIP, e.Sensor)
		}
		add("provider", e.Provider, e.SrcIP, e.Sensor)
	}

	var docs []clusterDoc
	for key, a := range groups {
		if len(a.ips) < 2 {
			continue
		}
		kind, value, _ := strings.Cut(key, "\x00")
		docs = append(docs, clusterDoc{
			Kind: kind, Value: value, Events: a.events, Sources: len(a.ips),
			Sensors: setSlice(a.sensors), Generated: now.UTC().Format(time.RFC3339),
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
