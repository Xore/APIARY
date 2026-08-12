package main

import (
	"encoding/json"
	"net/http"
)

// attacker_fusion.go (#1280): attacker-identity-worker (#1200) merges IPs
// into one attackers-v1 entity when they share 2+ strong signals
// (fingerprint, payload SHA-256, credential pair) -- but the merge itself
// is invisible on /attackers' entity panel today. An operator sees the
// result (N member IPs under one entity) with no visual trace of WHY --
// which signals actually matched, and how strongly. This computes, per
// signal category, how many distinct values are shared by 2+ of the
// entity's own member IPs -- direct visual evidence for the merge
// decision, categorized by which signal actually overlapped.
//
// Scoped to exactly the four signals the issue names: JA3/JA4 (#1275,
// wire-level fingerprints now queryable independent of alert status),
// p0f OS (#1277), SSH client banner, and payload hashes -- not every
// FingerKind this codebase tracks (HASSH/User-Agent/JA4H/SSH pubkey stay
// out, keeping the radar's axis count readable).
var attackerFusionCategories = []string{"JA3", "JA4", "p0f OS", "SSH client", "Payload hash"}

// attackerFusionResult is ECharts' own radar-series shape once reshaped
// client-side: one value per category, computed from the already-cached
// s.getEvents() the same way #1279's anomaly trend reads it -- no new ES
// query, this entity's own member IPs already appear in the in-memory
// event cache.
type attackerFusionResult struct {
	Categories []string `json:"categories"`
	Values     []int    `json:"values"`
	IPs        []string `json:"ips"`
}

// attackerFingerprintFusion counts, per category, how many distinct signal
// values are exhibited by 2 or more of ips -- a value seen from only one
// member IP is real telemetry but not evidence this specific merge was
// justified, so it doesn't count toward the fusion score.
func (s *store) attackerFingerprintFusion(ips []string) attackerFusionResult {
	ipSet := make(map[string]bool, len(ips))
	for _, ip := range ips {
		ipSet[ip] = true
	}

	// category -> signal value -> set of member IPs that exhibited it
	seenBy := make(map[string]map[string]map[string]bool, len(attackerFusionCategories))
	for _, c := range attackerFusionCategories {
		seenBy[c] = map[string]map[string]bool{}
	}
	record := func(category, value, ip string) {
		if seenBy[category][value] == nil {
			seenBy[category][value] = map[string]bool{}
		}
		seenBy[category][value][ip] = true
	}

	for _, ev := range s.getEvents() {
		if !ipSet[ev.SrcIP] {
			continue
		}
		if ev.Fingerprint != "" {
			if _, tracked := seenBy[ev.FingerKind]; tracked {
				record(ev.FingerKind, ev.Fingerprint, ev.SrcIP)
			}
		}
		if ev.Shasum != "" {
			record("Payload hash", ev.Shasum, ev.SrcIP)
		}
	}

	values := make([]int, len(attackerFusionCategories))
	for i, c := range attackerFusionCategories {
		shared := 0
		for _, ipsForValue := range seenBy[c] {
			if len(ipsForValue) >= 2 {
				shared++
			}
		}
		values[i] = shared
	}
	return attackerFusionResult{Categories: attackerFusionCategories, Values: values, IPs: ips}
}

// serveAttackerFingerprintFusion answers /api/attacker-fusion?id=... (#1280),
// same id-lookup shape serveAttackerGraph already established for this
// entity/IP-driven, no-caching-at-this-scale read pattern.
func (s *store) serveAttackerFingerprintFusion(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" || s.es == nil {
		http.NotFound(w, r)
		return
	}
	rows, err := readAttackers(s.es)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	for i := range rows {
		if rows[i].ID != id {
			continue
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(s.attackerFingerprintFusion(rows[i].IPs))
		return
	}
	http.NotFound(w, r)
}
