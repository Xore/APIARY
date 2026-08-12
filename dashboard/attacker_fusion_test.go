package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAttackerFingerprintFusionCountsSharedSignalsOnly (#1280) pins the
// core rule: a signal value exhibited by 2+ member IPs counts (it's
// evidence supporting the merge); a value only one member IP exhibits
// does not, even though it's real telemetry for that IP.
func TestAttackerFingerprintFusionCountsSharedSignalsOnly(t *testing.T) {
	s := &store{events: []storedEvent{
		// Both member IPs share this exact JA4 hash -- real merge evidence.
		{SrcIP: "203.0.113.1", FingerKind: "JA4", Fingerprint: "t13d1312h2_shared"},
		{SrcIP: "203.0.113.2", FingerKind: "JA4", Fingerprint: "t13d1312h2_shared"},
		// Only 203.0.113.1 has this SSH client banner -- not shared.
		{SrcIP: "203.0.113.1", FingerKind: "SSH client", Fingerprint: "libssh2_1.11.1"},
		// Both share this payload hash.
		{SrcIP: "203.0.113.1", Shasum: "aaaa"},
		{SrcIP: "203.0.113.2", Shasum: "aaaa"},
		// An event from an IP NOT in this entity must not leak in.
		{SrcIP: "198.51.100.9", FingerKind: "JA4", Fingerprint: "t13d1312h2_shared"},
	}}

	result := s.attackerFingerprintFusion([]string{"203.0.113.1", "203.0.113.2"})
	want := map[string]int{"JA3": 0, "JA4": 1, "p0f OS": 0, "SSH client": 0, "Payload hash": 1}
	for i, cat := range result.Categories {
		if result.Values[i] != want[cat] {
			t.Errorf("category %q = %d, want %d", cat, result.Values[i], want[cat])
		}
	}
}

// TestAttackerFingerprintFusionIgnoresUntrackedFingerKinds covers HASSH/
// User-Agent/JA4H/SSH pubkey -- deliberately out of scope per the issue's
// own four-signal list, must not silently appear as a fifth/sixth axis.
func TestAttackerFingerprintFusionIgnoresUntrackedFingerKinds(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", FingerKind: "HASSH", Fingerprint: "shared-hassh"},
		{SrcIP: "203.0.113.2", FingerKind: "HASSH", Fingerprint: "shared-hassh"},
	}}
	result := s.attackerFingerprintFusion([]string{"203.0.113.1", "203.0.113.2"})
	if len(result.Categories) != 5 {
		t.Fatalf("expected exactly 5 categories, got %+v", result.Categories)
	}
	total := 0
	for _, v := range result.Values {
		total += v
	}
	if total != 0 {
		t.Fatalf("HASSH must not contribute to any tracked category, got values %+v", result.Values)
	}
}

func TestAttackerFingerprintFusionSingleIPHasNoSharedSignals(t *testing.T) {
	s := &store{events: []storedEvent{
		{SrcIP: "203.0.113.1", FingerKind: "JA4", Fingerprint: "solo"},
	}}
	result := s.attackerFingerprintFusion([]string{"203.0.113.1"})
	for i, v := range result.Values {
		if v != 0 {
			t.Fatalf("a single-IP entity must show no shared signals, category %q = %d", result.Categories[i], v)
		}
	}
}

func TestServeAttackerFingerprintFusion404sWithoutID(t *testing.T) {
	s := &store{}
	rec := httptest.NewRecorder()
	s.serveAttackerFingerprintFusion(rec, httptest.NewRequest("GET", "/api/attacker-fusion", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestServeAttackerFingerprintFusion404sWithoutES(t *testing.T) {
	s := &store{}
	rec := httptest.NewRecorder()
	s.serveAttackerFingerprintFusion(rec, httptest.NewRequest("GET", "/api/attacker-fusion?id=whatever", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestServeAttackerFingerprintFusionWritesRealData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hits":{"hits":[{"_id":"entity-1","_source":{"id":"entity-1","ips":["203.0.113.1","203.0.113.2"]}}]}}`))
	}))
	defer srv.Close()

	s := &store{
		es: newESClient(srv.URL, ""),
		events: []storedEvent{
			{SrcIP: "203.0.113.1", FingerKind: "JA4", Fingerprint: "shared"},
			{SrcIP: "203.0.113.2", FingerKind: "JA4", Fingerprint: "shared"},
		},
	}
	rec := httptest.NewRecorder()
	s.serveAttackerFingerprintFusion(rec, httptest.NewRequest("GET", "/api/attacker-fusion?id=entity-1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var result attackerFusionResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	found := false
	for i, c := range result.Categories {
		if c == "JA4" && result.Values[i] == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected JA4=1 in the result, got %+v", result)
	}
}
