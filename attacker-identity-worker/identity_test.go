package main

import (
	"testing"
	"time"
)

func obs(ip string, fp, payload, cred string, when time.Time) *ipObservation {
	o := &ipObservation{ip: ip, signals: newSignalSet(), sensors: map[string]bool{"cowrie": true}, first: when, last: when, events: 1}
	if fp != "" {
		o.signals.fingerprints[fp] = true
	}
	if payload != "" {
		o.signals.payloads[payload] = true
	}
	if cred != "" {
		o.signals.creds[cred] = true
	}
	return o
}

func TestSharedSignalCountCountsCategoriesNotValues(t *testing.T) {
	a := newSignalSet()
	a.fingerprints["fp1"] = true
	a.payloads["hash1"] = true
	b := newSignalSet()
	b.fingerprints["fp1"] = true
	b.payloads["hash1"] = true
	if got := sharedSignalCount(a, b); got != 2 {
		t.Fatalf("got %d, want 2", got)
	}

	// Only fingerprints overlap -- one category, must not meet the
	// 2-signal threshold even though it's a real match.
	c := newSignalSet()
	c.fingerprints["fp1"] = true
	if got := sharedSignalCount(a, c); got != 1 {
		t.Fatalf("got %d, want 1", got)
	}
}

func TestResolveIdentitiesMergesTwoNewIPsSharingTwoSignals(t *testing.T) {
	now := time.Now()
	observations := map[string]*ipObservation{
		"203.0.113.1":  obs("203.0.113.1", "shared-fp", "shared-hash", "", now),
		"198.51.100.1": obs("198.51.100.1", "shared-fp", "shared-hash", "", now),
	}
	changed, absorbed := resolveIdentities(nil, observations)
	if len(absorbed) != 0 {
		t.Fatalf("no existing entities, nothing should be absorbed: %+v", absorbed)
	}
	if len(changed) != 1 {
		t.Fatalf("expected both IPs merged into 1 entity, got %d: %+v", len(changed), changed)
	}
	if len(changed[0].IPs) != 2 {
		t.Fatalf("expected 2 member IPs, got %+v", changed[0].IPs)
	}
}

func TestResolveIdentitiesDoesNotMergeOnASingleSharedSignal(t *testing.T) {
	now := time.Now()
	observations := map[string]*ipObservation{
		"203.0.113.1":  obs("203.0.113.1", "shared-fp", "", "", now),
		"198.51.100.1": obs("198.51.100.1", "shared-fp", "", "", now),
	}
	changed, _ := resolveIdentities(nil, observations)
	if len(changed) != 2 {
		t.Fatalf("a single shared signal must not merge two IPs, got %d entities: %+v", len(changed), changed)
	}
}

func TestResolveIdentitiesAddsIPToExistingEntity(t *testing.T) {
	now := time.Now()
	existing := &entity{
		ID: "existing-1", IPs: []string{"203.0.113.1"},
		Fingerprints: []string{"shared-fp"}, Payloads: []string{"shared-hash"},
	}
	observations := map[string]*ipObservation{
		"198.51.100.1": obs("198.51.100.1", "shared-fp", "shared-hash", "", now),
	}
	changed, absorbed := resolveIdentities([]*entity{existing}, observations)
	if len(absorbed) != 0 {
		t.Fatalf("expected nothing absorbed: %+v", absorbed)
	}
	if len(changed) != 1 || changed[0].ID != "existing-1" {
		t.Fatalf("expected the existing entity's ID preserved, got %+v", changed)
	}
	if len(changed[0].IPs) != 2 {
		t.Fatalf("expected 2 member IPs after merge, got %+v", changed[0].IPs)
	}
}

func TestResolveIdentitiesGrowsExistingMemberIPWithNewSignals(t *testing.T) {
	now := time.Now()
	existing := &entity{
		ID: "existing-1", IPs: []string{"203.0.113.1"},
		Fingerprints: []string{"old-fp"},
	}
	// Same member IP reappearing with a brand new payload signal -- must
	// accumulate onto the SAME entity, not create a second one.
	observations := map[string]*ipObservation{
		"203.0.113.1": obs("203.0.113.1", "", "new-hash", "", now),
	}
	changed, _ := resolveIdentities([]*entity{existing}, observations)
	if len(changed) != 1 || changed[0].ID != "existing-1" {
		t.Fatalf("got %+v", changed)
	}
	if len(changed[0].Payloads) != 1 || changed[0].Payloads[0] != "new-hash" {
		t.Fatalf("expected the new payload signal recorded: %+v", changed[0])
	}
	if len(changed[0].Fingerprints) != 1 || changed[0].Fingerprints[0] != "old-fp" {
		t.Fatalf("expected the old fingerprint signal preserved: %+v", changed[0])
	}
}

func TestResolveIdentitiesMergesTwoExistingEntitiesViaBridgingIP(t *testing.T) {
	now := time.Now()
	entityA := &entity{ID: "entity-a", IPs: []string{"203.0.113.1"}, Fingerprints: []string{"fp-a"}, Payloads: []string{"hash-shared"}, First: "2026-08-01T00:00:00Z", Last: "2026-08-01T00:00:00Z", Events: 5}
	entityB := &entity{ID: "entity-b", IPs: []string{"198.51.100.1"}, Fingerprints: []string{"fp-b"}, Payloads: []string{"hash-shared"}, First: "2026-08-02T00:00:00Z", Last: "2026-08-02T00:00:00Z", Events: 7}

	// A new IP that shares fingerprint+payload with A AND fingerprint+
	// payload with B -- bridges both, so A and B must merge into one.
	bridging := obs("192.0.2.1", "fp-a", "hash-shared", "", now)
	bridging.signals.fingerprints["fp-b"] = true
	observations := map[string]*ipObservation{"192.0.2.1": bridging}

	changed, absorbed := resolveIdentities([]*entity{entityA, entityB}, observations)
	if len(absorbed) != 1 {
		t.Fatalf("expected exactly one entity absorbed, got %+v", absorbed)
	}
	if len(changed) != 1 {
		t.Fatalf("expected the survivor entity as the only changed entity, got %d: %+v", len(changed), changed)
	}
	survivor := changed[0]
	if len(survivor.IPs) != 3 {
		t.Fatalf("expected all 3 IPs (A's, B's, bridging) on the survivor, got %+v", survivor.IPs)
	}
	if survivor.Events != 5+7+1 {
		t.Fatalf("expected event counts summed across the merge, got %d", survivor.Events)
	}
}

func TestResolveIdentitiesLeavesUntouchedEntitiesOutOfChanged(t *testing.T) {
	untouched := &entity{ID: "quiet-entity", IPs: []string{"203.0.113.99"}, Fingerprints: []string{"some-fp"}}
	observations := map[string]*ipObservation{
		"198.51.100.1": obs("198.51.100.1", "unrelated-fp", "unrelated-hash", "", time.Now()),
	}
	changed, absorbed := resolveIdentities([]*entity{untouched}, observations)
	if len(absorbed) != 0 {
		t.Fatalf("expected nothing absorbed: %+v", absorbed)
	}
	for _, e := range changed {
		if e.ID == "quiet-entity" {
			t.Fatal("an entity with no matching observation this cycle must not be rewritten")
		}
	}
}

func TestResolveIdentitiesIsDeterministicAcrossRuns(t *testing.T) {
	now := time.Now()
	build := func() map[string]*ipObservation {
		return map[string]*ipObservation{
			"203.0.113.1":  obs("203.0.113.1", "fp1", "hash1", "", now),
			"198.51.100.1": obs("198.51.100.1", "fp1", "hash1", "", now),
			"192.0.2.1":    obs("192.0.2.1", "fp2", "hash2", "", now),
		}
	}
	changedA, _ := resolveIdentities(nil, build())
	changedB, _ := resolveIdentities(nil, build())
	if len(changedA) != len(changedB) {
		t.Fatalf("non-deterministic entity count: %d vs %d", len(changedA), len(changedB))
	}
}
