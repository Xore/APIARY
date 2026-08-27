package main

import (
	"testing"
	"time"
)

func obs(ip string, fp, payload, cred string, when time.Time) *ipObservation {
	o := &ipObservation{ip: ip, signals: newSignalSet(), sensors: map[string]bool{"cowrie": true}, techniques: map[string]bool{}, first: when, last: when, events: 1}
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

// withTechniques mutates o's techniques set in place and returns it, so a
// call site reads as withTechniques(obs(...), "T1110") rather than
// threading a sixth positional arg through every existing obs() call.
func withTechniques(o *ipObservation, ids ...string) *ipObservation {
	for _, id := range ids {
		o.techniques[id] = true
	}
	return o
}

// TestResolveIdentitiesFoldsTechniquesIntoNewEntity (#1260): a brand new
// entity's Techniques field must carry forward whatever ATT&CK IDs its
// founding observation(s) brought in -- attacker-identity-worker's own
// durable coverage document, not just a per-request computation.
func TestResolveIdentitiesFoldsTechniquesIntoNewEntity(t *testing.T) {
	now := time.Now()
	observations := map[string]*ipObservation{
		"203.0.113.1":  withTechniques(obs("203.0.113.1", "shared-fp", "shared-hash", "", now), "T1110", "T1059"),
		"198.51.100.1": withTechniques(obs("198.51.100.1", "shared-fp", "shared-hash", "", now), "T1105"),
	}
	changed, _ := resolveIdentities(nil, observations)
	if len(changed) != 1 {
		t.Fatalf("expected both IPs merged into 1 entity, got %d: %+v", len(changed), changed)
	}
	want := []string{"T1059", "T1105", "T1110"} // sortedKeys' output order
	if got := changed[0].Techniques; !equalStrings(got, want) {
		t.Fatalf("Techniques = %+v, want %+v", got, want)
	}
}

// TestResolveIdentitiesGrowsExistingEntityTechniques (#1260): a member IP
// reappearing with a new technique must accumulate onto the entity's
// existing Techniques set, same as any other signal, and never drop a
// technique it already carried.
func TestResolveIdentitiesGrowsExistingEntityTechniques(t *testing.T) {
	now := time.Now()
	existing := &entity{ID: "existing-1", IPs: []string{"203.0.113.1"}, Techniques: []string{"T1110"}}
	observations := map[string]*ipObservation{
		"203.0.113.1": withTechniques(obs("203.0.113.1", "", "", "", now), "T1595"),
	}
	changed, _ := resolveIdentities([]*entity{existing}, observations)
	if len(changed) != 1 || changed[0].ID != "existing-1" {
		t.Fatalf("got %+v", changed)
	}
	want := []string{"T1110", "T1595"}
	if got := changed[0].Techniques; !equalStrings(got, want) {
		t.Fatalf("Techniques = %+v, want %+v", got, want)
	}
}

// TestMergeEntityIntoMergesTechniques (#1260): when two previously-
// separate entities merge (a bridging IP shares 2+ signals with both),
// the surviving entity's Techniques must be the union of both, not just
// the one it started with.
func TestMergeEntityIntoMergesTechniques(t *testing.T) {
	a := &entity{ID: "a", Techniques: []string{"T1110"}}
	b := &entity{ID: "b", Techniques: []string{"T1595"}}
	mergeEntityInto(a, b)
	finalizeEntity(a)
	want := []string{"T1110", "T1595"}
	if got := a.Techniques; !equalStrings(got, want) {
		t.Fatalf("Techniques = %+v, want %+v", got, want)
	}
}

// TestAbsorbOrdersByInstantOffUTCTimezone (#2341): with the process
// running somewhere other than UTC, the pre-fix code compared o.first's
// LOCAL RFC3339 rendering straight against the stored string -- an
// observation whose instant was genuinely earlier looked string-later and
// lost the first-seen ranking. Ranking must be decided on instants, and
// whatever we adopt must still land as pure-Z UTC.
func TestAbsorbOrdersByInstantOffUTCTimezone(t *testing.T) {
	zone := time.FixedZone("TEST+1000", 10*60*60)
	prev := time.Local
	time.Local = zone
	defer func() { time.Local = prev }()

	seen := &entity{ID: "identity-a", IPs: []string{"203.0.113.1"}, First: "2026-08-10T23:00:00Z"}

	// Renders locally as 2026-08-11T06:00:00+10:00, which string-sorts
	// AFTER the stored stamp, yet its instant (20:00Z) is two hours
	// EARLIER than 23:00Z.
	at := time.Date(2026, 8, 11, 6, 0, 0, 0, zone)
	if got := at.Format(time.RFC3339); got != "2026-08-11T06:00:00+10:00" {
		t.Fatalf("premise check failed: local render %q", got)
	}

	absorb(seen, obs("203.0.113.1", "fp-shared", "", "", at))
	if want := "2026-08-10T20:00:00Z"; seen.First != want {
		t.Fatalf("First = %q, want %q (the earlier instant wins even off-UTC)", seen.First, want)
	}
}

// TestAbsorbIgnoresLaterInstantAgainstMixedOffsetStoredStamp (#2341): a
// legacy document may carry a non-Z offset; its rendered string sorts
// independently of its instant, so only instant comparison keeps the real
// earliest-seen intact when a later observation arrives.
func TestAbsorbIgnoresLaterInstantAgainstMixedOffsetStoredStamp(t *testing.T) {
	stored := &entity{ID: "identity-b", First: "2026-08-11T02:00:00+11:00"} // = 2026-08-10T15:00:00Z

	later := time.Date(2026, 8, 10, 16, 0, 0, 0, time.UTC)
	absorb(stored, obs("203.0.113.7", "fp-x", "", "", later))
	if stored.First != "2026-08-11T02:00:00+11:00" {
		t.Fatalf("First = %q, want the stored stamp kept (16:00Z is LATER than its 15:00Z instant)", stored.First)
	}

	earlier := time.Date(2026, 8, 10, 14, 0, 0, 0, time.UTC)
	absorb(stored, obs("203.0.113.7", "fp-x", "", "", earlier))
	if want := "2026-08-10T14:00:00Z"; stored.First != want {
		t.Fatalf("First = %q, want %q (an actually-earlier instant still replaces it)", stored.First, want)
	}
}

// TestMergeEntityIntoPicksInstantsAcrossOffsets (#2341): mergeEntityInto
// compares stamps pulled from two stored documents; with mixed offsets a
// really-earlier First (or really-later Last) can render in a string that
// sorts the wrong way. The survivor must adopt by instant, re-rendered
// through UTC().
func TestMergeEntityIntoPicksInstantsAcrossOffsets(t *testing.T) {
	a := &entity{ID: "a", First: "2026-08-03T00:00:00Z"}
	b := &entity{ID: "b", First: "2026-08-03T03:00:00+05:00"} // = 2026-08-02T22:00:00Z -- earlier instant, later-rendered string
	mergeEntityInto(a, b)
	if want := "2026-08-02T22:00:00Z"; a.First != want {
		t.Fatalf("a.First = %q, want %q", a.First, want)
	}

	c := &entity{ID: "c", Last: "2026-08-05T20:00:00Z"}
	d := &entity{ID: "d", Last: "2026-08-06T05:00:00+11:00"} // = 2026-08-05T18:00:00Z -- earlier instant, later-rendered string
	mergeEntityInto(c, d)
	if c.Last != "2026-08-05T20:00:00Z" {
		t.Fatalf("c.Last = %q, want it kept (d's instant is EARLIER though its string renders later)", c.Last)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
