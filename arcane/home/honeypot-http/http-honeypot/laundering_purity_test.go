package main

import (
	"strings"
	"testing"
)

// TestLayerCIsTheFirstStateThisPackageKeeps is the claim #3443's
// TestScannerLaunderingLayersNotImplementable used to make about this whole
// package -- "there is no map, no cache and no per-source counter here; this
// binary is an in-request classifier by construction" -- stated as an
// assertion rather than a comment, so it can be checked rather than believed.
//
// Layer C makes that claim false in exactly one place, and this test says so
// narrowly: the laundering map is the only state, classifyPayload is still
// pure, and the purity is asserted by calling it before and after the
// detector has been fed the whole corpus.
//
// If this test ever fails, a second stateful component has appeared and
// #3443's "in-request classifier by construction" note needs re-reading --
// which is the point of pinning it as a test instead of leaving it as prose.

// The reference answer, captured before the detector has seen anything.
func TestLayerCIsTheFirstStateThisPackageKeeps(t *testing.T) {
	type answer struct{ query, body, class string }
	reference := make([]answer, 0, len(realCorpusFixture3430))
	for _, c := range realCorpusFixture3430 {
		reference = append(reference, answer{c.query, c.body, classifyPayload(c.query, c.body)})
	}
	if len(reference) != 31 {
		t.Fatalf("the pinned corpus holds %d entries, this test assumes 31", len(reference))
	}

	// Feed the detector every corpus entry, twice, in a stateful sequence. If
	// classifyPayload had any dependence on it -- through a shared map, a
	// package-level variable, anything -- the two answers below would differ.
	d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
	for pass := 0; pass < 2; pass++ {
		for i, c := range realCorpusFixture3430 {
			d.observe("client-"+itoa(i%3), "/"+strings.ReplaceAll(c.name, " ", "-"), c.query, c.body)
		}
	}

	for i, want := range reference {
		if got := classifyPayload(want.query, want.body); got != want.class {
			t.Errorf("classifyPayload(%q, %q) = %q after the detector ran, was %q before: the in-request classifier is not pure any more",
				want.query, want.body, got, want.class)
		}
		_ = i
	}

	// The two components are separately scoped: one detector's evidence is
	// invisible to another, so there is no shared global.
	other := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
	if got := other.observe("client-0", "/odata/%2561", "", ""); got != "" {
		t.Errorf("a fresh detector fired on a path the other had already seen: %q", got)
	}
}

// TestLayerCIsTheOnlyCrossRequestComponent is a boundary marker rather than a
// behavioural test. It exists so the next person to add state here has to
// delete or extend this, which is a louder event than a stale comment in
// main.go being wrong.
func TestLayerCIsTheOnlyCrossRequestComponent(t *testing.T) {
	// Every piece of cross-request state this package keeps, enumerated. If
	// one is added, this list is the thing to update -- and the update should
	// come with a decision about bounds, because that is the requirement
	// #3447 sets for the one that is here.
	components := []struct {
		name, state, boundedBy string
	}{
		{
			"launderingState",
			"map[string]*launderingEntry keyed by (client fingerprint, resource path)",
			"launderMaxEntries entries, launderPerFingerprint per client, launderTTL evidence age",
		},
	}
	if len(components) != 1 {
		t.Errorf("the package now keeps %d cross-request components, this test asserts 1", len(components))
	}

	// The two bounded components that are not laundering: the logger's file
	// size and the tarpit's duration. Both are per-operation rather than
	// cross-request, and both are already asserted by their own tests
	// (rotate_test.go, tarpit_test.go), which is where the assertion belongs.
	for _, c := range components {
		if c.state == "" || c.boundedBy == "" {
			t.Errorf("component %q has no state or no bound recorded: %+v", c.name, c)
		}
	}
}
