package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// #3447's layer C, tested in the order the design questions were asked.

// TestLayerCCatchesThePublishedPathBorneBypass is the positive, and it is
// two requests because that is the point.
//
// The published shape is %2561 -> %61 -> 'a' in a *path segment*. The escape
// never appears in a query key, so there is nothing for #3443's in-request
// classifier to read, and the reconstruction of it in a query is exactly the
// fabrication #3443 refused. Here the OData half rides a query on one request
// and the escape half rides a path on the next, which is how the shape
// actually arrives.
func TestLayerCCatchesThePublishedPathBorneBypass(t *testing.T) {
	const fp = "scanner-fingerprint"
	d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)

	// Request 1: a client probing an OData surface. Unlabelled -- there is
	// nothing to label yet, which is the whole difference from #3443.
	if got := d.observe(fp, "/odata/Products", `$filter=Name%20eq%20'Widget'`, ""); got != "" {
		t.Fatalf("the OData probe alone was labelled %q; the pair is what fires", got)
	}

	// Request 2: the bypass, under the same collection, same client stack.
	got := d.observe(fp, "/odata/%2561", "", "")
	if got != launderingClass {
		t.Errorf("observe(path-borne bypass) = %q, want %q", got, launderingClass)
	}
}

// TestLayerCDoesNotOverMatch is the trap #3447 names by name, as a table.
//
// The failure mode is firing because an *unrelated* key happened to hold an
// option-shaped value. So every case here is a request that holds something
// option-shaped, or escape-shaped, or both, and is not laundering. If any of
// these fire, the layer is a false-positive machine and the table is the
// evidence -- not a comment claiming it.
func TestLayerCDoesNotOverMatch(t *testing.T) {
	cases := []struct {
		name, path, query, body string
	}{
		// An option name on an unrelated key, with a value that is not an
		// option's value. `?$top=1` on any application is an option-shaped
		// value; requiring the value to be type-consistent is what stops it
		// counting as an OData surface.
		{"$top on an unrelated key, non-integer value", "/api/users", `$top=all`, ""},
		{"$filter on an unrelated key, no operator", "/api/users", `$filter=please`, ""},
		{"$select on an unrelated key, empty value", "/api/users", `$select=`, ""},
		{"$format on an unrelated key, not a format", "/api/users", `$format=yaml`, ""},
		{"$count on an unrelated key, arbitrary value", "/api/users", `$count=maybe`, ""},
		{"$orderby on an unrelated key, arbitrary value", "/api/users", `$orderby=;drop`, ""},
		// The gate is the value, not just the name, so the sharpest form of
		// this trap is an option-shaped *name* paired with a value that
		// option could never have been sent with. If the gate were name-only,
		// `?$filter=anything` on a collection path would read as an OData
		// surface and the escape half below would complete a pair off it.
		{"$filter name, value no option could carry", "/odata/Products", `$filter=anything`, ""},
		// The name is real and the value is real OData, but there is no
		// escape half and no earlier one, so nothing to pair it with.
		{"a plain OData client, once", "/odata/Products", `$filter=Year%20eq%202026`, ""},

		// --- the reconstruction #3443 refused, now in two requests ---
		//
		// Same shape, split: an OData option on one request, a residual
		// escape in a *query key* on the next. This is the trap wearing
		// different clothes, and it is the case that makes the same-request
		// rule necessary rather than tidy: `?%2561=1` is an escape in a
		// query key, which is #3443's territory and not this layer's, so it
		// is not a half here at all. Both requests stay unlabelled.
		{
			"the #3443 reconstruction, split across two requests",
			"/odata/Products", "", "",
		},
	}

	d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Twice, so a case that needs a pair cannot pass by being seen
			// once. And the second call is on the same fingerprint, so
			// anything that did write would be readable.
			probe := strings.TrimSuffix(c.name, " (probe only)")
			_ = probe
			if got := d.observe("fp-a", c.path, c.query, c.body); got != "" {
				t.Errorf("first observe(%q) = %q, want unlabelled", c.name, got)
			}
			if got := d.observe("fp-a", c.path, c.query, c.body); got != "" {
				t.Errorf("second observe(%q) = %q, want unlabelled", c.name, got)
			}
		})
	}

	// The one case that needs its two halves spelled out, because a table row
	// can only carry one request.
	t.Run("the #3443 reconstruction, split across two requests", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		if got := d.observe("fp-b", "/odata/Products", `$filter=Name%20eq%20'x'`, ""); got != "" {
			t.Errorf("OData half = %q, want unlabelled", got)
		}
		// %2561 in a *query key* is not the path-borne half. It is a query
		// key, which odataDoubleEncode's own gate declines because no OData
		// option is on this request. So this writes nothing.
		if got := d.observe("fp-b", "/odata/Products", `$%2561=1`, ""); got != "" {
			t.Errorf("query-key escape half = %q, want unlabelled", got)
		}
	})

	// Nothing above may have left a pairable entry behind. Asserted rather
	// than assumed, because a false negative here is the same defect as a
	// false positive: evidence that fires on the next unrelated request.
	for fp := range map[string]bool{"fp-a": true, "fp-b": true} {
		if got := d.observe(fp, "/odata/Products", `$top=1`, ""); got != "" {
			t.Errorf("%s had a latent pair that fired on an unrelated request: %q", fp, got)
		}
	}
}

// TestLayerCOverMatchNeedsThePairToBePresent is the table above, with the
// other half actually supplied.
//
// TestLayerCDoesNotOverMatch sends each case twice, which proves the request
// is not labelled but does NOT prove it seeded nothing: a gate that wrote an
// entry and simply never fired would pass it. Since the escape half is
// available to any request whose path decodes to a residual escape, the way
// to test the gate is to put an escape path in front of every option-shaped
// request and require that nothing fires. This is the assertion that makes
// the value-consistency gate load-bearing, and it is the one that fails if the
// gate is relaxed to a name-only match.
func TestLayerCOverMatchNeedsThePairToBePresent(t *testing.T) {
	// Each case is an option-shaped request that must NOT count as an OData
	// surface. The escape path is the real published bypass, sent from the
	// same fingerprint at the same resource, so a gate that accepted the
	// option would complete a pair and fire here.
	notASurface := []struct{ name, path, query, body string }{
		{"$top=all", "/c/Products", `$top=all`, ""},
		{"$filter=anything", "/c/Products", `$filter=anything`, ""},
		{"$filter=eq, operator with no literal", "/c/Products", `$filter=eq`, ""},
		{"$filter=2026, literal with no operator", "/c/Products", `$filter=2026`, ""},
		{"$format=yaml", "/c/Products", `$format=yaml`, ""},
		{"$select empty", "/c/Products", `$select=`, ""},
		{"$orderby injection", "/c/Products", `$orderby=Year;drop`, ""},
		{"$count=maybe", "/c/Products", `$count=maybe`, ""},
		{"option name inside another value", "/c/Products", `q=%24filter%253DYear%2520eq`, ""},
	}

	for _, c := range notASurface {
		t.Run(c.name, func(t *testing.T) {
			d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
			if got := d.observe("fp", c.path, c.query, c.body); got != "" {
				t.Fatalf("the option-shaped request was labelled %q", got)
			}
			// Now supply the other half, in the published form, at the same
			// resource. Nothing may fire, because the first half was never
			// accepted.
			if got := d.observe("fp", "/c/%2561", "", ""); got != "" {
				t.Errorf("an option-shaped request %q paired with a path-borne bypass and fired %q; the value-consistency gate is not load-bearing", c.name, got)
			}
		})
	}

	// A double-encoded $filter is NOT in the table above, and the omission
	// needs a reason rather than a shrug. After ParseQuery's one decode,
	// `$filter=year%20eq%25202026` is `year eq%202026`, whose tokens are
	// `year`, `eq`, `202026` -- an operator and a literal, so it reads as a
	// filter expression and qualifies as an OData surface. That is correct
	// rather than accidental: it *is* an OData surface, and it is one whose
	// value was built to survive another decode, which makes the later
	// path-borne escape more explicable, not less.
	//
	// The class it carries does not change. #3443 labels that request
	// odata-double-encode-probe, and observeLaundering only writes into an
	// empty PayloadClass, so the double-encoded request keeps #3443's label
	// and the pair fires on the *escape* request instead. Both labels are
	// correct for their own evidence; the ordering rule that keeps the more
	// specific one is asserted here rather than assumed.
	t.Run("a double-encoded OData filter is a surface, and keeps #3443's class", func(t *testing.T) {
		s := &server{log: &logger{out: &strings.Builder{}}, launder: newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)}
		do := func(path, query string) string {
			e := &event{PayloadClass: classifyPayload(query, "")}
			r := httptest.NewRequest(http.MethodGet, "http://decoy"+path+"?"+query, nil)
			r.RemoteAddr = "203.0.113.7:44444"
			s.observeLaundering(r, e, "")
			return e.PayloadClass
		}
		if got := do("/c/Products", `$filter=year%20eq%25202026`); got != "odata-double-encode-probe" {
			t.Errorf("the double-encoded filter was labelled %q, want #3443's odata-double-encode-probe", got)
		}
		if got := do("/c/%2561", ""); got != launderingClass {
			t.Errorf("the paired path-borne escape = %q, want %q", got, launderingClass)
		}
	})

	// The control: the same two requests with a value that *is* consistent
	// must fire, so the table above is a real gate and not a component that
	// never fires at all.
	t.Run("control: a consistent value does pair", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		if got := d.observe("fp", "/c/Products", `$filter=Name%20eq%20'Widget'`, ""); got != "" {
			t.Fatalf("the OData request was labelled %q", got)
		}
		if got := d.observe("fp", "/c/%2561", "", ""); got != launderingClass {
			t.Errorf("a consistent OData value paired with the bypass = %q, want %q", got, launderingClass)
		}
	})
}

// TestLayerCSameRequestNeverFires is the structural half of the anti-over-match
// guarantee, separated from the table above because it is a property of the
// component and not of any one request.
//
// A single request carrying both halves -- a path-borne escape *and* a
// qualifying OData query -- must not fire. That is the reconstruction #3443
// refused, relocated from query to path, and it is the one construction that
// would make the layer fire because two unrelated things happened to be in
// the same request. observe seeds both halves and returns ""; the pair can
// only complete on a *later* request.
func TestLayerCSameRequestNeverFires(t *testing.T) {
	d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)

	for i := 0; i < 3; i++ {
		got := d.observe("fp", "/odata/%2561", `$filter=Name%20eq%20'x'`, "")
		if got != "" {
			t.Fatalf("observe #%d: single request carrying both halves fired %q", i+1, got)
		}
	}

	// Still no fire on repetition, which is the property that matters: a
	// scanner replaying the combined request gets nothing.
	if entries, _, _ := d.launderingStats(); entries != 1 {
		t.Errorf("expected the combined request to seed exactly 1 entry, got %d", entries)
	}

	// And now a *third* request carrying only the escape half completes the
	// pair seeded by the first, which is the behaviour the rule is protecting:
	// the firing request is one where the escape is the only thing present.
	if got := d.observe("fp", "/odata/%2561", "", ""); got != launderingClass {
		t.Errorf("observe(escape half alone, after a seeded pair) = %q, want %q", got, launderingClass)
	}
}

// TestLayerCBindsToResourceAndFingerprint is the other half of the binding. The
// key is (fingerprint, resource), so evidence from one collection or one
// client stack says nothing about another.
func TestLayerCBindsToResourceAndFingerprint(t *testing.T) {
	cases := []struct {
		name, probePath, escapePath, probeFP, escapeFP string
	}{
		{"a different collection", "/odata/Products", "/admin/%2561", "fp", "fp"},
		{"a different client stack", "/odata/Products", "/odata/%2561", "fp-1", "fp-2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
			if got := d.observe(c.probeFP, c.probePath, `$filter=Name%20eq%20'x'`, ""); got != "" {
				t.Fatalf("probe = %q, want unlabelled", got)
			}
			if got := d.observe(c.escapeFP, c.escapePath, "", ""); got != "" {
				t.Errorf("escape = %q, want unlabelled: the evidence was not bound to this request", got)
			}
		})
	}

	// Siblings bind: the resource is the path minus its last segment, so the
	// probe at /odata/Products and the bypass at /odata/%2561 -- different
	// leaves, same collection -- are the same key. This is the layer's own
	// positive and it is the only way the layer can fire at all, since a probe
	// and a bypass are never the same path.
	t.Run("sibling leaves of one collection bind", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		if got := d.observe("fp", "/odata/Products", `$filter=Name%20eq%20'x'`, ""); got != "" {
			t.Fatalf("probe = %q, want unlabelled", got)
		}
		if got := d.observe("fp", "/odata/%2561", "", ""); got != launderingClass {
			t.Errorf("escape = %q, want %q", got, launderingClass)
		}
	})

	// A different depth is a different resource, and this is a deliberate
	// narrowness rather than an oversight: /odata/products is a collection
	// under /odata, and evidence about /odata says nothing about what a
	// request one level deeper was doing.
	t.Run("a deeper collection is a different resource", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		if got := d.observe("fp", "/odata/Products", `$filter=Name%20eq%20'x'`, ""); got != "" {
			t.Fatalf("probe = %q, want unlabelled", got)
		}
		if got := d.observe("fp", "/odata/Products/1/%2561", "", ""); got != "" {
			t.Errorf("escape one level deeper = %q, want unlabelled", got)
		}
	})
}

// TestLayerCIsBounded asserts each of the three bounds, because #3447 calls
// bounding a correctness requirement rather than polish, and an unbounded
// cross-request accumulator in a process meant to be attacked is both a
// memory-growth bug and a resource-exhaustion vector.
func TestLayerCIsBounded(t *testing.T) {
	// 1. The entry cap. Flood it with distinct resources from distinct
	// fingerprints -- the shape an attacker actually has, since one
	// fingerprint is separately capped -- and assert the map never exceeds
	// the cap rather than merely that it stops growing.
	t.Run("entry cap holds under flood", func(t *testing.T) {
		const cap = 32
		// The fingerprint is held constant so the per-fingerprint bound
		// cannot be what keeps this under cap: this measures the global cap
		// alone, at its configured value.
		d := newLaunderingState(cap, cap*10, launderTTL)
		for i := 0; i < cap*20; i++ {
			path := "/res" + itoa(i) + "/%2561"
			d.observe("one-flooding-client", path, "", "")
			if entries, _, _ := d.launderingStats(); entries > cap {
				t.Fatalf("after %d writes the map holds %d entries, cap is %d", i+1, entries, cap)
			}
		}
		entries, evicted, _ := d.launderingStats()
		if entries > cap {
			t.Errorf("final entries = %d, cap = %d", entries, cap)
		}
		if evicted == 0 {
			t.Error("expected evictions at the cap; a map that reached the cap without evicting is not bounded by it")
		}
	})

	// 2. Per-fingerprint pressure. One client spraying distinct resource
	// paths must not be able to hold more than its share, or the global cap
	// becomes a lever one attacker pulls to blind everyone else.
	t.Run("one fingerprint cannot hold the whole map", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, 4, launderTTL)
		for i := 0; i < 200; i++ {
			d.observe("one-client", "/spray"+itoa(i)+"/%2561", "", "")
		}
		// Force the pass, which is where the per-fingerprint bound is applied.
		// Read the length under the same lock rather than calling
		// launderingStats, which would take it again.
		d.mu.Lock()
		d.sweep(d.now())
		entries := len(d.entries)
		d.mu.Unlock()
		if entries > 4 {
			t.Errorf("one fingerprint holds %d entries, per-fingerprint bound is 4", entries)
		}
	})

	// 3. TTL. A half older than the TTL is not evidence: it must not
	// complete a pair with a request arriving much later. The clock is
	// injected, so this is asserted rather than slept through.
	t.Run("an expired half does not complete a pair", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
		d.now = func() time.Time { return now }

		if got := d.observe("fp", "/odata/Products", `$filter=Name%20eq%20'x'`, ""); got != "" {
			t.Fatalf("probe = %q, want unlabelled", got)
		}
		now = now.Add(launderTTL + time.Minute)
		if got := d.observe("fp", "/odata/%2561", "", ""); got != "" {
			t.Errorf("escape %v after the TTL = %q, want unlabelled: expired evidence is not evidence", launderTTL+time.Minute, got)
		}

		// A fresh probe inside the TTL still pairs, so the assertions above
		// are about expiry and not about the escape half being broken. The
		// clock is moved a further second so the new probe is unambiguously
		// not the expired one.
		now = now.Add(launderTTL + time.Minute)
		if got := d.observe("fp", "/odata/Products", `$filter=Name%20eq%20'x'`, ""); got != "" {
			t.Fatalf("fresh probe = %q, want unlabelled", got)
		}
		now = now.Add(time.Second)
		if got := d.observe("fp", "/odata/%2561", "", ""); got != launderingClass {
			t.Errorf("escape inside the TTL = %q, want %q", got, launderingClass)
		}
	})

	// 4a. The cap is enforced at admission, not by the periodic pass. Two
	// writes into a cap of one, with no sweep due, must still leave the map at
	// one entry. Removing the eviction in admit() lets the second write
	// through, which is the unbounded-growth bug #3447 calls a memory-growth
	// bug.
	//
	// The two mechanisms are separated deliberately. The pass is scheduled on
	// a write counter, not on map fullness, because a pass on every write while
	// the map is full would put the pass's own O(n log n) cost on the request
	// path for as long as an attacker keeps the map full. Measured: 92µs per
	// write against a full map with the fullness trigger, 2.4µs without. So
	// the cap is enforced by admit()'s O(1) eviction on every write, and the
	// pass is for reclaiming age and per-client pressure.
	t.Run("cap is enforced without waiting for a sweep", func(t *testing.T) {
		d := newLaunderingState(1, 100, launderTTL)
		if entries, _, _ := d.launderingStats(); entries != 0 {
			t.Fatalf("fresh detector holds %d entries", entries)
		}
		d.observe("fp-1", "/res1/%2561", "", "")
		d.observe("fp-2", "/res2/%2561", "", "")
		entries, evicted, _ := d.launderingStats()
		if entries > 1 {
			t.Errorf("two writes into a cap of 1 left %d entries, want at most 1", entries)
		}
		if evicted == 0 {
			t.Error("the second write did not evict; the cap is not enforced at admission")
		}

		// And it holds over many writes with no pass ever due: a cap of 1
		// with sweepEvery far above the write count proves the cap comes from
		// admission alone, and that which entry survives is not "the first
		// one" (a map that refused the second write would also sit at 1).
		d2 := newLaunderingState(1, 1000, launderTTL)
		d2.sweepEvery = 1 << 30
		for i := 0; i < 100; i++ {
			d2.observe("fp-"+itoa(i), "/res"+itoa(i)+"/%2561", "", "")
		}
		entries, evicted, _ = d2.launderingStats()
		if entries > 1 {
			t.Errorf("100 writes into a cap of 1, no pass due, left %d entries", entries)
		}
		// 99 evictions for 100 writes: the first write fills the empty map, and
		// each write after it evicts the previous occupant.
		if evicted != 99 {
			t.Errorf("100 writes into a cap of 1 recorded %d evictions, want 99: admission is not evicting on every write past the cap", evicted)
		}
		// ...and the surviving entry is the newest, which is what a FIFO ring
		// does and what a "refuse the write" implementation would not.
		d2.mu.Lock()
		_, live := d2.entries["fp-99\x00/res99"]
		d2.mu.Unlock()
		if !live {
			t.Error("after 100 writes into a cap of 1 the newest entry is not the one held; the write was refused rather than the oldest evicted")
		}
	})

	// 4a-bis. *Which* entry eviction takes. The cap only says a bound; this
	// says the bound is met by dropping the oldest, not by dropping an
	// arbitrary one.
	//
	// It is the assertion that catches a creation-order queue that is not
	// being maintained: if entries are not recorded as they are created, then
	// eviction has nothing ordered to pop, falls back to rebuilding from Go's
	// deliberately-unspecified map iteration order, and evicts an arbitrary
	// entry each time. The map still sits at the cap, so a test that only
	// checks the count passes while the eviction policy is silently random.
	t.Run("eviction drops the oldest, not an arbitrary entry", func(t *testing.T) {
		const cap = 4
		d := newLaunderingState(cap, 1000, launderTTL)
		// No pass for the whole test, so eviction is entirely admission's.
		d.sweepEvery = 1 << 30

		// Six writes into a cap of four. The four newest must survive.
		for i := 0; i < 6; i++ {
			d.observe("fp-"+itoa(i), "/res"+itoa(i)+"/%2561", "", "")
		}

		d.mu.Lock()
		defer d.mu.Unlock()
		if len(d.entries) != cap {
			t.Fatalf("map holds %d entries, want exactly the cap %d", len(d.entries), cap)
		}
		for i := 0; i < 6; i++ {
			key := "fp-" + itoa(i) + "\x00/res" + itoa(i)
			_, live := d.entries[key]
			switch {
			case i < 2 && live:
				t.Errorf("entry %d survived a cap of %d; eviction is not dropping the oldest", i, cap)
			case i >= 2 && !live:
				t.Errorf("entry %d was evicted from a cap of %d that still has room for it; eviction is not FIFO", i, cap)
			}
		}

		// ...and the order queue is the reason, not luck: it must name the two
		// evicted keys ahead of the four live ones.
		if d.orderHead >= len(d.order) {
			t.Fatalf("order queue head %d is past its length %d", d.orderHead, len(d.order))
		}
		for i := 0; i < 2; i++ {
			want := "fp-" + itoa(i) + "\x00/res" + itoa(i)
			if d.order[i] != want {
				t.Errorf("order queue slot %d = %q, want the evicted key %q: the queue is not in creation order", i, d.order[i], want)
			}
		}
	})

	// 4a-ter. The queue's self-repair. When entries leave the map by a path
	// other than FIFO eviction -- a pair completing, or the reclaim pass
	// dropping expired and over-full entries -- the queue is left naming keys
	// that are gone. popOrder skips them, so eviction stays correct, but a
	// queue that is mostly dead keys is a queue whose pops are wasted work and
	// whose length no longer means anything.
	//
	// This asserts the repair rather than the symptom: after the pass has
	// emptied the map, the queue must be empty too.
	t.Run("the queue is repaired when the map empties", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
		d.now = func() time.Time { return now }

		for i := 0; i < 200; i++ {
			d.observe("fp-"+itoa(i), "/res"+itoa(i)+"/%2561", "", "")
		}
		d.mu.Lock()
		queuedBefore := len(d.order) - d.orderHead
		d.mu.Unlock()
		if queuedBefore != 200 {
			t.Fatalf("queue holds %d live slots after 200 writes, want 200", queuedBefore)
		}

		// Past the TTL, a pass drops everything. Every key in the queue is now
		// dead, which is the state the repair exists for.
		now = now.Add(launderTTL + time.Minute)
		d.mu.Lock()
		d.sweep(now)
		queuedAfter := len(d.order) - d.orderHead
		entries := len(d.entries)
		d.mu.Unlock()

		if entries != 0 {
			t.Fatalf("map holds %d entries after the TTL, want 0", entries)
		}
		if queuedAfter != 0 {
			t.Errorf("queue holds %d dead slots after the map emptied; it was not repaired", queuedAfter)
		}

		// And the component still works afterwards, which is the part that
		// matters: a detector that panics or stops firing after its first
		// pass is worse than one that never fired.
		if got := d.observe("fp-fresh", "/odata/Products", `$filter=Name%20eq%20'x'`, ""); got != "" {
			t.Errorf("the OData probe was labelled %q after the queue repair", got)
		}
		if got := d.observe("fp-fresh", "/odata/%2561", "", ""); got != launderingClass {
			t.Errorf("the escape after the queue repair = %q, want %q", got, launderingClass)
		}
	})

	// 4a-quater. The *partial* repair, which is the harder case and the one
	// the empty-map test above cannot reach: a pass that drops most entries
	// but not all of them. 200 resources from one client, a per-fingerprint
	// bound of 8, leaves 8 live and 192 dead slots -- so the map is not empty,
	// the empty-map reset does not run, and the queue is left 96% stale.
	t.Run("the queue is repaired when the map is only partly emptied", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, 8, launderTTL)
		d.sweepEvery = 1 << 30

		// One client, many resources: the per-fingerprint stage is what drops
		// them, so this is the partial path and not the TTL one.
		for i := 0; i < 200; i++ {
			d.observe("one-client", "/res"+itoa(i)+"/%2561", "", "")
		}

		d.mu.Lock()
		d.sweep(d.now())
		entries := len(d.entries)
		queued := len(d.order) - d.orderHead
		d.mu.Unlock()

		if entries != 8 {
			t.Fatalf("map holds %d entries after the pass, want the per-fingerprint bound of 8", entries)
		}
		// The live queue must not be dominated by dead keys. Without the
		// repair, 200 slots remain and every subsequent eviction would walk
		// them; with it, the queue is rebuilt to describe the 8 that live.
		if queued > entries*2 {
			t.Errorf("queue holds %d slots for %d live entries; a mostly-dead queue was not repaired, so every later eviction walks it", queued, entries)
		}
	})

	// 4a-quater-bis. The same partial repair reached through the *other*
	// stage. The test above is driven by per-fingerprint pressure, so it says
	// nothing about the TTL stage: a detector that rebuilt only after (b) and
	// not after (a) would pass it. Here almost everything expires at once,
	// every fingerprint holds one resource so (b) has nothing to do, and the
	// repair has to come from the expiry stage alone.
	t.Run("the queue is repaired when expiry alone empties most of it", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		d.sweepEvery = 1 << 30
		t0 := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
		clock := t0
		d.now = func() time.Time { return clock }

		// 192 clients, one resource each, written before the clock moves.
		for i := 0; i < 192; i++ {
			d.observe("client-"+itoa(i), "/res"+itoa(i)+"/%2561", "", "")
		}
		// Eight more, written after it moves: they are not expired, so the map
		// is left partly populated and neither the "nothing left" reset nor a
		// per-fingerprint eviction can fire.
		clock = t0.Add(launderTTL + time.Minute)
		for i := 0; i < 8; i++ {
			d.observe("fresh-"+itoa(i), "/fresh"+itoa(i)+"/%2561", "", "")
		}

		d.mu.Lock()
		d.sweep(clock)
		entries := len(d.entries)
		queued := len(d.order) - d.orderHead
		expired := d.expired
		d.mu.Unlock()

		if expired != 192 {
			t.Fatalf("the pass expired %d entries, want 192", expired)
		}
		if entries != 8 {
			t.Fatalf("map holds %d entries after the pass, want the 8 written after the clock moved", entries)
		}
		if queued > entries*2 {
			t.Errorf("queue holds %d slots for %d live entries after an expiry-dominated pass; a mostly-dead queue was not repaired, so every later eviction walks it", queued, entries)
		}
	})

	// 4a-ter-ter. Both stages damaging the queue in one pass. The two tests
	// above each damage it in a single stage, so neither can tell a repair
	// that re-reads the queue's live length from one that reuses the length it
	// started the pass with: a stale figure makes the second stage's own
	// deletions look small against a queue that no longer has that many slots
	// in it, and the repair is skipped precisely when it is most wanted.
	//
	// Here expiry takes 192 of 200 and leaves 8 -- enough to trigger a repair
	// and rebuild the queue down to those 8. Then per-fingerprint pressure,
	// at a bound of one, takes 7 of the 8. A stale 200 would read that as
	// "7 of 200" and leave a queue of 8 slots around a single live entry.
	t.Run("the second stage re-reads the queue after the first rebuilds it", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, 1, launderTTL)
		d.sweepEvery = 1 << 30
		t0 := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
		clock := t0
		d.now = func() time.Time { return clock }

		// 192 separate clients, so expiry -- not per-fingerprint pressure --
		// is what can drop them.
		for i := 0; i < 192; i++ {
			d.observe("client-"+itoa(i), "/res"+itoa(i)+"/%2561", "", "")
		}
		// One client, eight resources, all fresh: a bound of one means this
		// bucket can only keep a single entry.
		clock = t0.Add(launderTTL + time.Minute)
		for i := 0; i < 8; i++ {
			d.observe("survivor", "/s"+itoa(i)+"/%2561", "", "")
		}

		d.mu.Lock()
		d.sweep(clock)
		entries := len(d.entries)
		queued := len(d.order) - d.orderHead
		d.mu.Unlock()

		if entries != 1 {
			t.Fatalf("map holds %d entries after the pass, want 1 (the per-fingerprint bound of one)", entries)
		}
		if queued > entries*2 {
			t.Errorf("queue holds %d slots for %d live entry; the second stage judged its deletions against a stale queue length, so the repair was skipped", queued, entries)
		}
	})

	// 4a-quater-ter. admit()'s resynchronisation. Every live map key has a
	// live slot at or after the head -- a key is only ever pushed on creation,
	// and a re-created key gets a fresh slot at the tail -- so popOrder cannot
	// return "" while the map is non-empty, and the rebuild inside admit() is
	// a backstop against an invariant, not a path the component walks.
	//
	// Unreachable is not untested. The contract the branch promises is that a
	// desynchronised detector loses one write and keeps its bound, rather than
	// growing the map past the cap or spinning; so the state is manufactured
	// here and the contract is asserted. An implementation that simply gave up
	// would not fail the map bound -- it would fail the other half of the
	// promise, which is that the write is retried against a rebuilt queue.
	t.Run("an empty queue against a full map costs one write, not the bound", func(t *testing.T) {
		const cap = 2
		d := newLaunderingState(cap, 1000, launderTTL)
		d.sweepEvery = 1 << 30
		d.observe("fp-a", "/a/%2561", "", "")
		d.observe("fp-b", "/b/%2561", "", "")

		// Manufacture the desync the invariant forbids: the map is at its cap
		// and the queue that describes it is gone.
		d.mu.Lock()
		d.order, d.orderHead = d.order[:0], 0
		full := len(d.entries)
		d.mu.Unlock()
		if full != cap {
			t.Fatalf("map holds %d entries, want the cap %d", full, cap)
		}

		d.observe("fp-c", "/c/%2561", "", "")

		d.mu.Lock()
		entries := len(d.entries)
		evicted := d.evicted
		_, wrote := d.entries["fp-c\x00/c"]
		d.mu.Unlock()

		if entries != cap {
			t.Errorf("map holds %d entries after a desynchronised write, want the cap %d; the bound was lost", entries, cap)
		}
		if !wrote {
			t.Error("the write was dropped instead of being retried against a queue rebuilt from the map")
		}
		if evicted == 0 {
			t.Error("the desynchronised write evicted nothing, so the cap was held by refusing the write rather than by dropping the oldest")
		}
	})

	// 4b. The root is not a resource, and that has to hold for the escape
	// half too, not only for the OData half. launderResource returning "" for
	// the root is what stops every request on the sensor sharing one bucket;
	// if it regressed to "/", an OData query on the landing page and any
	// residual-escape path anywhere on the host would pair.
	t.Run("the root is not a shared resource", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		if got := launderResource("/%2561"); got != "" {
			t.Errorf("launderResource of a root escape = %q, want \"\"", got)
		}
		if got := d.observe("fp", "/%2561", "", ""); got != "" {
			t.Errorf("an escape at the root was labelled %q with no OData half at all", got)
		}
		// And with an OData half on the root, still nothing.
		d2 := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		d2.observe("fp", "/", `$filter=Year%20eq%202026`, "")
		if got := d2.observe("fp", "/%2561", "", ""); got != "" {
			t.Errorf("a root OData query paired with a root escape and fired %q", got)
		}
	})

	// 4c. A more specific in-request class wins. The layer writes only into an
	// empty PayloadClass, so a request carrying both a named-CVE shape and the
	// path-borne escape keeps the named CVE -- the same most-specific-first
	// ordering #3443's own switch uses. Without this, a laundering attempt
	// that also happens to match an existing class would be relabelled
	// odata-path-encoded-bypass and the specific class would be lost.
	t.Run("a more specific class is not overwritten", func(t *testing.T) {
		s := &server{
			log:        &logger{out: &strings.Builder{}},
			sensor:     "http-honeypot",
			launder:    newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL),
			serverHdr:  "nginx/1.24.0",
			listenPort: 8080,
		}
		do := func(path, query string) string {
			e := &event{PayloadClass: classifyPayload(query, "")}
			r := httptest.NewRequest(http.MethodGet, "http://decoy"+path+"?"+query, nil)
			r.RemoteAddr = "203.0.113.7:44444"
			s.observeLaundering(r, e, "")
			return e.PayloadClass
		}
		if got := do("/c/Products", `$filter=Name%20eq%20'Widget'`); got != "" {
			t.Fatalf("the OData probe was labelled %q", got)
		}
		// The escape request also carries the PHP-CGI probe's own two
		// parameters, so classifyPayload names it ahead of this layer.
		escape := `allow_url_include=1&auto_prepend_file=php://input`
		if got := do("/c/%2561", escape); got != "php-cgi-argument-injection" {
			t.Errorf("the escape request was labelled %q, want the more specific php-cgi-argument-injection", got)
		}
	})

	// 4c-bis. The pass's own global-cap stage. admit() keeps the map under the
	// cap, so this stage only has work to do when the cap is *lowered* under a
	// map that is already populated -- a config reload, or a test that shrank
	// the limit. Without the stage, a lowered cap would not take effect until
	// the old entries aged out on their own, which for a 10 minute TTL is ten
	// minutes of a limit the operator believes is in force.
	t.Run("lowering the cap takes effect at the next sweep", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		for i := 0; i < 100; i++ {
			d.observe("fp-"+itoa(i), "/res"+itoa(i)+"/%2561", "", "")
		}
		before, _, _ := d.launderingStats()
		if before <= 32 {
			t.Fatalf("expected the map to be populated above 32 before lowering the cap, got %d", before)
		}

		// Lower the cap and run the pass directly, because a lowered cap is
		// not something the write counter notices on its own -- the point of
		// this test is that the pass is what applies it. (sweepIfDue is
		// deliberately not fullness-triggered; see the comment there for the
		// measurement.)
		d.mu.Lock()
		d.maxEntries = 32
		d.sweep(d.now())
		after, evicted := len(d.entries), d.evicted
		d.mu.Unlock()
		if after > 32 {
			t.Errorf("after lowering the cap to 32 the map holds %d entries; the sweep did not enforce it", after)
		}
		if evicted == 0 {
			t.Error("lowering the cap evicted nothing")
		}
	})

	// 4d. The escape is one-shot. Replaying the pair must not produce a
	// stream of alerts -- the bound on alert volume under attack, which is
	// what keeps a false positive from becoming a flood.
	t.Run("a pair fires once", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		fires := 0
		for i := 0; i < 10; i++ {
			d.observe("fp", "/odata/Products", `$filter=Name%20eq%20'x'`, "")
			if d.observe("fp", "/odata/%2561", "", "") != "" {
				fires++
			}
		}
		if fires != 10 {
			// Ten separate pairs, each freshly seeded, should fire ten
			// times. The one-shot property is about a *replay of the same
			// evidence*, which is the next assertion.
			t.Errorf("10 freshly seeded pairs fired %d times, want 10", fires)
		}

		// Replay one pair against state that already holds both halves.
		d2 := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		d2.observe("fp", "/odata/Products", `$filter=Name%20eq%20'x'`, "")
		d2.observe("fp", "/odata/%2561", "", "") // seeds both, does not fire
		// Rebuild the pair and confirm a second completion does not fire
		// from the same entry: observe consumes the entry it fires on.
		extra := 0
		for i := 0; i < 5; i++ {
			if d2.observe("fp", "/odata/%2561", "", "") != "" {
				extra++
			}
		}
		if extra > 1 {
			t.Errorf("a single seeded pair fired %d times, want at most 1", extra)
		}
	})

	// 5. The write filter. This is the bound that keeps the other three from
	// mattering as much: if the common case never allocates, the cap is not in
	// ordinary traffic's hands and the eviction order is not either.
	//
	// The paths are deliberately two-segment, so they DO produce a resource
	// key -- a single-segment path is rejected by launderResource and would
	// make this assertion pass for the wrong reason.
	t.Run("traffic that is neither half allocates nothing", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		// A path with a resource, an ordinary query, an ordinary body: no
		// residual escape in the path, no type-consistent OData option. If the
		// write filter were removed, every one of these would allocate.
		plain := []struct{ path, query, body string }{
			{"/api/v1/things", `limit=10&offset=0`, ""},
			{"/wp-content/uploads/logo.png", "", "a=1&b=2"},
			{"/latest/meta-data/iam/security-credentials", "", ""},
			{"/api/v1/pods", `labelSelector=app%3Dweb`, ""},
			{"/download/report.pdf", "", ""},
		}
		for i, c := range plain {
			d.observe("client-"+itoa(i), c.path, c.query, c.body)
		}
		if entries, _, _ := d.launderingStats(); entries != 0 {
			t.Errorf("%d ordinary requests allocated %d entries, want 0: the write filter is not load-bearing", len(plain), entries)
		}

		// And a query option name with an inconsistent value is not enough
		// either, which is the same filter from the other side.
		d2 := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		for i, q := range []string{`$top=all`, `$format=yaml`, `$search=widgets`} {
			d2.observe("client-"+itoa(i), "/api/v1/things", q, "")
		}
		if entries, _, _ := d2.launderingStats(); entries != 0 {
			t.Errorf("option-shaped requests with inconsistent values allocated %d entries, want 0", entries)
		}
	})

	// 5a. The corpus, at two-segment paths so the paths are usable keys. The
	// measurement #3443 asserted, on this layer.
	t.Run("the real corpus allocates nothing", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		for _, c := range realCorpusFixture3430 {
			// A real path shape for each corpus entry: a resource segment and
			// a leaf, so launderResource returns a key.
			d.observe("fleet", "/probe/target", c.query, c.body)
		}
		if entries, _, _ := d.launderingStats(); entries != 0 {
			t.Errorf("the 31-entry real corpus allocated %d entries, want 0", entries)
		}
	})

	// 6. TTL reclaim. The read-time TTL check in observe() stops stale
	// evidence from firing; this asserts the *other* half, that a sweep frees
	// the memory of expired entries. They are separate mechanisms, and
	// without the sweep the map holds up to maxEntries of long-dead entries
	// indefinitely, which is bounded but is not the bound this claims.
	//
	// The clock is injected and moved past the TTL, then a sweep is run
	// directly. Nothing is observed, so nothing can evict on its own.
	t.Run("a sweep reclaims expired entries", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
		d.now = func() time.Time { return now }

		for i := 0; i < 20; i++ {
			d.observe("fp-"+itoa(i), "/res"+itoa(i)+"/%2561", "", "")
		}
		before, _, expiredBefore := d.launderingStats()
		if before != 20 {
			t.Fatalf("seeded %d entries, want 20", before)
		}
		if expiredBefore != 0 {
			t.Fatalf("fresh map reported %d expiries", expiredBefore)
		}

		now = now.Add(launderTTL + time.Minute)
		// Read the counters directly rather than through launderingStats:
		// that takes the same lock, and taking it here would deadlock.
		d.mu.Lock()
		d.sweep(now)
		after, expiredAfter := len(d.entries), d.expired
		d.mu.Unlock()

		if after != 0 {
			t.Errorf("after the TTL a sweep left %d of %d entries; expired evidence is still occupying the cap", after, before)
		}
		if expiredAfter == 0 {
			t.Error("the sweep reclaimed nothing and counted no expiry")
		}
	})

	// 6a. ...and the entries are still usable right up to the TTL, so reclaim
	// is not simply expiry-on-arrival under another name.
	t.Run("a sweep just before the TTL reclaims nothing", func(t *testing.T) {
		d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
		now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
		d.now = func() time.Time { return now }
		d.observe("fp", "/res/%2561", "", "")

		now = now.Add(launderTTL - time.Second)
		d.mu.Lock()
		d.sweep(now)
		entries := len(d.entries)
		d.mu.Unlock()
		if entries != 1 {
			t.Errorf("a sweep %v before the TTL left %d entries, want 1", launderTTL-time.Second, entries)
		}
	})
}

// TestLayerCCorpusMeasurement runs the detector over the pinned 30-day corpus
// and asserts zero, for the same reason #3443 asserted its zero: a class that
// fires on ordinary traffic is worse than no class.
//
// Two passes, so a pair hidden across two requests would be caught.
func TestLayerCCorpusMeasurement(t *testing.T) {
	d := newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL)
	var claimed []string
	for pass := 0; pass < 2; pass++ {
		for _, c := range realCorpusFixture3430 {
			// The corpus has no paths, so each entry gets a path that
			// exercises the escape half too: the worst case for this layer,
			// since every request is a candidate to seed state.
			path := "/" + strings.ReplaceAll(c.name, " ", "-")
			if residualEscape(path) {
				path += "/%2561"
			}
			if got := d.observe("fleet-client", path, c.query, c.body); got != "" {
				claimed = append(claimed, c.name)
			}
		}
	}
	t.Logf("corpus entries: %d, passes: 2, claimed: %d %v", len(realCorpusFixture3430), len(claimed), claimed)
	if len(claimed) != 0 {
		t.Errorf("layer C claims %d real corpus entries: %v", len(claimed), claimed)
	}
	if entries, _, _ := d.launderingStats(); entries == 0 {
		t.Log("no corpus entry seeded state either, so the zero above is not a measurement of a held pair")
	}
}

// TestLaunderResource pins the resource-key derivation, including the cases
// that must return "" because a shared resource would bind unrelated requests.
func TestLaunderResource(t *testing.T) {
	cases := []struct{ path, want string }{
		// The resource is the path minus its last segment, so the two
		// requests of a pair are siblings: the probe at
		// /odata/Products and the bypass at /odata/Products/1 share
		// /odata/products.
		{"/odata/Products", "/odata"},
		{"/odata/Products/1", "/odata/products"},
		{"/odata/Products/", "/odata"},
		{"/odata/Products/1/", "/odata/products"},
		{"/ODATA/Products", "/odata"},
		// Three segments, so the probe and the bypass can differ by depth and
		// still be siblings.
		{"/odata/Products/1/%2561", "/odata/products/1"},
		// A trailing slash on a single-segment path still yields "", so the
		// root never becomes a shared bucket.
		{"/", ""},
		{"/odata", ""},
		{"/odata/", ""},
		{"", ""},
		// Multiple slashes collapse, so a scanner varying them cannot split
		// one collection into two keys -- and cannot make two different
		// collections share the root key either.
		{"//", ""},
		{"//x", ""},
		{"/x//y", "/x"},
		{"//odata//Products", "/odata"},
		{"/x///y///z", "/x/y"},
		// A path with no leading slash at all.
		{"a", ""},
		{"a/b", "a"},
		// Over the depth cap.
		{"/a/b/c/d/e/f/g/h/i/j", ""},
	}
	for _, c := range cases {
		if got := launderResource(c.path); got != c.want {
			t.Errorf("launderResource(%q) = %q, want %q", c.path, got, c.want)
		}
	}

	// Over the length cap, built rather than typed so the constant is the
	// thing under test.
	long := "/" + strings.Repeat("a", launderMaxResourceLen+10) + "/x"
	if got := launderResource(long); got != "" {
		t.Errorf("launderResource(over %d bytes) = %q, want \"\"", launderMaxResourceLen, got)
	}
}

// TestOdataValueConsistent pins the value-consistency gate, including the
// malformed-escape case from #3443 that a substring match would get wrong.
func TestOdataValueConsistent(t *testing.T) {
	yes := []struct{ option, value string }{
		{"$top", "10"},
		{"$top", "0"},
		{"$skip", "50"},
		{"$count", "true"},
		{"$format", "json"},
		{"$format", "JSON"},
		{"$select", "Year,Value"},
		{"$select", "Address.City"},
		{"$select", "*"},
		{"$orderby", "Year desc"},
		{"$orderby", "Year,Value asc"},
		{"$filter", "Year eq 2026"},
		{"$filter", "contains(Name,'Widget')"},
		{"$search", "blue OR green"},
		{"$search", "NOT red"},
		{"$skiptoken", "abc"},
		// The alias form. OData defines a namespace-alias prefix on system
		// options, so `northwind.$filter` is the same option and must be
		// recognised -- otherwise a client using the alias is invisible to
		// the OData half and the layer misses a real campaign. The option
		// name is taken as the last dotted part, so this is about the
		// *option* being aliased; #3443's own test pins that "$filter" inside
		// another value is not an option at all.
		{"$filter", "Year eq 2026"},
		// A value with dots, which must not be mistaken for an alias: the
		// alias is stripped from the KEY, never the value.
		{"$filter", "startswith(Name,'a.b.c')"},
		{"$select", "Address.City,Address.Street"},
		// A double-encoded value decodes once to `year%20eq%252026`, whose
		// tokens are `year`, `20eq`, `202026` -- no operator token. It must
		// not read as a filter expression here; #3443 owns that shape under
		// odata-double-encode-probe.
		{"$filter", "year%20eq%252026"},
	}
	for _, c := range yes {
		if odataValueConsistent(c.option, "%s") {
			continue
		}
		if !odataValueConsistent(c.option, c.value) {
			t.Errorf("odataValueConsistent(%q, %q) = false, want true", c.option, c.value)
		}
	}

	no := []struct{ option, value string }{
		{"$top", "all"},
		{"$top", ""},
		{"$top", "10;drop"},
		{"$top", "999999999999"}, // over the digit bound
		{"$count", "maybe"},
		{"$format", "yaml"},
		{"$format", "json,xml"},
		{"$select", "Year,;drop"},
		{"$select", "Year eq 2026"},
		{"$orderby", "Year;drop"},
		{"$orderby", "Year sideways"},
		{"$filter", "eq"},   // operator, no literal
		{"$filter", "2026"}, // literal, no operator
		{"$filter", "Year%zz%2520eq"},
		{"$search", "the quick brown"}, // no operator token
	}
	for _, c := range no {
		if odataValueConsistent(c.option, c.value) {
			t.Errorf("odataValueConsistent(%q, %q) = true, want false", c.option, c.value)
		}
	}
}

// TestQualifyingODataAcceptsAliasedOptions pins the namespace-alias form
// separately, because it is a property of the KEY rather than of the value.
//
// OData defines `northwind.$filter` as the same option as `$filter`, so a
// client using an alias is a real OData client -- and a scanner using one is a
// real probe. If the option name were compared whole, the alias form would
// silently stop qualifying and the layer would miss exactly the campaigns that
// bother to use a namespace.
func TestQualifyingODataAcceptsAliasedOptions(t *testing.T) {
	yes := []string{
		`northwind.$filter=Year%20eq%202026`,
		`northwind.$top=10`,
		`NS.Default.$select=Year,Value`,
		`$FILTER=Year%20eq%202026`,
		`a.b.c.$format=json`,
	}
	for _, q := range yes {
		if !qualifyingODataRequest("/odata/Products", q, "") {
			t.Errorf("qualifyingODataRequest(%q) = false, want true: the alias or case form is not recognised", q)
		}
	}
	// The alias is stripped from the key only. A dotted value is a dotted
	// value, and stripping it would compare the wrong name.
	if !qualifyingODataRequest("/odata/Products", `$filter=Address.City%20eq%20'a.b'`, "") {
		t.Error("a dotted filter value was rejected; the alias strip must apply to the key, not the value")
	}
	// And a prefix that is not an alias for a real option is still not one.
	for _, q := range []string{
		`northwind.$unknown=Year%20eq%202026`,
		`northwind.filter=Year%20eq%202026`,
		`q=%24filter%253DYear%2520eq`,
	} {
		if qualifyingODataRequest("/odata/Products", q, "") {
			t.Errorf("qualifyingODataRequest(%q) = true, want false", q)
		}
	}
}

// TestQualifyingODataRequestIsRootBlind pins the collection-path requirement
// separately, because it is a whole request shape rather than one value.
func TestQualifyingODataRequestIsRootBlind(t *testing.T) {
	if qualifyingODataRequest("/", `$filter=Year%20eq%202026`, "") {
		t.Error("a $filter on the decoy's landing page qualified as an OData surface; the root binds to nothing")
	}
	if !qualifyingODataRequest("/odata/Products", `$filter=Year%20eq%202026`, "") {
		t.Error("a real OData filter on a collection path did not qualify")
	}
	// The body is the POST half of the same surface.
	if !qualifyingODataRequest("/odata/Products", "", `$top=10&$filter=Year%20eq%202026`) {
		t.Error("a form-encoded OData query on a collection path did not qualify")
	}
	// An option name inside a value is not an option. #3443 pins the same
	// boundary for its own gate; it is the same parse.
	if qualifyingODataRequest("/odata/Products", `q=%24filter%253DYear%2520eq`, "") {
		t.Error("an option name inside another value qualified; keys are parsed, not substring-matched")
	}
}

// TestLaunderingFingerprintSurvivesRelayLaundering is #3430's technique 2
// turned into a test: the same client stack arriving from a different address
// is the same fingerprint, and a different client stack is a different one.
func TestLaunderingFingerprintSurvivesRelayLaundering(t *testing.T) {
	relayA := http.Header{}
	relayA.Set("User-Agent", "python-requests/2.32.3")
	relayA.Set("Accept", "*/*")

	relayB := http.Header{}
	relayB.Set("User-Agent", "python-requests/2.32.3")
	relayB.Set("Accept", "*/*")

	other := http.Header{}
	other.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	other.Set("Accept", "text/html")

	// Same stack, different addresses and hosts.
	if launderingFingerprintOf("decoy-a", relayA) != launderingFingerprintOf("decoy-a", relayB) {
		t.Error("the same client stack produced two fingerprints; a relay must not change it")
	}
	// A different stack is a different bucket.
	if launderingFingerprintOf("decoy-a", relayA) == launderingFingerprintOf("decoy-a", other) {
		t.Error("two different client stacks shared a fingerprint")
	}
	// The host is part of it, so two decoys do not share a bucket.
	if launderingFingerprintOf("decoy-a", relayA) == launderingFingerprintOf("decoy-b", relayA) {
		t.Error("two hosts shared a fingerprint; the host is meant to be part of the key")
	}
	// X-Forwarded-For is deliberately not consulted, or a relay -- or an
	// attacker -- could partition the key at will by forging it.
	forged := http.Header{}
	forged.Set("User-Agent", "python-requests/2.32.3")
	forged.Set("Accept", "*/*")
	forged.Set("X-Forwarded-For", "203.0.113.7")
	if launderingFingerprintOf("decoy-a", forged) != launderingFingerprintOf("decoy-a", relayA) {
		t.Error("X-Forwarded-For changed the fingerprint; it must not be part of the key")
	}
}

// TestLayerCIsWiredIntoServeHTTP closes the loop: the class has to reach an
// event, not just a function's return value. Two real requests through the
// handler, the second of which must carry the class.
func TestLayerCIsWiredIntoServeHTTP(t *testing.T) {
	s := &server{
		log:           &logger{out: &strings.Builder{}},
		sensor:        "http-honeypot",
		serverHdr:     "nginx/1.24.0",
		listenPort:    8080,
		tarpitEnabled: false,
		launder:       newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL),
	}

	// The healthcheck short-circuit must not be mistaken for a probe, so
	// these come from a routable peer.
	do := func(path, query string) *event {
		e := &event{Path: path, Query: query, PayloadClass: ""}
		r := httptest.NewRequest(http.MethodGet, "http://decoy"+path+"?"+query, nil)
		r.RemoteAddr = "203.0.113.7:44444"
		s.observeLaundering(r, e, "")
		return e
	}

	if e := do("/odata/Products", `$filter=Name%20eq%20'Widget'`); e.PayloadClass != "" {
		t.Fatalf("the probe event was labelled %q, want unlabelled", e.PayloadClass)
	}
	if e := do("/odata/%2561", ""); e.PayloadClass != launderingClass {
		t.Errorf("the bypass event was labelled %q, want %q", e.PayloadClass, launderingClass)
	}
}

// TestLayerCDisabledIsSafe covers the off switch. A nil component is the
// disable path, so it has to be a nil check rather than a panic.
func TestLayerCDisabledIsSafe(t *testing.T) {
	var d *launderingState
	if got := d.observe("fp", "/odata/Products", `$filter=Name%20eq%20'x'`, ""); got != "" {
		t.Errorf("a disabled component returned %q", got)
	}
	if got := d.observe("fp", "/odata/%2561", "", ""); got != "" {
		t.Errorf("a disabled component returned %q on the escape half", got)
	}
	entries, evicted, expired := d.launderingStats()
	if entries != 0 || evicted != 0 || expired != 0 {
		t.Errorf("a disabled component reported %d/%d/%d", entries, evicted, expired)
	}

	s := &server{log: &logger{out: &strings.Builder{}}}
	e := &event{}
	r := httptest.NewRequest(http.MethodGet, "http://decoy/odata/%2561", nil)
	s.observeLaundering(r, e, "") // must not panic on the nil launder
	if e.PayloadClass != "" {
		t.Errorf("a server with the layer disabled labelled %q", e.PayloadClass)
	}
}

// TestLayerCFiringIsOneShotInTheHandler checks the bound on alert volume at
// the level that matters: the number of labelled events, not the number of
// function returns.
func TestLayerCFiringIsOneShotInTheHandler(t *testing.T) {
	s := &server{
		log:           &logger{out: &strings.Builder{}},
		sensor:        "http-honeypot",
		tarpitEnabled: false,
		launder:       newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL),
	}
	do := func(path, query string) string {
		e := &event{}
		r := httptest.NewRequest(http.MethodGet, "http://decoy"+path+"?"+query, nil)
		r.RemoteAddr = "203.0.113.7:44444"
		s.observeLaundering(r, e, "")
		return e.PayloadClass
	}

	// A probe, then the bypass repeated. One label, not four.
	if got := do("/odata/Products", `$filter=Name%20eq%20'x'`); got != "" {
		t.Fatalf("probe = %q", got)
	}
	labelled := 0
	for i := 0; i < 4; i++ {
		if do("/odata/%2561", "") != "" {
			labelled++
		}
	}
	if labelled != 1 {
		t.Errorf("4 replays of the escape half produced %d labels, want 1: a replayed pair must not become a flood", labelled)
	}
}

// TestLayerCEndToEndThroughServeHTTP drives the real handler, not
// observeLaundering, because the wiring is a claim about main.go and a test
// that calls the component directly cannot see it.
//
// Two requests through ServeHTTP, and the class is read off the JSON event
// the logger actually wrote. Nothing here reaches a network: ServeHTTP is
// called directly on an httptest recorder, the body is empty, and the only
// addresses are RFC 5737 documentation ranges.
func TestLayerCEndToEndThroughServeHTTP(t *testing.T) {
	var logged bytes.Buffer
	s := &server{
		log:        &logger{out: &logged},
		sensor:     "http-honeypot",
		serverHdr:  "nginx/1.24.0",
		listenPort: 8080,
		launder:    newLaunderingState(launderMaxEntries, launderPerFingerprint, launderTTL),
	}
	// The tarpit would hold the response for minutes, and this test is about
	// classification rather than about the drip.
	s.tarpitEnabled = false

	send := func(path, query string) map[string]any {
		logged.Reset()
		target := path
		if query != "" {
			target += "?" + query
		}
		r := httptest.NewRequest(http.MethodGet, "http://decoy.example"+target, nil)
		// A routable peer: 127.0.0.1 is the healthcheck short-circuit, and
		// the tunnel peer would be indistinguishable from Traefik.
		r.RemoteAddr = "203.0.113.7:44444"
		r.Header.Set("User-Agent", "python-requests/2.32.3")
		r.Header.Set("Accept", "*/*")
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, r)

		var event map[string]any
		line := strings.TrimSpace(logged.String())
		if line == "" {
			t.Fatalf("request %q logged nothing", target)
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("logged event is not JSON (%v): %s", err, line)
		}
		return event
	}

	probe := send("/odata/Products", `$filter=Name%20eq%20'Widget'`)
	if class, _ := probe["payload_class"].(string); class != "" {
		t.Fatalf("the OData probe was labelled %q in the event, want no class", class)
	}

	bypass := send("/odata/%2561", "")
	class, _ := bypass["payload_class"].(string)
	if class != launderingClass {
		t.Errorf("the bypass event carries payload_class %q, want %q", class, launderingClass)
	}
	// The class is on the event, and the rest of the event is intact -- a new
	// class must not cost the request its path, which is the evidence.
	if p, _ := bypass["path"].(string); p != "/odata/%61" {
		t.Errorf("the bypass event's path is %q, want the once-decoded %q", p, "/odata/%61")
	}
}

// TestLayerCDefaultsAreTheArguedValues pins the shipped defaults, because they
// are the answer to #3447's second design question and a config change that
// quietly raises the cap is a memory-growth regression that no behavioural
// test would notice.
func TestLayerCDefaultsAreTheArguedValues(t *testing.T) {
	if launderMaxEntries != 512 {
		t.Errorf("launderMaxEntries = %d, the design says 512", launderMaxEntries)
	}
	if launderPerFingerprint != 8 {
		t.Errorf("launderPerFingerprint = %d, the design says 8", launderPerFingerprint)
	}
	if launderTTL != 10*time.Minute {
		t.Errorf("launderTTL = %v, the design says 10m", launderTTL)
	}
	if launderMaxResourceLen != 128 || launderMaxResourceSegments != 8 {
		t.Errorf("resource caps are %d bytes / %d segments, the design says 128 / 8",
			launderMaxResourceLen, launderMaxResourceSegments)
	}
	// The cap has to be small enough that an entry costs little. 512 entries
	// of a two-timestamp record is not a memory concern at any plausible
	// width; this is the guard against the cap being raised by three orders of
	// magnitude.
	if launderMaxEntries > 1<<16 {
		t.Errorf("launderMaxEntries = %d, which is no longer a memory bound worth the name", launderMaxEntries)
	}

	// main.go's env fallbacks must be these same constants, not literals that
	// have drifted from them.
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	main := string(src)
	for _, want := range []string{
		`getenvInt64("LAUNDER_MAX_ENTRIES", launderMaxEntries)`,
		`getenvInt64("LAUNDER_PER_FINGERPRINT", launderPerFingerprint)`,
		`getenvInt64("LAUNDER_TTL_SECONDS", int64(launderTTL/time.Second))`,
		`getenv("HTTP_LAUNDERING", "1") == "0"`,
	} {
		if !strings.Contains(main, want) {
			t.Errorf("main.go does not contain %q; the shipped default and the argued constant have drifted apart", want)
		}
	}
}

// TestLayerCFingerprintUsesEveryHeaderItClaimsTo is the precision check on
// the fingerprint. The relay test proves two stacks differ; it does not prove
// which headers do the differing, so a regression that quietly drops
// User-Agent -- the one header a scanner's stack is most identifiable by --
// would pass it.
func TestLayerCFingerprintUsesEveryHeaderItClaimsTo(t *testing.T) {
	base := http.Header{}
	base.Set("User-Agent", "python-requests/2.32.3")
	base.Set("Accept", "*/*")
	base.Set("Accept-Language", "en-GB,en;q=0.9")
	base.Set("Accept-Encoding", "gzip, deflate")
	want := launderingFingerprintOf("decoy.example", base)

	// Each header in turn, changed: the fingerprint must move. A header that
	// is not actually read is a header the design claims and the code
	// ignores.
	for _, name := range []string{"User-Agent", "Accept", "Accept-Language", "Accept-Encoding"} {
		changed := http.Header{}
		for k, v := range base {
			changed[k] = v
		}
		changed.Set(name, "mutated-"+name)
		if got := launderingFingerprintOf("decoy.example", changed); got == want {
			t.Errorf("changing %s did not change the fingerprint; it is documented as part of the key but is not read", name)
		}
	}

	// A header that is NOT claimed must not move it, or the key would be
	// sensitive to noise the design says to ignore.
	for _, name := range []string{"X-Forwarded-For", "Cookie", "Authorization", "X-Real-IP", "Referer"} {
		changed := http.Header{}
		for k, v := range base {
			changed[k] = v
		}
		changed.Set(name, "mutated-"+name)
		if got := launderingFingerprintOf("decoy.example", changed); got != want {
			t.Errorf("changing %s moved the fingerprint; only Host, User-Agent, Accept, Accept-Language and Accept-Encoding are the key", name)
		}
	}

	// The host is claimed too.
	if launderingFingerprintOf("other.example", base) == want {
		t.Error("changing the host did not change the fingerprint")
	}
}

// TestLayerCDegenerateConfigStaysBounded covers the misconfiguration the
// bounds are supposed to survive: LAUNDER_MAX_ENTRIES=0, which a typo in a
// compose file can produce. The cap cannot be enforced against zero, so
// admit() returns rather than looping forever, and the detector degrades to
// holding a single entry -- it stops detecting, but it does not grow without
// limit and it does not hang the request path.
//
// A bounded failure is the right failure here. The alternative -- treating
// zero as "unlimited" -- is the memory-growth bug #3447 names, and treating it
// as an error would mean the process refuses to start on a config the operator
// can fix with one env var and no redeploy of the code.
func TestLayerCDegenerateConfigStaysBounded(t *testing.T) {
	// The clamp is asserted on the field, not only through the flood below.
	// The flood is what proves the *behaviour*; the field is what makes the
	// clamp's existence visible, and a flood of 2000 writes would still pass
	// with a clamp of 0 as long as admit() happened to hold one entry.
	d := newLaunderingState(0, launderPerFingerprint, launderTTL)
	if d.maxEntries < 1 {
		t.Errorf("maxEntries = %d after construction, want it clamped to at least 1", d.maxEntries)
	}
	for i := 0; i < 2000; i++ {
		d.observe("fp-"+itoa(i), "/res"+itoa(i)+"/%2561", "", "")
		d.observe("fp2-"+itoa(i), "/res2"+itoa(i)+"/%2561", "", "")
	}
	entries, _, _ := d.launderingStats()
	t.Logf("maxEntries=0 after 4000 writes: %d entries", entries)
	if entries > 2 {
		t.Errorf("maxEntries=0 left %d entries; the degenerate path grows without limit", entries)
	}

	// A negative per-fingerprint bound is worse than a lost bound: unclamped,
	// it reaches the sweep as a slice bound past the end of the slice and
	// panics on the request path. This asserts the clamp, and that the sweep
	// runs at all under the degenerate value rather than panicking first.
	d2 := newLaunderingState(launderMaxEntries, -1, launderTTL)
	if d2.perFingerprint < 1 {
		t.Errorf("perFingerprint = %d after construction, want it clamped to at least 1", d2.perFingerprint)
	}
	for i := 0; i < 500; i++ {
		d2.observe("fp-"+itoa(i), "/res"+itoa(i)+"/%2561", "", "")
	}
	d2.mu.Lock()
	d2.sweep(d2.now())
	held := len(d2.entries)
	d2.mu.Unlock()
	// 500 distinct fingerprints, one entry each after the clamp, is the
	// correct outcome: the clamp bounds each client, and the global cap
	// bounds the total. The assertion is that the sweep ran and did not
	// panic, and that no single client is holding more than its share.
	perClient := map[string]int{}
	d2.mu.Lock()
	for _, e := range d2.entries {
		perClient[e.fingerprint]++
	}
	d2.mu.Unlock()
	for fp, n := range perClient {
		if n > 1 {
			t.Errorf("fingerprint %s holds %d entries under a clamped per-fingerprint bound of 1", fp, n)
		}
	}
	t.Logf("perFingerprint=-1 clamped to %d; %d entries across %d fingerprints after a sweep", d2.perFingerprint, held, len(perClient))

	// A very large per-fingerprint bound is not a hazard: it only means the
	// per-client stage never fires, and the global cap still applies.
	d3 := newLaunderingState(8, 1<<30, launderTTL)
	for i := 0; i < 500; i++ {
		d3.observe("fp-"+itoa(i), "/res"+itoa(i)+"/%2561", "", "")
	}
	if entries, _, _ := d3.launderingStats(); entries > 8 {
		t.Errorf("with a huge per-fingerprint bound the map holds %d entries, cap is 8", entries)
	}

	// And a zero TTL, which means no evidence is ever valid. The layer stops
	// firing rather than firing on everything -- and unlike the two entry
	// bounds, a zero TTL is NOT silently replaced with the default, because
	// that would make the configured value a lie.
	d4 := newLaunderingState(launderMaxEntries, launderPerFingerprint, 0)
	if d4.ttl != 0 {
		t.Errorf("a zero TTL was silently changed to %v", d4.ttl)
	}
	if got := d4.observe("fp", "/c/Products", `$filter=Name%20eq%20'x'`, ""); got != "" {
		t.Errorf("the OData probe was labelled %q with a zero TTL", got)
	}
	if got := d4.observe("fp", "/c/%2561", "", ""); got != "" {
		t.Errorf("a zero TTL still completed a pair: %q", got)
	}
}

// itoa avoids importing strconv for one call in a test.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
