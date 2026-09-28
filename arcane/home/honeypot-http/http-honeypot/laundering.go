package main

// laundering.go implements #3447 -- layer C of #3430's scanner-laundering
// classification, the one shape that cannot be decided from a single request.
//
// THE SHAPE. #3430's double-encoding bypass is %2561 -> %61 -> 'a': a path
// segment that survives one decode and only becomes a character after the
// next. The escape rides the *path*, and #3443 (layers A/B) is an in-request
// classifier over (RawQuery, body) that is never given the path, so the shape
// is invisible to it. #3443's agent could have made the gate pass by
// reconstructing the bypass in a query -- scan every key for a residue, claim
// the request because some *unrelated* key elsewhere held an OData option --
// and refused to, pinning that reconstruction as a negative test instead.
// That refusal is why this file exists, so this file does not do it either,
// and the refusal is structural rather than a matter of restraint: see
// "the same-request rule" below, which makes an in-request match impossible
// by construction rather than by policy.
//
// WHAT MAKES IT STATEFUL. "Is this request laundering?" is not a property of
// the request. It is a property of the *pair*: a client that first proves an
// OData surface exists and then sends a path that only becomes meaningful
// after a second decode. The two halves are separate requests, so something
// has to remember the first until the second arrives. That memory is the
// whole point of this layer, and it is the only stateful thing in a package
// that is otherwise an in-request classifier by construction -- #3443 says
// so in TestScannerLaunderingLayersNotImplementable, and that sentence is now
// out of date in exactly one direction, corrected there and in
// TestLayerCIsTheFirstStateThisPackageKeeps.
//
// #3447 asks two design questions. Both are answered here rather than in a
// design note, because a design that is not in the code is not a design:
//
//   1. WHERE THE STATE LIVES. In main.go's `server` struct, in this
//      process's heap, as a single map guarded by one mutex. In the request
//      pipeline (ServeHTTP calls observe on every request) and outliving the
//      request (an entry written by request N is read by request N+1).
//      Not per-connection: a relay-laundering client is not the connection it
//      arrives on, and #3430's technique 2 is precisely that the source
//      address is worthless, so a per-connection key would both miss the
//      attack it exists for and be destroyed by ordinary keep-alive churn.
//      Not on disk: a second file on the hot path of a process that is
//      *meant* to be attacked is a second thing to fill, and the durable
//      record is already the event log, which Elasticsearch can window after
//      the fact. Nothing here needs to survive a restart -- the evidence is
//      at most a few minutes old, so a restart loses a window, not a fact.
//
//   2. HOW IT IS BOUNDED. Three independent bounds, because they bound
//      different things and one of them is not enough:
//
//      - launderMaxEntries caps the map. Memory bound. The oldest entry is
//        evicted to admit a new one, so an attacker who floods the map cannot
//        blind the detector by filling it -- he can only evict the entries
//        that have not been used yet, and every eviction is counted.
//      - launderPerFingerprint caps how much of the map one client can hold,
//        so a single source spraying distinct resource paths cannot evict
//        everyone else's evidence. Without it the global cap is a lever.
//      - launderTTL bounds the *age of the evidence*, not the memory. A half
//        older than the TTL does not count towards completing a pair, so a
//        stale observation cannot be resurrected by a request arriving much
//        later. There is deliberately no timer, no ticker and no background
//        goroutine: expiry is checked on read and reclaimed by the same
//        amortised pass that enforces the cap, so there is nothing here that
//        can outlive the process or leak a goroutine per deployment.
//
//      The cap is enforced off a creation-order queue rather than a scan for
//      the least-recently-used entry, which makes eviction O(1) on the request
//      path instead of O(n). That queue is a second bounded structure, not an
//      unbounded one: it compacts when half its prefix is consumed, and the
//      sweep rebuilds it when the pass has killed more than half of it. See
//      repairQueue, whose threshold is where the mutation sweep found a real
//      bug and where two equivalent mutants are now recorded.
//
//      At the cap the answer is "evict the oldest and count it", not "refuse
//      new entries" and not "grow". Refusing would let a flood disable the
//      detector outright; growing is the memory-growth bug #3447 names. The
//      counters are what make saturation visible, since a saturated detector
//      is a detector whose coverage claim is void and must not be reported as
//      if it were still complete.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// The class this layer produces. Deliberately distinct from #3443's
// odata-double-encode-probe: that one is an OData option carrying a
// double-encoded value and is decided from one request, this one is an OData
// surface followed by a double-encoded *path* and needs two.
const launderingClass = "odata-path-encoded-bypass"

const (
	// 512 entries at ~100 bytes each is well under a megabyte, and a map
	// this size is swept in microseconds. The value is chosen so the cap
	// cannot be reached by ordinary traffic: observe only ever writes an
	// entry for a request that carried a path-borne residual escape or a
	// value-consistent OData option, which is a small minority of a fleet
	// whose 30-day window held 583 distinct payload values across 11,139
	// requests (#1888, quoted in classifyPayload). 512 is a ceiling, not a
	// working set.
	launderMaxEntries = 512

	// Per client fingerprint. The reason the global cap alone is not enough:
	// without this, one attacker who sends 512 OData-shaped requests at 512
	// distinct resource paths evicts every other client's evidence, and the
	// detector's coverage becomes a function of whoever attacked last.
	launderPerFingerprint = 8

	// 10 minutes. Long enough to span a scanner's probe-then-exploit cadence
	// -- a client that maps a surface and comes back to it is not instant --
	// and short enough that a half cannot be paired with a request long after
	// the fact. There is no measured cadence behind this number and none is
	// claimed; it is the order of magnitude a human-driven manual probe and a
	// scripted sweep have in common.
	launderTTL = 10 * time.Minute

	// The amortised pass runs at most once per this many writes, so the
	// steady-state cost of bounding is O(1) per request rather than O(n).
	launderSweepEvery = 64

	// The resource key is derived from an attacker-controlled path, so it is
	// capped before it becomes a map key. 128 bytes is deeper than any real
	// API path and shorter than the request line a server accepts.
	launderMaxResourceLen = 128

	// ...and so is its depth, so the key cannot be 128 one-character
	// segments and nothing downstream has to walk an unbounded path.
	launderMaxResourceSegments = 8

	// Header bytes fed to the fingerprint hash. User-Agent alone can be large
	// and it is attacker-controlled; the hash only needs enough to
	// distinguish client stacks.
	launderFingerprintBytes = 512

	// Saturation is reported every this many evictions rather than every one,
	// so the report cannot itself become the thing that fills a log.
	launderReportEvery = 1000
)

// odataSystemOptions is the set of OData system query options, keyed by the
// name after any namespace-alias prefix. Same list, and the same
// last-dotted-part rule, as odataDoubleEncode in main.go -- deliberately the
// same, because both halves are asking the same question ("is there an OData
// surface here?"), and two different lists would make the two answers
// disagree for no reason.
var odataSystemOptions = map[string]bool{
	"$select": true, "$filter": true, "$expand": true, "$orderby": true,
	"$top": true, "$skip": true, "$count": true, "$apply": true,
	"$format": true, "$search": true, "$skiptoken": true, "$index": true,
}

// launderingEntry is the whole of the cross-request state for one
// (fingerprint, resource) pair: which halves have been seen, and when.
//
// Two timestamps rather than two booleans, because the TTL is a property of
// the evidence and a boolean cannot carry it. An old half is treated as
// absent on read; the timestamps are what make that decidable without a
// timer.
type launderingEntry struct {
	// fingerprint is denormalised onto the entry so the sweep can count
	// per-client pressure without re-parsing keys.
	fingerprint string
	odataAt     time.Time
	escapeAt    time.Time
	touched     time.Time
}

// complete reports whether both halves have been seen. Neither may be the
// half this very request carried -- observe guarantees that, see
// sameRequest -- so a complete entry is by construction a pair of *different*
// requests, which is the property that makes the layer sound.
func (e *launderingEntry) complete() bool {
	return !e.odataAt.IsZero() && !e.escapeAt.IsZero()
}

// launderingState is the bounded cross-request component. A nil pointer is a
// valid, disabled component: every method returns early, so the off switch
// (HTTP_LAUNDERING=0) is a nil field and not a branch at each call site.
type launderingState struct {
	mu      sync.Mutex
	entries map[string]*launderingEntry
	// order is a ring of keys in creation order, so eviction at the cap is
	// O(1) rather than an O(n) scan of the whole map per write.
	//
	// That scan was measured, not assumed: with the oldest-entry search done
	// inline, a write against a full 512-entry map cost 79µs, versus 0.9µs
	// for a write that does not have to evict. A write path whose cost depends
	// on how full the map is -- and which an attacker controls the fullness of
	// -- is an amplification lever, so the ring is the fix and the measurement
	// is why. See the benchmark in the PR body.
	//
	// Eviction is therefore creation-order (FIFO), not least-recently-used.
	// That is a deliberate trade rather than an oversight: an entry that is
	// used to complete a pair is *deleted* by observe, never evicted, so
	// "recently touched" only means "probed recently and not yet exploited".
	// A ring is O(1) and a scan is O(n); the difference in policy is small and
	// the difference in cost under a flood is not.
	order     []string
	orderHead int

	maxEntries     int
	perFingerprint int
	ttl            time.Duration
	sweepEvery     int

	// now is injectable so the TTL can be tested without sleeping, which is
	// the only way to test a bound honestly.
	now func() time.Time

	sinceSweep int
	evicted    int
	expired    int
}

// newLaunderingState builds the component, clamping the two entry bounds to
// sane minima.
//
// The clamping is not defensive decoration. Without it a negative
// LAUNDER_PER_FINGERPRINT reaches the sweep as `len(keys) - perFingerprint`,
// which is a slice bound past the end of the slice and a panic on the request
// path of a process meant to be attacked -- one env typo away. A config error
// should cost coverage, never availability, so out-of-range values are raised
// to the smallest value that still means something: one entry, per client, and
// a cap of one.
func newLaunderingState(maxEntries, perFingerprint int, ttl time.Duration) *launderingState {
	if maxEntries < 1 {
		maxEntries = 1
	}
	// The creation-order queue is preallocated to the cap. Without this,
	// append() grows it geometrically and the growth is invisible in
	// len(d.entries) -- the queue would be the one structure in the component
	// whose memory is not bounded by the number the operator set.
	order := make([]string, 0, maxEntries)
	if perFingerprint < 1 {
		perFingerprint = 1
	}
	// A zero or negative TTL is NOT clamped. It means no evidence is ever
	// valid, so the layer never fires -- which is the honest reading of the
	// value, and a visible loss of coverage rather than a silent substitution
	// of a TTL the operator did not choose.
	return &launderingState{
		entries:        make(map[string]*launderingEntry),
		order:          order,
		maxEntries:     maxEntries,
		perFingerprint: perFingerprint,
		ttl:            ttl,
		sweepEvery:     launderSweepEvery,
		now:            time.Now,
	}
}

// observe folds one request into the state and returns the class name when
// this request *completed* a pair.
//
// Three properties, in order of how much they matter:
//
//  1. THE SAME-REQUEST RULE. A single request carrying both halves never
//     fires. It records the halves and returns "". This is the anti-over-match
//     guarantee and it is enforced here rather than argued for in a comment:
//     the escape and the option are never evaluated against each other inside
//     one request, so there is no code path on which "this request had an
//     OData option and *something else* had a residue" can reach a return
//     value. #3443's pinned negative -- `$filter=year%20eq%202026&%2561=1` --
//     asks for exactly that and must keep asking for it; this rule is why it
//     can, on any request, in any order, with any number of keys.
//
//  2. THE BINDING. The key is (fingerprint, resource) and never the client
//     alone. "This client once sent an OData option" is not evidence about
//     this request -- it is evidence about the internet. "This client sent an
//     OData option for *this collection* and then sent a double-decoding
//     segment *under that same collection*" is evidence about a bypass.
//
//  3. THE WRITE FILTER. An entry is only created for a request that carried
//     one of the two halves. Ordinary traffic neither writes nor touches the
//     map, so neither the memory bound nor the eviction order is in the
//     attacker's hands by default.
func (d *launderingState) observe(fingerprint, decodedPath, rawQuery, body string) string {
	if d == nil || fingerprint == "" {
		return ""
	}

	// A request that is neither a qualifying OData surface nor a
	// double-decoding path is not evidence and does not get to allocate.
	// Computed before the lock, so the common case is two cheap string scans
	// and no contention.
	resource := launderResource(decodedPath)
	if resource == "" {
		return ""
	}
	odataHalf := qualifyingODataRequest(decodedPath, rawQuery, body)
	escapeHalf := pathBorneResidualEscape(decodedPath)
	if !odataHalf && !escapeHalf {
		return ""
	}

	now := d.now()
	key := fingerprint + "\x00" + resource

	d.mu.Lock()
	defer d.mu.Unlock()

	// Amortised reclaim, on a write counter rather than on map fullness --
	// see sweepIfDue for the measurement behind that choice.
	d.sweepIfDue(now)
	entry, existed := d.entries[key]
	if !existed {
		d.admit()
		entry = &launderingEntry{fingerprint: fingerprint, touched: now}
		d.entries[key] = entry
		d.pushOrder(key)
	} else {
		entry.touched = now
	}

	// Write the halves this request carries. If it carries both, the
	// timestamps are set from the same instant and the guard below refuses to
	// complete a pair from one request, so the escape and the option are never
	// evaluated against each other inside a single request.
	if odataHalf {
		entry.odataAt = now
	}
	if escapeHalf {
		entry.escapeAt = now
	}
	sameRequest := odataHalf && escapeHalf

	// A half older than the TTL is not evidence, whatever the entry says.
	if !entry.odataAt.IsZero() && now.Sub(entry.odataAt) > d.ttl {
		entry.odataAt = time.Time{}
	}
	if !entry.escapeAt.IsZero() && now.Sub(entry.escapeAt) > d.ttl {
		entry.escapeAt = time.Time{}
	}

	if sameRequest || !entry.complete() {
		return ""
	}

	// One pair, one label. Consuming the entry is what bounds the alert
	// volume under attack: a scanner that replays the pair a thousand times
	// gets one event, and the evidence it would need to replay is gone.
	//
	// The ring keeps the key until it is next popped; dropOrder retires it
	// there if it is no longer in the map, so a deleted entry costs one
	// skipped slot rather than unbounded growth.
	delete(d.entries, key)
	d.report(now)
	return launderingClass
}

// pushOrder records a key as the newest in the creation-order queue. Called
// with the lock held.
//
// The queue is a slice with a head index rather than a true ring, so that a
// pop is a bounds check and an index bump. It is compacted when the dead
// prefix is at least half the slice, which bounds the slice at 2*maxEntries
// without amortised bookkeeping on the write path.
func (d *launderingState) pushOrder(key string) {
	d.order = append(d.order, key)
}

// popOrder returns the oldest key that is still live in the map, retiring
// every slot it passes. Returns "" when nothing live remains. Called with the
// lock held.
func (d *launderingState) popOrder() string {
	for d.orderHead < len(d.order) {
		key := d.order[d.orderHead]
		d.orderHead++
		if _, live := d.entries[key]; live {
			d.compactOrder()
			return key
		}
	}
	d.compactOrder()
	return ""
}

// compactOrder drops the consumed prefix once it is at least half the slice,
// which bounds the queue at 2*maxEntries with no amortised bookkeeping on the
// write path. Called with the lock held.
func (d *launderingState) compactOrder() {
	if d.orderHead == 0 {
		return
	}
	if d.orderHead >= len(d.order) {
		d.order, d.orderHead = d.order[:0], 0
		return
	}
	if d.orderHead*2 < len(d.order) {
		return
	}
	d.order = append(d.order[:0], d.order[d.orderHead:]...)
	d.orderHead = 0
}

// admit frees one slot when the map is at its cap, evicting in creation order.
// Called with the lock held, and O(1) per eviction.
//
// Eviction is FIFO rather than LRU on purpose; see the field comment on
// order. What matters for the bound is not which entry leaves but that one
// does, and that the choice does not cost a scan of the whole map on the
// write path.
func (d *launderingState) admit() {
	for len(d.entries) >= d.maxEntries {
		key := d.popOrder()
		// Empty queue with a full map: the queue and the map have lost sync,
		// which sweep() repairs (it rebuilds the queue from the map). Refusing
		// to evict here is a bounded failure -- one write is skipped -- and
		// preferable to an unbounded one.
		if key == "" {
			d.rebuildOrder()
			if key = d.popOrder(); key == "" {
				return
			}
		}
		delete(d.entries, key)
		d.evicted++
	}
}

// rebuildOrder reconstructs the creation-order queue from the map. The map's
// iteration order is deliberately unspecified, so this is a *fairness* repair,
// not an ordering guarantee: it restores the queue/map correspondence, which
// is what keeps eviction O(1) and the cap enforced. Called with the lock held.
func (d *launderingState) rebuildOrder() {
	d.order, d.orderHead = d.order[:0], 0
	for k := range d.entries {
		d.order = append(d.order, k)
	}
}

// repairQueue rebuilds the creation-order queue when this sweep has killed so
// much of the live queue that walking the dead keys costs more than rebuilding
// it. Called with the lock held.
//
// The trigger is the number of keys the pass actually deleted, not the queue's
// consumed prefix. A prefix-based trigger looks right and is wrong: entries can
// also leave the map without ever being popped -- a sweep's expiry and
// per-fingerprint stages delete in place -- so a queue can be almost entirely
// dead while orderHead is still 0 and "half consumed" is false. The pass that
// produced the damage is the pass that knows how much of it there is, so it
// reports the count.
//
// Two variants of the threshold below are equivalent mutants and are not
// pinned, deliberately. Rebuilding unconditionally, and rebuilding at "half
// dead" rather than "more than half dead", differ only in how often an O(n)
// map walk runs inside a pass that is itself O(n log n) and fires at most once
// per sweepEvery writes. Neither changes an entry bound, an expiry, an
// eviction, or a class the layer emits: popOrder skips dead keys either way,
// so the cap holds without any repair at all. A repair is about not wasting
// work, and "waste less work" is a cost policy, not a promise this component
// makes to anyone -- so pinning it would assert an implementation detail
// rather than a bound.
func (d *launderingState) repairQueue(queuedBefore, deleted int) {
	if deleted*2 > queuedBefore {
		d.rebuildOrder()
	}
}

// sweepIfDue runs the bounded reclaim pass on its amortised schedule: at most
// once per sweepEvery writes. Called with the lock held.
//
// Deliberately NOT also triggered by the map being at its cap. Making room is
// admit()'s job and is O(1) per eviction; running the whole O(n log n) pass
// on every write once the map is full would put a ~78µs cost on the request
// path for as long as an attacker keeps the map full -- which is exactly the
// lever a write path whose cost depends on how full the map is hands out. That
// was measured, not assumed: with the cap clause here, a write against a full
// 512-entry map cost 92µs against 1µs for a write that did not evict.
//
// The cap is still enforced on every write; it is just enforced by admit()'s
// O(1) eviction rather than by a full pass.
func (d *launderingState) sweepIfDue(now time.Time) {
	d.sinceSweep++
	if d.sinceSweep < d.sweepEvery {
		return
	}
	d.sinceSweep = 0
	d.sweep(now)
}

// sweep is the single bounded pass that enforces all three bounds. O(n log n)
// over at most maxEntries entries. Called with the lock held.
//
// Order matters only for how much work each stage does, not for the outcome:
// expiry first (it frees the most), then the global cap, then per-fingerprint
// pressure (which can only then be relieved by the cap's own accounting).
func (d *launderingState) sweep(now time.Time) {
	// The live length of the queue, sampled once so each stage can say how much
	// of the queue it just invalidated.
	queuedBefore := len(d.order) - d.orderHead
	deleted := 0

	// (a) TTL. Age bounds evidence, and this is where the memory of
	// expired evidence goes too, which is why there is no timer.
	for k, e := range d.entries {
		if now.Sub(e.touched) > d.ttl {
			delete(d.entries, k)
			d.expired++
			deleted++
		}
	}
	// Expired keys leave the map without ever being popped, so the queue is
	// now partly stale. popOrder skips what is gone; this rebuilds instead
	// when most of it is.
	d.repairQueue(queuedBefore, deleted)
	if len(d.entries) == 0 {
		// Nothing left, so the queue has nothing to describe either. Resetting
		// it here rather than only at the end is what stops a long-lived
		// detector from accumulating dead keys in the queue between sweeps.
		d.order, d.orderHead = d.order[:0], 0
		return
	}

	// (b) per-fingerprint pressure. One pass to bucket, then drop each
	// over-full bucket's oldest, so this stays n log n rather than the n^2 a
	// repeated "find this fingerprint's oldest" would be.
	buckets := make(map[string][]string, len(d.entries))
	touched := make(map[string]time.Time, len(d.entries))
	for k, e := range d.entries {
		buckets[e.fingerprint] = append(buckets[e.fingerprint], k)
		touched[k] = e.touched
	}
	// Re-anchor on the queue as stage (a) left it: a rebuild above reset the
	// consumed prefix, so the live length is the right basis for stage (b)'s
	// own count.
	queuedBefore = len(d.order) - d.orderHead
	deleted = 0
	for _, keys := range buckets {
		if len(keys) <= d.perFingerprint {
			continue
		}
		sort.Slice(keys, func(i, j int) bool { return touched[keys[i]].Before(touched[keys[j]]) })
		// perFingerprint >= 1 is guaranteed by newLaunderingState, so
		// len(keys)-perFingerprint is in [0, len(keys)).
		for _, k := range keys[:len(keys)-d.perFingerprint] {
			delete(d.entries, k)
			d.evicted++
			deleted++
		}
	}
	// The queue may now name keys the map no longer holds. popOrder skips
	// those, so the correspondence does not have to be repaired here -- but if
	// the queue is more than half dead it is cheaper to rebuild than to walk.
	d.repairQueue(queuedBefore, deleted)

	// (c) the global cap. Belt and braces: admit() already keeps the map
	// under maxEntries, so this fires only if the config lowered maxEntries
	// under a running map.
	if len(d.entries) <= d.maxEntries {
		return
	}
	all := make([]string, 0, len(d.entries))
	for k := range d.entries {
		all = append(all, k)
	}
	// The guard above established len(all) > maxEntries, and
	// newLaunderingState established maxEntries >= 1, so this slice bound is
	// inside the slice by construction rather than by hoping. Eviction here is
	// by touch time rather than creation order: this path runs at most once
	// per 64 writes and is already paying for a sort.
	sort.Slice(all, func(i, j int) bool { return touched[all[i]].Before(touched[all[j]]) })
	for _, k := range all[:len(all)-d.maxEntries] {
		delete(d.entries, k)
		d.evicted++
	}
	// The creation-order queue no longer describes the map, so rebuild it
	// rather than let the next admit() pop slots that are already gone.
	d.rebuildOrder()
}

// report surfaces saturation on stderr, rate-limited. A detector at its cap
// has void coverage, and an operator who cannot see that will read the
// absence of alerts as the absence of attacks. Called with the lock held.
func (d *launderingState) report(now time.Time) {
	if d.evicted == 0 || d.evicted%launderReportEvery != 0 {
		return
	}
	fmt.Fprintf(os.Stderr,
		"http-honeypot: laundering layer C at its evidence cap (%d entries) -- %d evictions, %d expired as of %s; coverage under the cap is not complete\n",
		d.maxEntries, d.evicted, d.expired, now.UTC().Format(time.RFC3339))
}

// launderingStats reports the state of the bounds. Exists so the tests can
// assert them rather than trust them, and so the numbers are reachable
// without exporting anything.
func (d *launderingState) launderingStats() (entries, evicted, expired int) {
	if d == nil {
		return 0, 0, 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries), d.evicted, d.expired
}

// observeLaundering is the ServeHTTP seam. See the file header for where the
// state lives and why; this is the whole integration.
//
// Two rules that are not obvious from the call site:
//
// The halves are recorded whether or not this request is labelled. A probe
// that some more specific class already claimed still tells us the OData
// surface exists, and dropping that would lose the pair.
//
// The label is written only into an empty PayloadClass. classifyPayload
// names something more specific when it fires, and #3443's own ordering rule
// -- most identifying shape first, first match wins -- applies here too: this
// layer is the last case, not the first.
func (s *server) observeLaundering(r *http.Request, e *event, body string) {
	if s.launder == nil {
		return
	}
	if got := s.launder.observe(launderingFingerprint(r), r.URL.Path, r.URL.RawQuery, body); got != "" && e.PayloadClass == "" {
		e.PayloadClass = got
	}
}

// launderResource derives the correlation key's resource half from a decoded
// path: the path with its last segment removed, so `/api/products/Items` and
// `/api/products/%2561` are the same resource and therefore comparable.
//
// Returns "" for anything not comparable, and "" is the reason several
// over-match shapes cannot fire:
//
//   - the root, and any single-segment path. A real OData service has a
//     collection (`/odata/Products`); a `$filter` on the decoy's landing page
//     binds to nothing, and admitting it would make "/" a resource every
//     request on the sensor shares.
//   - a trailing slash is the collection itself, so `/api/products` and
//     `/api/products/` agree -- `/api` -- rather than disagreeing on a slash
//     an attacker controls.
//   - over the length or depth cap, so the key is bounded.
//
// Lowercased, because the decoy's own dispatch is case-insensitive
// (serve() lowercases before matching) and an attacker varying case is not
// evidence of a different resource.
func launderResource(decodedPath string) string {
	// Empty segments are collapsed first, and this is not tidiness. Without
	// it, `//Products` and `/Products` -- which every HTTP server routes
	// identically, and which a scanner emits to slip a naive path filter --
	// produce different keys, and `//x` produces the resource "/" while a
	// different `//y` also produces "/": two unrelated collections sharing
	// one key, which is precisely the over-match this layer must not have.
	// Collapsing makes the key agree with what the decoy actually dispatched.
	p := collapseSlashes(strings.ToLower(decodedPath))
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	i := strings.LastIndexByte(p, '/')
	// The root and any single-segment path are not a resource. This guard is
	// exactly equivalent to letting i == 0 fall through, because p[:0] is the
	// empty string and "" is not a usable key -- so no test can distinguish
	// the two forms, and TestLaunderResource pins the behaviour instead. It
	// is kept because it states the reason rather than relying on a reader
	// noticing that a zero-length slice is falsy.
	if i <= 0 {
		return ""
	}
	res := p[:i]
	if len(res) > launderMaxResourceLen {
		return ""
	}
	if strings.Count(res, "/") > launderMaxResourceSegments {
		return ""
	}
	return res
}

// collapseSlashes reduces every run of '/' to a single one, so the key
// reflects the path the decoy dispatched rather than the exact bytes a
// scanner chose to send. Bounded by the input length, which ServeHTTP has
// already bounded, and allocates once per call on a request that carried a
// half -- the write filter in observe() has already run by then.
func collapseSlashes(p string) string {
	if !strings.Contains(p, "//") {
		return p
	}
	var b strings.Builder
	b.Grow(len(p))
	prevSlash := false
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '/' {
			if prevSlash {
				continue
			}
			prevSlash = true
		} else {
			prevSlash = false
		}
		b.WriteByte(c)
	}
	return b.String()
}

// pathBorneResidualEscape reports whether a *decoded* path still holds a
// %XX escape, which is the shape #3443 could not see: the value never appears
// in a query key, it appears in the path after the server's own one decode.
//
// The path is scanned and the query is not. That separation is the whole
// layer: the query-side equivalent is #3443's odata-double-encode-probe,
// which is decided in-request and needs none of this.
//
// The published bypass decodes to a plain letter ('a' from %2561), so this
// deliberately does not require the escape to be a path metacharacter --
// requiring one would miss the published shape, which is the shape that
// matters.
func pathBorneResidualEscape(decodedPath string) bool {
	return residualEscape(decodedPath)
}

// qualifyingODataRequest reports whether a request is a well-formed OData
// system query against a collection path -- the first half of the pair.
//
// "Well-formed" is doing the real work here, and it is the direct answer to
// the over-match trap #3447 names. An OData *option name* is cheap: `?$top=1`
// on any parameter of any application is an option-shaped value on an
// unrelated key, and a detector that fires on those is a false-positive
// machine. So the name is necessary and nowhere near sufficient:
//
//   - the name must be a real OData system option, compared after any
//     namespace-alias prefix, case-insensitively, on parsed keys (so `$filter`
//     inside some other *value* cannot produce it);
//   - the value must be type-consistent with that option -- $top and $skip a
//     bare integer, $format a known format token, $select an identifier list,
//     $orderby an identifier with an optional sort direction, $filter and
//     $search an expression carrying an OData operator and a literal;
//   - the request must be against a collection, not the root.
//
// A client probing an OData surface sends a query that parses as one, because
// it has to: it is looking for a response. A parameter that happens to be
// named $filter does not.
func qualifyingODataRequest(decodedPath, query, body string) bool {
	if launderResource(decodedPath) == "" {
		return false
	}
	for _, raw := range []string{query, body} {
		values, err := url.ParseQuery(raw)
		if err != nil && len(values) == 0 {
			continue
		}
		for key, vals := range values {
			name := strings.ToLower(key)
			if i := strings.LastIndexByte(name, '.'); i >= 0 {
				name = name[i+1:]
			}
			if !odataSystemOptions[name] {
				continue
			}
			for _, v := range vals {
				if odataValueConsistent(name, v) {
					return true
				}
			}
		}
	}
	return false
}

// odataValueConsistent reports whether v is a value that option could
// plausibly have been sent with by something talking to an OData service.
func odataValueConsistent(option, v string) bool {
	val := strings.TrimSpace(v)
	if val == "" {
		return false
	}
	switch option {
	case "$top", "$skip":
		return odataBoundedInt(val, 9)
	case "$count":
		// OData v4 allows $count=true as well as an integer.
		return odataBoundedInt(val, 9) || strings.EqualFold(val, "true") || strings.EqualFold(val, "false")
	case "$format":
		switch strings.ToLower(val) {
		case "json", "xml", "text", "atom", "json-verbose", "jsonminimalmetadata",
			"jsonfullmetadata", "minimalmetadata", "fullmetadata", "xmlfull":
			return true
		}
		return false
	case "$select", "$expand":
		if val == "*" {
			return true
		}
		for _, part := range strings.Split(val, ",") {
			if !odataIdentifierPath(strings.TrimSpace(part)) {
				return false
			}
		}
		return true
	case "$orderby":
		for _, part := range strings.Split(val, ",") {
			fields := strings.Fields(strings.TrimSpace(part))
			if len(fields) == 0 || !odataIdentifierPath(fields[0]) {
				return false
			}
			if len(fields) == 1 {
				continue
			}
			if len(fields) != 2 || !strings.EqualFold(fields[1], "asc") && !strings.EqualFold(fields[1], "desc") {
				return false
			}
		}
		return true
	case "$filter":
		// An operator *and* a literal. Either alone is not a query anybody
		// sends: `$filter=eq` is not a filter, and `$filter=2026` is an
		// ordinary parameter wearing an option's name.
		idents, literal := odataTokens(val)
		if !literal {
			return false
		}
		for _, id := range idents {
			if odataOperators[id] {
				return true
			}
		}
		return false
	case "$search":
		// Asymmetric with $filter, deliberately. $search takes free text, so
		// demanding a literal would be meaningless -- and demanding nothing
		// would make `?$search=anything` on any application's collection
		// path an OData surface, which is the over-match this gate exists to
		// prevent. So an operator token is the bar: a bare word is not
		// evidence, a structured search is.
		idents, _ := odataTokens(val)
		for _, id := range idents {
			if odataOperators[id] {
				return true
			}
		}
		return false
	case "$skiptoken", "$apply", "$index":
		// No shape worth guessing at; presence on a collection is the signal.
		return true
	}
	return false
}

// odataOperators are the OData comparison, logical and query functions,
// matched as whole identifier tokens and never as substrings. Substring
// matching is what would make `year%20eq%25202026` look like a filter
// expression, and that string is a double-encoded probe that #3443 already
// owns under a different class.
var odataOperators = map[string]bool{
	"eq": true, "ne": true, "gt": true, "ge": true, "lt": true, "le": true,
	"and": true, "or": true, "not": true, "in": true,
	"contains": true, "startswith": true, "endswith": true, "substringof": true,
	"indexof": true, "length": true, "tolower": true, "toupper": true,
	"trim": true, "concat": true, "substring": true, "replace": true,
	"year": true, "month": true, "day": true, "hour": true, "minute": true,
	"second": true, "mindatetime": true, "maxdatetime": true, "now": true,
}

// odataTokens splits an expression into lowercased identifier tokens and
// reports whether it carries a literal -- a quoted string or a number. Both
// are required: an operator alone (`$filter=eq`) is not a query anybody
// sends, and a literal alone is an ordinary parameter.
func odataTokens(s string) ([]string, bool) {
	var idents []string
	literal := false
	var run strings.Builder
	flush := func() {
		if run.Len() == 0 {
			return
		}
		tok := strings.ToLower(run.String())
		run.Reset()
		if odataAllDigits(tok) {
			literal = true
			return
		}
		idents = append(idents, tok)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' || c == '"':
			// A quoted literal counts even when it is empty, which is what
			// `$filter=Name eq ''` sends.
			literal = true
			flush()
			for i++; i < len(s) && s[i] != c; i++ {
			}
		case odataIdentByte(c):
			run.WriteByte(c)
		default:
			flush()
		}
	}
	flush()
	return idents, literal
}

func odataIdentByte(c byte) bool {
	return c == '_' || odataAlpha(c) || (c >= '0' && c <= '9')
}

func odataAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func odataAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// odataBoundedInt reports whether s is an integer with at most maxDigits
// digits, so $top=99999999999999 (a scanner padding) is not read as a
// client's page size.
func odataBoundedInt(s string, maxDigits int) bool {
	return odataAllDigits(s) && len(s) <= maxDigits
}

// odataIdentifierPath reports whether s is a dotted identifier path with no
// operators, no literals and no punctuation -- `Year`, `Address.City`,
// `Address/City`.
func odataIdentifierPath(s string) bool {
	if s == "" || len(s) > launderMaxResourceLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !odataIdentByte(c) && c != '.' && c != '/' {
			return false
		}
	}
	return true
}

// launderingFingerprint is the correlation key's client half.
//
// Deliberately NOT keyed on the source address. #3430's technique 2 is relay
// laundering, and its whole effect is to make the source address worthless: a
// per-IP rule sees one request from a public scanner and stops. A relay
// changes the address; it does not change the HTTP client stack that emitted
// the headers, so User-Agent / Accept / Accept-Language / Accept-Encoding and
// the Host are what survives the laundering. This is #3430's own observation
// -- correlate on a header-set hash rather than on IP -- applied inside the
// sensor, at a window of minutes, instead of in the backend, over an
// unbounded window.
//
// The cost of that choice is stated rather than hidden: every curl on the
// internet shares this fingerprint, so the fingerprint alone is not evidence
// of anything. It is a bucket, and the resource binding plus the two
// value-consistency tests are what make a bucket worth reading.
func launderingFingerprint(r *http.Request) string {
	return launderingFingerprintOf(r.Host, r.Header)
}

// launderingFingerprintOf is the testable core of the fingerprint.
func launderingFingerprintOf(host string, header http.Header) string {
	h := sha256.New()
	write := func(s string) {
		if len(s) > launderFingerprintBytes {
			s = s[:launderFingerprintBytes]
		}
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	write(host)
	for _, name := range []string{"User-Agent", "Accept", "Accept-Language", "Accept-Encoding"} {
		write(header.Get(name))
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}
