# #3447 — scanner-laundering layer C: the stateful component

Status: implemented. The two design questions the issue named are answered in
`arcane/home/honeypot-http/http-honeypot/laundering.go`, in the file header,
next to the code they govern. This document is the summary and the record of
what was measured.

## The shape

`#3430`'s double-encoding bypass is `%2561` → `%61` → `a`: a **path** segment
that survives one decode and only becomes a character after the next. The
escape never appears in a query key, so `#3443`'s in-request classifier
(`classifyPayload(RawQuery, body)`) cannot see it. `#3443`'s agent could have
closed the gap by reconstructing the bypass in a query — scan every key for a
residue, claim the request because some unrelated key elsewhere held an OData
option — and refused to, pinning the reconstruction as a negative test. That
refusal is why this issue exists in the right shape.

The refusal is preserved here as a structural property rather than as
restraint: see *The over-match trap* below.

## Question 1 — where does the state live?

**In the `server` struct, in this process's heap, in the request pipeline, and
outliving the request.** One `map[string]*launderingEntry` behind one
`sync.Mutex`, owned by `*server`, read and written by `ServeHTTP` on every
request. An entry written by request N is read by request N+1.

| Option considered | Verdict | Why |
|---|---|---|
| per-connection | rejected | A relay-laundering client is not the connection it arrives on, and `#3430`'s technique 2 is exactly that the source address is worthless. A per-connection key would miss the attack it exists for *and* be destroyed by ordinary keep-alive churn. |
| on-disk | rejected | A second file on the hot path of a process that is *meant* to be attacked is a second thing to fill. The durable record is already the event log, and Elasticsearch can window it after the fact. Nothing here needs to survive a restart — the evidence is minutes old, so a restart loses a window, not a fact. |
| in the request pipeline | **chosen** | It is the only place where the class can still be attached to the event. A post-hoc log query cannot retro-label an already-written event, which is the whole deliverable. |

The counterweight: `classifyPayload` stays pure. It is never given the path,
the headers, or any history, and `TestLayerCIsTheFirstStateThisPackageKeeps`
asserts that by calling it over the whole pinned corpus before and after the
detector has run.

## Question 2 — how is it bounded?

Three independent bounds, because they bound different things.

| Bound | Value | Bounds | Config |
|---|---|---|---|
| `launderMaxEntries` | 512 | memory | `LAUNDER_MAX_ENTRIES` |
| `launderPerFingerprint` | 8 | one client's share of the cap | `LAUNDER_PER_FINGERPRINT` |
| `launderTTL` | 10 min | age of *evidence* | `LAUNDER_TTL_SECONDS` |

Plus two key-shape caps (`launderMaxResourceLen` 128 bytes,
`launderMaxResourceSegments` 8) so an attacker-controlled path cannot become
an unbounded map key, and one fingerprint-input cap (512 bytes).

**At the cap:** evict the oldest and count it. Not "refuse new entries" — a
flood would switch the detector off — and not "grow", which is the
memory-growth bug `#3447` names. Evictions are counted and reported on stderr
every 1000, because a detector at its cap has **void coverage** and an
operator who cannot see that will read the absence of alerts as the absence of
attacks.

**No timer, no ticker, no goroutine.** TTL is checked on read, and the memory
of expired evidence is reclaimed by the same amortised `O(n log n)` pass that
enforces the cap (at most once per 64 writes). There is nothing here that can
leak a goroutine per deployment.

**The cap has a second structure behind it.** Eviction is FIFO off a
creation-order queue rather than a scan for the least-recently-used entry, so
it is O(1) per eviction instead of O(n) on the request path. That queue is
itself bounded: it compacts when half its prefix is consumed, and the sweep
rebuilds it when the pass has killed more than half of it. The bounds are
therefore on *memory* and on *eviction cost* together, and both are pinned.

**What keeps the bounds from mattering much:** an entry is only created for a
request that carried *one of the two halves*. Ordinary traffic neither writes
nor touches the map, so the cap is not in ordinary traffic's hands. Asserted
over the pinned 31-entry corpus at two-segment paths, which are usable keys —
a single-segment path is rejected by `launderResource` and would make the
assertion pass for the wrong reason.

**One-shot.** A completed pair deletes its entry, so a scanner replaying the
pair a thousand times gets one event. This is the bound on alert volume under
attack, and it is what keeps a false positive from becoming a flood.

## The over-match trap

`#3447` names the failure mode: fire because an *unrelated* key happened to
hold an option-shaped value. Three mechanisms, in order of strength:

**1. The same-request rule — structural.** A single request carrying both
halves seeds the state and returns `""`. The pair can only complete on a
*later* request. There is no code path on which "this request had an OData
option and something else had a residue" can reach a return value. This is
why `#3443`'s pinned negative keeps its `want: ""` — the trap is now
impossible by construction rather than avoided by policy.
(`TestLayerCSameRequestNeverFires`; removing the rule fails the test.)

**2. The binding.** The key is `(fingerprint, resource)`, never the client
alone. "This client once sent an OData option" is evidence about the internet.
"This client sent an OData option for *this collection* and then sent a
double-decoding segment *under that same collection*" is evidence about a
bypass. The resource is the path minus its last segment, so the probe and the
bypass — necessarily different paths — are siblings. The root is not a
resource, or every request on the sensor would share one bucket.

**3. The value-consistency gate.** An OData *option name* is cheap: `?$top=1`
on any application is an option-shaped value. So the value must also be
type-consistent with the option — `$top`/`$skip` a bare bounded integer,
`$format` a known token, `$select` an identifier list, `$orderby` an
identifier with an optional direction, `$filter` an operator *and* a literal,
`$search` an operator token (asymmetric on purpose: `$search` takes free text,
so demanding a literal is meaningless and demanding nothing makes
`?$search=anything` an OData surface). Keys are parsed, never
substring-matched, so `$filter` inside another value cannot trigger it.

`TestLayerCOverMatchNeedsThePairToBePresent` is the table that makes this
load-bearing: each non-surface is sent, then the *real* published bypass is
sent at the same resource from the same fingerprint, and nothing may fire.
A control with a consistent value must fire, so the table is a real gate and
not a component that never fires.

### The fingerprint

Deliberately **not** keyed on the source address — that is `#3430`'s own
observation, applied inside the sensor: a relay changes the address, not the
HTTP client stack. The key is `Host` + `User-Agent` + `Accept` +
`Accept-Language` + `Accept-Encoding`, hashed. `X-Forwarded-For` is excluded on
purpose, or an attacker could partition the key at will by forging it.

The cost is stated rather than hidden: every curl on the internet shares this
fingerprint, so the fingerprint alone is evidence of nothing. It is a bucket;
mechanisms 2 and 3 are what make a bucket worth reading.

## The `#3443` pin: examined, and deliberately kept

The brief said `#3443`'s negative "fails if this ever starts matching" and
would need updating when layer C lands. It was examined against the landed
code. **Its expectation does not need changing**, and the reasoning is recorded
in `odata_double_encode_test.go` at the pin itself:

1. Layer C does not reach the case. The escape half is read from the **path**
   (`pathBorneResidualEscape`); `%2561` as a *query key* is `#3443`'s
   territory, so it is not a half for this layer and cannot complete a pair.
   Even replayed twice it does not fire.
2. More generally, the same-request rule makes an in-request option-vs-unrelated-escape
   match impossible in code, not by policy.

So the trap is structurally impossible rather than merely avoided, and
relaxing the pin would *reopen* the trap rather than record progress. Changing
`want` to the new class would have required fabricating the query form into a
match — the exact move `#3443`'s agent refused. That is recorded, not done.

What *did* change, and is pinned elsewhere:

- `TestScannerLaunderingLayersNotImplementable` said "There is no map, no cache
  and no per-source counter in the package — an in-request classifier by
  construction." That is now false in one place. Amended in place, with the
  narrowness of the amendment spelled out, plus an assertion that `#3443`'s
  own class still works and its layers are still unimplementable.
- `TestLaunderingClassIsNotA3430Layer` asserts the two classes are unreachable
  from each other's inputs, in both directions.
- `TestLayerCCatchesThePublishedPathBorneBypass` fires on the real two-request
  shape the path actually produces.

Note on naming: `#3430`'s layer C (cross-source header-fingerprint clustering
over an event window) and `#3447`'s "layer C" are **different things under the
same name**. `#3447` does not implement `#3430`'s layer C and does not make it
implementable — a bounded map keyed by `(fingerprint, resource)` is a pairing
over one client and one collection, not a window over the fleet.

## Measured

```
corpus entries (#3443 pinned fixture):        31
layer C claims, 2 passes:                      0 []
layer C entries allocated, 2-segment paths:    0
published shapes (#3443, unchanged):      14 caught, 0 missed []
ungated residual-escape (unchanged):           3   <- #3443's own measurement, same number
```

Both load-bearing zeros are **asserted, not logged**, so a future corpus
sample containing these shapes fails the test instead of letting the number
drift.

Test counts, same package, `#3443`'s head vs this branch:

```
pr-3443:  75 top-level / 111 subtests / 0 fail
#3447:    97 top-level / 154 subtests / 0 fail
```

No existing test was edited, weakened or skipped. `gofmt -l` clean, `go vet`
clean, `go test -race` clean.

### Mutation-checked

44 mutants, applied one at a time to the shipped source, 42 killed. Each
killed mutant turns the suite red:

| Removed | Failing test |
|---|---|
| the same-request rule | `TestLayerCSameRequestNeverFires` |
| the value-consistency gate | `TestLayerCOverMatchNeedsThePairToBePresent` (7 subtests) |
| the `$filter` literal requirement | `TestQualifyingODataAcceptsAliasedOptions` |
| the `$search` asymmetry | `TestQualifyingODataRequestIsRootBlind` |
| slash collapsing | `TestLayerCBindsToResourceAndFingerprint` |
| the resource half of the key | `TestLayerCBindsToResourceAndFingerprint` |
| the fingerprint half of the key | `TestLayerCBindsToResourceAndFingerprint` |
| `User-Agent` from the fingerprint | `TestLayerCFingerprintUsesEveryHeaderItClaimsTo` |
| `Cookie` into the fingerprint | `TestLayerCFingerprintUsesEveryHeaderItClaimsTo` |
| `X-Forwarded-For` into the fingerprint | `TestLaunderingFingerprintSurvivesRelayLaundering` |
| eviction at admission | `TestLayerCIsBounded/cap_is_enforced_without_waiting_for_a_sweep` |
| the eviction counter | `TestLayerCIsBounded` (report/`evicted` assertions) |
| `pushOrder` | `TestLayerCIsBounded/eviction_drops_the_oldest_not_an_arbitrary_entry` |
| `admit()`'s queue resync | `TestLayerCIsBounded/an_empty_queue_against_a_full_map_costs_one_write_not_the_bound` |
| the sweep's per-fingerprint stage | `TestLayerCIsBounded/one_fingerprint_cannot_hold_the_whole_map` |
| the sweep's global-cap stage | `TestLayerCIsBounded/lowering_the_cap_takes_effect_at_the_next_sweep` |
| the sweep's TTL reclaim | `TestLayerCIsBounded/a_sweep_reclaims_expired_entries` |
| either read-time TTL check | `TestLayerCIsBounded/an_expired_half_does_not_complete_a_pair` |
| the write filter | `TestLayerCIsBounded/traffic_that_is_neither_half_allocates_nothing` |
| entry consumption on fire | `TestLayerCFiringIsOneShotInTheHandler` |
| `PayloadClass` precedence | `TestLayerCIsBounded/a_more_specific_class_is_not_overwritten` |
| the resource length/depth cap | `TestLaunderResource` |
| the `$top` digit bound | `TestQualifyingODataRequestIsRootBlind` |
| the aliased-option name | `TestQualifyingODataAcceptsAliasedOptions` |
| either config clamp | `TestLayerCDegenerateConfigStaysBounded` |
| the whole queue self-repair | `TestLayerCIsBounded` (both partial-repair subtests) |
| the repair after the expiry stage | `TestLayerCIsBounded/the_queue_is_repaired_when_expiry_alone_empties_most_of_it` |
| the repair after the per-fingerprint stage | `TestLayerCIsBounded/the_queue_is_repaired_when_the_map_is_only_partly_emptied` |
| either stage's delete counter | the same two subtests, respectively |
| the `*2` in the repair threshold | both partial-repair subtests |
| the re-anchor between the two stages | `TestLayerCIsBounded/the_second_stage_re-reads_the_queue_after_the_first_rebuilds_it` |
| the `ServeHTTP` seam | `TestLayerCEndToEndThroughServeHTTP` |
| the `HTTP_LAUNDERING` off switch | `TestLayerCDisabledIsSafe` |
| the shipped defaults / env fallbacks | `TestLayerCDefaultsAreTheArguedValues` |

**This pass found a real bug, not just a missing test.** The queue self-repair
originally triggered on the *consumed prefix* (`orderHead * 2 >= len(order)`),
which looks right and is wrong: a sweep's expiry and per-fingerprint stages
delete keys **in place**, without ever popping them, so a queue can be almost
entirely dead while `orderHead` is still `0` and "half consumed" is false. The
repair never fired. It now triggers on the number of keys the pass actually
deleted — the pass that did the damage is the pass that knows how much of it
there is — and the threshold re-reads the queue's live length between stages,
because a rebuild in stage (a) makes the length stage (b) started with stale.
Three tests were added rather than the mutant being accepted: one for each
stage, and one for the re-anchor.

#### The two survivors, and why they are not pinned

Both are the same `repairQueue` threshold, and both are genuinely equivalent:
rebuilding the queue *unconditionally*, and rebuilding at "half dead" rather
than "more than half dead". Neither changes an entry bound, an expiry, an
eviction, or a class the layer emits — `popOrder` skips dead keys, so the cap
holds with no repair at all. A repair exists to avoid *wasted work*, and how
often a pass spends CPU on its own bookkeeping is a cost policy, not a promise
the component makes. Pinning it would assert an implementation detail. Both
are recorded in the code at the threshold. The equivalent-mutant note in
`launderResource` (the `i <= 0` root guard, where `p[:0]` is also `""`) is
recorded the same way.

An earlier pass of this check found four further tests that passed under a
mutation they were supposed to catch (the cap only showed up in a long test
that also triggered sweeps; the root-blindness and `PayloadClass`-precedence
cases had no test at all). Those tests were added rather than the mutations
being accepted.

## Not validated, and stated as such

- **Volume against the live corpus.** That needs the deployed sensor and the
  `honeypot-v2-*` indices, neither reachable from a PR. The zero above is
  measured against the fixture on `main` (#1888's 30-day window, mirrored
  entry-for-entry in `payload_test.go`), not the fleet.
- **Whether a real laundering campaign produces this pair.** No capture exists;
  `#3430` is a research note citing a public third-party investigation. The
  positives follow the published shapes. If a real campaign probes and exploits
  on *different* collections, or rotates its client stack between the two
  requests, this layer misses it. That is a false-negative cost of the binding
  in mechanism 2, and it is a deliberate trade for the over-match protection.
- **The 10-minute TTL** has no measured cadence behind it. It is the order of
  magnitude a manual probe and a scripted sweep share. It is configurable for
  exactly that reason.
- **No de-risking by making the gate stricter after the fact.** If the
  per-fingerprint or value-consistency gates turn out to be too tight in
  production, the honest response is to measure that, not to relax a bound
  quietly.

## Rollout

Rebuild and redeploy `honeypot-http` on the homeserver. **No new event field**
— the layer writes into the existing `payload_class` — so `openapi.json` needs
no regeneration.

New configuration, all with working defaults, no action required:
`HTTP_LAUNDERING=0` to disable, `LAUNDER_MAX_ENTRIES`,
`LAUNDER_PER_FINGERPRINT`, `LAUNDER_TTL_SECONDS` to move the bounds.

Worth watching after deploy: `evicted` climbing steadily means the cap is
below what the fleet's traffic needs, and the stderr line says so every 1000
evictions.

## Security

- [x] No real credentials, private addresses, payloads, PCAPs, keys or `.env`
  files. Test addresses are RFC 5737 documentation ranges (`203.0.113.0/24`).
- [x] Inert fixtures only. No live endpoint, no attack traffic, no docker, no
  production Elasticsearch, no GPU, no model load. Tests drive
  `ServeHTTP` against an `httptest` recorder.
- [x] No new exposed port or route. The listener is untouched.
- [x] Bounded cost on the hot path: the write filter runs before the lock, the
  common case is two cheap string scans and no contention, the body is already
  capped at 64 KiB by `ServeHTTP`, and the amortised pass runs at most once per
  64 writes.
- [x] The new map is the only cross-request state in the package, enumerated
      and pinned in `TestLayerCIsTheOnlyCrossRequestComponent`.
