package main

// identity.go -- #1200: the missing piece #1204's gap analysis called out
// entirely: campaigns (#1199) are CIDR-scoped and recomputed from scratch
// every cycle; clusters (#1199) are fingerprint/payload/ASN buckets with
// no merge across signal types. Neither produces a durable attacker
// *entity* -- an IP is not a stable identity, and nothing ties an actor's
// appearances across IP churn into one profile. This does: it merges IPs
// into persistent entities when they share 2+ strong signals (fingerprint,
// payload SHA-256, credential pair) -- a single shared signal never merges
// two IPs alone, per the epic's own "decided up front" tunable, which it
// flags as something to revisit once real merge behavior is observed
// live. That observation starts now, not before.
//
// Unlike campaigns-v1/attacker-clusters-v1 (correlator-worker, #1199),
// entities here are durable: an entity, once created, is never deleted for
// going quiet, and its member IPs/signals only ever grow, never shrink.
// The one exception is entity-to-entity merging (see mergeEntityInto)
// when two previously-separate entities turn out to share a member.

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// signalSet is the (fingerprints, payloads, creds) a single IP or an
// entity carries -- the common shape sharedSignalCount compares.
type signalSet struct {
	fingerprints map[string]bool
	payloads     map[string]bool
	creds        map[string]bool
}

func newSignalSet() signalSet {
	return signalSet{fingerprints: map[string]bool{}, payloads: map[string]bool{}, creds: map[string]bool{}}
}

func (s signalSet) merge(other signalSet) {
	for k := range other.fingerprints {
		s.fingerprints[k] = true
	}
	for k := range other.payloads {
		s.payloads[k] = true
	}
	for k := range other.creds {
		s.creds[k] = true
	}
}

func intersects(a, b map[string]bool) bool {
	small, big := a, b
	if len(b) < len(a) {
		small, big = b, a
	}
	for k := range small {
		if big[k] {
			return true
		}
	}
	return false
}

// sharedSignalCount is the merge criterion's core: how many of the three
// signal categories (fingerprint/payload/cred) have at least one value in
// common between a and b. >=2 is a merge; 0 or 1 is not, regardless of how
// many individual values overlap within that one category.
func sharedSignalCount(a, b signalSet) int {
	n := 0
	if intersects(a.fingerprints, b.fingerprints) {
		n++
	}
	if intersects(a.payloads, b.payloads) {
		n++
	}
	if intersects(a.creds, b.creds) {
		n++
	}
	return n
}

// mergeThreshold is the epic's own tunable -- see this file's header for
// why it's a constant here rather than something derived, and #1205's own
// "decided up front" note that it's expected to be revisited once real
// merge behavior is observed live.
const mergeThreshold = 2

// ipObservation is one IP's accumulated signals from a single fetch
// window -- buildIPObservations' output, resolveIdentities' input.
type ipObservation struct {
	ip         string
	signals    signalSet
	sensors    map[string]bool
	techniques map[string]bool
	first      time.Time
	last       time.Time
	events     int
}

// buildIPObservations groups a fetch window's events by source IP.
func buildIPObservations(evs []corrEvent) map[string]*ipObservation {
	out := map[string]*ipObservation{}
	for _, e := range evs {
		o := out[e.SrcIP]
		if o == nil {
			o = &ipObservation{ip: e.SrcIP, signals: newSignalSet(), sensors: map[string]bool{}, techniques: map[string]bool{}}
			out[e.SrcIP] = o
		}
		o.events++
		o.sensors[e.Sensor] = true
		for _, t := range e.Techniques {
			if t != "" {
				o.techniques[t] = true
			}
		}
		if e.Fingerprint != "" {
			o.signals.fingerprints[e.Fingerprint] = true
		}
		if e.Shasum != "" {
			o.signals.payloads[e.Shasum] = true
		}
		if validCredentialPair(e.User, e.Pass) {
			o.signals.creds[e.User+" / "+e.Pass] = true
		}
		if o.first.IsZero() || e.When.Before(o.first) {
			o.first = e.When
		}
		if e.When.After(o.last) {
			o.last = e.When
		}
	}
	return out
}

// entity is one durable attacker identity -- attackers-v1's own document
// shape (json tags define the stored field names).
type entity struct {
	ID           string   `json:"id"`
	IPs          []string `json:"ips"`
	Fingerprints []string `json:"fingerprints"`
	Payloads     []string `json:"payloads"`
	Credentials  []string `json:"credentials"`
	Sensors      []string `json:"sensors"`
	Events       int      `json:"events"`
	First        string   `json:"first"`
	Last         string   `json:"last"`
	Updated      string   `json:"updated"`
	Verdicts     []string `json:"verdicts,omitempty"`
	// Techniques (#1260) is this entity's own durable MITRE ATT&CK
	// technique-coverage document -- the union of every canonical_attck_
	// techniques (#1261) ID any member IP's events have carried, folded in
	// by absorb/mergeEntityInto the same way Sensors already is. Unlike
	// the dashboard's own aggregateTechniques (still the correct, complete
	// per-session/per-attacker-page computation -- see #1260's own
	// follow-up comment for why that stays untouched), this is scoped to
	// only the techniques ip-enrichment-worker can derive from fields it
	// already promotes (T1110/T1059.x/T1105/T1595 -- not T1190 or the ICS
	// techniques, which need fields no worker in this pipeline promotes
	// today).
	Techniques []string `json:"techniques,omitempty"`

	// unexported working state, not persisted -- rebuilt from the fields
	// above via entitySignals when an existing doc is loaded.
	ipSet        map[string]bool
	sensorSet    map[string]bool
	techniqueSet map[string]bool
	signals      signalSet
}

func entitySignals(e *entity) signalSet {
	if e.signals.fingerprints != nil {
		return e.signals
	}
	s := newSignalSet()
	for _, v := range e.Fingerprints {
		s.fingerprints[v] = true
	}
	for _, v := range e.Payloads {
		s.payloads[v] = true
	}
	for _, v := range e.Credentials {
		s.creds[v] = true
	}
	e.signals = s
	return s
}

func entityIPSet(e *entity) map[string]bool {
	if e.ipSet != nil {
		return e.ipSet
	}
	m := map[string]bool{}
	for _, ip := range e.IPs {
		m[ip] = true
	}
	e.ipSet = m
	return m
}

func entitySensorSet(e *entity) map[string]bool {
	if e.sensorSet != nil {
		return e.sensorSet
	}
	m := map[string]bool{}
	for _, s := range e.Sensors {
		m[s] = true
	}
	e.sensorSet = m
	return m
}

func entityTechniqueSet(e *entity) map[string]bool {
	if e.techniqueSet != nil {
		return e.techniqueSet
	}
	m := map[string]bool{}
	for _, t := range e.Techniques {
		m[t] = true
	}
	e.techniqueSet = m
	return m
}

// parseStamp turns a stored RFC3339 timestamp back into an instant, zero
// when the string is empty or unparseable -- the read-side counterpart to
// every `.UTC().Format(time.RFC3339)` write site in this file (#2341).
// Ordering decisions are made on time.Time, never on the rendered strings:
// an off-UTC container renders observations in local time, and documents
// carried over from a bad era may hold non-Z offsets, so lexicographic
// comparison of RFC3339 strings misorders first/last-seen across them.
func parseStamp(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// absorb folds o's IPs/signals/sensors/techniques/events/time-range into e
// in place.
func absorb(e *entity, o *ipObservation) {
	entityIPSet(e)[o.ip] = true
	entitySignals(e).merge(o.signals)
	sensors := entitySensorSet(e)
	for s := range o.sensors {
		sensors[s] = true
	}
	techniques := entityTechniqueSet(e)
	for t := range o.techniques {
		techniques[t] = true
	}
	e.Events += o.events
	// #2341: adopt by instant, not by rendered string -- the pre-fix path
	// formatted o.first without .UTC() and compared it straight against the
	// stored stamp, so off-UTC containers (or mixed-offset stored docs)
	// misordered first-seen. parseStamp gives e.First back as a time.Time;
	// adoption still re-renders through .UTC() so the index keeps pure-Z.
	if first := parseStamp(e.First); !o.first.IsZero() && (first.IsZero() || o.first.UTC().Before(first)) {
		e.First = o.first.UTC().Format(time.RFC3339)
	}
	if last := parseStamp(e.Last); !o.last.IsZero() && o.last.UTC().After(last) {
		e.Last = o.last.UTC().Format(time.RFC3339)
	}
}

// mergeEntityInto folds b's members/signals into a in place (a survives,
// b is discarded by the caller -- resolveIdentities returns b's ID in its
// "absorbed" list so main.go can delete that now-stale document).
func mergeEntityInto(a, b *entity) {
	for ip := range entityIPSet(b) {
		entityIPSet(a)[ip] = true
	}
	entitySignals(a).merge(entitySignals(b))
	for s := range entitySensorSet(b) {
		entitySensorSet(a)[s] = true
	}
	for t := range entityTechniqueSet(b) {
		entityTechniqueSet(a)[t] = true
	}
	a.Events += b.Events
	// #2341: same instant-not-string rule as absorb -- both sides come from
	// stored documents and may be in mixed offsets until rewritten; the
	// really-earlier/really-later instant wins, re-rendered through UTC().
	if bf := parseStamp(b.First); !bf.IsZero() {
		if af := parseStamp(a.First); af.IsZero() || bf.Before(af) {
			a.First = bf.UTC().Format(time.RFC3339)
		}
	}
	if bl := parseStamp(b.Last); !bl.IsZero() && bl.After(parseStamp(a.Last)) {
		a.Last = bl.UTC().Format(time.RFC3339)
	}
}

func newEntityID(seedIP string, at time.Time) string {
	sum := sha256.Sum256([]byte("attacker:" + seedIP + ":" + at.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(sum[:16])
}

// resolveIdentities merges this cycle's per-IP observations into existing,
// returning the full set of entities that changed this cycle (new or
// updated -- callers write these) and the IDs of any entity absorbed into
// another and therefore now stale (callers delete these). Entities that
// didn't change this cycle are neither returned nor touched -- durable
// identity means "leave it alone until there's new evidence", not
// "recompute and rewrite everything every cycle" the way campaigns-v1
// works.
func resolveIdentities(existing []*entity, observations map[string]*ipObservation) (changed []*entity, absorbed []string) {
	ipToEntity := map[string]*entity{}
	for _, e := range existing {
		for ip := range entityIPSet(e) {
			ipToEntity[ip] = e
		}
	}

	// candidates is every entity a not-yet-a-member IP can match against --
	// starts as existing, and grows as this cycle creates brand new
	// entities, so e.g. IP B (processed after IP A) can still merge with
	// the entity IP A just created moments ago in the same cycle, not only
	// with entities that existed before this cycle started.
	candidates := append([]*entity{}, existing...)

	// Deterministic iteration order so a run over the same input always
	// merges the same way -- Go's map iteration order is randomized, and
	// two dashboard-adjacent operators comparing runs (or a test) would
	// otherwise see different entity groupings from identical data.
	ips := make([]string, 0, len(observations))
	for ip := range observations {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	touched := map[string]*entity{} // by entity ID, dedup for the return value
	absorbedSet := map[string]bool{}

	for _, ip := range ips {
		o := observations[ip]
		target := ipToEntity[ip]

		if target == nil {
			// Not yet a member of anything -- look for a candidate entity
			// (pre-existing, or created earlier this same cycle) this IP's
			// signals now qualify it to join. If it qualifies for more
			// than one, merge those entities together too (they were
			// always the same actor, this observation is just the first
			// evidence that reveals it).
			var matches []*entity
			for _, e := range candidates {
				if absorbedSet[e.ID] {
					continue // already folded into another match this cycle
				}
				if sharedSignalCount(o.signals, entitySignals(e)) >= mergeThreshold {
					matches = append(matches, e)
				}
			}
			if len(matches) > 0 {
				target = matches[0]
				for _, extra := range matches[1:] {
					mergeEntityInto(target, extra)
					absorbedSet[extra.ID] = true
					delete(touched, extra.ID)
					for eip := range entityIPSet(extra) {
						ipToEntity[eip] = target
					}
				}
			} else {
				target = &entity{ID: newEntityID(ip, o.first), signals: newSignalSet(), ipSet: map[string]bool{}, sensorSet: map[string]bool{}, techniqueSet: map[string]bool{}}
				candidates = append(candidates, target)
			}
			ipToEntity[ip] = target
		}

		absorb(target, o)
		touched[target.ID] = target
	}

	changed = make([]*entity, 0, len(touched))
	for _, e := range touched {
		finalizeEntity(e)
		changed = append(changed, e)
	}
	sort.Slice(changed, func(i, j int) bool { return changed[i].ID < changed[j].ID })

	for id := range absorbedSet {
		absorbed = append(absorbed, id)
	}
	sort.Strings(absorbed)
	return changed, absorbed
}

// finalizeEntity flattens an entity's working maps back into its
// persisted slice fields, sorted for stable JSON output.
func finalizeEntity(e *entity) {
	e.IPs = sortedKeys(entityIPSet(e))
	sig := entitySignals(e)
	e.Fingerprints = sortedKeys(sig.fingerprints)
	e.Payloads = sortedKeys(sig.payloads)
	e.Credentials = sortedKeys(sig.creds)
	e.Sensors = sortedKeys(entitySensorSet(e))
	e.Techniques = sortedKeys(entityTechniqueSet(e))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if strings.TrimSpace(k) != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
