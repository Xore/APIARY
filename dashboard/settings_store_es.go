package main

// settings_store_es.go — Elasticsearch-backed persistence for the typed
// settings documents (roadmap §5), replacing the local-file
// atomicSettingsStore this file's predecessor comment once described.
//
// #787: with two dashboard replicas sharing one Elasticsearch cluster, a
// local file on the shared /state volume kept each replica's in-memory
// cache correct on disk but not in memory -- Get() never re-read the file
// after startup, so a setting toggled via replica A's admin UI was
// invisible to replica B until it was restarted. Confirmed live:
// /agent-campaigns (gated on the config's ShowMLPanels flag) 404'd on every
// other page load, depending on which replica handled the request.
//
// Elasticsearch is the one backend both replicas already treat as shared
// source of truth (matching the #638 intelligence-archive precedent and the
// generated-reports store, reports_es.go). This store keeps one singleton
// document per index -- a fixed, hardcoded ID, not a natural per-entity key
// -- reusing the same docGet/docIndex compare-and-swap idiom already used by
// ip_block.go/ml_anomaly_ack.go/alerts.go for per-entity documents.
//
// Get() stays a pure in-memory read: it's called many times per page render
// (page_presentation.go's template funcs, authorization.go, settings_api.go,
// ...), so a live Elasticsearch round trip on every call would regress
// latency and load. Instead, a background poll loop periodically re-fetches
// the document (docGet hits Elasticsearch's realtime /_doc/{id} endpoint,
// not subject to index.refresh_interval the way _search is, so a write from
// one replica is visible to the other's very next poll tick) and refreshes
// the in-memory cache. Staleness is bounded by settingsPollInterval instead
// of "forever until restart."
//
// Degraded()/ReadOnly() are deliberately NOT a permanent latch the way the
// old file-backed store's were. A corrupt local file needed a human to fix
// it; Elasticsearch being briefly unreachable (a rolling restart, a network
// blip) is transient far more often, and latching permanently would turn a
// 30-second outage into "restart the dashboard to recover" -- strictly
// worse than today. Both flags self-heal on the next successful
// refresh()/Update().

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// settingsPollInterval bounds how stale one replica's in-memory cache can be
// relative to what another replica just wrote. Short enough that a toggle
// is visible on the other replica within a few seconds of a human clicking
// it; cheap enough that steady-state load against Elasticsearch is
// negligible next to this stack's own sensor-ingestion volume (three
// stores x two replicas x one docGet per interval).
const settingsPollInterval = 3 * time.Second

// settingsWriteRetries matches ipBlockWriteRetries' retry count for the same
// compare-and-swap idiom (ip_block.go) -- a losing race against a concurrent
// writer is retried against a freshly re-fetched document, not treated as a
// hard failure.
const settingsWriteRetries = 5

// esSettingsStore persists one typed settings document as a single
// Elasticsearch document at a fixed id. Construct it with
// newESSettingsStore; the zero value is not usable.
type esSettingsStore[T any] struct {
	mu       sync.RWMutex
	es       *esClient
	index    string
	id       string
	payload  T
	revision int64
	updated  time.Time
	defaults T
	validate func(T) error

	// pollInterval is set once at construction and never mutated again --
	// deliberately a per-instance field, not a shared package var. An
	// earlier version used a package var tests could shrink for faster
	// polling, and go test -race caught the real bug in that design: one
	// test's cleanup restoring the var could race against a *different*,
	// unrelated test's brand new pollLoop goroutine reading it for the
	// first time, since pollLoop goroutines are never stopped and outlive
	// the test that spawned them. A field set before the goroutine starts
	// and read only by that same goroutine afterward has no such race.
	pollInterval time.Duration

	readOnly   bool // most recent Elasticsearch attempt failed; self-heals
	degraded   bool // no successful load yet this process lifetime; self-heals
	loadedOnce bool
}

// newESSettingsStore constructs the store, performs one synchronous load
// (bounded by esClient's own HTTP timeout, matching the other synchronous
// Elasticsearch calls already in main.go's startup path), and starts a
// background poll loop. es == nil (Elasticsearch not configured) leaves the
// store permanently degraded and read-only, serving compiled defaults --
// the same "always usable" posture the file-backed store had for a
// missing/corrupt file.
func newESSettingsStore[T any](es *esClient, index, id string, defaults T, validate func(T) error) *esSettingsStore[T] {
	return newESSettingsStoreWithPollInterval(es, index, id, defaults, validate, settingsPollInterval)
}

// newESSettingsStoreWithPollInterval is newESSettingsStore with an explicit
// poll interval -- an escape hatch for tests that need to observe a poll
// tick without waiting settingsPollInterval's full 3 seconds. Production
// code should always use newESSettingsStore (the real interval).
func newESSettingsStoreWithPollInterval[T any](es *esClient, index, id string, defaults T, validate func(T) error, pollInterval time.Duration) *esSettingsStore[T] {
	store := &esSettingsStore[T]{
		es:           es,
		index:        index,
		id:           id,
		payload:      defaults,
		defaults:     defaults,
		validate:     validate,
		pollInterval: pollInterval,
	}
	store.refresh()
	if es != nil {
		go store.pollLoop()
	}
	return store
}

func (s *esSettingsStore[T]) pollLoop() {
	for range time.Tick(s.pollInterval) {
		s.refresh()
	}
}

// refresh re-fetches the document from Elasticsearch and updates the
// in-memory cache if it changed. Any problem (Elasticsearch unreachable,
// corrupt document, failed validation) leaves the previous payload
// untouched and marks readOnly, mirroring loadFrom's old "any problem
// leaves the previous payload untouched" contract.
func (s *esSettingsStore[T]) refresh() {
	// s.es is only ever mutated by tests (production code sets it once at
	// construction and never again), but reading it must still go through
	// the lock -- caught live by go test -race, which flagged this exact
	// field access racing against a test that swaps s.es to simulate an
	// Elasticsearch endpoint recovering after an outage.
	s.mu.RLock()
	es := s.es
	s.mu.RUnlock()
	if es == nil {
		s.mu.Lock()
		s.degraded, s.readOnly = true, true
		s.mu.Unlock()
		return
	}
	hit, found, err := es.docGet(s.index, s.id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.readOnly = true
		if !s.loadedOnce {
			s.degraded = true
		}
		return
	}
	s.readOnly, s.loadedOnce, s.degraded = false, true, false
	if !found {
		// No document yet: a normal first-boot/empty state, not degraded --
		// distinct from "Elasticsearch is unreachable."
		return
	}
	var envelope storedEnvelope
	if json.Unmarshal(hit.Source, &envelope) != nil {
		return
	}
	if envelope.Revision == s.revision {
		return // unchanged since the last successful load
	}
	migrated, err := migratePayload(envelope.SchemaVersion, envelope.Payload)
	if err != nil {
		return
	}
	var candidate T
	if !strictDecode(migrated, &candidate) {
		return
	}
	if s.validate != nil {
		if err := s.validate(candidate); err != nil {
			return
		}
	}
	s.payload, s.revision, s.updated = candidate, envelope.Revision, envelope.Updated
}

// Get returns the current payload and its ETag. The payload must be treated
// as read-only; mutations go through Update.
func (s *esSettingsStore[T]) Get() (T, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.payload, settingsETag(s.payload, s.revision)
}

// GetFresh forces a synchronous refresh before returning, for the narrow
// set of callers that read their own (or another replica's) very recent
// write and cannot tolerate the poll interval's staleness window. #787:
// confirmed live -- creating a report definition on one dashboard replica
// and immediately generating from it landed the generate request on the
// other replica often enough to matter, whose cache hadn't yet polled the
// new definition, producing a spurious 404 seconds after a successful
// create. Get() stays the default for everything else (page renders,
// authorization checks, ...) precisely because those callers are frequent
// and do not need this guarantee -- forcing a live Elasticsearch round
// trip on every Get() would regress all of them to pay this cost.
func (s *esSettingsStore[T]) GetFresh() (T, string) {
	s.refresh()
	return s.Get()
}

// Revision exposes the current revision for diagnostics.
func (s *esSettingsStore[T]) Revision() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

// ReadOnly reports whether the most recent attempt to reach Elasticsearch
// failed. Self-heals on the next successful refresh or Update.
func (s *esSettingsStore[T]) ReadOnly() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readOnly
}

// Recovered has no equivalent concept here (there is no local backup
// generation to recover from) -- kept only for interface parity with the
// old file-backed store, so callers built against that interface don't need
// to change.
func (s *esSettingsStore[T]) Recovered() bool {
	return false
}

// Degraded reports whether this store has never yet successfully loaded
// real state from Elasticsearch since this process started, and is serving
// compiled defaults. Self-heals the first time refresh() succeeds,
// including a legitimate "no document yet" result.
func (s *esSettingsStore[T]) Degraded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.degraded
}

// settingsETag hashes the marshaled payload the same way the old store's
// etagLocked() did -- a stable hash-of-content string, not Elasticsearch's
// internal _seq_no, so existing callers/tests comparing ETag values see no
// behavior change.
func settingsETag[T any](payload T, revision int64) string {
	raw, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return fmt.Sprintf(`"r%d-%s"`, revision, hex.EncodeToString(sum[:6]))
}

// Update applies mutate to a copy of the current payload, validates the
// result, and persists it to Elasticsearch with optimistic concurrency.
// ifMatch implements the same contract as the old store: a non-empty value
// must equal the current ETag (checked against a freshly fetched document,
// not the possibly-stale in-memory cache) or the update fails with
// errStaleRevision. It returns the new ETag and the dotted names of the
// fields that changed (for audit records).
//
// Unlike the old store, a losing compare-and-swap race
// (errESConflict, i.e. another writer updated the document between this
// call's own docGet and docIndex) is retried against a freshly re-fetched
// document rather than treated as a hard failure -- the same idiom as
// ip_block.go's block(). ifMatch is re-checked against each freshly fetched
// document on every attempt, so a caller whose expectation has genuinely
// gone stale gets errStaleRevision immediately rather than silently
// retrying past it.
func (s *esSettingsStore[T]) Update(ifMatch string, mutate func(*T) error) (string, []string, error) {
	s.mu.RLock()
	es := s.es
	s.mu.RUnlock()
	if es == nil {
		return "", nil, errStoreReadOnly
	}
	for attempt := 0; attempt < settingsWriteRetries; attempt++ {
		hit, found, err := es.docGet(s.index, s.id)
		if err != nil {
			s.mu.Lock()
			s.readOnly = true
			s.mu.Unlock()
			return "", nil, errStoreReadOnly
		}
		current, revision := s.defaults, int64(0)
		if found {
			var envelope storedEnvelope
			if json.Unmarshal(hit.Source, &envelope) != nil {
				return "", nil, fmt.Errorf("settings store: corrupt document %s/%s", s.index, s.id)
			}
			migrated, err := migratePayload(envelope.SchemaVersion, envelope.Payload)
			if err != nil {
				return "", nil, err
			}
			if !strictDecode(migrated, &current) {
				return "", nil, fmt.Errorf("settings store: corrupt document %s/%s", s.index, s.id)
			}
			revision = envelope.Revision
		}
		if ifMatch != "" && stripWeakPrefix(ifMatch) != settingsETag(current, revision) {
			return "", nil, errStaleRevision
		}
		// Deep-copy through JSON so mutations can never alias slices or maps
		// shared with the fetched payload.
		oldJSON, err := json.Marshal(current)
		if err != nil {
			return "", nil, err
		}
		var candidate T
		if json.Unmarshal(oldJSON, &candidate) != nil {
			candidate = current
		}
		if err := mutate(&candidate); err != nil {
			return "", nil, err
		}
		if s.validate != nil {
			if err := s.validate(candidate); err != nil {
				return "", nil, err
			}
		}
		newJSON, err := json.Marshal(candidate)
		if err != nil {
			return "", nil, err
		}
		changed := changedFields(oldJSON, newJSON)
		newRevision, updatedAt := revision+1, time.Now().UTC()
		envelopeJSON, err := json.Marshal(storedEnvelope{
			SchemaVersion: settingsSchemaVersion,
			Revision:      newRevision,
			Updated:       updatedAt,
			Payload:       newJSON,
		})
		if err != nil {
			return "", nil, err
		}
		writeErr := es.docIndex(s.index, s.id, envelopeJSON, !found, hit.SeqNo, hit.PrimaryTerm)
		if writeErr == nil {
			s.mu.Lock()
			s.payload, s.revision, s.updated = candidate, newRevision, updatedAt
			s.readOnly, s.degraded, s.loadedOnce = false, false, true
			s.mu.Unlock()
			return settingsETag(candidate, newRevision), changed, nil
		}
		if errors.Is(writeErr, errESConflict) {
			continue
		}
		s.mu.Lock()
		s.readOnly = true
		s.mu.Unlock()
		return "", nil, errStoreReadOnly
	}
	return "", nil, errStaleRevision
}
