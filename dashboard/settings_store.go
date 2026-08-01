package main

// settings_store.go — atomic, revisioned JSON persistence for the typed
// settings documents (roadmap §5). One store manages one document with:
//
//   - a schema-versioned envelope and strict decode (unknown fields fail the
//     load and trigger backup recovery instead of being silently dropped);
//   - write-to-temp, fsync, atomic rename, and a retained .bak generation;
//   - last-known-good recovery: a corrupt primary falls back to the backup,
//     and when both are unreadable the store serves compiled defaults in
//     read-only mode rather than taking down the dashboard;
//   - a monotonically increasing revision and an ETag for optimistic
//     concurrency (If-Match) on every mutation;
//   - an in-process read/write lock and audit records for every outcome.
//
// This matches the current single-instance deployment. If dashboard replicas
// are ever introduced, migrate these stores to SQLite before scaling (§5).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	errStoreReadOnly = errors.New("settings store is read-only after a persistence failure")
	errStaleRevision = errors.New("settings were modified concurrently; reload and retry")
	errUnknownRecord = errors.New("no settings record for this subject")
)

// stripWeakPrefix removes a leading weak-validator marker ("W/") from an
// incoming If-Match value before comparing it against a freshly computed
// strong ETag. #177: every settings save through this store -- preferences
// and admin configuration alike -- failed as a false conflict, unconditionally,
// since the feature shipped, even for a single session on the very first
// attempt. Traced live (temporary server-side logging comparing the exact
// bytes): the client's If-Match arrived as `W/"r0-...` while this store's
// own freshly computed ETag was `"r0-...` -- byte-identical except for the
// weak marker. This dashboard never emits a weak ETag itself, so something
// in the proxy chain in front of it (Cloudflare and Traefik both sit in
// front, and both can transparently compress responses; either downgrading
// a strong validator to weak on a compressed response is standard proxy
// behavior, not a bug in that layer) added it on the way to the browser,
// which then dutifully echoed it back as If-Match. A naive byte-for-byte
// comparison against the freshly computed strong ETag never matches, even
// though the underlying value is identical. Stripping the marker before
// comparing is safe specifically because we control both ends: the "weak"
// value only ever differs from our own strong one by this exact prefix,
// added by an intermediary we trust, never by an actual different
// representation.
func stripWeakPrefix(etag string) string {
	if strings.HasPrefix(etag, "W/") {
		return etag[2:]
	}
	return etag
}

// maxSettingsBytes bounds a single settings document on load. Settings are
// small typed documents; anything larger is corruption or abuse.
const maxSettingsBytes = 1 << 20

// atomicSettingsStore persists one typed settings document. Construct it with
// newAtomicSettingsStore; the zero value is not usable.
type atomicSettingsStore[T any] struct {
	mu        sync.RWMutex
	path      string
	backup    string
	payload   T
	revision  int64
	updated   time.Time
	defaults  T
	validate  func(T) error
	readOnly  bool
	recovered bool // loaded from the .bak generation after a corrupt primary
	degraded  bool // primary and backup both unreadable; serving defaults
}

// newAtomicSettingsStore loads the document at path (falling back to path.bak
// and then to defaults) and validates it. The returned store is always
// usable; check Degraded() to learn whether persisted state was lost.
func newAtomicSettingsStore[T any](path string, defaults T, validate func(T) error) *atomicSettingsStore[T] {
	store := &atomicSettingsStore[T]{
		path:     path,
		backup:   path + ".bak",
		payload:  defaults,
		defaults: defaults,
		validate: validate,
	}
	if store.loadFrom(store.path) {
		return store
	}
	if store.loadFrom(store.backup) {
		store.recovered = true
		return store
	}
	// Primary and backup are both missing or unreadable. A missing file on
	// first boot is normal and writable; a corrupt file means persisted state
	// was lost and the store goes read-only until an operator intervenes.
	if _, err := os.Stat(store.path); err == nil {
		store.degraded = true
		store.readOnly = true
	}
	return store
}

// loadFrom reads, migrates, decodes, and validates one generation. It returns
// false for any problem, leaving the previous payload untouched.
func (s *atomicSettingsStore[T]) loadFrom(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > maxSettingsBytes {
		return false
	}
	var envelope storedEnvelope
	if !strictDecode(raw, &envelope) {
		return false
	}
	payload, err := migratePayload(envelope.SchemaVersion, envelope.Payload)
	if err != nil {
		return false
	}
	var candidate T
	if !strictDecode(payload, &candidate) {
		return false
	}
	if s.validate != nil {
		if err := s.validate(candidate); err != nil {
			return false
		}
	}
	s.payload = candidate
	s.revision = envelope.Revision
	s.updated = envelope.Updated
	return true
}

// strictDecode unmarshals a single JSON document, rejecting unknown fields,
// trailing data, and malformed input.
func strictDecode(raw []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	return decoder.Decode(&struct{}{}) == io.EOF
}

// Get returns the current payload and its ETag. The payload must be treated
// as read-only; mutations go through Update.
func (s *atomicSettingsStore[T]) Get() (T, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.payload, s.etagLocked()
}

// Revision exposes the current revision for diagnostics.
func (s *atomicSettingsStore[T]) Revision() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

// ReadOnly reports whether mutations are currently rejected.
func (s *atomicSettingsStore[T]) ReadOnly() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readOnly
}

// Recovered reports whether the store loaded from its backup generation.
func (s *atomicSettingsStore[T]) Recovered() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.recovered
}

// Degraded reports whether all persisted state was unreadable at startup and
// the store is serving compiled defaults.
func (s *atomicSettingsStore[T]) Degraded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.degraded
}

func (s *atomicSettingsStore[T]) etagLocked() string {
	sum := sha256.Sum256(s.marshalLocked())
	return fmt.Sprintf(`"r%d-%s"`, s.revision, hex.EncodeToString(sum[:6]))
}

func (s *atomicSettingsStore[T]) marshalLocked() []byte {
	raw, err := json.Marshal(s.payload)
	if err != nil {
		return nil
	}
	return raw
}

// Update applies mutate to a copy of the payload, validates the result, and
// persists it atomically. ifMatch implements optimistic concurrency: a
// non-empty value must equal the current ETag or the update fails with
// errStaleRevision. It returns the new ETag and the dotted names of the
// fields that changed (for audit records). On a persistence failure the
// store switches to read-only so later requests see a consistent state
// instead of a half-written document.
func (s *atomicSettingsStore[T]) Update(ifMatch string, mutate func(*T) error) (string, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readOnly {
		return "", nil, errStoreReadOnly
	}
	if ifMatch != "" && stripWeakPrefix(ifMatch) != s.etagLocked() {
		return "", nil, errStaleRevision
	}
	// Deep-copy through JSON so mutations can never alias slices or maps
	// shared with the live payload.
	var candidate T
	if raw := s.marshalLocked(); raw != nil {
		if err := json.Unmarshal(raw, &candidate); err != nil {
			return "", nil, err
		}
	} else {
		candidate = s.payload
	}
	if err := mutate(&candidate); err != nil {
		return "", nil, err
	}
	if s.validate != nil {
		if err := s.validate(candidate); err != nil {
			return "", nil, err
		}
	}
	var changed []string
	if oldJSON := s.marshalLocked(); oldJSON != nil {
		if newJSON, err := json.Marshal(candidate); err == nil {
			changed = changedFields(oldJSON, newJSON)
		}
	}
	s.revision++
	s.updated = time.Now().UTC()
	if err := s.persistLocked(candidate); err != nil {
		s.revision--
		s.readOnly = true
		return "", nil, fmt.Errorf("persist settings: %w", err)
	}
	s.payload = candidate
	return s.etagLocked(), changed, nil
}

// persistLocked writes the envelope atomically and refreshes the backup
// generation. The backup holds the NEW state (not the previous one): its
// purpose is crash recovery, not history — history and rollback live in the
// revision/audit layer.
func (s *atomicSettingsStore[T]) persistLocked(payload T) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	envelope, err := json.Marshal(storedEnvelope{
		SchemaVersion: settingsSchemaVersion,
		Revision:      s.revision,
		Updated:       s.updated,
		Payload:       payloadJSON,
	})
	if err != nil {
		return err
	}
	envelope = append(envelope, '\n')
	if err := atomicWriteFile(s.path, envelope); err != nil {
		return err
	}
	return atomicWriteFile(s.backup, envelope)
}

// atomicWriteFile writes data to path via a same-directory temporary file,
// fsync, and rename. The file gets mode 0600 and the directory 0750.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".settings-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		// A leftover temp file after a crash is ignored by the loader; remove
		// it on the error paths where we still can.
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// Best-effort directory sync so the rename itself is durable. Not
	// supported on Windows; the rename is still atomic there.
	if runtime.GOOS != "windows" {
		if dirFile, err := os.Open(dir); err == nil {
			_ = dirFile.Sync()
			_ = dirFile.Close()
		}
	}
	return nil
}
