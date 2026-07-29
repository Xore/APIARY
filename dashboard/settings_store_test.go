package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func newTestConfigStore(t *testing.T) (*atomicSettingsStore[dashboardConfig], string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "dashboard-config.json")
	return newAtomicSettingsStore(path, defaultDashboardConfig(), validateConfig), path
}

func TestStorePersistsAcrossRestart(t *testing.T) {
	store, path := newTestConfigStore(t)
	etag, changed, err := store.Update("", func(c *dashboardConfig) error {
		c.Presentation.DashboardTitle = "Operations"
		c.Behavior.MaxExportRows = 5000
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 2 {
		t.Fatalf("changed fields = %v, want 2 entries", changed)
	}
	reloaded := newAtomicSettingsStore(path, defaultDashboardConfig(), validateConfig)
	cfg, reloadedETag := reloaded.Get()
	if cfg.Presentation.DashboardTitle != "Operations" || cfg.Behavior.MaxExportRows != 5000 {
		t.Fatalf("persisted config not reloaded: %+v", cfg)
	}
	if reloadedETag != etag {
		t.Fatalf("ETag changed across restart: %s vs %s", reloadedETag, etag)
	}
	if reloaded.Revision() != 1 || reloaded.Recovered() || reloaded.Degraded() || reloaded.ReadOnly() {
		t.Fatalf("unexpected store state: rev=%d recovered=%v degraded=%v readonly=%v",
			reloaded.Revision(), reloaded.Recovered(), reloaded.Degraded(), reloaded.ReadOnly())
	}
}

func TestStoreRecoversFromBackupWhenPrimaryCorrupt(t *testing.T) {
	store, path := newTestConfigStore(t)
	if _, _, err := store.Update("", func(c *dashboardConfig) error {
		c.Presentation.DashboardTitle = "Recovered title"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded := newAtomicSettingsStore(path, defaultDashboardConfig(), validateConfig)
	cfg, _ := reloaded.Get()
	if !reloaded.Recovered() || reloaded.Degraded() {
		t.Fatalf("expected backup recovery, recovered=%v degraded=%v", reloaded.Recovered(), reloaded.Degraded())
	}
	if cfg.Presentation.DashboardTitle != "Recovered title" {
		t.Fatalf("backup did not restore last-known-good state: %+v", cfg.Presentation)
	}
	if reloaded.ReadOnly() {
		t.Fatal("a recovered store must stay writable")
	}
}

func TestStoreDefaultsReadOnlyWhenAllGenerationsCorrupt(t *testing.T) {
	store, path := newTestConfigStore(t)
	if _, _, err := store.Update("", func(c *dashboardConfig) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, generation := range []string{path, path + ".bak"} {
		if err := os.WriteFile(generation, []byte("garbage"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reloaded := newAtomicSettingsStore(path, defaultDashboardConfig(), validateConfig)
	cfg, _ := reloaded.Get()
	if !reloaded.Degraded() || !reloaded.ReadOnly() {
		t.Fatalf("expected degraded read-only store, degraded=%v readonly=%v", reloaded.Degraded(), reloaded.ReadOnly())
	}
	if cfg.Presentation.AppName != defaultDashboardConfig().Presentation.AppName {
		t.Fatal("degraded store must serve compiled defaults")
	}
	if _, _, err := reloaded.Update("", func(c *dashboardConfig) error { return nil }); !errors.Is(err, errStoreReadOnly) {
		t.Fatalf("degraded store must reject writes, got %v", err)
	}
}

func TestStoreIgnoresStrayTempFiles(t *testing.T) {
	store, path := newTestConfigStore(t)
	if _, _, err := store.Update("", func(c *dashboardConfig) error {
		c.Presentation.DashboardTitle = "Stable"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash mid-write: a garbage temp file next to the document.
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), ".settings-abcdef.tmp"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded := newAtomicSettingsStore(path, defaultDashboardConfig(), validateConfig)
	cfg, _ := reloaded.Get()
	if cfg.Presentation.DashboardTitle != "Stable" || reloaded.Degraded() {
		t.Fatalf("stray temp file broke the load: %+v", cfg.Presentation)
	}
}

func TestStoreRejectsStaleETag(t *testing.T) {
	store, _ := newTestConfigStore(t)
	_, first := store.Get()
	if _, _, err := store.Update(first, func(c *dashboardConfig) error {
		c.Presentation.DashboardTitle = "First"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Update(first, func(c *dashboardConfig) error {
		c.Presentation.DashboardTitle = "Second"
		return nil
	}); !errors.Is(err, errStaleRevision) {
		t.Fatalf("stale ETag must conflict, got %v", err)
	}
	cfg, _ := store.Get()
	if cfg.Presentation.DashboardTitle != "First" {
		t.Fatalf("conflicting write changed state: %+v", cfg.Presentation)
	}
}

func TestStoreValidationFailureLeavesStateUntouched(t *testing.T) {
	store, path := newTestConfigStore(t)
	before, beforeETag := store.Get()
	if _, _, err := store.Update("", func(c *dashboardConfig) error {
		c.Honeypot.AlertCampaignScore = 500
		return nil
	}); err == nil || !errors.Is(err, errSettingsValidation) {
		t.Fatalf("invalid update must fail with validation error, got %v", err)
	}
	after, afterETag := store.Get()
	if beforeETag != afterETag || before.Honeypot != after.Honeypot {
		t.Fatal("rejected update changed store state or ETag")
	}
	reloaded := newAtomicSettingsStore(path, defaultDashboardConfig(), validateConfig)
	cfg, _ := reloaded.Get()
	if cfg.Honeypot.AlertCampaignScore != defaultDashboardConfig().Honeypot.AlertCampaignScore {
		t.Fatal("rejected update reached the disk")
	}
}

func TestStoreRejectsUnknownFieldsAndOversizedDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "dashboard-config.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	// Unknown payload field: strict decode must fail and, with no valid
	// backup, the store serves defaults (file exists → degraded read-only).
	unknown := `{"schema_version":1,"revision":1,"updated":"2026-07-29T00:00:00Z","payload":{"presentation":{},"behavior":{},"honeypot":{},"surprise":true}}`
	if err := os.WriteFile(path, []byte(unknown), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newAtomicSettingsStore(path, defaultDashboardConfig(), validateConfig)
	if !store.Degraded() {
		t.Fatal("unknown fields in a persisted document must not be silently accepted")
	}
	// Oversized document: beyond the bounded read, never parsed.
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", maxSettingsBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", []byte(strings.Repeat(" ", maxSettingsBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	oversized := newAtomicSettingsStore(path, defaultDashboardConfig(), validateConfig)
	if !oversized.Degraded() {
		t.Fatal("oversized documents must be rejected at load")
	}
}

func TestStoreSerializesConcurrentUpdates(t *testing.T) {
	store, path := newTestConfigStore(t)
	const writers = 8
	const writesPerWriter = 5
	var wg sync.WaitGroup
	errs := make(chan error, writers*writesPerWriter)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < writesPerWriter; i++ {
				// Optimistic concurrency: retry on conflict. The assertion is
				// that no revision is lost and no write corrupts the document.
				for {
					_, etag := store.Get()
					_, _, err := store.Update(etag, func(c *dashboardConfig) error {
						c.Behavior.MaxExportRows++
						return nil
					})
					if errors.Is(err, errStaleRevision) {
						continue
					}
					if err != nil {
						errs <- err
					}
					break
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent update failed: %v", err)
	}
	cfg, _ := store.Get()
	want := defaultDashboardConfig().Behavior.MaxExportRows + writers*writesPerWriter
	if cfg.Behavior.MaxExportRows != want {
		t.Fatalf("lost updates: max_export_rows = %d, want %d", cfg.Behavior.MaxExportRows, want)
	}
	reloaded := newAtomicSettingsStore(path, defaultDashboardConfig(), validateConfig)
	reloadedCfg, _ := reloaded.Get()
	if reloadedCfg.Behavior.MaxExportRows != want || reloaded.Degraded() {
		t.Fatal("concurrent writes corrupted the persisted document")
	}
}

func TestStoreWriteFailureSwitchesToReadOnly(t *testing.T) {
	// Point the store at a path whose parent is a file: every write fails.
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, []byte("file, not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	failing := newAtomicSettingsStore(filepath.Join(blocked, "config.json"), defaultDashboardConfig(), validateConfig)
	if _, _, err := failing.Update("", func(c *dashboardConfig) error { return nil }); err == nil {
		t.Fatal("write into an unwritable location must fail")
	}
	if !failing.ReadOnly() {
		t.Fatal("a persistence failure must switch the store to read-only")
	}
	if _, _, err := failing.Update("", func(c *dashboardConfig) error { return nil }); !errors.Is(err, errStoreReadOnly) {
		t.Fatalf("read-only store must reject further writes, got %v", err)
	}
}

func TestStoreUpdateWithoutETagIsUnconditional(t *testing.T) {
	store, _ := newTestConfigStore(t)
	if _, _, err := store.Update("", func(c *dashboardConfig) error { c.Behavior.ReadOnly = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Update("", func(c *dashboardConfig) error { c.Behavior.ReadOnly = false; return nil }); err != nil {
		t.Fatalf("internal unconditional writes must not conflict: %v", err)
	}
	cfg, _ := store.Get()
	if cfg.Behavior.ReadOnly {
		t.Fatal("second unconditional write did not apply")
	}
}
