package main

import (
	"os"
	"path/filepath"
	"testing"
)

// #86: loadGoldenImageStatus reads golden-image-status.sh's output back out
// of WINDOWS_SANDBOX_RESULTS_DIR without any new mount/env var, and must not
// error the page when the file is absent (fresh install, timer hasn't run
// yet) or malformed.
func TestLoadGoldenImageStatusMissingReturnsNil(t *testing.T) {
	t.Setenv("WINDOWS_SANDBOX_RESULTS_DIR", t.TempDir())
	if status := loadGoldenImageStatus(); status != nil {
		t.Fatalf("expected nil for a missing status file, got %+v", status)
	}
}

func TestLoadGoldenImageStatusNoEnvReturnsNil(t *testing.T) {
	t.Setenv("WINDOWS_SANDBOX_RESULTS_DIR", "")
	if status := loadGoldenImageStatus(); status != nil {
		t.Fatalf("expected nil when WINDOWS_SANDBOX_RESULTS_DIR is unset, got %+v", status)
	}
}

func TestLoadGoldenImageStatusParsesFreshImage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WINDOWS_SANDBOX_RESULTS_DIR", dir)
	body := `{"path":"/x/win11-analysis.qcow2","built_at":"2026-08-05T10:00:00Z","age_days":0,"checksum_written":true,"checksum_verified":true,"stale_monthly":false,"stale_iso_eval":false,"checked_at":"2026-08-05T19:36:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, "golden-image-status.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	status := loadGoldenImageStatus()
	if status == nil {
		t.Fatal("expected a parsed status, got nil")
	}
	if status.StaleMonthly || status.StaleISOEval {
		t.Fatalf("fresh image must not be flagged stale: %+v", status)
	}
	if !status.ChecksumVerified {
		t.Fatalf("expected checksum_verified=true, got %+v", status)
	}
}

func TestLoadGoldenImageStatusFlagsStaleISOEval(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WINDOWS_SANDBOX_RESULTS_DIR", dir)
	body := `{"age_days":95,"checksum_written":true,"checksum_verified":true,"stale_monthly":true,"stale_iso_eval":true}`
	if err := os.WriteFile(filepath.Join(dir, "golden-image-status.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	status := loadGoldenImageStatus()
	if status == nil || !status.StaleISOEval {
		t.Fatalf("expected stale_iso_eval=true past the 90-day eval ISO window, got %+v", status)
	}
}
