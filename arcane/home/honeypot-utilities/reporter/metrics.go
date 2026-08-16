package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// metrics counts every decision the processor makes, per docs/ip-reporting-
// plan.md Phase 4's ask for an operator-visible view distinguishing
// attempted/suppressed/dry-run/successful/failed.
//
// This container is deliberately not on honeynet (see docker-compose.
// utilities.yml's own comment on the reporter service: no legitimate reason
// to reach any other container, only to read log files and, once live,
// reach AbuseIPDB/Blocklist.de over the public internet) -- so a scraped
// HTTP /metrics endpoint is the wrong shape here, it would need a new
// network attachment this container's own isolation design deliberately
// avoids. Instead this writes a periodic JSON snapshot into
// REPORTER_DATA_DIR, the same volume-based, no-network pattern
// reporter-data already uses for the audit log and dedup store. Making
// that snapshot actually visible in the dashboard (mirroring it the way
// es-results-importer mirrors Ghidra/sandbox/GitHub-analysis results) is
// a separate follow-up, not done by this file.
type metrics struct {
	attempted           atomic.Int64 // every event that reached a report decision point (passed whitelist, categorization, threshold)
	suppressedCooldown  atomic.Int64
	suppressedGreynoise atomic.Int64
	dryRun              atomic.Int64
	sent                atomic.Int64
	failed              atomic.Int64
}

var m metrics

type metricsSnapshot struct {
	Attempted           int64     `json:"attempted"`
	SuppressedCooldown  int64     `json:"suppressed_cooldown"`
	SuppressedGreynoise int64     `json:"suppressed_greynoise"`
	DryRun              int64     `json:"dry_run"`
	Sent                int64     `json:"sent"`
	Failed              int64     `json:"failed"`
	UpdatedAt           time.Time `json:"updated_at"`
}

func (mx *metrics) snapshot() metricsSnapshot {
	return metricsSnapshot{
		Attempted:           mx.attempted.Load(),
		SuppressedCooldown:  mx.suppressedCooldown.Load(),
		SuppressedGreynoise: mx.suppressedGreynoise.Load(),
		DryRun:              mx.dryRun.Load(),
		Sent:                mx.sent.Load(),
		Failed:              mx.failed.Load(),
		UpdatedAt:           time.Now().UTC(),
	}
}

// writeMetricsLoop periodically overwrites dataDir/metrics.json with the
// current snapshot -- write-to-temp-then-rename so a reader (or a future
// importer) never sees a half-written file.
func writeMetricsLoop(dataDir string, interval time.Duration) {
	path := filepath.Join(dataDir, "metrics.json")
	for {
		if err := writeMetricsSnapshot(path, m.snapshot()); err != nil {
			log.Printf("reporter: writing metrics snapshot: %v", err)
		}
		time.Sleep(interval)
	}
}

func writeMetricsSnapshot(path string, snap metricsSnapshot) error {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
