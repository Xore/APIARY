package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func metricLabel(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n").Replace(value)
}

func (s *store) serveMetrics(w http.ResponseWriter, r *http.Request) {
	snap := s.get()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP honeypot_events_total Normalized events in the dashboard tail.\n# TYPE honeypot_events_total gauge\nhoneypot_events_total %d\n", snap.Total)
	fmt.Fprintf(w, "# HELP honeypot_events_24h Events observed in the last 24 hours.\n# TYPE honeypot_events_24h gauge\nhoneypot_events_24h %d\n", snap.Last24h)
	fmt.Fprintf(w, "honeypot_unique_sources %d\nhoneypot_payload_observations %d\n", snap.UniqueIPs, snap.Downloads)
	// The size of the source-recovery gap (#54, #75). /source-health shows it to
	// a human; exporting it is what lets a change to the VPS side be judged on a
	// before-and-after number instead of an impression.
	fmt.Fprintf(w, "# HELP honeypot_unattributed_events Events that reached a sensor over the tunnel and could not be joined back to a real source.\n# TYPE honeypot_unattributed_events gauge\nhoneypot_unattributed_events %d\n", snap.Unattributed)
	for _, sensor := range snap.Sensors {
		fmt.Fprintf(w, "honeypot_sensor_events{sensor=\"%s\",state=\"%s\"} %d\n", metricLabel(sensor.Name), metricLabel(sensor.State), sensor.Count)
	}
	state := map[string]int{"green": 1, "yellow": 2, "red": 3}[snap.ES.State]
	fmt.Fprintf(w, "honeypot_elasticsearch_state %d\nhoneypot_elasticsearch_documents %d\nhoneypot_dead_letters_total %d\nhoneypot_dead_letters_24h %d\n", state, snap.ES.Documents, snap.ES.DeadLetters, snap.ES.RecentDeadLetters)
	fmt.Fprintf(w, "honeypot_filebeat_failed_total %d\nhoneypot_filebeat_dropped_total %d\nhoneypot_filebeat_active %d\n", snap.ES.FilebeatFailed, snap.ES.FilebeatDropped, snap.ES.FilebeatActive)
	fmt.Fprintf(w, "honeypot_yara_samples %d\nhoneypot_yara_matches %d\nhoneypot_yara_errors %d\n", snap.YARA.Samples, snap.YARA.Matched, snap.YARA.Errors)
	results := loadSandboxResults()
	status := loadSandboxStatus()
	highRisk := 0
	packets := 0
	for _, result := range results {
		if result.RiskScore >= 50 {
			highRisk++
		}
		packets += result.NetworkSummary.Packets
	}
	fmt.Fprintf(w, "honeypot_sandbox_results %d\nhoneypot_sandbox_high_risk %d\nhoneypot_sandbox_packets %d\n", len(results), highRisk, packets)
	fmt.Fprintf(w, "honeypot_sandbox_queue{state=\"handoff\"} %d\nhoneypot_sandbox_queue{state=\"queued\"} %d\nhoneypot_sandbox_queue{state=\"running\"} %d\nhoneypot_sandbox_queue{state=\"failed\"} %d\n", status.Handoff, status.Counts.Queued, status.Counts.Running, status.Counts.Failed)
	githubStatus := loadGitHubAnalysisStatus()
	fmt.Fprintf(w, "honeypot_github_analysis_queue{state=\"handoff\"} %d\nhoneypot_github_analysis_queue{state=\"queued\"} %d\nhoneypot_github_analysis_queue{state=\"running\"} %d\nhoneypot_github_analysis_queue{state=\"failed\"} %d\n", githubStatus.Handoff, githubStatus.Queued, githubStatus.Running, githubStatus.Failed)
	runtime := currentRuntime()
	fmt.Fprintf(w, "honeypot_dashboard_goroutines %d\n", runtime.Goroutines)
	if value := cgroupBytes("/sys/fs/cgroup/memory.current"); value >= 0 {
		fmt.Fprintf(w, "honeypot_dashboard_memory_bytes %s\n", strconv.FormatInt(value, 10))
	}
	s.writeSettingsMetrics(w)
}

// writeSettingsMetrics exposes the Milestone G operational view of the
// settings subsystem: store health (read-only / degraded / recovered flags),
// configuration revision, retained audit volume, and failure counters. All
// flags are gauges so alerting can fire on any transition to 1.
func (s *store) writeSettingsMetrics(w http.ResponseWriter) {
	settings := s.settings
	if settings == nil {
		return
	}
	flag := func(value bool) int {
		if value {
			return 1
		}
		return 0
	}
	fmt.Fprintf(w, "# HELP honeypot_settings_config_revision Current dashboard configuration revision.\n# TYPE honeypot_settings_config_revision gauge\nhoneypot_settings_config_revision %d\n", settings.config.Revision())
	fmt.Fprintf(w, "# HELP honeypot_settings_store_readonly Settings store refusing writes (1) because Elasticsearch is unreachable, or healthy (0). Self-heals on the next successful poll.\n# TYPE honeypot_settings_store_readonly gauge\n")
	fmt.Fprintf(w, "honeypot_settings_store_readonly{store=\"config\"} %d\nhoneypot_settings_store_readonly{store=\"users\"} %d\n", flag(settings.config.ReadOnly()), flag(settings.users.inner.ReadOnly()))
	fmt.Fprintf(w, "# HELP honeypot_settings_store_degraded Settings store serving compiled defaults because it has never yet loaded real state from Elasticsearch this process lifetime. Self-heals on the next successful poll.\n# TYPE honeypot_settings_store_degraded gauge\n")
	fmt.Fprintf(w, "honeypot_settings_store_degraded{store=\"config\"} %d\nhoneypot_settings_store_degraded{store=\"users\"} %d\n", flag(settings.config.Degraded()), flag(settings.users.inner.Degraded()))
	fmt.Fprintf(w, "# HELP honeypot_settings_store_recovered Always 0: #787 moved this store to Elasticsearch, which has no local backup-generation concept to recover from. Kept for metric-name stability.\n# TYPE honeypot_settings_store_recovered gauge\n")
	fmt.Fprintf(w, "honeypot_settings_store_recovered{store=\"config\"} %d\nhoneypot_settings_store_recovered{store=\"users\"} %d\n", flag(settings.config.Recovered()), flag(settings.users.inner.Recovered()))
	fmt.Fprintf(w, "# HELP honeypot_settings_projected_users Users with a dashboard projection and stored preferences.\n# TYPE honeypot_settings_projected_users gauge\nhoneypot_settings_projected_users %d\n", len(settings.users.Projections()))
	fmt.Fprintf(w, "# HELP honeypot_settings_audit_events Settings audit events retained in the current log generation (capped at 500).\n# TYPE honeypot_settings_audit_events gauge\nhoneypot_settings_audit_events %d\n", len(settings.audit.read(500)))
	fmt.Fprintf(w, "# HELP honeypot_settings_save_failures_total Rejected settings writes by kind.\n# TYPE honeypot_settings_save_failures_total counter\n")
	fmt.Fprintf(w, "honeypot_settings_save_failures_total{kind=\"preferences\"} %d\nhoneypot_settings_save_failures_total{kind=\"config\"} %d\n", settings.preferenceFailures.Load(), settings.configFailures.Load())
	fmt.Fprintf(w, "# HELP honeypot_settings_retention_removed_total Orphaned user projections removed by the retention sweep.\n# TYPE honeypot_settings_retention_removed_total counter\nhoneypot_settings_retention_removed_total %d\n", settings.retentionRemoved.Load())
}

func cgroupBytes(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return -1
	}
	return n
}
