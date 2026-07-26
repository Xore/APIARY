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
	runtime := currentRuntime()
	fmt.Fprintf(w, "honeypot_dashboard_goroutines %d\n", runtime.Goroutines)
	if value := cgroupBytes("/sys/fs/cgroup/memory.current"); value >= 0 {
		fmt.Fprintf(w, "honeypot_dashboard_memory_bytes %s\n", strconv.FormatInt(value, 10))
	}
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
