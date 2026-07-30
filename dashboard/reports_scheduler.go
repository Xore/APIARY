package main

// reports_scheduler.go — the Reports studio scheduler (R4). A single
// goroutine wakes on a short tick, renders every due definition through the
// same pipeline as manual generation (origin "schedule"), and advances the
// schedule. A failing definition logs and moves to its next fire time — it
// never hot-loops and never blocks other schedules. Generated artifacts are
// bounded by the store's retention pruning either way.

import (
	"fmt"
	"time"
)

// reportScheduleLoop runs until the process exits; the dashboard is a
// single-instance deployment, so no leader election is needed (§5).
func (s *store) reportScheduleLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.runDueReports()
	}
}

// runDueReports renders every definition whose schedule is due. It is
// exported to tests through the store and is safe to call at any time.
func (s *store) runDueReports() {
	if s == nil || s.reports == nil {
		return
	}
	now := time.Now().UTC()
	for _, def := range s.reports.dueReports(now) {
		_, _, err := s.renderDefinitionToStored(def.ID, "schedule")
		if err != nil {
			fmt.Printf("dashboard: scheduled report %s (%q) failed: %v\n", def.ID, def.Name, err)
		}
		s.reports.markScheduledRun(def.ID, now, err == nil)
	}
}
