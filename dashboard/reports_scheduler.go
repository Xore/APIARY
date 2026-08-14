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
		s.runDueReportsRecovered()
	}
}

// runDueReportsRecovered wraps runDueReports with a top-level recover
// (#1340): renderDueReport already recovers from a panic within one
// definition's own render, but this is a second, outer safety net for a
// panic anywhere else in runDueReports (e.g. dueReports itself) so a single
// bad tick can never take down the whole process.
func (s *store) runDueReportsRecovered() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("dashboard: report scheduler tick panicked: %v\n", r)
		}
	}()
	s.runDueReports()
}

// runDueReports renders every definition whose schedule is due. It is
// exported to tests through the store and is safe to call at any time.
func (s *store) runDueReports() {
	if s == nil || s.reports == nil {
		return
	}
	now := time.Now().UTC()
	for _, def := range s.reports.dueReports(now) {
		err := s.renderDueReport(def)
		s.reports.markScheduledRun(def.ID, now, err == nil)
	}
}

// renderDefinitionForSchedule is renderDueReport's render step, indirected
// through a package variable so tests can simulate a panic deep in the
// rendering pipeline without needing to actually reach one through real
// report data (#1340) -- exercising renderDueReport's recover() the same
// way a genuine pathological Scope/Template combination would.
var renderDefinitionForSchedule = (*store).renderDefinitionToStored

// renderDueReport renders one due definition, recovering from a panic so a
// single pathological Scope/Template combination can't crash the whole
// dashboard process (#1340): reportScheduleLoop runs in a bare background
// goroutine with nothing else catching a panic, unlike a manually-triggered
// "Generate PDF" request, which is already protected by net/http's own
// per-connection recover(). Without this, a panic here would also crash
// before markScheduledRun ever runs, so the same still-due definition gets
// picked up again on the very next tick after the process restarts,
// producing a persistent crash-restart loop for that one report.
// Recovering per-definition (rather than only around the ticker loop) also
// means one panicking definition doesn't abort the rest of the same tick's
// due reports.
func (s *store) renderDueReport(def reportDefinition) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			fmt.Printf("dashboard: scheduled report %s (%q) panicked: %v\n", def.ID, def.Name, r)
		}
	}()
	_, _, err = renderDefinitionForSchedule(s, def.ID, "schedule")
	if err != nil {
		fmt.Printf("dashboard: scheduled report %s (%q) failed: %v\n", def.ID, def.Name, err)
	}
	return err
}
