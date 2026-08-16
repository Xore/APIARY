package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidateReportSchedule(t *testing.T) {
	valid := &reportSchedule{Enabled: true, Frequency: "daily", Hour: 6, Minute: 30}
	if err := validateReportSchedule(valid); err != nil {
		t.Fatalf("valid daily schedule rejected: %v", err)
	}
	if err := validateReportSchedule(&reportSchedule{Enabled: false}); err != nil {
		t.Fatalf("disabled schedule must carry no constraints: %v", err)
	}
	if err := validateReportSchedule(nil); err != nil {
		t.Fatalf("missing schedule must be valid: %v", err)
	}
	cases := []struct {
		name     string
		schedule reportSchedule
		want     string
	}{
		{"bad frequency", reportSchedule{Enabled: true, Frequency: "hourly", Hour: 6}, "schedule.frequency"},
		{"hour low", reportSchedule{Enabled: true, Frequency: "daily", Hour: -1}, "schedule.hour"},
		{"hour high", reportSchedule{Enabled: true, Frequency: "daily", Hour: 24}, "schedule.hour"},
		{"minute high", reportSchedule{Enabled: true, Frequency: "daily", Hour: 6, Minute: 60}, "schedule.minute"},
		{"weekday high", reportSchedule{Enabled: true, Frequency: "weekly", Hour: 6, Weekday: 7}, "schedule.weekday"},
		{"month day zero", reportSchedule{Enabled: true, Frequency: "monthly", Hour: 6, MonthDay: 0}, "schedule.month_day"},
		{"month day high", reportSchedule{Enabled: true, Frequency: "monthly", Hour: 6, MonthDay: 29}, "schedule.month_day"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReportSchedule(&tc.schedule)
			if !errors.Is(err, errSettingsValidation) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation error = %v, want settings validation naming %q", err, tc.want)
			}
		})
	}
}

func TestNextScheduleRun(t *testing.T) {
	// 2026-07-29 is a Wednesday.
	from := time.Date(2026, 7, 29, 10, 15, 0, 0, time.UTC)
	cases := []struct {
		name     string
		schedule reportSchedule
		want     time.Time
	}{
		{"daily later today", reportSchedule{Frequency: "daily", Hour: 12, Minute: 0}, time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)},
		{"daily wraps", reportSchedule{Frequency: "daily", Hour: 6, Minute: 30}, time.Date(2026, 7, 30, 6, 30, 0, 0, time.UTC)},
		{"weekly later this week", reportSchedule{Frequency: "weekly", Hour: 9, Weekday: 5}, time.Date(2026, 7, 31, 9, 0, 0, 0, time.UTC)},
		{"weekly same day earlier", reportSchedule{Frequency: "weekly", Hour: 6, Weekday: 3}, time.Date(2026, 8, 5, 6, 0, 0, 0, time.UTC)},
		{"monthly later this month", reportSchedule{Frequency: "monthly", Hour: 7, MonthDay: 31}, time.Date(2026, 7, 31, 7, 0, 0, 0, time.UTC)},
		{"monthly wraps", reportSchedule{Frequency: "monthly", Hour: 7, MonthDay: 1}, time.Date(2026, 8, 1, 7, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextScheduleRun(&tc.schedule, from); !got.Equal(tc.want) {
				t.Fatalf("nextScheduleRun() = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestScheduledReportLifecycle proves a definition with an enabled schedule
// gets a computed fire time, renders through the scheduler with origin
// "schedule", and advances its cadence; a failing definition advances too
// instead of hot-looping.
func TestScheduledReportLifecycle(t *testing.T) {
	s := newReportTestStore(t)

	def := sampleDefinition("custom")
	def.Name = "Daily brief"
	def.Schedule = &reportSchedule{Enabled: true, Frequency: "daily", Hour: 6, Minute: 30}
	created, _, err := s.reports.putDefinition("", def)
	if err != nil {
		t.Fatalf("create scheduled definition: %v", err)
	}
	if created.Schedule.NextRunAt.IsZero() || !created.Schedule.NextRunAt.After(time.Now().UTC()) {
		t.Fatalf("enabled schedule must compute a future fire time, got %s", created.Schedule.NextRunAt)
	}
	if len(s.reports.dueReports(time.Now().UTC())) != 0 {
		t.Fatal("fresh schedule must not be due immediately")
	}

	// Move the fire time into the past, as the ticker would find it.
	past := time.Now().UTC().Add(-time.Minute)
	if _, _, err := s.reports.inner.Update("", func(doc *reportsDocument) error {
		doc.Definitions[0].Schedule.NextRunAt = past
		return nil
	}); err != nil {
		t.Fatalf("backdate schedule: %v", err)
	}

	s.runDueReports()

	doc, _ := s.reports.document()
	generated, err := s.reports.listGenerated()
	if err != nil {
		t.Fatalf("listGenerated: %v", err)
	}
	if len(generated) != 1 || generated[0].Origin != "schedule" || generated[0].DefinitionID != created.ID {
		t.Fatalf("scheduled run artifacts = %+v, want one origin=schedule report", generated)
	}
	after := doc.Definitions[0].Schedule
	if after.LastRunAt.IsZero() {
		t.Fatal("successful scheduled run must record LastRunAt")
	}
	if !after.NextRunAt.After(time.Now().UTC()) {
		t.Fatalf("schedule must advance after a run, got %s", after.NextRunAt)
	}

	// A failing definition (dangling sandbox job) advances without an artifact.
	broken := sampleDefinition("sandbox")
	broken.Name = "Broken sandbox digest"
	broken.Scope.Job = "no-such-job"
	broken.Schedule = &reportSchedule{Enabled: true, Frequency: "daily", Hour: 6, Minute: 30}
	created2, _, err := s.reports.putDefinition("", broken)
	if err != nil {
		t.Fatalf("create failing definition: %v", err)
	}
	if _, _, err := s.reports.inner.Update("", func(doc *reportsDocument) error {
		doc.Definitions[1].Schedule.NextRunAt = past
		return nil
	}); err != nil {
		t.Fatalf("backdate failing schedule: %v", err)
	}
	s.runDueReports()
	doc, _ = s.reports.document()
	generated, err = s.reports.listGenerated()
	if err != nil {
		t.Fatalf("listGenerated: %v", err)
	}
	if len(generated) != 1 {
		t.Fatalf("failed run must not produce artifacts, have %+v", generated)
	}
	failing := doc.Definitions[1].Schedule
	if !failing.LastRunAt.IsZero() {
		t.Fatal("failed run must not move LastRunAt")
	}
	if !failing.NextRunAt.After(time.Now().UTC()) {
		t.Fatal("failed schedule must still advance to its next fire time")
	}
	_ = created2
}

// TestRenderDueReportRecoversFromPanic is a regression test for #1340:
// renderDueReport must recover a panic from the render step and turn it
// into an error, not let it propagate and crash the process -- matching
// the safety net net/http already provides per-request.
func TestRenderDueReportRecoversFromPanic(t *testing.T) {
	previous := renderDefinitionForSchedule
	t.Cleanup(func() { renderDefinitionForSchedule = previous })
	renderDefinitionForSchedule = func(s *store, id, origin string) (generatedReport, string, error) {
		panic("boom: pathological scope/template combination")
	}

	s := newReportTestStore(t)
	err := s.renderDueReport(reportDefinition{ID: "def-1", Name: "Panicking report"})
	if err == nil {
		t.Fatal("expected renderDueReport to return an error for a panicking render, got nil")
	}
	if !strings.Contains(err.Error(), "panic") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected the recovered panic to be reflected in the error, got %v", err)
	}
}

// TestRunDueReportsRecoversAndAdvancesSchedule is a regression test for
// #1340's failure mode: without recovery, a panicking definition crashes
// the whole process before markScheduledRun ever runs, so the same
// still-due definition gets picked up again on the very next tick after
// restart -- a persistent crash-restart loop. With recovery, the run still
// advances the schedule (same as any other failed run) and the process
// keeps running to process the rest of the tick.
func TestRunDueReportsRecoversAndAdvancesSchedule(t *testing.T) {
	previous := renderDefinitionForSchedule
	t.Cleanup(func() { renderDefinitionForSchedule = previous })
	renderDefinitionForSchedule = func(s *store, id, origin string) (generatedReport, string, error) {
		panic("boom")
	}

	s := newReportTestStore(t)
	def := sampleDefinition("custom")
	def.Name = "Panicking scheduled report"
	def.Schedule = &reportSchedule{Enabled: true, Frequency: "daily", Hour: 6, Minute: 30}
	created, _, err := s.reports.putDefinition("", def)
	if err != nil {
		t.Fatalf("create scheduled definition: %v", err)
	}
	past := time.Now().UTC().Add(-time.Minute)
	if _, _, err := s.reports.inner.Update("", func(doc *reportsDocument) error {
		doc.Definitions[0].Schedule.NextRunAt = past
		return nil
	}); err != nil {
		t.Fatalf("backdate schedule: %v", err)
	}

	// The panic inside runDueReports must not propagate out of this call --
	// a real regression here would fail the test process itself (a bare
	// panic in a test goroutine crashes `go test`), not just this assertion.
	s.runDueReports()

	doc, _ := s.reports.document()
	failing := doc.Definitions[0].Schedule
	if !failing.LastRunAt.IsZero() {
		t.Fatal("a panicking run must not record LastRunAt, same as any other failed run")
	}
	if !failing.NextRunAt.After(time.Now().UTC()) {
		t.Fatal("schedule must still advance to its next fire time after a panicking run, not get stuck re-firing every tick")
	}
	_ = created
}

// TestScheduleDisablesCleanly proves turning a schedule off clears the fire
// time so the scheduler ignores the definition.
func TestScheduleDisablesCleanly(t *testing.T) {
	s := newReportTestStore(t)
	def := sampleDefinition("custom")
	def.Schedule = &reportSchedule{Enabled: true, Frequency: "weekly", Hour: 9, Weekday: 1}
	created, _, err := s.reports.putDefinition("", def)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	created.Schedule.Enabled = false
	if _, _, err := s.reports.putDefinition("", created); err != nil {
		t.Fatalf("disable: %v", err)
	}
	loaded, _ := s.reports.definition(created.ID)
	if !loaded.Schedule.NextRunAt.IsZero() {
		t.Fatal("disabled schedule must clear NextRunAt")
	}
	if len(s.reports.dueReports(time.Now().UTC().Add(365*24*time.Hour))) != 0 {
		t.Fatal("disabled schedule must never be due")
	}
}
