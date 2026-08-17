package main

// Design-refresh helpers for the overview hero (OV-B) and the KPI
// sparkline (3B) -- see ui/overview.html and page_presentation.go's
// templateFuncs entries.

import (
	"fmt"
	"time"
)

// overviewGreeting builds the hero's one-line serif greeting: a salutation
// from the server-local hour plus a clause derived from the same
// ActivityState string aggregate.go already computes for the 24h KPI tile.
func overviewGreeting(activityState string) string {
	var salutation string
	switch hour := time.Now().Hour(); {
	case hour < 5:
		salutation = "Quiet hours"
	case hour < 12:
		salutation = "Good morning"
	case hour < 18:
		salutation = "Good afternoon"
	case hour < 22:
		salutation = "Good evening"
	default:
		salutation = "Late shift"
	}
	var clause string
	switch activityState {
	case "normal":
		clause = "traffic is at its usual rhythm."
	case "spike":
		clause = "a traffic spike is underway."
	case "elevated":
		clause = "traffic is running hotter than usual."
	case "low":
		clause = "the sensors are unusually quiet."
	default:
		// "baseline unavailable" / "insufficient baseline ..." -- the
		// first day of a deployment, or ES temporarily unreadable.
		clause = "the traffic baseline is still building."
	}
	return fmt.Sprintf("%s — %s", salutation, clause)
}

// displayTime normalizes a raw upstream timestamp string (RFC3339 with
// nanos/micros, with or without an explicit offset) into the dashboard's
// standard "2006-01-02 15:04:05" display form (#1566 -- ml-anomalies and
// auth-events used to print "2026-08-11T15:23:03.350000+00:00" verbatim).
// Anything unparseable renders unchanged: a raw string beats a fabricated
// date. The cell keeps its data-hp-utc twin, so per-viewer timezone
// conversion (hp-app.js applyTimeDisplay) is unaffected.
func displayTime(raw string) string {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC().Format("2006-01-02 15:04:05")
		}
	}
	return raw
}

// sparkBar is one bar of the KPI sparkline: a 1-based nth-child position
// and a height percentage, consumed by a nonced <style> block exactly the
// way heatmapCell.Pct is (Xore/theme docs/CSP.md -- no inline styles).
type sparkBar struct {
	N   int
	Pct int
}

// hourlySpark sums the sensor heatmap's columns into per-hour totals and
// normalizes them against the busiest hour. Empty input yields nil, which
// the template treats as "no sparkline".
func hourlySpark(rows []heatmapRow) []sparkBar {
	if len(rows) == 0 {
		return nil
	}
	width := 0
	for _, row := range rows {
		if len(row.Cells) > width {
			width = len(row.Cells)
		}
	}
	if width == 0 {
		return nil
	}
	totals := make([]int, width)
	max := 0
	for _, row := range rows {
		for i, cell := range row.Cells {
			totals[i] += cell.Count
			if totals[i] > max {
				max = totals[i]
			}
		}
	}
	if max == 0 {
		return nil
	}
	bars := make([]sparkBar, width)
	for i, total := range totals {
		pct := total * 100 / max
		if pct < 4 {
			pct = 4 // keep even silent hours visible as a baseline tick
		}
		bars[i] = sparkBar{N: i + 1, Pct: pct}
	}
	return bars
}

// feedBreak gives the event explorer its EV-D time-grouped feed rhythm: the
// minute label ("15:04") when event i opens a new minute group, "" while the
// previous event shares the minute. Works on the same normalized "2006-01-02
// 15:04:05" strings storedEvent.Time already carries; an unparseable pair
// simply never breaks, which degrades to the old ungrouped table. The first
// row of every remote batch (offset fragments render in isolation) starts
// its own group -- at worst that duplicates a label across a batch seam.
func feedBreak(events []storedEvent, i int) string {
	if i < 0 || i >= len(events) || len(events[i].Time) < 16 {
		return ""
	}
	minute := events[i].Time[:16]
	if i > 0 && len(events[i-1].Time) >= 16 && events[i-1].Time[:16] == minute {
		return ""
	}
	return minute[11:]
}
