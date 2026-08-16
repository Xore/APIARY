package main

import (
	"html/template"
	"os"
	"strings"
	"testing"
	"time"
)

func TestVisualizationAndSessionShellsMatchHydratedShapes(t *testing.T) {
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))
	selected := attackerRow{ID: "entity-fixture"}
	var attackers strings.Builder
	if err := tmpl.ExecuteTemplate(&attackers, "attackers", &attackersPage{Generated: time.Now(), Selected: &selected}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"data-attacker-graph-loading", "data-chart-loading", `aria-busy="true"`} {
		if !strings.Contains(attackers.String(), want) {
			t.Fatalf("attacker visualization shell missing %q", want)
		}
	}
	var kill strings.Builder
	if err := tmpl.ExecuteTemplate(&kill, "kill-chain", &killChainPage{Generated: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(kill.String(), "data-chart-loading") != 3 {
		t.Fatal("all three kill-chain frames must have distinct chart-shaped loading surfaces")
	}
	var session strings.Builder
	if err := tmpl.ExecuteTemplate(&session, "session", &sessionPage{ID: "session-fixture"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Sensors", "Credentials", "Commands", "Payload hashes", "MITRE ATT&amp;CK techniques", "Chronological replay", "card__scroll"} {
		if !strings.Contains(session.String(), want) {
			t.Fatalf("session shell missing hydrated-shape region %q", want)
		}
	}
	for _, file := range []string{"static/hp-attackers.js", "static/hp-kill-chain.js"} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(source), `aria-busy`) || !strings.Contains(string(source), `role`) {
			t.Fatalf("%s does not settle its chart frame accessibly", file)
		}
	}
}
