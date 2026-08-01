package main

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEventDetailModalContract is #59's event-detail modal, reviewed here as
// its own data-attribute contract: each row's "details" trigger
// (data-hp-evidence) must have exactly one matching hidden body
// (data-hp-evidence-body) carrying the full normalized event as escaped
// JSON, plus pivot links -- rendered through the existing shared
// hp-evidence.js viewer (no new JS controller for this modal).
func TestEventDetailModalContract(t *testing.T) {
	s := &store{}
	s.events = []storedEvent{
		{Time: "2026-08-01 10:00", Sensor: "cowrie", SrcIP: "203.0.113.9", Session: "sess-a", Command: "id", Detail: "login attempt"},
		{Time: "2026-08-01 10:01", Sensor: "cowrie", SrcIP: "203.0.113.10", Session: "sess-b", Command: "ls", Detail: "login attempt"},
	}
	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))

	page := s.eventsData(httptest.NewRequest("GET", "/events", nil))
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "events", &page); err != nil {
		t.Fatalf("events page does not render: %v", err)
	}
	html := out.String()

	triggers := extractAttrValues(html, `data-hp-evidence="`)
	bodies := extractAttrValues(html, `data-hp-evidence-body="`)
	if len(triggers) != 2 || len(bodies) != 2 {
		t.Fatalf("expected 2 trigger/body pairs for 2 events, got triggers=%v bodies=%v", triggers, bodies)
	}
	if triggers[0] == triggers[1] {
		t.Fatalf("two distinct events produced the same evidence key: %q", triggers[0])
	}
	for _, key := range triggers {
		found := false
		for _, b := range bodies {
			if b == key {
				found = true
			}
		}
		if !found {
			t.Fatalf("trigger key %q has no matching data-hp-evidence-body", key)
		}
	}

	for _, want := range []string{
		// html/template escapes quotes even in a <pre> text node, so the JSON
		// dump's literal `"` becomes `&#34;` -- still valid, still readable,
		// still exactly the content-integrity property that matters here.
		`&#34;SrcIP&#34;: &#34;203.0.113.9&#34;`, `&#34;SrcIP&#34;: &#34;203.0.113.10&#34;`,
		"investigate/ip/203.0.113.9", "sessions/sess-a",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("rendered event detail is missing %q", want)
		}
	}
}

// TestEventDetailModalEscapesHostileContent proves the guide's own
// requirement for this class of modal ("never inject raw ... bytes as
// HTML") holds for the event-detail JSON dump specifically: html/template's
// auto-escaping must turn a markup-shaped Detail field into inert text, both
// in the visible row and inside the JSON block a real attacker-controlled
// command could otherwise reach.
func TestEventDetailModalEscapesHostileContent(t *testing.T) {
	s := &store{}
	s.events = []storedEvent{
		{Time: "2026-08-01 10:00", Sensor: "cowrie", SrcIP: "203.0.113.9", Command: `<img src=x onerror=alert(1)>`, Detail: `<script>alert(1)</script>`},
	}
	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Parse("")).Funcs(funcs)
	tmpl = template.Must(tmpl.Parse(pageTemplate))

	page := s.eventsData(httptest.NewRequest("GET", "/events", nil))
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "events", &page); err != nil {
		t.Fatalf("events page does not render: %v", err)
	}
	html := out.String()

	for _, hostile := range []string{"<script>alert(1)</script>", "<img src=x onerror=alert(1)>"} {
		if strings.Contains(html, hostile) {
			t.Fatalf("hostile event content reached the rendered page unescaped: %q", hostile)
		}
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("expected the hostile Detail value to appear HTML-escaped in the JSON dump")
	}
}

func extractAttrValues(html, prefix string) []string {
	var values []string
	rest := html
	for {
		idx := strings.Index(rest, prefix)
		if idx < 0 {
			break
		}
		rest = rest[idx+len(prefix):]
		end := strings.Index(rest, `"`)
		if end < 0 {
			break
		}
		values = append(values, rest[:end])
		rest = rest[end:]
	}
	return values
}
