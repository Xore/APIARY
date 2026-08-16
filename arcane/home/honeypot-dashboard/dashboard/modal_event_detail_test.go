package main

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEventDetailInlineContract covers #1447's in-flow event evidence: every
// row carries one complete, bounded normalized record plus its pivots, with
// no modal trigger or hidden evidence body between the analyst and the data.
func TestEventDetailInlineContract(t *testing.T) {
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

	if got := strings.Count(html, `data-hp-event-detail="`); got != 2 {
		t.Fatalf("expected one inline normalized record per event, got %d", got)
	}
	for _, forbidden := range []string{`data-hp-evidence="`, `data-hp-evidence-body="`} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("event detail is still modal-only or hidden: %q", forbidden)
		}
	}

	for _, want := range []string{
		// html/template escapes quotes even in a <pre> text node, so the JSON
		// dump's literal `"` becomes `&#34;` -- still valid, still readable,
		// still exactly the content-integrity property that matters here.
		`&#34;SrcIP&#34;: &#34;203.0.113.9&#34;`, `&#34;SrcIP&#34;: &#34;203.0.113.10&#34;`,
		"investigate/ip/203.0.113.9", "sessions/sess-a", `class="card__scroll"><pre class="code"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("rendered event detail is missing %q", want)
		}
	}
}

// TestEventTimestampCarriesUTCAttribute (#282): the events table's <td> must
// expose the raw UTC instant as a machine-readable data-hp-utc attribute
// alongside the fixed UTC display string, so client-side JS can reformat it
// into the viewer's own timezone preference without a server round trip. An
// event whose timestamp never parsed (UTC left "" by utcOrEmpty) must not
// get the attribute at all -- reformatting a zero-value UTC string would
// turn "the raw unparsed line" into a fabricated, wrong-looking date.
func TestEventTimestampCarriesUTCAttribute(t *testing.T) {
	s := &store{}
	s.events = []storedEvent{
		{Time: "2026-08-01 10:00:00", UTC: "2026-08-01T10:00:00Z", Sensor: "cowrie", SrcIP: "203.0.113.9", Detail: "login attempt"},
		{Time: "unparseable-raw-line", UTC: "", Sensor: "cowrie", SrcIP: "203.0.113.10", Detail: "login attempt"},
	}
	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))

	page := s.eventsData(httptest.NewRequest("GET", "/events", nil))
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "events", &page); err != nil {
		t.Fatalf("events page does not render: %v", err)
	}
	html := out.String()

	if !strings.Contains(html, `data-hp-utc="2026-08-01T10:00:00Z"`) {
		t.Fatal("rendered event row is missing its data-hp-utc attribute")
	}
	if !strings.Contains(html, "unparseable-raw-line") {
		t.Fatal("the raw, unparsed timestamp string must still render as-is")
	}
	if strings.Contains(html, `data-hp-utc=""`) {
		t.Fatal("an event with no parsed timestamp must not get an empty data-hp-utc attribute")
	}
}

// TestEventDetailInlineEscapesHostileContent proves html/template's
// auto-escaping must turn a markup-shaped Detail field into inert text, both
// in the visible row and inside the JSON block a real attacker-controlled
// command could otherwise reach.
func TestEventDetailInlineEscapesHostileContent(t *testing.T) {
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
