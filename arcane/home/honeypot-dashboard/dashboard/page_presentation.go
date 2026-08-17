package main

// page_presentation.go — wires the administrator-configurable presentation
// namespace (roadmap §4, Milestone E step 3) into the shared shell. Templates
// call these template funcs; each call reads the live configuration store, so
// a saved branding change is visible on the next page render (impact class
// new-request). All values render through html/template escaping — the domain
// validator already rejects control characters, so configured copy can never
// introduce markup or script.

import (
	"encoding/json"
	"hash/fnv"
	"html/template"
	"strconv"
	"strings"
	"time"
)

// bannerView is the effective maintenance/incident banner for the current
// render: configured text within its expiry window, or the maintenance-mode
// fallback from the behavior namespace.
type bannerView struct {
	Text     string
	Severity string
}

// activeBannerView computes the banner for now. An empty banner text with
// maintenance mode enabled still announces maintenance; an expired banner
// never renders. The severity comes from the validated allowlist.
func activeBannerView(p presentationConfig, b behaviorConfig, now time.Time) *bannerView {
	text := strings.TrimSpace(p.BannerText)
	severity := p.BannerSeverity
	if severity == "" {
		severity = "info"
	}
	if text != "" {
		if p.BannerExpires != "" {
			if expiry, err := time.Parse(time.RFC3339, p.BannerExpires); err == nil && now.After(expiry) {
				return nil
			}
		}
		return &bannerView{Text: text, Severity: severity}
	}
	if b.MaintenanceMode {
		return &bannerView{Text: "Dashboard is in maintenance mode.", Severity: "warning"}
	}
	return nil
}

// brandHTML renders the configured brand (BrandPrefix + AppName, #776) with
// the // accent span the brand mark uses. The combined text is escaped first;
// the accent replacement then only ever wraps the literal "//" separator,
// never configured content.
func brandHTML(name string) template.HTML {
	escaped := template.HTMLEscapeString(strings.TrimSpace(name))
	escaped = strings.Replace(escaped, "//", `<span class="hp-brand-accent">//</span>`, 1)
	return template.HTML(escaped) //nolint:gosec // escaped above; only the accent span is added
}

// brandText renders the same configured brand as brandHTML but as plain
// text, for contexts like <title> that can't hold the accent-span markup.
func brandText(prefix, name string) string {
	return strings.TrimSpace(prefix) + strings.TrimSpace(name)
}

// mlPanelsEnabled reports the live behavior.show_ml_panels setting (#181):
// the "Experimental ML/LLM panels" toggle persisted correctly but nothing
// ever read it, so /ml-anomalies stayed reachable regardless of its state.
// This is the single source of truth for that gate -- the sidebar's nav
// link (via the "behavior" template func above) and this handler check must
// agree, or the page would be hidden but still directly reachable by URL
// (or linked but 404ing) depending on which side went stale.
func (s *store) mlPanelsEnabled() bool {
	if s == nil || s.settings == nil {
		return defaultDashboardConfig().Behavior.ShowMLPanels
	}
	cfg, _ := s.settings.config.Get()
	return cfg.Behavior.ShowMLPanels
}

// templateFuncs builds the FuncMap shared by every dashboard page. The
// presentation funcs resolve the effective configuration at render time; a
// nil store or settings service serves the compiled defaults, so the shell
// renders even while the settings stores are unavailable.
func templateFuncs(s *store, _ template.HTML) template.FuncMap {
	presentation := func() presentationConfig {
		if s == nil || s.settings == nil {
			return defaultDashboardConfig().Presentation
		}
		cfg, _ := s.settings.config.Get()
		return cfg.Presentation
	}
	behavior := func() behaviorConfig {
		if s == nil || s.settings == nil {
			return defaultDashboardConfig().Behavior
		}
		cfg, _ := s.settings.config.Get()
		return cfg.Behavior
	}
	return template.FuncMap{
		"asset":             assetURL,
		"chatMessageText":   chatMessageText,
		"chatToolCallsText": chatToolCallsText,
		// inc turns a 0-based {{range}} index into a 1-based CSS
		// :nth-child() position, for the activity chart's per-bar height
		// rule (see overview.html) -- nth-child counts from 1, {{range}}
		// counts from 0.
		"inc": func(i int) int { return i + 1 },
		// template.JS, not string: html/template's contextual auto-escaper
		// treats a plain-string pipeline result inside a <script> value
		// position (window.x = {{json .}};) as untrusted JS string data and
		// re-encodes it as a quoted, escaped JS string literal -- the
		// caller ends up with window.x === "[...]" (a string) rather than
		// the parsed array/object, silently breaking every .map/.forEach
		// call on it. template.JS marks this as already-safe JS/JSON, which
		// is honored only within a genuine JS context; verified this still
		// gets ordinary HTML-escaping when used in an HTML text context
		// instead (events.html's <pre>{{json .}}</pre>), so this is safe
		// for both of this function's call sites, not just the broken one.
		"json": func(value any) template.JS {
			b, _ := json.MarshalIndent(value, "", "  ")
			return template.JS(b)
		},
		"dict": func(pairs ...any) map[string]any {
			m := make(map[string]any, len(pairs)/2)
			for i := 0; i+1 < len(pairs); i += 2 {
				key, _ := pairs[i].(string)
				m[key] = pairs[i+1]
			}
			return m
		},
		// eventKey gives each event row a stable-within-the-page DOM key for
		// the shared evidence-viewer contract (#59): identical marshaled
		// content always yields the same key, distinct content practically
		// never collides. Non-cryptographic on purpose -- this is a DOM
		// lookup key, not a security boundary.
		"eventKey": func(e storedEvent) string {
			b, _ := json.Marshal(e)
			h := fnv.New64a()
			h.Write(b)
			return strconv.FormatUint(h.Sum64(), 36)
		},
		"presentation": presentation,
		"behavior":     behavior,
		// Design refresh (OV-B): the overview hero's humane one-line
		// greeting -- salutation by server-local hour, clause from the
		// same ActivityState the 24h KPI tile already shows.
		"overviewGreeting": overviewGreeting,
		// #1566: normalize raw upstream ISO timestamps for display.
		"displayTime": displayTime,
		// Design refresh 2 (EV-D): minute-break labels for the event feed.
		"feedBreak": feedBreak,
		// Design refresh (3B): 24 column totals of the sensor heatmap,
		// normalized to the busiest hour, for the events-24h KPI tile's
		// sparkline. Rendered via a nonced <style> (same CSP posture as
		// the heatmap's own cells).
		"hourlySpark":           hourlySpark,
		"reportPresetRows":      func() []reportPresetRow { return reportPresetRowsFor(presentation().ReportPresets) },
		"brandHTML":             func() template.HTML { return brandHTML(presentation().BrandPrefix + presentation().AppName) },
		"brandText":             func() string { return brandText(presentation().BrandPrefix, presentation().AppName) },
		"activeBanner":          func() *bannerView { return activeBannerView(presentation(), behavior(), time.Now()) },
		"intelBadgeClass":       intelBadgeClass,
		"icsSeverityBadgeClass": icsSeverityBadgeClass,
		"workbenchRunSummary":   workbenchRunSummary,
		// utcOrEmpty gives the header "generated"/"updated" timestamp the
		// same data-hp-utc twin events.html's rows carry, so hp-app.js's
		// shared timezone/clock-format conversion (see hp-app.js's
		// applyTimeDisplay) applies to it too instead of it being stuck in
		// whatever zone/format the server process itself renders in.
		"utcOrEmpty": utcOrEmpty,
		// #1203: shortAttackerID trims the entity ID for display in
		// attackers.html's header and table. The graph itself (node/edge
		// data for the selected entity's member IPs) is served by
		// /api/attacker-graph and rendered client-side by hp-attackers.js
		// (Cytoscape.js), not through a template func.
		"shortAttackerID": shortAttackerID,
		// #1260: links attacker-identity-worker's own durable
		// Techniques field (bare ATT&CK IDs) on attackers.html the same
		// way techniquesForEvent's own attackTechnique.URL already does.
		"attckTechniqueURL": attckTechniqueURL,
	}
}
