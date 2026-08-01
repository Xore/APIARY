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

// brandHTML renders the configured application name with the // accent span
// the brand mark uses. The name is escaped first; the accent replacement then
// only ever wraps the literal "//" separator, never configured content.
func brandHTML(name string) template.HTML {
	escaped := template.HTMLEscapeString(strings.TrimSpace(name))
	escaped = strings.Replace(escaped, "//", `<span class="hp-brand-accent">//</span>`, 1)
	return template.HTML(escaped) //nolint:gosec // escaped above; only the accent span is added
}

// templateFuncs builds the FuncMap shared by every dashboard page. The
// presentation funcs resolve the effective configuration at render time; a
// nil store or settings service serves the compiled defaults, so the shell
// renders even while the settings stores are unavailable.
func templateFuncs(s *store, world template.HTML) template.FuncMap {
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
		"asset":    assetURL,
		"worldMap": func() template.HTML { return world },
		"json": func(value any) string {
			b, _ := json.MarshalIndent(value, "", "  ")
			return string(b)
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
		"brandHTML":    func() template.HTML { return brandHTML(presentation().AppName) },
		"activeBanner": func() *bannerView { return activeBannerView(presentation(), behavior(), time.Now()) },
	}
}
