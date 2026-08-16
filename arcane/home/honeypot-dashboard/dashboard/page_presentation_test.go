package main

import (
	"html/template"
	"strings"
	"testing"
	"time"
)

// renderOverview executes the overview page against a store whose
// configuration was mutated by configure. It proves the shell reads the live
// configuration store at render time (impact class new-request).
func renderOverview(t *testing.T, configure func(*dashboardConfig)) string {
	t.Helper()
	s := newSettingsAPITestStore(t, "admin")
	if configure != nil {
		if _, _, err := s.settings.config.Update("", func(c *dashboardConfig) error {
			configure(c)
			return nil
		}); err != nil {
			t.Fatalf("configure: %v", err)
		}
	}
	tmpl, err := template.New("t").Funcs(templateFuncs(s, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "page", snapshot{}); err != nil {
		t.Fatalf("overview page does not execute: %v", err)
	}
	return out.String()
}

// #181: mlPanelsEnabled is the single source of truth the /ml-anomalies
// handler gates on (main.go) -- the nav link's visibility is asserted
// separately in TestMLAnomaliesNavReflectsShowMLPanels, but both must agree
// with this same underlying value or the page ends up hidden-but-reachable
// or linked-but-404ing.
func TestMLPanelsEnabledTracksLiveConfig(t *testing.T) {
	if (*store)(nil).mlPanelsEnabled() {
		t.Fatal("a nil store must fall back to the compiled default (off)")
	}
	s := newSettingsAPITestStore(t, "admin")
	if s.mlPanelsEnabled() {
		t.Fatal("compiled default must be off")
	}
	if _, _, err := s.settings.config.Update("", func(c *dashboardConfig) error {
		c.Behavior.ShowMLPanels = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !s.mlPanelsEnabled() {
		t.Fatal("must reflect the live setting once enabled")
	}
}

func TestShellRendersConfiguredPresentation(t *testing.T) {
	html := renderOverview(t, func(c *dashboardConfig) {
		c.Presentation.BrandPrefix = ""
		c.Presentation.AppName = "SOCOPS//NOC"
		c.Presentation.ProductLabel = "Blue team"
		c.Presentation.DashboardTitle = "Operations bridge"
		c.Presentation.DashboardSubtitle = "Everything the night shift needs."
		c.Presentation.FooterText = "internal use only"
		c.Presentation.BannerText = "Cluster upgrade on Sunday"
		c.Presentation.BannerSeverity = "warning"
	})
	for _, want := range []string{
		"SOCOPS<span class=\"hp-brand-accent\">//</span>NOC",
		"<small>Blue team</small>",
		"<h1>Operations bridge</h1>",
		"Everything the night shift needs.",
		"internal use only",
		"alert alert--warning",
		"Cluster upgrade on Sunday",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("configured shell missing %q", want)
		}
	}
}

func TestShellDefaultsRenderUnchangedCopy(t *testing.T) {
	html := renderOverview(t, nil)
	for _, want := range []string{
		">APIARY</strong>",
		"<small>Defensive operations</small>",
		"<h1>Honeypot command center</h1>",
		"Live attack telemetry, captured evidence",
		"do not expose without auth",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("default shell must keep the previous copy, missing %q", want)
		}
	}
	if strings.Contains(html, `role="status" style="flex-basis:100%`) {
		t.Fatal("no banner may render without configured text or maintenance mode")
	}
}

func TestShellBannerRules(t *testing.T) {
	// Maintenance mode alone announces maintenance without configured text.
	html := renderOverview(t, func(c *dashboardConfig) {
		c.Behavior.MaintenanceMode = true
	})
	if !strings.Contains(html, "Dashboard is in maintenance mode.") || !strings.Contains(html, "alert--warning") {
		t.Fatal("maintenance mode must render the default warning banner")
	}
	// An expired banner never renders.
	html = renderOverview(t, func(c *dashboardConfig) {
		c.Presentation.BannerText = "old news"
		c.Presentation.BannerExpires = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	})
	if strings.Contains(html, "old news") {
		t.Fatal("expired banner must not render")
	}
	// A future expiry renders with the default info severity.
	html = renderOverview(t, func(c *dashboardConfig) {
		c.Presentation.BannerText = "planned work"
		c.Presentation.BannerExpires = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	})
	if !strings.Contains(html, "planned work") || !strings.Contains(html, "alert--info") {
		t.Fatal("active banner must render with default info severity")
	}
}

// TestShellConfiguredCopyIsEscaped is the Milestone E exit criterion: no
// configurable text can introduce executable content into the shell.
func TestShellConfiguredCopyIsEscaped(t *testing.T) {
	payload := `<script>alert(1)</script>`
	html := renderOverview(t, func(c *dashboardConfig) {
		c.Presentation.AppName = payload
		c.Presentation.DashboardTitle = payload
		c.Presentation.BannerText = payload
		c.Presentation.FooterText = payload
	})
	if strings.Contains(html, payload) {
		t.Fatal("configured copy must never render as executable markup")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatal("configured copy must render escaped")
	}
}

func TestBrandHTMLAccentOnlyWrapsSeparator(t *testing.T) {
	rendered := string(brandHTML(`A//B <img>`))
	if !strings.Contains(rendered, `A<span class="hp-brand-accent">//</span>B &lt;img&gt;`) {
		t.Fatalf("brand escaping wrong: %s", rendered)
	}
}
