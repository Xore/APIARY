package main

import (
	"html/template"
	"strings"
	"testing"
)

// TestSettingsPageIsPermanentDialog executes the /settings template and
// asserts the permanent-dialog contract from the roadmap: the page IS a
// modal, the nested confirmation is a DESCENDANT of it (browser top-layer
// invariant), Escape has no close control, and every personal pane and
// preference control is server-rendered.
func TestSettingsPageIsPermanentDialog(t *testing.T) {
	tmpl, err := template.New("t").Funcs(template.FuncMap{
		"worldMap": func() template.HTML { return "" },
		"json":     func(any) string { return "" },
		"dict":     func(...any) map[string]any { return nil },
	}).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "settings", nil); err != nil {
		t.Fatalf("settings page does not execute: %v", err)
	}
	html := out.String()

	for _, want := range []string{
		`data-permanent-dialog`, `modal modal--permanent`, `id="hp-settings"`,
		`data-hp-settings-search`, `data-hp-settings-back`, `data-hp-settings-status`,
		`/static/hp-settings.js`,
		`data-hp-pane="account"`, `data-hp-pane="appearance"`, `data-hp-pane="navigation"`,
		`data-hp-pane="time"`, `data-hp-pane="map"`,
		`data-hp-pane-nav="account"`, `data-hp-pane-nav="appearance"`,
		`data-hp-pane-nav="navigation"`, `data-hp-pane-nav="time"`, `data-hp-pane-nav="map"`,
		`data-hp-save="appearance"`, `data-hp-save="navigation"`,
		`data-hp-save="time"`, `data-hp-save="map"`, `data-hp-reset-all`,
		`data-hp-acct-name`, `data-hp-acct-subject`, `data-hp-acct-role`,
		`data-hp-acct-caps`, `data-hp-acct-link`, `data-hp-acct-logout`,
		`id="hp-settings-confirm-backdrop"`, `id="hp-settings-confirm"`,
		`data-hp-confirm-cancel`, `data-hp-confirm-action`, `role="alertdialog"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("settings page missing marker %q", want)
		}
	}

	// Every preference field of the settings domain must have a control.
	for _, pref := range []string{
		"theme", "density", "reduced_motion", "high_contrast", "large_evidence_text",
		"landing_page", "collapsed_sidebar", "remember_filters", "open_details_new_tab",
		"rows_per_page", "wrap_long_values", "timezone", "clock", "timestamps",
		"auto_refresh", "refresh_interval_seconds", "live_toasts", "notify_severity",
		"notify_sound", "notify_desktop", "map_basemap", "map_clustering",
		"map_animation", "default_event_window", "preserve_filters",
	} {
		if !strings.Contains(html, `data-pref="`+pref+`"`) {
			t.Fatalf("settings page missing control for preference %q", pref)
		}
	}

	// The nested confirmation must appear INSIDE the permanent dialog: the
	// permanent dialog opens first, and both confirm elements follow it.
	dialogAt := strings.Index(html, `data-permanent-dialog`)
	backdropAt := strings.Index(html, `id="hp-settings-confirm-backdrop"`)
	confirmAt := strings.Index(html, `id="hp-settings-confirm"`)
	if dialogAt < 0 || backdropAt < dialogAt || confirmAt < backdropAt {
		t.Fatal("nested confirmation must be a descendant of the permanent dialog")
	}

	// A permanent dialog has no close affordance and no placeholder identity.
	if strings.Contains(html, "modal__close") {
		t.Fatal("permanent settings dialog must not render a close control")
	}
	if strings.Contains(html, "dashboard operator") {
		t.Fatal("settings page must render only the auth-backend provided identity")
	}
}

// TestSettingsControllerContract pins the client behaviors the permanent
// dialog and its nested confirmation rely on, so a refactor of hp-settings.js
// cannot silently drop the modal contract, the Escape policy, or the
// concurrency handling.
func TestSettingsControllerContract(t *testing.T) {
	data, err := staticAssets.ReadFile("static/hp-settings.js")
	if err != nil {
		t.Fatal("static/hp-settings.js must be embedded with the dashboard assets")
	}
	js := string(data)
	for _, want := range []string{
		"showModal()", // opens as a true modal
		`"cancel", event => event.preventDefault()`, // Escape never closes settings
		"beforeunload",                 // unsaved-changes guard
		`.get("pane")`,                 // ?pane= deep link
		"history.replaceState",         // pane switches update the URL
		`PANE_META[name]`,              // unknown pane names fall back
		"/api/settings/me",             // load endpoint
		"/api/settings/me/preferences", // save endpoint
		"/api/settings/me/preferences/reset",
		`"If-Match"`,                   // optimistic concurrency
		"status === 409",               // conflict: reload latest
		"status === 422",               // validation: field-named message
		"status === 429",               // throttled
		"/api/whoami",                  // read-only identity
		"/_auth/logout",                // logout stays on the auth origin
		"state.confirmCallback = null", // confirm executes exactly once
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("hp-settings.js missing behavior %q", want)
		}
	}
}

// TestSettingsLinkedFromAccountMenu ensures the dashboard shell exposes the
// /settings page from the account dropdown next to the auth-account popup.
func TestSettingsLinkedFromAccountMenu(t *testing.T) {
	partial := mustReadUI("partials/dashboard.html")
	if !strings.Contains(partial, `data-hp-account-dashboard-settings`) ||
		!strings.Contains(partial, `href="/settings"`) {
		t.Fatal("account menu must link to the /settings page")
	}
	if !strings.Contains(partial, "Account &amp; security") {
		t.Fatal("auth-account popup entry must be labeled Account & security")
	}
}
