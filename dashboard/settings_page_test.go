package main

import (
	"html/template"
	"strings"
	"testing"
)

// renderSettings executes the settings modal fragment with the given admin flag.
func renderSettings(t *testing.T, admin bool) string {
	t.Helper()
	tmpl, err := template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "settingsModal", settingsPageData{Admin: admin}); err != nil {
		t.Fatalf("settings modal does not execute: %v", err)
	}
	return out.String()
}

// TestSettingsModalIsCenteredOverlay executes the settings fragment and
// asserts the centered-modal contract: it is a fragment (no page chrome), it
// opens as a closable overlay with backdrop and close control, the nested
// confirmation is a DESCENDANT of it (browser top-layer invariant), and every
// personal pane and preference control is server-rendered.
func TestSettingsModalIsCenteredOverlay(t *testing.T) {
	html := renderSettings(t, false)

	for _, want := range []string{
		`class="modal hp-dash-settings"`, `id="hp-settings"`,
		`id="hp-dash-settings-backdrop"`, `data-hp-settings-close`, `modal__close`,
		`aria-labelledby="hp-dash-settings-title"`, `id="hp-dash-settings-title"`,
		`data-hp-settings-search`, `data-hp-settings-status`,
		`data-hp-pane="account"`, `data-hp-pane="appearance"`, `data-hp-pane="navigation"`,
		`data-hp-pane="time"`, `data-hp-pane="map"`,
		`data-hp-pane-nav="account"`, `data-hp-pane-nav="appearance"`,
		`data-hp-pane-nav="navigation"`, `data-hp-pane-nav="time"`, `data-hp-pane-nav="map"`,
		`data-hp-save="appearance"`, `data-hp-save="navigation"`,
		`data-hp-save="time"`, `data-hp-save="map"`, `data-hp-reset-all`,
		`data-hp-acct-name`, `data-hp-acct-subject`, `data-hp-acct-role`,
		`data-hp-acct-caps`, `data-hp-acct-link`, `data-hp-acct-logout`,
		`id="hp-settings-confirm"`,
		`data-hp-confirm-cancel`, `data-hp-confirm-action`, `role="alertdialog"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("settings modal missing marker %q", want)
		}
	}

	// A fragment, not a page: no document chrome, no script/stylesheet tags,
	// and no permanent-dialog leftovers from the old /settings page.
	for _, absent := range []string{
		"<!doctype", "<html", "<head>", "<head ", "<body", "<script",
		"data-permanent-dialog", "modal--permanent", `data-hp-settings-back`,
		// MODALS.md strategy 1: a native dialog opened with showModal() uses
		// its own ::backdrop and must not be paired with a sibling backdrop.
		`id="hp-settings-confirm-backdrop"`,
	} {
		if strings.Contains(html, absent) {
			t.Fatalf("settings modal must not contain page marker %q", absent)
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
			t.Fatalf("settings modal missing control for preference %q", pref)
		}
	}

	// The nested confirmation must appear INSIDE the modal: the modal opens
	// first and the confirmation follows it, before the modal closes.
	dialogAt := strings.Index(html, `id="hp-settings"`)
	confirmAt := strings.Index(html, `id="hp-settings-confirm"`)
	if dialogAt < 0 || confirmAt < dialogAt || !strings.HasSuffix(strings.TrimSpace(html), "</section>") {
		t.Fatal("nested confirmation must be a descendant of the settings modal")
	}

	if strings.Contains(html, "dashboard operator") {
		t.Fatal("settings modal must render only the auth-backend provided identity")
	}
}

// The shared confirmation is the deepest layer when it is open, so it must
// stop the keydown reaching the settings modal's own document listener —
// plain stopPropagation would not, since both listen on document.
func TestSharedConfirmationOwnsEscapeWhileOpen(t *testing.T) {
	data, err := staticAssets.ReadFile("static/hp-modals.js")
	if err != nil {
		t.Fatal("static/hp-modals.js must be embedded with the dashboard assets")
	}
	js := string(data)
	for _, want := range []string{"stopImmediatePropagation()", "isOpen:"} {
		if !strings.Contains(js, want) {
			t.Fatalf("shared confirmation controller is missing %q", want)
		}
	}
}

// TestSettingsControllerContract pins the client behaviors the centered modal
// and its nested confirmation rely on, so a refactor of hp-settings.js cannot
// silently drop the modal contract, the Escape policy, or the concurrency
// handling.
func TestSettingsControllerContract(t *testing.T) {
	data, err := staticAssets.ReadFile("static/hp-settings.js")
	if err != nil {
		t.Fatal("static/hp-settings.js must be embedded with the dashboard assets")
	}
	js := string(data)
	for _, want := range []string{
		"/api/settings/modal", // lazy fragment fetch
		"hp-dash-settings-root",
		`"#settings"`, // hash opens the modal (old /settings bookmarks)
		`"Escape"`,    // Escape closes the modal
		"closeSettings",
		"showModal()",                  // nested confirm is a true modal
		"beforeunload",                 // unsaved-changes guard
		`PANE_META[name]`,              // unknown pane names fall back
		"/api/settings/me",             // load endpoint
		"/api/settings/me/preferences", // save endpoint
		"/api/settings/me/preferences/reset",
		`"If-Match"`,                       // optimistic concurrency
		"status === 409",                   // conflict: reload latest
		"status === 422",                   // validation: field-named message
		"status === 429",                   // throttled
		"/api/whoami",                      // read-only identity
		`actions.logout || "/auth/logout"`, // native RP-initiated logout
		"state.confirmCallback = null",     // confirm executes exactly once
		// Administration (Milestone E): validate → confirm → PATCH, env pins,
		// staged honeypot thresholds, history/rollback, users, and audit.
		"/api/settings/config",
		"/api/settings/config/validate",
		"/api/settings/config/rollback",
		"/api/settings/config/history",
		"/api/settings/users",
		"/api/settings/audit",
		// #257: Elasticsearch history and dead-letters moved into admin-only
		// panes, reusing the same endpoints the standalone pages used.
		"/api/history",
		"/api/dead-letters",
		"/export/history.json",
		"restart-required", // staged impact is confirmed explicitly
		"(environment)",    // env-pinned fields show their source
		"data-cfg",         // admin controls are keyed by data-cfg
		"flattenConfig",    // dotted-name snapshots drive dirty tracking
		// Escape belongs to the deepest layer: the settings surface yields to
		// the shared destructive confirmation as well as to its own.
		"window.HoneypotModals?.isOpen()",
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("hp-settings.js missing behavior %q", want)
		}
	}

	// The controller must scope its DOM queries to the injected fragment so
	// the host page can never collide with the settings DOM.
	for _, absent := range []string{
		`document.querySelector("[data-pref]")`,
		`document.querySelectorAll("[data-pref]")`,
		"history.replaceState", // a modal never rewrites the page URL
		`.get("pane")`,         // no ?pane= page deep links anymore
	} {
		if strings.Contains(js, absent) {
			t.Fatalf("hp-settings.js must not contain %q", absent)
		}
	}
}

// TestSettingsAdminPanesAreServerGated proves the administration panes exist
// only in documents rendered for a live-introspected admin (§12: hiding is
// server-side, never client-side alone). A non-admin document carries no
// admin markup at all — no controls to merely "hide".
func TestSettingsAdminPanesAreServerGated(t *testing.T) {
	admin := renderSettings(t, true)
	for _, want := range []string{
		`data-hp-pane-nav="branding"`, `data-hp-pane-nav="report-presets"`, `data-hp-pane-nav="behavior"`, `data-hp-pane-nav="honeypot"`,
		`data-hp-pane-nav="users"`, `data-hp-pane-nav="services"`, `data-hp-pane-nav="history"`, `data-hp-pane-nav="audit"`,
		`data-hp-pane-nav="elasticsearch"`, `data-hp-pane-nav="dead-letters"`,
		`data-hp-pane="branding"`, `data-hp-pane="report-presets"`, `data-hp-pane="behavior"`, `data-hp-pane="honeypot"`,
		`data-hp-pane="users"`, `data-hp-pane="services"`, `data-hp-pane="history"`, `data-hp-pane="audit"`,
		`data-hp-pane="elasticsearch"`, `data-hp-pane="dead-letters"`,
		`data-hp-report-preset="executive"`, `data-hp-report-preset-name`, `data-hp-report-preset-description`,
		`data-hp-report-preset-save`,
		`hp-es-history-results`, `hp-es-history-run`, `hp-es-history-export`,
		`hp-dead-letters-rows`, `hp-dead-letters-run`, `hp-dead-letters-purge`,
		`data-cfg="presentation.app_name"`, `data-cfg="presentation.help_link_url"`,
		`data-cfg="presentation.banner_severity"`, `data-cfg="presentation.ai_disclaimer"`,
		`data-cfg="behavior.default_landing"`, `data-cfg="behavior.rows_per_page_options"`,
		`data-cfg="behavior.maintenance_mode"`, `data-cfg="behavior.read_only"`,
		`data-cfg="honeypot.alert_cooldown"`, `data-cfg="honeypot.yara_max_bytes"`,
		`data-cfg-source="honeypot.alert_cooldown"`,
		`data-hp-cfg-save="branding"`, `data-hp-cfg-save="behavior"`, `data-hp-cfg-save="honeypot"`,
		`data-hp-users-list`, `data-hp-history-list`, `data-hp-audit-list`, `data-hp-audit-filter`,
		`data-hp-apply-command`,
		`data-hp-services-list`, `data-hp-services-refresh`,
		`data-hp-evidence="services-log"`, `data-hp-evidence-body="services-log"`,
	} {
		if !strings.Contains(admin, want) {
			t.Fatalf("admin settings document missing marker %q", want)
		}
	}

	user := renderSettings(t, false)
	for _, absent := range []string{
		`data-hp-pane-nav="branding"`, `data-hp-pane="branding"`, `data-cfg=`,
		`data-hp-pane-nav="report-presets"`, `data-hp-pane="report-presets"`, `data-hp-report-preset=`,
		`data-hp-users-list`, `data-hp-history-list`, `data-hp-audit-list`,
		`data-hp-services-list`,
		`data-hp-pane-nav="elasticsearch"`, `data-hp-pane="elasticsearch"`,
		`data-hp-pane-nav="dead-letters"`, `data-hp-pane="dead-letters"`,
		`Administration`,
	} {
		if strings.Contains(user, absent) {
			t.Fatalf("non-admin settings document must not contain admin marker %q", absent)
		}
	}
}

// TestSettingsServicesPaneUsesThemeDataDisplay (#258 follow-up): the Services
// pane was rendering its table with hp-table/hp-table-wrap, dead classes with
// no CSS definition anywhere in this repo -- confirmed by grepping both
// hp-dashboard.css and theme.css before this change. Restyled to match
// Xore/theme's own "Data display" example (examples/components.html#data): a
// metric-grid summary above a table-scroll/data-table pair.
func TestSettingsServicesPaneUsesThemeDataDisplay(t *testing.T) {
	admin := renderSettings(t, true)
	for _, gone := range []string{`class="hp-table"`, `class="hp-table-wrap"`} {
		if strings.Contains(admin, gone) {
			t.Fatalf("services pane still renders the dead %q class", gone)
		}
	}
	for _, want := range []string{
		`data-hp-services-summary`,
		`data-hp-services-metric="healthy"`, `data-hp-services-metric="attention"`, `data-hp-services-metric="total"`,
		`class="table-scroll"`, `class="data-table"`,
	} {
		if !strings.Contains(admin, want) {
			t.Fatalf("services pane is missing %q", want)
		}
	}
}

// TestSettingsLinkedFromAccountMenu ensures the dashboard shell opens the
// settings modal from the account dropdown next to the auth-account popup,
// loads the modal controller on every page, and provides the injection root.
func TestSettingsLinkedFromAccountMenu(t *testing.T) {
	partial := mustReadUI("partials/dashboard.html")
	if !strings.Contains(partial, `data-hp-account-dashboard-settings`) ||
		!strings.Contains(partial, `href="#settings"`) {
		t.Fatal("account menu must open the settings modal via the #settings hash")
	}
	if !strings.Contains(partial, "Account &amp; security") {
		t.Fatal("auth-account popup entry must be labeled Account & security")
	}
	if !strings.Contains(partial, "/static/hp-settings.js") {
		t.Fatal("shell must load the settings modal controller on every page")
	}
	if !strings.Contains(partial, `id="hp-dash-settings-root"`) {
		t.Fatal("shell must provide the settings modal injection root")
	}
}
