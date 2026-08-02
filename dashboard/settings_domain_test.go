package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDefaultPreferencesAndConfigValidate(t *testing.T) {
	if err := validatePreferences(defaultPreferences()); err != nil {
		t.Fatalf("default preferences must validate: %v", err)
	}
	if err := validateConfig(defaultDashboardConfig()); err != nil {
		t.Fatalf("default configuration must validate: %v", err)
	}
}

func TestPreferencesRejectInvalidEnumsAndBounds(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*userPreferences)
		want   string
	}{
		{"theme", func(p *userPreferences) { p.Theme = "neon" }, "theme"},
		{"rows", func(p *userPreferences) { p.RowsPerPage = 51 }, "rows_per_page"},
		{"timezone", func(p *userPreferences) { p.Timezone = "Mars/Olympus" }, "timezone"},
		{"refresh", func(p *userPreferences) { p.RefreshInterval = 1 }, "refresh_interval_seconds"},
		{"window", func(p *userPreferences) { p.DefaultEventWindow = "365d" }, "default_event_window"},
		{"severity", func(p *userPreferences) { p.NotifySeverity = "extreme" }, "notify_severity"},
		{"landing", func(p *userPreferences) { p.LandingPage = "https://evil.example" }, "landing_page"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefs := defaultPreferences()
			tc.mutate(&prefs)
			err := validatePreferences(prefs)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q rejection, got %v", tc.want, err)
			}
		})
	}
}

func TestValidTimezoneHandlesSpecialValues(t *testing.T) {
	for _, tz := range []string{"browser", "UTC", "utc", "Europe/Berlin", "America/New_York"} {
		if !validTimezone(tz) {
			t.Fatalf("timezone %q must be accepted", tz)
		}
	}
	for _, tz := range []string{"", "Berlin", "Europe/Berlin; DROP", "Not/AZone"} {
		if validTimezone(tz) {
			t.Fatalf("timezone %q must be rejected", tz)
		}
	}
}

func TestConfigRejectsUnsafeOrOutOfRangeValues(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*dashboardConfig)
		want   string
	}{
		{"empty app name", func(c *dashboardConfig) { c.Presentation.AppName = "" }, "app_name"},
		{"overlong title", func(c *dashboardConfig) { c.Presentation.DashboardTitle = strings.Repeat("x", 81) }, "dashboard_title"},
		{"control character", func(c *dashboardConfig) { c.Presentation.FooterText = "a\x07b" }, "footer_text"},
		{"http link", func(c *dashboardConfig) { c.Presentation.HelpLinkURL = "http://example.com" }, "help_link_url"},
		{"credential link", func(c *dashboardConfig) { c.Presentation.HelpLinkURL = "https://user" + ":pw@example.com" }, "help_link_url"},
		{"banner severity", func(c *dashboardConfig) { c.Presentation.BannerSeverity = "sparkles" }, "banner_severity"},
		{"banner expiry", func(c *dashboardConfig) { c.Presentation.BannerExpires = "next friday" }, "banner_expires"},
		{"export rows low", func(c *dashboardConfig) { c.Behavior.MaxExportRows = 10 }, "max_export_rows"},
		{"export rows high", func(c *dashboardConfig) { c.Behavior.MaxExportRows = 100001 }, "max_export_rows"},
		{"rows subset", func(c *dashboardConfig) { c.Behavior.RowsPerPageOptions = []int{25, 500} }, "rows_per_page_options"},
		{"refresh subset", func(c *dashboardConfig) { c.Behavior.RefreshIntervals = []int{} }, "refresh_interval_seconds_options"},
		{"map provider", func(c *dashboardConfig) { c.Behavior.MapProvider = "https://tiles.evil.example/{z}.png" }, "map_provider"},
		{"cooldown syntax", func(c *dashboardConfig) { c.Honeypot.AlertCooldown = "soon" }, "alert_cooldown"},
		{"cooldown bounds", func(c *dashboardConfig) { c.Honeypot.AlertCooldown = "30s" }, "alert_cooldown"},
		{"campaign score", func(c *dashboardConfig) { c.Honeypot.AlertCampaignScore = 101 }, "alert_campaign_score"},
		{"yara interval", func(c *dashboardConfig) { c.Honeypot.YaraScanIntervalSeconds = 60 }, "yara_scan_interval_seconds"},
		{"yara bytes", func(c *dashboardConfig) { c.Honeypot.YaraMaxBytes = 1 }, "yara_max_bytes"},
		{"dedupe interval", func(c *dashboardConfig) { c.Honeypot.PayloadDedupeIntervalSeconds = 100000 }, "payload_dedupe_interval_seconds"},
		{"ml threshold low", func(c *dashboardConfig) { c.Honeypot.MLAlertThreshold = 0.1 }, "ml_alert_threshold"},
		{"ml threshold high", func(c *dashboardConfig) { c.Honeypot.MLAlertThreshold = 1.0 }, "ml_alert_threshold"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultDashboardConfig()
			tc.mutate(&cfg)
			err := validateConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q rejection, got %v", tc.want, err)
			}
		})
	}
}

func TestHoneypotEnvPinsReportDeploymentOverrides(t *testing.T) {
	env := map[string]string{
		"HONEYPOT_ALERT_COOLDOWN": "12h",
		"YARA_SCAN_INTERVAL":      "1800",
		"ML_ALERT_THRESHOLD":      "0.8",
	}
	pinned := pinnedHoneypotFields(func(name string) string { return env[name] })
	if len(pinned) != 3 || pinned["alert_cooldown"] != "12h" || pinned["yara_scan_interval_seconds"] != "1800" ||
		pinned["ml_alert_threshold"] != "0.8" {
		t.Fatalf("unexpected pinned fields: %#v", pinned)
	}
	for field := range honeypotFieldEnv() {
		if _, ok := pinned[field]; ok && field != "alert_cooldown" && field != "yara_scan_interval_seconds" && field != "ml_alert_threshold" {
			t.Fatalf("field %s must not be pinned", field)
		}
	}
}

// TestMLAlertThresholdMatchesWorkerEnvVarName is #65's own correctness
// requirement (docs/ml-worker-plan.md §11.5): a dashboard-staged value and
// the deployment environment must never mean two different things for this
// field, which only holds if the env var name is exactly the one
// ml-worker/worker.py itself reads.
func TestMLAlertThresholdMatchesWorkerEnvVarName(t *testing.T) {
	if honeypotFieldEnv()["ml_alert_threshold"] != "ML_ALERT_THRESHOLD" {
		t.Fatalf("ml_alert_threshold must pin to ML_ALERT_THRESHOLD, the exact env var worker.py reads, got %q",
			honeypotFieldEnv()["ml_alert_threshold"])
	}
}

func TestMigratePayloadRejectsUnsupportedVersions(t *testing.T) {
	payload := json.RawMessage(`{"ok":true}`)
	if _, err := migratePayload(settingsSchemaVersion, payload); err != nil {
		t.Fatalf("current version must pass through: %v", err)
	}
	if _, err := migratePayload(settingsSchemaVersion+1, payload); err == nil {
		t.Fatal("a newer schema version must be rejected")
	}
	// Version 0 predates every registered migration step (1:
	// migrateAddMLAlertThresholdDefault, 2: migrateAddDefaultTimezone) and
	// must still be rejected rather than silently misread. Not expressed as
	// settingsSchemaVersion-N: every step this repo has added so far keeps
	// the migration chain unbroken back to version 1, so an N large enough
	// to reach a genuinely unregistered version keeps changing as new steps
	// land -- 0 is unregistered by construction, not by coincidence.
	if _, err := migratePayload(0, payload); err == nil {
		t.Fatal("a version with no registered migration path must be rejected")
	}
}

// #65/#180: honeypot.ml_alert_threshold was added as a required,
// range-validated field without a schema version bump or a migration.
// Confirmed live: any dashboard-config.json persisted before this field
// existed decoded fine (a missing field just zero-values) but then failed
// validateConfig's [0.5, 0.99] bounds check on the resulting 0, so the
// store fell back to compiled defaults, read-only, discarding every other
// saved setting until an operator intervened. This is the exact
// reproduction, using the real load path (migratePayload then strictDecode
// then validateConfig), not just the migration function in isolation.
func TestMigrationBackfillsMissingMLAlertThreshold(t *testing.T) {
	preExistingPayload := json.RawMessage(`{"presentation":{"app_name":"X","ai_disclaimer":"d"},` +
		`"behavior":{"default_landing":"/","default_time_window":"24h","rows_per_page_options":[25,50,100],` +
		`"max_export_rows":10000,"refresh_interval_seconds_options":[15,30,60,300],"source_stale_minutes":10,"map_provider":"osm"},` +
		`"honeypot":{"alert_cooldown":"6h","alert_campaign_score":80,"sandbox_alert_risk_score":50,` +
		`"yara_scan_interval_seconds":900,"yara_max_bytes":67108864,"payload_dedupe_interval_seconds":3600}}`)
	migrated, err := migratePayload(1, preExistingPayload)
	if err != nil {
		t.Fatalf("migration from version 1 must succeed: %v", err)
	}
	var cfg dashboardConfig
	if !strictDecode(migrated, &cfg) {
		t.Fatal("migrated payload must still strict-decode into dashboardConfig")
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("migrated payload must pass validation, got: %v", err)
	}
	if cfg.Honeypot.MLAlertThreshold != defaultDashboardConfig().Honeypot.MLAlertThreshold {
		t.Fatalf("ml_alert_threshold = %v, want the compiled default %v",
			cfg.Honeypot.MLAlertThreshold, defaultDashboardConfig().Honeypot.MLAlertThreshold)
	}

	// A payload that already has the field (written by a newer binary, or
	// migrated once already) must be left alone, not overwritten.
	alreadySet := json.RawMessage(`{"presentation":{},"behavior":{},"honeypot":{"ml_alert_threshold":0.9}}`)
	migratedAgain, err := migratePayload(1, alreadySet)
	if err != nil {
		t.Fatal(err)
	}
	var cfg2 dashboardConfig
	if !strictDecode(migratedAgain, &cfg2) {
		t.Fatal("strict decode failed")
	}
	if cfg2.Honeypot.MLAlertThreshold != 0.9 {
		t.Fatalf("migration overwrote an already-present value: got %v, want 0.9", cfg2.Honeypot.MLAlertThreshold)
	}

	// A payload with no "honeypot" object at all (e.g. the unrelated
	// per-subject preferences/projection document, which shares this same
	// migration registry) must pass through completely unchanged.
	unrelated := json.RawMessage(`{"users":[{"subject":"x"}]}`)
	passedThrough, err := migratePayload(1, unrelated)
	if err != nil {
		t.Fatal(err)
	}
	if string(passedThrough) != string(unrelated) {
		t.Fatalf("migration must not touch a payload with no honeypot object, got %s", passedThrough)
	}
}

// TestMigrationBackfillsMissingDefaultTimezone (#282) uses the exact shape of
// a real pre-existing dashboard-config.json (schema version 2, no
// behavior.default_timezone key) confirmed live on the deployed homeserver --
// this is the same failure mode #65's ml_alert_threshold migration above
// already fixed once: a required, validated field added without a migration
// decodes fine (missing field just zero-values to "") but then fails
// validTimezone("")'s check, so validateConfig rejects the whole document.
func TestMigrationBackfillsMissingDefaultTimezone(t *testing.T) {
	preExistingPayload := json.RawMessage(`{"presentation":{"app_name":"XORE//HP","ai_disclaimer":"d"},` +
		`"behavior":{"default_landing":"/","default_time_window":"24h","rows_per_page_options":[25,50,100],` +
		`"max_export_rows":10000,"refresh_interval_seconds_options":[15,30,60,300],"source_stale_minutes":10,"map_provider":"osm"},` +
		`"honeypot":{"alert_cooldown":"6h","alert_campaign_score":80,"sandbox_alert_risk_score":50,` +
		`"yara_scan_interval_seconds":900,"yara_max_bytes":67108864,"payload_dedupe_interval_seconds":3600,"ml_alert_threshold":0.75}}`)
	migrated, err := migratePayload(2, preExistingPayload)
	if err != nil {
		t.Fatalf("migration from version 2 must succeed: %v", err)
	}
	var cfg dashboardConfig
	if !strictDecode(migrated, &cfg) {
		t.Fatal("migrated payload must still strict-decode into dashboardConfig")
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("migrated payload must pass validation, got: %v", err)
	}
	if cfg.Behavior.DefaultTimezone != defaultDashboardConfig().Behavior.DefaultTimezone {
		t.Fatalf("default_timezone = %q, want the compiled default %q",
			cfg.Behavior.DefaultTimezone, defaultDashboardConfig().Behavior.DefaultTimezone)
	}

	// A payload that already has the field must be left alone.
	alreadySet := json.RawMessage(`{"presentation":{},"behavior":{"default_timezone":"Europe/Berlin"},"honeypot":{}}`)
	migratedAgain, err := migratePayload(2, alreadySet)
	if err != nil {
		t.Fatal(err)
	}
	var cfg2 dashboardConfig
	if !strictDecode(migratedAgain, &cfg2) {
		t.Fatal("strict decode failed")
	}
	if cfg2.Behavior.DefaultTimezone != "Europe/Berlin" {
		t.Fatalf("migration overwrote an already-present value: got %q, want Europe/Berlin", cfg2.Behavior.DefaultTimezone)
	}

	// A payload with no "behavior" object at all (the unrelated per-subject
	// preferences/projection document, sharing this same migration registry)
	// must pass through completely unchanged.
	unrelated := json.RawMessage(`{"users":[{"subject":"x"}]}`)
	passedThrough, err := migratePayload(2, unrelated)
	if err != nil {
		t.Fatal(err)
	}
	if string(passedThrough) != string(unrelated) {
		t.Fatalf("migration must not touch a payload with no behavior object, got %s", passedThrough)
	}
}

func TestChangedFieldsReportsDottedNamesOnly(t *testing.T) {
	oldJSON := []byte(`{"presentation":{"app_name":"A","footer_text":"x"},"behavior":{"read_only":false}}`)
	newJSON := []byte(`{"presentation":{"app_name":"B","footer_text":"x"},"behavior":{"read_only":true}}`)
	got := changedFields(oldJSON, newJSON)
	want := map[string]bool{"presentation.app_name": true, "behavior.read_only": true}
	if len(got) != len(want) {
		t.Fatalf("changed fields = %v, want %v", got, want)
	}
	for _, field := range got {
		if !want[field] {
			t.Fatalf("unexpected changed field %q in %v", field, got)
		}
	}
	// Values must never leak into the report, even when the text is sensitive.
	for _, field := range got {
		if strings.Contains(field, "B") || strings.Contains(field, "true") {
			t.Fatalf("changed field %q leaks a value", field)
		}
	}
}
