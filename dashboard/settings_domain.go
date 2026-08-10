package main

// settings_domain.go — typed schemas, defaults, validation, and migration for
// the dashboard-owned settings stores described in
// docs/settings-user-configuration-roadmap.md (§3–5) and its honeypot system
// configuration addendum (§12). Everything in this file is pure domain logic:
// no I/O and no globals, so the rules are unit-testable in isolation.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// errSettingsValidation wraps every domain validation failure so callers can
// distinguish "rejected by the schema" (invalid) from persistence problems
// (error) without string matching.
var errSettingsValidation = errors.New("settings validation failed")

// settingsSchemaVersion is the current on-disk schema. The migration registry
// below exists so future versions slot in without touching the store layer.
const settingsSchemaVersion = 4

// migrations upgrades a persisted payload from schema version N to N+1.
// Unknown older versions fail loudly instead of being silently misread, and
// newer versions are rejected so a rolled-back binary never truncates data
// it does not understand.
var migrations = map[int]func(json.RawMessage) (json.RawMessage, error){
	1: migrateAddMLAlertThresholdDefault,
	2: migrateAddDefaultTimezone,
	3: migrateAddBrandPrefix,
}

// migrateAddMLAlertThresholdDefault backfills honeypot.ml_alert_threshold
// (#65) for config documents persisted before that field existed. It was
// added as a required, range-validated field without a schema version bump
// or a migration -- confirmed live: any pre-existing dashboard-config.json
// decoded fine (missing fields just zero-value) but then failed
// honeypot.ml_alert_threshold's [0.5, 0.99] bounds check on the resulting
// 0, so validateConfig rejected it and the store fell back to serving
// compiled defaults, read-only, discarding every other saved setting
// (branding, feature toggles, everything) until an operator intervened.
//
// This registry is shared by every esSettingsStore, including the
// unrelated per-user preferences/projection document, so this must be a
// no-op for any payload shape that isn't a dashboardConfig: no "honeypot"
// object, or one that already has the field (already migrated, or written
// by a newer binary that always includes it).
func migrateAddMLAlertThresholdDefault(payload json.RawMessage) (json.RawMessage, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(payload, &doc); err != nil {
		return payload, nil
	}
	honeypotRaw, ok := doc["honeypot"]
	if !ok {
		return payload, nil
	}
	var honeypot map[string]json.RawMessage
	if err := json.Unmarshal(honeypotRaw, &honeypot); err != nil {
		return payload, nil
	}
	if _, exists := honeypot["ml_alert_threshold"]; exists {
		return payload, nil
	}
	honeypot["ml_alert_threshold"] = json.RawMessage(fmt.Sprintf("%v", defaultDashboardConfig().Honeypot.MLAlertThreshold))
	newHoneypot, err := json.Marshal(honeypot)
	if err != nil {
		return nil, err
	}
	doc["honeypot"] = newHoneypot
	return json.Marshal(doc)
}

// migrateAddDefaultTimezone backfills behavior.default_timezone (#282) for
// config documents persisted before that field existed -- same failure
// shape migrateAddMLAlertThresholdDefault above already fixed once: a
// required, validated field added without a migration decodes fine (missing
// fields just zero-value) but then fails validTimezone("")'s check on the
// resulting "", so validateConfig rejects the whole document and the store
// falls back to serving compiled defaults, read-only, discarding every
// other saved setting until an operator intervenes.
//
// Shared migration registry, so this must be a no-op for any payload shape
// that isn't a dashboardConfig: no "behavior" object, or one that already
// has the field.
func migrateAddDefaultTimezone(payload json.RawMessage) (json.RawMessage, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(payload, &doc); err != nil {
		return payload, nil
	}
	behaviorRaw, ok := doc["behavior"]
	if !ok {
		return payload, nil
	}
	var behavior map[string]json.RawMessage
	if err := json.Unmarshal(behaviorRaw, &behavior); err != nil {
		return payload, nil
	}
	if _, exists := behavior["default_timezone"]; exists {
		return payload, nil
	}
	encoded, err := json.Marshal(defaultDashboardConfig().Behavior.DefaultTimezone)
	if err != nil {
		return nil, err
	}
	behavior["default_timezone"] = encoded
	newBehavior, err := json.Marshal(behavior)
	if err != nil {
		return nil, err
	}
	doc["behavior"] = newBehavior
	return json.Marshal(doc)
}

// migrateAddBrandPrefix backfills presentation.brand_prefix (#776) for
// payloads persisted before the accent prefix was split out of app_name.
// If the existing app_name already starts with a non-empty compiled default
// prefix, the prefix is peeled off into its own field so the composed brand
// renders identically to before. Otherwise the operator's app_name is left
// untouched and brand_prefix defaults to empty.
func migrateAddBrandPrefix(payload json.RawMessage) (json.RawMessage, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(payload, &doc); err != nil {
		return payload, nil
	}
	presentationRaw, ok := doc["presentation"]
	if !ok {
		return payload, nil
	}
	var presentation map[string]json.RawMessage
	if err := json.Unmarshal(presentationRaw, &presentation); err != nil {
		return payload, nil
	}
	if _, exists := presentation["brand_prefix"]; exists {
		return payload, nil
	}
	var appName string
	if raw, exists := presentation["app_name"]; exists {
		_ = json.Unmarshal(raw, &appName)
	}
	defaultPrefix := defaultDashboardConfig().Presentation.BrandPrefix
	prefix := ""
	if defaultPrefix != "" && strings.HasPrefix(appName, defaultPrefix) {
		prefix = defaultPrefix
		appName = strings.TrimPrefix(appName, defaultPrefix)
	}
	encodedPrefix, err := json.Marshal(prefix)
	if err != nil {
		return nil, err
	}
	encodedName, err := json.Marshal(appName)
	if err != nil {
		return nil, err
	}
	presentation["brand_prefix"] = encodedPrefix
	presentation["app_name"] = encodedName
	newPresentation, err := json.Marshal(presentation)
	if err != nil {
		return nil, err
	}
	doc["presentation"] = newPresentation
	return json.Marshal(doc)
}

// ---------------------------------------------------------------------------
// Per-user preferences (roadmap §3)
// ---------------------------------------------------------------------------

type userPreferences struct {
	Theme              string `json:"theme"`
	Density            string `json:"density"`
	ReducedMotion      string `json:"reduced_motion"`
	CollapsedSidebar   bool   `json:"collapsed_sidebar"`
	LandingPage        string `json:"landing_page"`
	RememberFilters    bool   `json:"remember_filters"`
	RowsPerPage        int    `json:"rows_per_page"`
	WrapLongValues     bool   `json:"wrap_long_values"`
	Timezone           string `json:"timezone"`
	Clock              string `json:"clock"`
	Timestamps         string `json:"timestamps"`
	AutoRefresh        bool   `json:"auto_refresh"`
	RefreshInterval    int    `json:"refresh_interval_seconds"`
	LiveToasts         bool   `json:"live_toasts"`
	MapBasemap         string `json:"map_basemap"`
	MapClustering      bool   `json:"map_clustering"`
	MapAnimation       bool   `json:"map_animation"`
	HighContrast       bool   `json:"high_contrast"`
	LargeEvidenceText  bool   `json:"large_evidence_text"`
	NotifySeverity     string `json:"notify_severity"`
	NotifySound        bool   `json:"notify_sound"`
	NotifyDesktop      bool   `json:"notify_desktop"`
	DefaultEventWindow string `json:"default_event_window"`
	PreserveFilters    bool   `json:"preserve_filters"`
	OpenDetailsNewTab  bool   `json:"open_details_new_tab"`
}

func defaultPreferences() userPreferences {
	return userPreferences{
		Theme:              "system",
		Density:            "comfortable",
		ReducedMotion:      "system",
		LandingPage:        "/",
		RowsPerPage:        50,
		Timezone:           "browser",
		Clock:              "h24",
		Timestamps:         "relative",
		AutoRefresh:        true,
		RefreshInterval:    30,
		LiveToasts:         true,
		MapBasemap:         "system",
		MapClustering:      true,
		MapAnimation:       true,
		NotifySeverity:     "high",
		DefaultEventWindow: "24h",
	}
}

// defaultPreferencesWithSiteTimezone is defaultPreferences with Timezone
// overridden by the site-wide default (#282), for the two places a fresh
// preferences document gets materialized for a subject: first contact
// (userStore.Upsert) and an explicit reset (userStore.ResetPreferences).
// siteDefault is the operator's own behavior.default_timezone -- validated
// already by validateConfig, but checked again here since a config store
// left in its pre-migration/degraded state could still hand back "".
func defaultPreferencesWithSiteTimezone(siteDefault string) userPreferences {
	prefs := defaultPreferences()
	if validTimezone(siteDefault) {
		prefs.Timezone = siteDefault
	}
	return prefs
}

// Bounded choice sets. Refresh intervals and page sizes are deliberately
// closed lists so a preference can never turn the dashboard into a
// denial-of-service client against itself or Elasticsearch.
var (
	allowedThemes          = []string{"system", "dark", "light"}
	allowedDensities       = []string{"comfortable", "compact"}
	allowedMotionModes     = []string{"system", "on", "off"}
	allowedLandingPages    = []string{"/", "/events", "/alerts", "/source-health", "/ips", "/payloads", "/sandbox", "/campaigns", "/clusters", "/commands", "/history", "/dead-letters"}
	allowedRowsPerPage     = []int{10, 25, 50, 100}
	allowedClocks          = []string{"h24", "h12"}
	allowedTimestampStyles = []string{"relative", "absolute"}
	allowedRefreshSeconds  = []int{10, 15, 30, 60, 120, 300}
	allowedBasemaps        = []string{"system", "osm", "offline"}
	allowedSeverities      = []string{"low", "medium", "high", "critical"}
	allowedEventWindows    = []string{"1h", "6h", "24h", "7d", "30d"}
)

func validatePreferences(p userPreferences) error {
	var problems []string
	if !oneOf(p.Theme, allowedThemes) {
		problems = append(problems, "theme must be system, dark or light")
	}
	if !oneOf(p.Density, allowedDensities) {
		problems = append(problems, "density must be comfortable or compact")
	}
	if !oneOf(p.ReducedMotion, allowedMotionModes) {
		problems = append(problems, "reduced_motion must be system, on or off")
	}
	if !oneOf(p.LandingPage, allowedLandingPages) {
		problems = append(problems, "landing_page must be a known dashboard route")
	}
	if !oneOfInt(p.RowsPerPage, allowedRowsPerPage) {
		problems = append(problems, "rows_per_page must be one of 10, 25, 50, 100")
	}
	if !validTimezone(p.Timezone) {
		problems = append(problems, "timezone must be browser, utc or an IANA zone name")
	}
	if !oneOf(p.Clock, allowedClocks) {
		problems = append(problems, "clock must be h24 or h12")
	}
	if !oneOf(p.Timestamps, allowedTimestampStyles) {
		problems = append(problems, "timestamps must be relative or absolute")
	}
	if !oneOfInt(p.RefreshInterval, allowedRefreshSeconds) {
		problems = append(problems, "refresh_interval_seconds must be one of 10, 15, 30, 60, 120, 300")
	}
	if !oneOf(p.MapBasemap, allowedBasemaps) {
		problems = append(problems, "map_basemap must be system, osm or offline")
	}
	if !oneOf(p.NotifySeverity, allowedSeverities) {
		problems = append(problems, "notify_severity must be low, medium, high or critical")
	}
	if !oneOf(p.DefaultEventWindow, allowedEventWindows) {
		problems = append(problems, "default_event_window must be one of 1h, 6h, 24h, 7d, 30d")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: invalid preferences: %s", errSettingsValidation, strings.Join(problems, "; "))
	}
	return nil
}

// validTimezone accepts "browser", "utc", or an IANA zone. When the runtime
// has no zoneinfo database at all (minimal containers), fall back to a strict
// shape check rather than rejecting every zone.
func validTimezone(tz string) bool {
	if tz == "" {
		return false
	}
	if strings.EqualFold(tz, "browser") || strings.EqualFold(tz, "utc") {
		return true
	}
	if _, err := time.LoadLocation(tz); err == nil {
		return true
	}
	if _, err := time.LoadLocation("UTC"); err == nil {
		return false // database works; the name itself was invalid
	}
	if len(tz) > 64 || !strings.Contains(tz, "/") {
		return false
	}
	for _, r := range tz {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '/' || r == '_' || r == '-' || r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Global administrator configuration (roadmap §4 + §12 honeypot namespace)
// ---------------------------------------------------------------------------

type presentationConfig struct {
	// BrandPrefix (#776) is the accent-styled lead-in rendered before AppName
	// (empty by default) -- split out so an operator can rebrand the product
	// name without losing the prefix, or drop the prefix entirely for a
	// white-label deployment, independently of AppName.
	BrandPrefix       string `json:"brand_prefix"`
	AppName           string `json:"app_name"`
	ProductLabel      string `json:"product_label"`
	DashboardTitle    string `json:"dashboard_title"`
	DashboardSubtitle string `json:"dashboard_subtitle"`
	OrgName           string `json:"org_name"`
	OverviewIntro     string `json:"overview_intro"`
	HelpLinkLabel     string `json:"help_link_label"`
	HelpLinkURL       string `json:"help_link_url"`
	BannerText        string `json:"banner_text"`
	BannerSeverity    string `json:"banner_severity"`
	BannerExpires     string `json:"banner_expires"`
	FooterText        string `json:"footer_text"`
	AIDisclaimer      string `json:"ai_disclaimer"`
	PrivacyNotice     string `json:"privacy_notice"`
	// ReportPresets (#477) overrides a Report Studio preset's displayed name
	// and/or description without touching its structural definition (theme,
	// window, elements) -- those stay compiled, since they're report logic,
	// not chrome. Keyed by reportTemplate.ID; an absent key or an empty
	// override field means "use the compiled default". A key that no longer
	// names a known template (a preset renamed/removed in a later release)
	// is simply never applied by reportTemplateCatalogWithOverrides -- see
	// its own comment -- rather than rejected, so a stale override left over
	// from an old catalog can't turn an unrelated config save into an error.
	ReportPresets map[string]reportPresetOverride `json:"report_presets,omitempty"`
}

// reportPresetOverride is one admin-edited Name/Description pair for a
// Report Studio preset (#477). Both fields are optional independently of
// each other -- an operator can rename a preset without also rewriting its
// description.
type reportPresetOverride struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type behaviorConfig struct {
	DefaultLanding     string `json:"default_landing"`
	DefaultTimeWindow  string `json:"default_time_window"`
	RowsPerPageOptions []int  `json:"rows_per_page_options"`
	MaxExportRows      int    `json:"max_export_rows"`
	RefreshIntervals   []int  `json:"refresh_interval_seconds_options"`
	SourceStaleMinutes int    `json:"source_stale_minutes"`
	MapProvider        string `json:"map_provider"`
	ShowMLPanels       bool   `json:"show_ml_panels"`
	MaintenanceMode    bool   `json:"maintenance_mode"`
	ReadOnly           bool   `json:"read_only"`
	// ShowProblemReportButton (#1147) gates the "Report a problem" button
	// present on every page. Off by default: the button's own capture
	// (click/nav trail, console errors, failed requests, a DOM snapshot,
	// recent API bodies) is meaningful surface area an operator should
	// opt into deliberately, not something a fresh install silently turns
	// on for every user.
	ShowProblemReportButton bool `json:"show_problem_report_button"`
	// DefaultTimezone (#282) is what a brand new user's own Timezone
	// preference starts as -- the "real site-wide default concept" that
	// issue asked for, distinct from a hardcoded "browser" literal every
	// new subject used to get regardless of the operator's own locale.
	// Same accepted values as the per-user preference (validTimezone):
	// "browser", "utc", or an IANA zone. A user's own preference, once set,
	// always wins over this.
	DefaultTimezone string `json:"default_timezone"`
}

// honeypotConfig holds the Tier 2 staged operational thresholds from the §12
// addendum. Values here are staged only: applying them to the consuming
// services requires an operator-run restart and is never triggered by a save.
type honeypotConfig struct {
	AlertCooldown                string `json:"alert_cooldown"`
	AlertCampaignScore           int    `json:"alert_campaign_score"`
	SandboxAlertRiskScore        int    `json:"sandbox_alert_risk_score"`
	YaraScanIntervalSeconds      int    `json:"yara_scan_interval_seconds"`
	YaraMaxBytes                 int64  `json:"yara_max_bytes"`
	PayloadDedupeIntervalSeconds int    `json:"payload_dedupe_interval_seconds"`
	// MLAlertThreshold (#65, docs/ml-worker-plan.md §11.5) pins the same
	// ML_ALERT_THRESHOLD env var ml-worker/worker.py itself reads -- a
	// dashboard-staged value and the deployment environment can never mean
	// two different things for this field.
	MLAlertThreshold float64 `json:"ml_alert_threshold"`
}

type dashboardConfig struct {
	Presentation presentationConfig `json:"presentation"`
	Behavior     behaviorConfig     `json:"behavior"`
	Honeypot     honeypotConfig     `json:"honeypot"`
}

func defaultDashboardConfig() dashboardConfig {
	return dashboardConfig{
		Presentation: presentationConfig{
			BrandPrefix:    "",
			AppName:        "APIARY",
			ProductLabel:   "Defensive operations",
			DashboardTitle: "Honeypot command center",
			AIDisclaimer:   "AI-generated analysis may be wrong; verify against raw evidence.",
		},
		Behavior: behaviorConfig{
			DefaultLanding:     "/",
			DefaultTimeWindow:  "24h",
			RowsPerPageOptions: []int{25, 50, 100},
			MaxExportRows:      10000,
			RefreshIntervals:   []int{15, 30, 60, 300},
			SourceStaleMinutes: 10,
			MapProvider:        "osm",
			DefaultTimezone:    "utc",
		},
		Honeypot: honeypotConfig{
			AlertCooldown:                "6h",
			AlertCampaignScore:           80,
			SandboxAlertRiskScore:        50,
			YaraScanIntervalSeconds:      900,
			YaraMaxBytes:                 67108864,
			PayloadDedupeIntervalSeconds: 3600,
			MLAlertThreshold:             0.75, // matches worker.py's own ML_ALERT_THRESHOLD default
		},
	}
}

// honeypotFieldEnv maps every honeypot config field to the deployment
// environment variable that can pin it. A field whose variable is set is
// reported with source "environment" by the effective-config API and is
// rejected on write — the UI never overrides deployment configuration.
func honeypotFieldEnv() map[string]string {
	return map[string]string{
		"alert_cooldown":                  "HONEYPOT_ALERT_COOLDOWN",
		"alert_campaign_score":            "HONEYPOT_ALERT_CAMPAIGN_SCORE",
		"sandbox_alert_risk_score":        "SANDBOX_ALERT_RISK_SCORE",
		"yara_scan_interval_seconds":      "YARA_SCAN_INTERVAL",
		"yara_max_bytes":                  "YARA_MAX_BYTES",
		"payload_dedupe_interval_seconds": "PAYLOAD_DEDUPE_INTERVAL",
		"ml_alert_threshold":              "ML_ALERT_THRESHOLD",
	}
}

// pinnedHoneypotFields returns the subset of honeypot fields currently pinned
// by the deployment environment. lookup is injected so the rule stays pure.
func pinnedHoneypotFields(lookup func(string) string) map[string]string {
	pinned := map[string]string{}
	for field, env := range honeypotFieldEnv() {
		if value := strings.TrimSpace(lookup(env)); value != "" {
			pinned[field] = value
		}
	}
	return pinned
}

// text bounds per field; configurable copy is plain single-purpose text, not
// documents. Control characters are always rejected (no HTML, no markup).
var presentationTextLimits = map[string]int{
	"brand_prefix":       20,
	"app_name":           60,
	"product_label":      30,
	"dashboard_title":    80,
	"dashboard_subtitle": 200,
	"org_name":           80,
	"overview_intro":     500,
	"help_link_label":    40,
	"banner_text":        280,
	"footer_text":        200,
	"ai_disclaimer":      300,
	"privacy_notice":     300,
}

// reportPresetNameLimit/reportPresetDescriptionLimit (#477) match the
// compiled catalog's own copy length in reports_store.go's
// reportTemplateCatalog -- an override should never be able to produce
// wildly longer text than the built-in presets already use.
const reportPresetNameLimit = 80
const reportPresetDescriptionLimit = 300

var allowedBannerSeverities = []string{"", "info", "success", "warning", "danger"}
var allowedMapProviders = []string{"osm", "offline"}

func validateConfig(c dashboardConfig) error {
	var problems []string
	p := c.Presentation
	texts := map[string]string{
		"brand_prefix":       p.BrandPrefix,
		"app_name":           p.AppName,
		"product_label":      p.ProductLabel,
		"dashboard_title":    p.DashboardTitle,
		"dashboard_subtitle": p.DashboardSubtitle,
		"org_name":           p.OrgName,
		"overview_intro":     p.OverviewIntro,
		"help_link_label":    p.HelpLinkLabel,
		"banner_text":        p.BannerText,
		"footer_text":        p.FooterText,
		"ai_disclaimer":      p.AIDisclaimer,
		"privacy_notice":     p.PrivacyNotice,
	}
	for field, limit := range presentationTextLimits {
		value := texts[field]
		if utf8.RuneCountInString(value) > limit {
			problems = append(problems, fmt.Sprintf("presentation.%s must be at most %d characters", field, limit))
		}
		if strings.IndexFunc(value, func(r rune) bool { return r < 0x20 && r != '\n' || r == 0x7f }) >= 0 {
			problems = append(problems, fmt.Sprintf("presentation.%s must not contain control characters", field))
		}
	}
	if p.AppName == "" {
		problems = append(problems, "presentation.app_name must not be empty")
	}
	if !validHTTPSURL(p.HelpLinkURL) {
		problems = append(problems, "presentation.help_link_url must be empty or an https:// URL")
	}
	if !oneOf(p.BannerSeverity, allowedBannerSeverities) {
		problems = append(problems, "presentation.banner_severity must be empty, info, success, warning or danger")
	}
	if p.BannerExpires != "" {
		if _, err := time.Parse(time.RFC3339, p.BannerExpires); err != nil {
			problems = append(problems, "presentation.banner_expires must be RFC 3339 or empty")
		}
	}
	knownPresets := map[string]bool{}
	for _, template := range reportTemplateCatalog() {
		knownPresets[template.ID] = true
	}
	controlChar := func(r rune) bool { return r < 0x20 && r != '\n' || r == 0x7f }
	for id, override := range p.ReportPresets {
		if !knownPresets[id] {
			problems = append(problems, fmt.Sprintf("presentation.report_presets has an unknown template id %q", id))
			continue
		}
		if utf8.RuneCountInString(override.Name) > reportPresetNameLimit {
			problems = append(problems, fmt.Sprintf("presentation.report_presets.%s.name must be at most %d characters", id, reportPresetNameLimit))
		}
		if utf8.RuneCountInString(override.Description) > reportPresetDescriptionLimit {
			problems = append(problems, fmt.Sprintf("presentation.report_presets.%s.description must be at most %d characters", id, reportPresetDescriptionLimit))
		}
		if strings.IndexFunc(override.Name, controlChar) >= 0 || strings.IndexFunc(override.Description, controlChar) >= 0 {
			problems = append(problems, fmt.Sprintf("presentation.report_presets.%s must not contain control characters", id))
		}
	}

	b := c.Behavior
	if !oneOf(b.DefaultLanding, allowedLandingPages) {
		problems = append(problems, "behavior.default_landing must be a known dashboard route")
	}
	if !oneOf(b.DefaultTimeWindow, allowedEventWindows) {
		problems = append(problems, "behavior.default_time_window must be one of 1h, 6h, 24h, 7d, 30d")
	}
	if !subsetInt(b.RowsPerPageOptions, allowedRowsPerPage) || len(b.RowsPerPageOptions) == 0 {
		problems = append(problems, "behavior.rows_per_page_options must be a non-empty subset of 10, 25, 50, 100")
	}
	if b.MaxExportRows < 100 || b.MaxExportRows > 100000 {
		problems = append(problems, "behavior.max_export_rows must be between 100 and 100000")
	}
	if !subsetInt(b.RefreshIntervals, allowedRefreshSeconds) || len(b.RefreshIntervals) == 0 {
		problems = append(problems, "behavior.refresh_interval_seconds_options must be a non-empty subset of 10, 15, 30, 60, 120, 300")
	}
	if b.SourceStaleMinutes < 2 || b.SourceStaleMinutes > 120 {
		problems = append(problems, "behavior.source_stale_minutes must be between 2 and 120")
	}
	if !oneOf(b.MapProvider, allowedMapProviders) {
		problems = append(problems, "behavior.map_provider must be osm or offline")
	}
	if !validTimezone(b.DefaultTimezone) {
		problems = append(problems, "behavior.default_timezone must be browser, utc or an IANA zone name")
	}

	h := c.Honeypot
	cooldown, err := time.ParseDuration(h.AlertCooldown)
	if err != nil || cooldown < 5*time.Minute || cooldown > 168*time.Hour {
		problems = append(problems, "honeypot.alert_cooldown must be a duration between 5m and 168h")
	}
	if h.AlertCampaignScore < 0 || h.AlertCampaignScore > 100 {
		problems = append(problems, "honeypot.alert_campaign_score must be between 0 and 100")
	}
	if h.SandboxAlertRiskScore < 0 || h.SandboxAlertRiskScore > 100 {
		problems = append(problems, "honeypot.sandbox_alert_risk_score must be between 0 and 100")
	}
	if h.YaraScanIntervalSeconds < 300 || h.YaraScanIntervalSeconds > 86400 {
		problems = append(problems, "honeypot.yara_scan_interval_seconds must be between 300 and 86400")
	}
	if h.YaraMaxBytes < 1<<20 || h.YaraMaxBytes > 1<<30 {
		problems = append(problems, "honeypot.yara_max_bytes must be between 1048576 and 1073741824")
	}
	if h.PayloadDedupeIntervalSeconds < 300 || h.PayloadDedupeIntervalSeconds > 86400 {
		problems = append(problems, "honeypot.payload_dedupe_interval_seconds must be between 300 and 86400")
	}
	if h.MLAlertThreshold < 0.5 || h.MLAlertThreshold > 0.99 {
		problems = append(problems, "honeypot.ml_alert_threshold must be between 0.5 and 0.99")
	}

	if len(problems) > 0 {
		return fmt.Errorf("%w: invalid configuration: %s", errSettingsValidation, strings.Join(problems, "; "))
	}
	return nil
}

// validHTTPSURL allows an empty value or an https:// URL with a host and no
// userinfo or fragment. Configurable links never carry credentials.
func validHTTPSURL(raw string) bool {
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}

func oneOf(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func oneOfInt(value int, allowed []int) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func subsetInt(values, allowed []int) bool {
	for _, value := range values {
		if !oneOfInt(value, allowed) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Schema envelope and migration (roadmap §5)
// ---------------------------------------------------------------------------

// storedEnvelope is the on-disk wrapper shared by every settings store. The
// payload is kept raw so the store layer can enforce the schema version
// before the typed payload is decoded.
type storedEnvelope struct {
	SchemaVersion int             `json:"schema_version"`
	Revision      int64           `json:"revision"`
	Updated       time.Time       `json:"updated"`
	Payload       json.RawMessage `json:"payload"`
}

// migratePayload brings a persisted payload up to settingsSchemaVersion.
// v1 is current, so any older version without a registered migration and any
// newer version is an error — never a silent reinterpretation.
func migratePayload(version int, payload json.RawMessage) (json.RawMessage, error) {
	if version == settingsSchemaVersion {
		return payload, nil
	}
	if version > settingsSchemaVersion {
		return nil, fmt.Errorf("settings schema version %d is newer than supported version %d", version, settingsSchemaVersion)
	}
	for version < settingsSchemaVersion {
		step, ok := migrations[version]
		if !ok {
			return nil, fmt.Errorf("no migration registered for settings schema version %d", version)
		}
		upgraded, err := step(payload)
		if err != nil {
			return nil, fmt.Errorf("migrate settings schema version %d: %w", version, err)
		}
		payload = upgraded
		version++
	}
	return payload, nil
}

// changedFields reports dotted field names whose values differ between two
// JSON documents, one level deep ("presentation.app_name"). Used for audit
// records; never includes values, so sensitive content stays out of the log.
func changedFields(oldJSON, newJSON []byte) []string {
	var oldDoc, newDoc map[string]json.RawMessage
	if json.Unmarshal(oldJSON, &oldDoc) != nil || json.Unmarshal(newJSON, &newDoc) != nil {
		return nil
	}
	var changed []string
	for key, newValue := range newDoc {
		oldValue, ok := oldDoc[key]
		if !ok {
			changed = append(changed, key)
			continue
		}
		var oldChild, newChild map[string]json.RawMessage
		if json.Unmarshal(oldValue, &oldChild) == nil && json.Unmarshal(newValue, &newChild) == nil &&
			oldChild != nil && newChild != nil {
			for childKey, childNew := range newChild {
				childOld, childOK := oldChild[childKey]
				if !childOK || string(childOld) != string(childNew) {
					changed = append(changed, key+"."+childKey)
				}
			}
			for childKey := range oldChild {
				if _, childOK := newChild[childKey]; !childOK {
					changed = append(changed, key+"."+childKey)
				}
			}
			continue
		}
		if string(oldValue) != string(newValue) {
			changed = append(changed, key)
		}
	}
	for key := range oldDoc {
		if _, ok := newDoc[key]; !ok {
			changed = append(changed, key)
		}
	}
	return changed
}
