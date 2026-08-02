package main

// settings_admin_api.go — the administrator configuration endpoints from
// roadmap §6 (Milestone E):
//
//	GET   /api/settings/config             effective config + per-field source
//	PATCH /api/settings/config             typed partial update (If-Match)
//	POST  /api/settings/config/validate    preview with impact classification
//	POST  /api/settings/config/rollback    restore a retained revision
//	GET   /api/settings/config/history     revision history (newest first)
//	GET   /api/settings/users              read-only user projections
//	GET   /api/settings/audit              settings audit log (newest first)
//
// Every endpoint requires a live-introspected identity with the admin role —
// configuration writes are never gated behind the DASHBOARD_REQUIRE_ADMIN
// development switch. Mutations additionally require a same-origin request,
// stay under the shared per-subject write limit, and record an audit event
// plus a full revision snapshot for rollback. Honeypot fields pinned by the
// deployment environment are reported with source "environment" and rejected
// on write (§12): the UI can never override deployment configuration, and the
// typed schema itself keeps Tier 3 values (secrets, endpoints, commands) from
// ever becoming editable.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxConfigBody bounds a configuration patch. The typed document is small;
// 32 KiB is generous headroom.
const maxConfigBody = 32 << 10

// configFieldImpact classifies a changed field for the validation preview
// (roadmap §6): live values apply immediately, new-request values show on
// subsequent renders, restart-required values are staged for an operator-run
// restart and never trigger one themselves.
func configFieldImpact(field string) string {
	switch {
	case strings.HasPrefix(field, "honeypot."):
		return "restart-required"
	case field == "behavior.maintenance_mode" || field == "behavior.read_only" || field == "behavior.show_ml_panels":
		return "live"
	case strings.HasPrefix(field, "behavior.") || strings.HasPrefix(field, "presentation."):
		return "new-request"
	default:
		return "new-request"
	}
}

// presentationPatch / behaviorPatch / honeypotPatch mirror the configuration
// schema with pointer fields, so a PATCH distinguishes "absent" from "zero".
type presentationPatch struct {
	AppName           *string `json:"app_name"`
	ProductLabel      *string `json:"product_label"`
	DashboardTitle    *string `json:"dashboard_title"`
	DashboardSubtitle *string `json:"dashboard_subtitle"`
	OrgName           *string `json:"org_name"`
	OverviewIntro     *string `json:"overview_intro"`
	HelpLinkLabel     *string `json:"help_link_label"`
	HelpLinkURL       *string `json:"help_link_url"`
	BannerText        *string `json:"banner_text"`
	BannerSeverity    *string `json:"banner_severity"`
	BannerExpires     *string `json:"banner_expires"`
	FooterText        *string `json:"footer_text"`
	AIDisclaimer      *string `json:"ai_disclaimer"`
	PrivacyNotice     *string `json:"privacy_notice"`
}

type behaviorPatch struct {
	DefaultLanding     *string `json:"default_landing"`
	DefaultTimeWindow  *string `json:"default_time_window"`
	RowsPerPageOptions *[]int  `json:"rows_per_page_options"`
	MaxExportRows      *int    `json:"max_export_rows"`
	RefreshIntervals   *[]int  `json:"refresh_interval_seconds_options"`
	SourceStaleMinutes *int    `json:"source_stale_minutes"`
	MapProvider        *string `json:"map_provider"`
	ShowMLPanels       *bool   `json:"show_ml_panels"`
	MaintenanceMode    *bool   `json:"maintenance_mode"`
	ReadOnly           *bool   `json:"read_only"`
	DefaultTimezone    *string `json:"default_timezone"`
}

type honeypotPatch struct {
	AlertCooldown                *string  `json:"alert_cooldown"`
	AlertCampaignScore           *int     `json:"alert_campaign_score"`
	SandboxAlertRiskScore        *int     `json:"sandbox_alert_risk_score"`
	YaraScanIntervalSeconds      *int     `json:"yara_scan_interval_seconds"`
	YaraMaxBytes                 *int64   `json:"yara_max_bytes"`
	PayloadDedupeIntervalSeconds *int     `json:"payload_dedupe_interval_seconds"`
	MLAlertThreshold             *float64 `json:"ml_alert_threshold"`
}

type configPatch struct {
	Presentation *presentationPatch `json:"presentation"`
	Behavior     *behaviorPatch     `json:"behavior"`
	Honeypot     *honeypotPatch     `json:"honeypot"`
}

func (p configPatch) empty() bool {
	return p.Presentation == nil && p.Behavior == nil && p.Honeypot == nil
}

// apply copies every present field onto c and returns the dotted names of the
// fields it set. The names feed the pinned-field check, the impact preview,
// and the audit record.
func (p configPatch) apply(c *dashboardConfig) []string {
	var fields []string
	if q := p.Presentation; q != nil {
		set := func(name string, dst *string, value *string) {
			if value != nil {
				*dst = *value
				fields = append(fields, "presentation."+name)
			}
		}
		set("app_name", &c.Presentation.AppName, q.AppName)
		set("product_label", &c.Presentation.ProductLabel, q.ProductLabel)
		set("dashboard_title", &c.Presentation.DashboardTitle, q.DashboardTitle)
		set("dashboard_subtitle", &c.Presentation.DashboardSubtitle, q.DashboardSubtitle)
		set("org_name", &c.Presentation.OrgName, q.OrgName)
		set("overview_intro", &c.Presentation.OverviewIntro, q.OverviewIntro)
		set("help_link_label", &c.Presentation.HelpLinkLabel, q.HelpLinkLabel)
		set("help_link_url", &c.Presentation.HelpLinkURL, q.HelpLinkURL)
		set("banner_text", &c.Presentation.BannerText, q.BannerText)
		set("banner_severity", &c.Presentation.BannerSeverity, q.BannerSeverity)
		set("banner_expires", &c.Presentation.BannerExpires, q.BannerExpires)
		set("footer_text", &c.Presentation.FooterText, q.FooterText)
		set("ai_disclaimer", &c.Presentation.AIDisclaimer, q.AIDisclaimer)
		set("privacy_notice", &c.Presentation.PrivacyNotice, q.PrivacyNotice)
	}
	if q := p.Behavior; q != nil {
		if q.DefaultLanding != nil {
			c.Behavior.DefaultLanding = *q.DefaultLanding
			fields = append(fields, "behavior.default_landing")
		}
		if q.DefaultTimeWindow != nil {
			c.Behavior.DefaultTimeWindow = *q.DefaultTimeWindow
			fields = append(fields, "behavior.default_time_window")
		}
		if q.RowsPerPageOptions != nil {
			c.Behavior.RowsPerPageOptions = append([]int(nil), (*q.RowsPerPageOptions)...)
			fields = append(fields, "behavior.rows_per_page_options")
		}
		if q.MaxExportRows != nil {
			c.Behavior.MaxExportRows = *q.MaxExportRows
			fields = append(fields, "behavior.max_export_rows")
		}
		if q.RefreshIntervals != nil {
			c.Behavior.RefreshIntervals = append([]int(nil), (*q.RefreshIntervals)...)
			fields = append(fields, "behavior.refresh_interval_seconds_options")
		}
		if q.SourceStaleMinutes != nil {
			c.Behavior.SourceStaleMinutes = *q.SourceStaleMinutes
			fields = append(fields, "behavior.source_stale_minutes")
		}
		if q.MapProvider != nil {
			c.Behavior.MapProvider = *q.MapProvider
			fields = append(fields, "behavior.map_provider")
		}
		if q.DefaultTimezone != nil {
			c.Behavior.DefaultTimezone = *q.DefaultTimezone
			fields = append(fields, "behavior.default_timezone")
		}
		if q.ShowMLPanels != nil {
			c.Behavior.ShowMLPanels = *q.ShowMLPanels
			fields = append(fields, "behavior.show_ml_panels")
		}
		if q.MaintenanceMode != nil {
			c.Behavior.MaintenanceMode = *q.MaintenanceMode
			fields = append(fields, "behavior.maintenance_mode")
		}
		if q.ReadOnly != nil {
			c.Behavior.ReadOnly = *q.ReadOnly
			fields = append(fields, "behavior.read_only")
		}
	}
	if q := p.Honeypot; q != nil {
		if q.AlertCooldown != nil {
			c.Honeypot.AlertCooldown = *q.AlertCooldown
			fields = append(fields, "honeypot.alert_cooldown")
		}
		if q.AlertCampaignScore != nil {
			c.Honeypot.AlertCampaignScore = *q.AlertCampaignScore
			fields = append(fields, "honeypot.alert_campaign_score")
		}
		if q.SandboxAlertRiskScore != nil {
			c.Honeypot.SandboxAlertRiskScore = *q.SandboxAlertRiskScore
			fields = append(fields, "honeypot.sandbox_alert_risk_score")
		}
		if q.YaraScanIntervalSeconds != nil {
			c.Honeypot.YaraScanIntervalSeconds = *q.YaraScanIntervalSeconds
			fields = append(fields, "honeypot.yara_scan_interval_seconds")
		}
		if q.YaraMaxBytes != nil {
			c.Honeypot.YaraMaxBytes = *q.YaraMaxBytes
			fields = append(fields, "honeypot.yara_max_bytes")
		}
		if q.PayloadDedupeIntervalSeconds != nil {
			c.Honeypot.PayloadDedupeIntervalSeconds = *q.PayloadDedupeIntervalSeconds
			fields = append(fields, "honeypot.payload_dedupe_interval_seconds")
		}
		if q.MLAlertThreshold != nil {
			c.Honeypot.MLAlertThreshold = *q.MLAlertThreshold
			fields = append(fields, "honeypot.ml_alert_threshold")
		}
	}
	return fields
}

// configResponse is the administrator view of the effective configuration:
// the typed document, its revision, the store health flags, and the source of
// every honeypot field (§12: staged values and environment pins must be
// distinguishable from a silent lie).
type configResponse struct {
	Config     dashboardConfig   `json:"config"`
	Revision   int64             `json:"revision"`
	ReadOnly   bool              `json:"read_only"`
	Degraded   bool              `json:"degraded"`
	Sources    map[string]string `json:"sources"`
	PinnedEnvs map[string]string `json:"pinned_environment,omitempty"`
}

// configSources reports where each honeypot value comes from and whether the
// persisted document is live or a compiled fallback.
func (s *settingsService) configSources() (map[string]string, map[string]string) {
	pinned := pinnedHoneypotFields(func(key string) string {
		return strings.TrimSpace(getenv(key, ""))
	})
	sources := map[string]string{}
	origin := "persisted"
	if s.config.Degraded() {
		origin = "compiled"
	}
	for field := range honeypotFieldEnv() {
		if _, ok := pinned[field]; ok {
			sources["honeypot."+field] = "environment"
		} else if origin == "compiled" {
			sources["honeypot."+field] = "compiled"
		} else {
			sources["honeypot."+field] = "staged"
		}
	}
	return sources, pinned
}

// adminSettingsIdentity enforces the shared administrator guard: a live
// identity with the admin role, and for mutations a same-origin request under
// the per-subject write limit.
func (s *store) adminSettingsIdentity(w http.ResponseWriter, r *http.Request, write bool) (authenticatedIdentity, bool) {
	if s == nil || s.settings == nil {
		http.Error(w, "settings service unavailable", http.StatusServiceUnavailable)
		return authenticatedIdentity{}, false
	}
	identity, ok := requireIdentity(w, r)
	if !ok {
		return authenticatedIdentity{}, false
	}
	if identity.Role != "admin" {
		http.Error(w, "administrator role required", http.StatusForbidden)
		return authenticatedIdentity{}, false
	}
	if write {
		if !sameOriginRequest(r) {
			http.Error(w, "same-origin request required", http.StatusForbidden)
			return authenticatedIdentity{}, false
		}
		if !s.settings.writes.allow(identity.Subject) {
			w.Header().Set("Retry-After", strconv.Itoa(int(preferenceWriteWindow/time.Second)))
			http.Error(w, "too many settings writes; retry shortly", http.StatusTooManyRequests)
			return authenticatedIdentity{}, false
		}
	}
	return identity, true
}

func (s *store) writeConfig(w http.ResponseWriter) {
	config, etag := s.settings.config.Get()
	sources, pinned := s.settings.configSources()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	_ = json.NewEncoder(w).Encode(configResponse{
		Config:     config,
		Revision:   s.settings.config.Revision(),
		ReadOnly:   s.settings.config.ReadOnly(),
		Degraded:   s.settings.config.Degraded(),
		Sources:    sources,
		PinnedEnvs: pinned,
	})
}

// serveSettingsConfig handles GET (effective configuration) and PATCH (typed
// partial update) on /api/settings/config.
func (s *store) serveSettingsConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if _, ok := s.adminSettingsIdentity(w, r, false); !ok {
			return
		}
		s.writeConfig(w)
	case http.MethodPatch:
		s.patchSettingsConfig(w, r)
	default:
		w.Header().Set("Allow", "GET, PATCH")
		http.Error(w, "GET or PATCH required", http.StatusMethodNotAllowed)
	}
}

func (s *store) patchSettingsConfig(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.adminSettingsIdentity(w, r, true)
	if !ok {
		return
	}
	if contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))); !strings.HasPrefix(contentType, "application/json") {
		http.Error(w, "Content-Type: application/json required", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxConfigBody))
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	var patch configPatch
	if !strictDecode(body, &patch) {
		s.auditConfig(identity, r, "config.update", nil, "invalid")
		http.Error(w, "invalid or unknown configuration fields", http.StatusBadRequest)
		return
	}
	if patch.empty() {
		http.Error(w, "patch must set at least one configuration field", http.StatusBadRequest)
		return
	}
	_, pinned := s.settings.configSources()
	var fields []string
	_, _, err = s.settings.config.Update(r.Header.Get("If-Match"), func(c *dashboardConfig) error {
		fields = patch.apply(c)
		for _, field := range fields {
			if name, pinnedField := strings.CutPrefix(field, "honeypot."); pinnedField {
				if _, isPinned := pinned[name]; isPinned {
					return fmt.Errorf("%w: honeypot.%s is pinned by the deployment environment", errSettingsValidation, name)
				}
			}
		}
		return nil
	})
	if err != nil {
		s.settings.configFailures.Add(1)
		s.auditConfigResult(identity, r, "config.update", fields, err)
		writePreferenceError(w, err)
		return
	}
	payload, _ := s.settings.config.Get()
	raw, _ := json.Marshal(payload)
	s.settings.history.append(configHistoryEntry{
		Revision: s.settings.config.Revision(),
		Actor:    identity.Subject,
		Username: identity.Username,
		Action:   "update",
		Fields:   fields,
		Payload:  raw,
	})
	s.auditConfig(identity, r, "config.update", fields, "success")
	s.writeConfig(w)
}

// serveSettingsConfigValidate previews a patch without persisting it: the
// caller sees the changed fields, their impact classification, and any
// validation problems before deciding to save (roadmap §6).
func (s *store) serveSettingsConfigValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.adminSettingsIdentity(w, r, true); !ok {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxConfigBody))
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	var patch configPatch
	if !strictDecode(body, &patch) || patch.empty() {
		http.Error(w, "invalid or empty configuration patch", http.StatusBadRequest)
		return
	}
	current, _ := s.settings.config.Get()
	candidate := current
	fields := patch.apply(&candidate)
	_, pinned := s.settings.configSources()
	type change struct {
		Field  string `json:"field"`
		Impact string `json:"impact"`
	}
	changes := make([]change, 0, len(fields))
	var problems []string
	for _, field := range fields {
		impact := configFieldImpact(field)
		if name, ok := strings.CutPrefix(field, "honeypot."); ok {
			if _, isPinned := pinned[name]; isPinned {
				impact = "rejected"
				problems = append(problems, field+" is pinned by the deployment environment")
			}
		}
		changes = append(changes, change{Field: field, Impact: impact})
	}
	if err := validateConfig(candidate); err != nil {
		problems = append(problems, err.Error())
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"valid":    len(problems) == 0,
		"changes":  changes,
		"problems": problems,
	})
}

// serveSettingsConfigRollback restores one retained revision as a NEW
// revision (history is append-only; rollback never rewrites the past).
func (s *store) serveSettingsConfigRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := s.adminSettingsIdentity(w, r, true)
	if !ok {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<10))
	if err != nil {
		http.Error(w, "request body unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	var request struct {
		Revision int64 `json:"revision"`
	}
	if !strictDecode(body, &request) || request.Revision < 0 {
		http.Error(w, "a non-negative revision is required", http.StatusBadRequest)
		return
	}
	entry, found := s.settings.history.find(request.Revision)
	if !found {
		http.Error(w, "revision is no longer retained", http.StatusNotFound)
		return
	}
	var restored dashboardConfig
	if !strictDecode(entry.Payload, &restored) {
		http.Error(w, "retained revision is unreadable", http.StatusUnprocessableEntity)
		return
	}
	_, _, err = s.settings.config.Update(r.Header.Get("If-Match"), func(c *dashboardConfig) error {
		*c = restored
		return nil
	})
	if err != nil {
		s.settings.configFailures.Add(1)
		s.auditConfigResult(identity, r, "config.rollback", nil, err)
		writePreferenceError(w, err)
		return
	}
	payload, _ := s.settings.config.Get()
	raw, _ := json.Marshal(payload)
	s.settings.history.append(configHistoryEntry{
		Revision: s.settings.config.Revision(),
		Actor:    identity.Subject,
		Username: identity.Username,
		Action:   "rollback",
		Fields:   []string{"*"},
		Payload:  raw,
	})
	s.auditConfig(identity, r, "config.rollback", []string{"*"}, "success")
	s.writeConfig(w)
}

// configHistoryView is the history API shape: everything needed for review
// and rollback selection, without the retained payload snapshots.
type configHistoryView struct {
	Revision int64    `json:"revision"`
	Time     string   `json:"time"`
	Actor    string   `json:"actor_subject"`
	Username string   `json:"actor_username"`
	Action   string   `json:"action"`
	Fields   []string `json:"fields,omitempty"`
}

func (s *store) serveSettingsConfigHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.adminSettingsIdentity(w, r, false); !ok {
		return
	}
	entries := s.settings.history.read(configHistoryReadLimit)
	views := make([]configHistoryView, 0, len(entries))
	for _, entry := range entries {
		views = append(views, configHistoryView{
			Revision: entry.Revision,
			Time:     entry.Time.UTC().Format("2006-01-02 15:04:05 UTC"),
			Actor:    entry.Actor,
			Username: entry.Username,
			Action:   entry.Action,
			Fields:   entry.Fields,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"entries":           views,
		"current_revision":  s.settings.config.Revision(),
		"retained_revision": true,
	})
}

// userProjectionView is the read-only administration view of one projected
// dashboard user. Preferences stay out of the list payload; the authoritative
// user management surface is auth-backend.
type userProjectionView struct {
	Subject            string `json:"subject"`
	LastUsername       string `json:"last_username"`
	LastDisplayName    string `json:"last_display_name,omitempty"`
	RoleSnapshot       string `json:"role_snapshot"`
	FirstSeen          string `json:"first_seen_at"`
	LastSeen           string `json:"last_seen_at"`
	PreferencesVersion int    `json:"preferences_version"`
}

func (s *store) serveSettingsUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.adminSettingsIdentity(w, r, false); !ok {
		return
	}
	projections := s.settings.users.Projections()
	views := make([]userProjectionView, 0, len(projections))
	for _, p := range projections {
		views = append(views, userProjectionView{
			Subject:            p.Subject,
			LastUsername:       p.LastUsername,
			LastDisplayName:    p.LastDisplayName,
			RoleSnapshot:       p.RoleSnapshot,
			FirstSeen:          p.FirstSeen.UTC().Format("2006-01-02 15:04:05 UTC"),
			LastSeen:           p.LastSeen.UTC().Format("2006-01-02 15:04:05 UTC"),
			PreferencesVersion: p.PreferencesVersion,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"users": views})
}

// serveSettingsAudit returns the settings audit log, newest first, with
// optional ?action= and ?limit= (max 500) filters.
func (s *store) serveSettingsAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.adminSettingsIdentity(w, r, false); !ok {
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	events := s.settings.audit.read(500)
	filtered := make([]auditEvent, 0, limit)
	for _, event := range events {
		if action != "" && event.Action != action {
			continue
		}
		filtered = append(filtered, event)
		if len(filtered) >= limit {
			break
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"events": filtered})
}

// auditConfig records one configuration mutation outcome. Failures of the
// audit write itself never affect the mutation response.
func (s *store) auditConfig(identity authenticatedIdentity, r *http.Request, action string, fields []string, result string) {
	s.settings.audit.log(auditEvent{
		Actor:     identity.Subject,
		Username:  identity.Username,
		RequestID: requestID(r),
		ClientIP:  clientIP(r),
		Action:    action,
		Fields:    fields,
		Revision:  s.settings.config.Revision(),
		Result:    result,
	})
}

func (s *store) auditConfigResult(identity authenticatedIdentity, r *http.Request, action string, fields []string, err error) {
	result := "error"
	switch {
	case errors.Is(err, errStaleRevision):
		result = "conflict"
	case errors.Is(err, errSettingsValidation) || strings.Contains(err.Error(), "pinned by the deployment environment"):
		result = "invalid"
	}
	s.auditConfig(identity, r, action, fields, result)
}
