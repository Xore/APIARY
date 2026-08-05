package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// adminConfigRequest issues one request against an admin-role settings store.
func adminConfigRequest(t *testing.T, s *store, method, target string, sameOrigin bool, body string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	request := settingsRequest(t, method, target, sameOrigin, body)
	switch {
	case strings.Contains(target, "/config/validate"):
		s.serveSettingsConfigValidate(response, request)
	case strings.Contains(target, "/config/rollback"):
		s.serveSettingsConfigRollback(response, request)
	case strings.Contains(target, "/config/history"):
		s.serveSettingsConfigHistory(response, request)
	case strings.Contains(target, "/users"):
		s.serveSettingsUsers(response, request)
	case strings.Contains(target, "/audit"):
		s.serveSettingsAudit(response, request)
	default:
		s.serveSettingsConfig(response, request)
	}
	return response
}

func TestAdminEndpointsRejectNonAdminAndAnonymous(t *testing.T) {
	targets := []struct{ method, target string }{
		{http.MethodGet, "/api/settings/config"},
		{http.MethodPatch, "/api/settings/config"},
		{http.MethodPost, "/api/settings/config/validate"},
		{http.MethodPost, "/api/settings/config/rollback"},
		{http.MethodGet, "/api/settings/config/history"},
		{http.MethodGet, "/api/settings/users"},
		{http.MethodGet, "/api/settings/audit"},
	}
	nonAdmin := newSettingsAPITestStore(t, "user")
	for _, target := range targets {
		response := adminConfigRequest(t, nonAdmin, target.method, target.target, true, `{"presentation":{"app_name":"x"}}`)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s %s with user role: status = %d, want 403", target.method, target.target, response.Code)
		}
	}
	// No session cookie at all fails closed with 401.
	admin := newSettingsAPITestStore(t, "admin")
	response := httptest.NewRecorder()
	admin.serveSettingsConfig(response, httptest.NewRequest(http.MethodGet, "/api/settings/config", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous config read: status = %d, want 401", response.Code)
	}
}

func getConfig(t *testing.T, s *store) (configResponse, string) {
	t.Helper()
	response := adminConfigRequest(t, s, http.MethodGet, "/api/settings/config", false, "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET config status = %d, body = %s", response.Code, response.Body.String())
	}
	var parsed configResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	if response.Header().Get("ETag") == "" {
		t.Fatal("GET config must return an ETag")
	}
	return parsed, response.Header().Get("ETag")
}

func TestGetConfigReportsSourcesAndEnvPins(t *testing.T) {
	t.Setenv("HONEYPOT_ALERT_COOLDOWN", "2h")
	s := newSettingsAPITestStore(t, "admin")
	parsed, _ := getConfig(t, s)
	if parsed.Sources["honeypot.alert_cooldown"] != "environment" {
		t.Fatalf("env-pinned field must report source environment, got %q", parsed.Sources["honeypot.alert_cooldown"])
	}
	if parsed.PinnedEnvs["alert_cooldown"] != "2h" {
		t.Fatalf("pinned value must be reported, got %#v", parsed.PinnedEnvs)
	}
	if parsed.Sources["honeypot.alert_campaign_score"] != "staged" {
		t.Fatalf("unpinned honeypot field must report source staged, got %q", parsed.Sources["honeypot.alert_campaign_score"])
	}
	if parsed.Config.Presentation.AppName == "" {
		t.Fatal("config must serve compiled defaults on first boot")
	}
}

func TestPatchConfigAppliesRotatesETagAndAudits(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	_, etag := getConfig(t, s)
	request := settingsRequest(t, http.MethodPatch, "/api/settings/config", true,
		`{"presentation":{"app_name":"SOCOPS"},"behavior":{"maintenance_mode":true}}`)
	request.Header.Set("If-Match", etag)
	response := httptest.NewRecorder()
	s.serveSettingsConfig(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") == etag {
		t.Fatal("successful patch must rotate the ETag")
	}
	updated, _ := getConfig(t, s)
	if updated.Config.Presentation.AppName != "SOCOPS" || !updated.Config.Behavior.MaintenanceMode {
		t.Fatalf("patch not applied: %#v", updated.Config.Presentation)
	}
	if updated.Revision != 1 {
		t.Fatalf("revision = %d, want 1", updated.Revision)
	}
	events := s.settings.audit.read(10)
	if len(events) == 0 || events[0].Action != "config.update" || events[0].Result != "success" {
		t.Fatalf("update must be audited: %#v", events)
	}
	if !containsString(events[0].Fields, "presentation.app_name") || !containsString(events[0].Fields, "behavior.maintenance_mode") {
		t.Fatalf("audit must name changed fields: %#v", events[0].Fields)
	}
	history := s.settings.history.read(10)
	if len(history) != 2 || history[0].Revision != 1 || history[0].Action != "update" || len(history[0].Payload) == 0 {
		t.Fatalf("history snapshot missing: %#v", history)
	}
	if history[1].Revision != 0 || history[1].Action != "seed" {
		t.Fatalf("history must retain the seeded initial revision: %#v", history)
	}
}

// #477: an admin-edited Report Studio preset name/description round-trips
// through PATCH and is reflected by /api/reports/templates, while the
// structural catalog fields (theme, window, elements) stay compiled.
func TestPatchConfigAppliesReportPresetOverrides(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	esStore := newMemESDocStore()
	esSrv := httptest.NewServer(esStore.handler())
	t.Cleanup(esSrv.Close)
	s.reports = newReportStore(filepath.Join(t.TempDir(), "reports.json"), newESClient(esSrv.URL, ""))
	_, etag := getConfig(t, s)
	request := settingsRequest(t, http.MethodPatch, "/api/settings/config", true,
		`{"presentation":{"report_presets":{"executive":{"name":"Board summary","description":"Custom copy"}}}}`)
	request.Header.Set("If-Match", etag)
	response := httptest.NewRecorder()
	s.serveSettingsConfig(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, body = %s", response.Code, response.Body.String())
	}
	updated, _ := getConfig(t, s)
	override, ok := updated.Config.Presentation.ReportPresets["executive"]
	if !ok || override.Name != "Board summary" || override.Description != "Custom copy" {
		t.Fatalf("report preset override not persisted: %#v", updated.Config.Presentation.ReportPresets)
	}
	events := s.settings.audit.read(10)
	if len(events) == 0 || !containsString(events[0].Fields, "presentation.report_presets") {
		t.Fatalf("audit must name the changed field: %#v", events)
	}

	templatesResponse := httptest.NewRecorder()
	s.serveReportTemplates(templatesResponse, settingsRequest(t, http.MethodGet, "/api/reports/templates", false, ""))
	if templatesResponse.Code != http.StatusOK {
		t.Fatalf("GET templates status = %d", templatesResponse.Code)
	}
	var body struct {
		Templates []reportTemplate `json:"templates"`
	}
	if err := json.NewDecoder(templatesResponse.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	var executive reportTemplate
	found := false
	for _, tmpl := range body.Templates {
		if tmpl.ID == "executive" {
			executive, found = tmpl, true
		}
	}
	if !found {
		t.Fatal("executive template missing from catalog")
	}
	if executive.Name != "Board summary" || executive.Description != "Custom copy" {
		t.Fatalf("overridden template = %#v, want overridden name/description", executive)
	}
	if executive.Theme != "dark" || executive.Window != "24h" || len(executive.Elements) == 0 {
		t.Fatalf("structural fields must stay compiled, got %#v", executive)
	}
}

func TestValidateConfigRejectsUnknownOrOversizedReportPresetOverride(t *testing.T) {
	base := defaultDashboardConfig()
	base.Presentation.ReportPresets = map[string]reportPresetOverride{
		"not-a-real-template": {Name: "x"},
	}
	if err := validateConfig(base); err == nil {
		t.Fatal("unknown report preset id must be rejected")
	}

	base.Presentation.ReportPresets = map[string]reportPresetOverride{
		"executive": {Name: strings.Repeat("x", reportPresetNameLimit+1)},
	}
	if err := validateConfig(base); err == nil {
		t.Fatal("oversized report preset name must be rejected")
	}

	base.Presentation.ReportPresets = map[string]reportPresetOverride{
		"executive": {Description: strings.Repeat("x", reportPresetDescriptionLimit+1)},
	}
	if err := validateConfig(base); err == nil {
		t.Fatal("oversized report preset description must be rejected")
	}

	base.Presentation.ReportPresets = map[string]reportPresetOverride{
		"executive": {Name: "Fine name", Description: "Fine description"},
	}
	if err := validateConfig(base); err != nil {
		t.Fatalf("valid report preset override must be accepted: %v", err)
	}
}

func TestPatchConfigRejectsEnvPinnedHoneypotField(t *testing.T) {
	t.Setenv("HONEYPOT_ALERT_COOLDOWN", "2h")
	s := newSettingsAPITestStore(t, "admin")
	response := adminConfigRequest(t, s, http.MethodPatch, "/api/settings/config", true,
		`{"honeypot":{"alert_cooldown":"12h"}}`)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("pinned write: status = %d, want 422; body = %s", response.Code, response.Body.String())
	}
	updated, _ := getConfig(t, s)
	if updated.Config.Honeypot.AlertCooldown != "6h" {
		t.Fatal("rejected pinned write must not change the staged value")
	}
	// The same field is accepted the moment the pin is gone — the rule follows
	// the environment, not a static denylist entry.
	if err := os.Unsetenv("HONEYPOT_ALERT_COOLDOWN"); err != nil {
		t.Fatal(err)
	}
	s2 := newSettingsAPITestStore(t, "admin")
	response = adminConfigRequest(t, s2, http.MethodPatch, "/api/settings/config", true,
		`{"honeypot":{"alert_cooldown":"12h"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("unpinned honeypot write: status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestPatchConfigConcurrencyAndOriginGuards(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	request := settingsRequest(t, http.MethodPatch, "/api/settings/config", true, `{"presentation":{"app_name":"SOCOPS"}}`)
	request.Header.Set("If-Match", `"r0-000000000000"`)
	response := httptest.NewRecorder()
	s.serveSettingsConfig(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale If-Match: status = %d, want 409", response.Code)
	}
	response = adminConfigRequest(t, s, http.MethodPatch, "/api/settings/config", false, `{"presentation":{"app_name":"SOCOPS"}}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin write: status = %d, want 403", response.Code)
	}
	response = adminConfigRequest(t, s, http.MethodPatch, "/api/settings/config", true, `{"presentation":{"app_name":""}}`)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid value: status = %d, want 422", response.Code)
	}
	response = adminConfigRequest(t, s, http.MethodPatch, "/api/settings/config", true, `{"webhook_url":"https://example.invalid"}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: status = %d, want 400", response.Code)
	}
}

func TestValidateConfigPreviewsImpactWithoutPersisting(t *testing.T) {
	t.Setenv("SANDBOX_ALERT_RISK_SCORE", "70")
	s := newSettingsAPITestStore(t, "admin")
	_, etagBefore := getConfig(t, s)
	response := adminConfigRequest(t, s, http.MethodPost, "/api/settings/config/validate", true,
		`{"presentation":{"app_name":"SOCOPS"},"behavior":{"maintenance_mode":true},"honeypot":{"alert_cooldown":"12h","sandbox_alert_risk_score":60}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("validate status = %d, body = %s", response.Code, response.Body.String())
	}
	var preview struct {
		Valid   bool `json:"valid"`
		Changes []struct {
			Field  string `json:"field"`
			Impact string `json:"impact"`
		} `json:"changes"`
		Problems []string `json:"problems"`
	}
	if err := json.NewDecoder(response.Body).Decode(&preview); err != nil {
		t.Fatal(err)
	}
	impacts := map[string]string{}
	for _, change := range preview.Changes {
		impacts[change.Field] = change.Impact
	}
	want := map[string]string{
		"presentation.app_name":             "new-request",
		"behavior.maintenance_mode":         "live",
		"honeypot.alert_cooldown":           "restart-required",
		"honeypot.sandbox_alert_risk_score": "rejected",
	}
	for field, impact := range want {
		if impacts[field] != impact {
			t.Fatalf("impact for %s = %q, want %q (all: %#v)", field, impacts[field], impact, impacts)
		}
	}
	if preview.Valid {
		t.Fatal("preview with a pinned field must not be valid")
	}
	_, etagAfter := getConfig(t, s)
	if etagBefore != etagAfter {
		t.Fatal("validation preview must not persist anything")
	}
}

func TestConfigRollbackRestoresRetainedRevision(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	adminConfigRequest(t, s, http.MethodPatch, "/api/settings/config", true, `{"presentation":{"app_name":"SOCOPS"}}`)
	adminConfigRequest(t, s, http.MethodPatch, "/api/settings/config", true, `{"presentation":{"app_name":"SOCOPS-2"}}`)
	current, _ := getConfig(t, s)
	if current.Revision != 2 || current.Config.Presentation.AppName != "SOCOPS-2" {
		t.Fatalf("setup failed: revision %d, name %q", current.Revision, current.Config.Presentation.AppName)
	}
	response := adminConfigRequest(t, s, http.MethodPost, "/api/settings/config/rollback", true, `{"revision":0}`)
	if response.Code != http.StatusOK {
		t.Fatalf("rollback to defaults: status = %d, body = %s", response.Code, response.Body.String())
	}
	restored, _ := getConfig(t, s)
	if restored.Config.Presentation.AppName != "APIARY" {
		t.Fatalf("rollback must restore the revision 0 payload, got %q", restored.Config.Presentation.AppName)
	}
	if restored.Revision != 3 {
		t.Fatalf("rollback must create a NEW revision, got %d", restored.Revision)
	}
	history := s.settings.history.read(10)
	if len(history) == 0 || history[0].Action != "rollback" || history[0].Revision != 3 {
		t.Fatalf("rollback must be recorded in history: %#v", history)
	}
	events := s.settings.audit.read(10)
	if len(events) == 0 || events[0].Action != "config.rollback" || events[0].Result != "success" {
		t.Fatalf("rollback must be audited: %#v", events)
	}
	response = adminConfigRequest(t, s, http.MethodPost, "/api/settings/config/rollback", true, `{"revision":9999}`)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown revision: status = %d, want 404", response.Code)
	}
}

// TestConfigHistorySeedsInitialRevision ensures the compiled-default state is
// rollback-able even before the first admin write.
func TestConfigHistorySeedsInitialRevision(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	adminConfigRequest(t, s, http.MethodPatch, "/api/settings/config", true, `{"presentation":{"app_name":"SOCOPS"}}`)
	response := adminConfigRequest(t, s, http.MethodGet, "/api/settings/config/history", false, "")
	if response.Code != http.StatusOK {
		t.Fatalf("history status = %d", response.Code)
	}
	var parsed struct {
		Entries []configHistoryView `json:"entries"`
	}
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Entries) < 2 {
		t.Fatalf("history must retain the initial revision and the update: %#v", parsed.Entries)
	}
	if parsed.Entries[0].Revision != 1 || parsed.Entries[1].Revision != 0 {
		t.Fatalf("history must be newest first from revision 0: %#v", parsed.Entries)
	}
}

func TestSettingsUsersAndAuditViews(t *testing.T) {
	s := newSettingsAPITestStore(t, "admin")
	// A whoami call projects the current user; the admin list must show it.
	response := httptest.NewRecorder()
	s.serveWhoAmI(response, settingsRequest(t, http.MethodGet, "/api/whoami", false, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("whoami status = %d", response.Code)
	}
	response = adminConfigRequest(t, s, http.MethodGet, "/api/settings/users", false, "")
	if response.Code != http.StatusOK {
		t.Fatalf("users status = %d", response.Code)
	}
	var users struct {
		Users []userProjectionView `json:"users"`
	}
	if err := json.NewDecoder(response.Body).Decode(&users); err != nil {
		t.Fatal(err)
	}
	if len(users.Users) != 1 || users.Users[0].LastUsername != "analyst" || users.Users[0].RoleSnapshot != "admin" {
		t.Fatalf("unexpected projections: %#v", users.Users)
	}
	// Preferences stay out of the list payload.
	if strings.Contains(response.Body.String(), "preferences\":{") {
		t.Fatal("user list must not embed full preference documents")
	}

	adminConfigRequest(t, s, http.MethodPatch, "/api/settings/config", true, `{"presentation":{"app_name":"SOCOPS"}}`)
	response = adminConfigRequest(t, s, http.MethodGet, "/api/settings/audit?action=config.update", false, "")
	var audit struct {
		Events []auditEvent `json:"events"`
	}
	if err := json.NewDecoder(response.Body).Decode(&audit); err != nil {
		t.Fatal(err)
	}
	if len(audit.Events) == 0 || audit.Events[0].Action != "config.update" {
		t.Fatalf("filtered audit view: %#v", audit.Events)
	}
	response = adminConfigRequest(t, s, http.MethodGet, "/api/settings/audit?action=preferences.reset", false, "")
	if err := json.NewDecoder(response.Body).Decode(&audit); err != nil {
		t.Fatal(err)
	}
	if len(audit.Events) != 0 {
		t.Fatalf("action filter must exclude non-matching events: %#v", audit.Events)
	}
}

// TestConfigSchemaCannotExposeTier3Values is the §12 denylist regression: no
// configuration schema field may ever name a deployment secret, endpoint,
// credential, or execution primitive — those stay outside the UI forever.
func TestConfigSchemaCannotExposeTier3Values(t *testing.T) {
	forbidden := []string{
		"webhook", "token", "secret", "password", "credential", "smtp",
		"elasticsearch", "arkime", "kibana", "docker", "socket", "bind",
		"compose", "command", "exec", "path", "volume", "network", "introspection",
	}
	for _, schemaType := range []reflect.Type{
		reflect.TypeOf(presentationConfig{}),
		reflect.TypeOf(behaviorConfig{}),
		reflect.TypeOf(honeypotConfig{}),
		reflect.TypeOf(presentationPatch{}),
		reflect.TypeOf(behaviorPatch{}),
		reflect.TypeOf(honeypotPatch{}),
	} {
		for i := 0; i < schemaType.NumField(); i++ {
			tag := schemaType.Field(i).Tag.Get("json")
			name, _, _ := strings.Cut(tag, ",")
			for _, denied := range forbidden {
				if strings.Contains(name, denied) {
					t.Fatalf("schema field %q in %v contains denied term %q — Tier 3 values must never become editable", name, schemaType, denied)
				}
			}
		}
	}
	// Every env-pinnable honeypot field must exist in the schema (no orphan
	// pins) and vice versa (no unpinnable Tier 2 field).
	schema := map[string]bool{}
	honeypot := reflect.TypeOf(honeypotConfig{})
	for i := 0; i < honeypot.NumField(); i++ {
		name, _, _ := strings.Cut(honeypot.Field(i).Tag.Get("json"), ",")
		schema[name] = true
	}
	for field := range honeypotFieldEnv() {
		if !schema[field] {
			t.Fatalf("env map names %q, which is not a honeypot schema field", field)
		}
		delete(schema, field)
	}
	for orphan := range schema {
		t.Fatalf("honeypot schema field %q has no environment mapping — every Tier 2 field must declare its pin", orphan)
	}
}
