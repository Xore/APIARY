package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Milestone G: the settings subsystem must be observable through /metrics —
// store health flags, configuration revision, failure counters, and
// projection volume all appear as Prometheus text.
func TestSettingsMetricsExposed(t *testing.T) {
	s := newSettingsAPITestStore(t, "user")
	getPreferences(t, s) // projects the caller so writes reach the store

	// A rejected write must count as a save failure.
	response := httptest.NewRecorder()
	s.servePreferencesPatch(response, settingsRequest(t, http.MethodPatch, "/api/settings/me/preferences", true, `{"theme":"neon"}`))
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid theme must be rejected, status = %d, body = %s", response.Code, response.Body.String())
	}

	recorder := httptest.NewRecorder()
	s.serveMetrics(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()

	exact := []string{
		`honeypot_settings_store_readonly{store="config"} 0`,
		`honeypot_settings_store_readonly{store="users"} 0`,
		`honeypot_settings_store_degraded{store="config"} 0`,
		`honeypot_settings_store_recovered{store="users"} 0`,
		"honeypot_settings_projected_users 1",
		`honeypot_settings_save_failures_total{kind="preferences"} 1`,
		`honeypot_settings_save_failures_total{kind="config"} 0`,
		"honeypot_settings_retention_removed_total 0",
	}
	for _, line := range exact {
		if !strings.Contains(body, line+"\n") && !strings.HasSuffix(body, line) {
			t.Errorf("metrics output missing %q", line)
		}
	}
	prefixes := []string{
		"honeypot_settings_config_revision ",
		"honeypot_settings_audit_events ",
	}
	for _, prefix := range prefixes {
		if !strings.Contains(body, prefix) {
			t.Errorf("metrics output missing prefix %q", prefix)
		}
	}
}

// A store without the settings service (settings == nil) must still render
// the base metrics — the settings block is skipped entirely.
func TestMetricsWithoutSettingsService(t *testing.T) {
	s := &store{}
	recorder := httptest.NewRecorder()
	s.serveMetrics(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics must render without settings, status = %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "honeypot_settings_") {
		t.Fatal("settings metrics must be absent when the service is disabled")
	}
}
