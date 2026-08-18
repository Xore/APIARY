package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// newSettingsAPITestStore builds a store whose settings service is backed by
// an in-memory Elasticsearch stand-in (memESDocStore, alerts_test.go) --
// config/users are Elasticsearch-backed singleton documents since #787 --
// with the identity test backend configured for role. The audit/history
// logs stay local-file-backed (unaffected by #787, see settings_store_es.go's
// own header comment for why), so those two still live in a temp directory.
func newSettingsAPITestStore(t *testing.T, role string) *store {
	t.Helper()
	configureIdentityTestBackend(t, role)
	dir := t.TempDir()
	esStore := newMemESDocStore()
	esSrv := httptest.NewServer(esStore.handler())
	t.Cleanup(esSrv.Close)
	es := newESClient(esSrv.URL, "")
	return &store{
		es: es,
		settings: newSettingsService(
			es,
			filepath.Join(dir, "audit.jsonl"),
			filepath.Join(dir, "history.jsonl"),
		),
	}
}

func settingsRequest(t *testing.T, method, target string, sameOrigin bool, body string) *http.Request {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, target, reader)
	addIdentityTestCookie(request)
	if sameOrigin {
		request.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func getPreferences(t *testing.T, s *store) (preferencesResponse, string) {
	t.Helper()
	response := httptest.NewRecorder()
	s.serveSettingsMe(response, settingsRequest(t, http.MethodGet, "/api/settings/me", false, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/settings/me status = %d, body = %s", response.Code, response.Body.String())
	}
	var parsed preferencesResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	return parsed, response.Header().Get("ETag")
}

func TestSettingsMeRequiresIdentity(t *testing.T) {
	s := newSettingsAPITestStore(t, "user")
	request := httptest.NewRequest(http.MethodGet, "/api/settings/me", nil) // no session cookie
	response := httptest.NewRecorder()
	s.serveSettingsMe(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out read must fail closed, status = %d", response.Code)
	}
}

func TestSettingsMeReturnsDefaultsWithETagAndNoStore(t *testing.T) {
	s := newSettingsAPITestStore(t, "user")
	parsed, etag := getPreferences(t, s)
	if etag == "" {
		t.Fatal("GET must return an ETag for optimistic concurrency")
	}
	if parsed.Preferences.Theme != "system" || parsed.Preferences.RowsPerPage != 50 {
		t.Fatalf("expected compiled defaults, got %+v", parsed.Preferences)
	}
	// The read must have projected the caller, so later writes succeed.
	if len(s.settings.users.Projections()) != 1 {
		t.Fatal("first read must create the user projection")
	}
}

func TestPreferencesPatchAppliesAndPersists(t *testing.T) {
	s := newSettingsAPITestStore(t, "user")
	_, etag := getPreferences(t, s)

	request := settingsRequest(t, http.MethodPatch, "/api/settings/me/preferences", true,
		`{"theme":"dark","rows_per_page":100,"notify_sound":true}`)
	request.Header.Set("If-Match", etag)
	response := httptest.NewRecorder()
	s.servePreferencesPatch(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, body = %s", response.Code, response.Body.String())
	}
	var parsed preferencesResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Preferences.Theme != "dark" || parsed.Preferences.RowsPerPage != 100 || !parsed.Preferences.NotifySound {
		t.Fatalf("patch not applied: %+v", parsed.Preferences)
	}
	if response.Header().Get("ETag") == etag {
		t.Fatal("successful patch must rotate the ETag")
	}

	// Untouched fields keep their values, and the write is visible from a
	// second, independent store against the same Elasticsearch backend --
	// standing in for the dashboard's second replica (#787): the write must
	// be visible there too, not just in this store's own in-memory cache.
	if parsed.Preferences.Density != "comfortable" {
		t.Fatalf("partial patch clobbered untouched fields: %+v", parsed.Preferences)
	}
	reloaded := newUserStore(s.es, s.settings.audit)
	prefs, _, ok := reloaded.Preferences("b65ab0dc-cc07-4b3d-9af0-b482dbb4b096")
	if !ok || prefs.Theme != "dark" {
		t.Fatal("patched preferences did not persist")
	}

	// The mutation is audited with the actor and outcome.
	events := s.settings.audit.read(5)
	if len(events) == 0 || events[0].Result != "success" || events[0].Action != "preferences.update" {
		t.Fatalf("patch missing audit record: %+v", events)
	}
}

// Regression: the Appearance pane saves theme and palette together (the
// palette picker's "claude" never string-matches the stored "" default, so
// the pane's diff always includes it). preferencesPatch was missing the
// palette field, so the strict decoder rejected the whole patch with
// "invalid or unknown preference fields" on every appearance save.
func TestPreferencesPatchAcceptsPalette(t *testing.T) {
	s := newSettingsAPITestStore(t, "user")
	_, etag := getPreferences(t, s)

	request := settingsRequest(t, http.MethodPatch, "/api/settings/me/preferences", true,
		`{"theme":"dark","palette":"ocean"}`)
	request.Header.Set("If-Match", etag)
	response := httptest.NewRecorder()
	s.servePreferencesPatch(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, body = %s", response.Code, response.Body.String())
	}
	var parsed preferencesResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Preferences.Theme != "dark" || parsed.Preferences.Palette != "ocean" {
		t.Fatalf("palette patch not applied: %+v", parsed.Preferences)
	}

	// A palette outside the allowlist still fails per-field validation
	// (settings_domain.go's allowedPalettes), not the unknown-field guard.
	_, etag = getPreferences(t, s)
	bad := settingsRequest(t, http.MethodPatch, "/api/settings/me/preferences", true,
		`{"palette":"hotdog"}`)
	bad.Header.Set("If-Match", etag)
	badResponse := httptest.NewRecorder()
	s.servePreferencesPatch(badResponse, bad)
	if badResponse.Code == http.StatusOK {
		t.Fatal("invalid palette value must be rejected")
	}
	if strings.Contains(badResponse.Body.String(), "unknown preference fields") {
		t.Fatalf("invalid palette hit the unknown-field guard instead of validation: %s", badResponse.Body.String())
	}
}

func TestPreferencesPatchGuards(t *testing.T) {
	s := newSettingsAPITestStore(t, "user")
	_, etag := getPreferences(t, s)

	cases := []struct {
		name       string
		configure  func(*http.Request)
		body       string
		sameOrigin bool
		wantStatus int
	}{
		{"cross origin", func(r *http.Request) {}, `{"theme":"dark"}`, false, http.StatusForbidden},
		{"wrong content type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, `{"theme":"dark"}`, true, http.StatusUnsupportedMediaType},
		{"unknown field", func(r *http.Request) {}, `{"theme":"dark","is_admin":true}`, true, http.StatusBadRequest},
		{"empty patch", func(r *http.Request) {}, `{}`, true, http.StatusBadRequest},
		{"invalid value", func(r *http.Request) {}, `{"theme":"neon"}`, true, http.StatusUnprocessableEntity},
		{"stale etag", func(r *http.Request) { r.Header.Set("If-Match", `"r0-000000000000"`) }, `{"theme":"dark"}`, true, http.StatusConflict},
		{"malformed json", func(r *http.Request) {}, `{`, true, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := settingsRequest(t, http.MethodPatch, "/api/settings/me/preferences", tc.sameOrigin, tc.body)
			tc.configure(request)
			response := httptest.NewRecorder()
			s.servePreferencesPatch(response, request)
			if response.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body = %s", response.Code, tc.wantStatus, response.Body.String())
			}
		})
	}

	// None of the rejected attempts may have changed stored state.
	prefs, currentETag, _ := s.settings.users.Preferences("b65ab0dc-cc07-4b3d-9af0-b482dbb4b096")
	if prefs.Theme != "system" || currentETag != etag {
		t.Fatal("rejected patches changed stored preferences")
	}
}

func TestPreferencesPatchWithoutIdentityFailsClosed(t *testing.T) {
	s := newSettingsAPITestStore(t, "user")
	request := httptest.NewRequest(http.MethodPatch, "/api/settings/me/preferences", strings.NewReader(`{"theme":"dark"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response := httptest.NewRecorder()
	s.servePreferencesPatch(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out write must fail closed, status = %d", response.Code)
	}
}

func TestPreferencesResetRestoresDefaults(t *testing.T) {
	s := newSettingsAPITestStore(t, "user")
	_, etag := getPreferences(t, s)

	patch := settingsRequest(t, http.MethodPatch, "/api/settings/me/preferences", true, `{"theme":"light","density":"compact"}`)
	patch.Header.Set("If-Match", etag)
	patchResponse := httptest.NewRecorder()
	s.servePreferencesPatch(patchResponse, patch)
	if patchResponse.Code != http.StatusOK {
		t.Fatalf("setup patch failed: status = %d, body = %s", patchResponse.Code, patchResponse.Body.String())
	}

	reset := settingsRequest(t, http.MethodPost, "/api/settings/me/preferences/reset", true, "")
	response := httptest.NewRecorder()
	s.servePreferencesReset(response, reset)
	if response.Code != http.StatusOK {
		t.Fatalf("reset status = %d, body = %s", response.Code, response.Body.String())
	}
	var parsed preferencesResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	defaults := defaultPreferences()
	if parsed.Preferences.Theme != defaults.Theme || parsed.Preferences.Density != defaults.Density {
		t.Fatalf("reset did not restore defaults: %+v", parsed.Preferences)
	}
}

func TestPreferencesWritesAreRateLimitedPerSubject(t *testing.T) {
	s := newSettingsAPITestStore(t, "user")
	getPreferences(t, s) // create the projection
	var last int
	for i := 0; i < preferenceWriteLimit+1; i++ {
		response := httptest.NewRecorder()
		s.servePreferencesPatch(response, settingsRequest(t, http.MethodPatch, "/api/settings/me/preferences", true, `{"notify_sound":true}`))
		last = response.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("write beyond the per-subject limit must be throttled, status = %d", last)
	}
	// Reads stay available while writes are throttled.
	if _, etag := getPreferences(t, s); etag == "" {
		t.Fatal("throttled subject must still read preferences")
	}
}

func TestSettingsRoutesRejectWrongMethods(t *testing.T) {
	s := newSettingsAPITestStore(t, "user")
	for method, target := range map[string]string{
		http.MethodPost:  "/api/settings/me",
		http.MethodGet:   "/api/settings/me/preferences",
		http.MethodPatch: "/api/settings/me/preferences/reset",
	} {
		request := settingsRequest(t, method, target, true, "")
		response := httptest.NewRecorder()
		switch target {
		case "/api/settings/me":
			s.serveSettingsMe(response, request)
		case "/api/settings/me/preferences":
			s.servePreferencesPatch(response, request)
		default:
			s.servePreferencesReset(response, request)
		}
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: status = %d, want 405", method, target, response.Code)
		}
	}
}
