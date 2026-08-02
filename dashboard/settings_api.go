package main

// settings_api.go — the self-service preference endpoints from roadmap §6
// (Milestone C):
//
//	GET   /api/settings/me                      read effective preferences
//	PATCH /api/settings/me/preferences          typed partial update
//	POST  /api/settings/me/preferences/reset    restore compiled defaults
//
// Every request resolves its subject through live auth-backend introspection
// (requireIdentity); there is no way to name another subject. Mutations
// require a same-origin request (CSRF), a JSON content type, a bounded body,
// an optional If-Match for optimistic concurrency, and stay under a
// per-subject write rate limit. Every outcome is audited by the user store.

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxPreferencesBody bounds a preference patch. The full typed document is
// well under 2 KiB; 16 KiB leaves generous headroom without inviting abuse.
const maxPreferencesBody = 16 << 10

// preferenceWriteLimit and preferenceWriteWindow implement the per-subject
// write rate limit from roadmap §6. Reads are not limited: they serve an
// in-memory document.
const (
	preferenceWriteLimit  = 20
	preferenceWriteWindow = time.Minute
)

// writeLimiter is a per-key sliding-window limiter for settings writes.
type writeLimiter struct {
	mu     sync.Mutex
	writes map[string][]time.Time
}

func newWriteLimiter() *writeLimiter {
	return &writeLimiter{writes: map[string][]time.Time{}}
}

// allow records one attempted write for key and reports whether it is under
// the limit. Rejected attempts count too, so a client hammering an invalid
// patch cannot starve its own later valid writes selectively — all of its
// writes are throttled equally.
func (l *writeLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	kept := l.writes[key][:0]
	for _, at := range l.writes[key] {
		if now.Sub(at) < preferenceWriteWindow {
			kept = append(kept, at)
		}
	}
	if len(kept) >= preferenceWriteLimit {
		l.writes[key] = kept
		return false
	}
	l.writes[key] = append(kept, now)
	return true
}

// preferencesPatch is the typed PATCH body. Pointer fields distinguish
// "absent" from "zero", so a client can set false or 0 explicitly. Unknown
// fields are rejected by the strict decoder, which keeps the allowlist from
// roadmap §6 enforceable in exactly one place.
type preferencesPatch struct {
	Theme              *string `json:"theme"`
	Density            *string `json:"density"`
	ReducedMotion      *string `json:"reduced_motion"`
	CollapsedSidebar   *bool   `json:"collapsed_sidebar"`
	LandingPage        *string `json:"landing_page"`
	RememberFilters    *bool   `json:"remember_filters"`
	RowsPerPage        *int    `json:"rows_per_page"`
	WrapLongValues     *bool   `json:"wrap_long_values"`
	Timezone           *string `json:"timezone"`
	Clock              *string `json:"clock"`
	Timestamps         *string `json:"timestamps"`
	AutoRefresh        *bool   `json:"auto_refresh"`
	RefreshInterval    *int    `json:"refresh_interval_seconds"`
	LiveToasts         *bool   `json:"live_toasts"`
	MapBasemap         *string `json:"map_basemap"`
	MapClustering      *bool   `json:"map_clustering"`
	MapAnimation       *bool   `json:"map_animation"`
	HighContrast       *bool   `json:"high_contrast"`
	LargeEvidenceText  *bool   `json:"large_evidence_text"`
	NotifySeverity     *string `json:"notify_severity"`
	NotifySound        *bool   `json:"notify_sound"`
	NotifyDesktop      *bool   `json:"notify_desktop"`
	DefaultEventWindow *string `json:"default_event_window"`
	PreserveFilters    *bool   `json:"preserve_filters"`
	OpenDetailsNewTab  *bool   `json:"open_details_new_tab"`
}

func (p preferencesPatch) empty() bool {
	return p == preferencesPatch{}
}

// apply copies every present field onto prefs.
func (p preferencesPatch) apply(prefs *userPreferences) {
	if p.Theme != nil {
		prefs.Theme = *p.Theme
	}
	if p.Density != nil {
		prefs.Density = *p.Density
	}
	if p.ReducedMotion != nil {
		prefs.ReducedMotion = *p.ReducedMotion
	}
	if p.CollapsedSidebar != nil {
		prefs.CollapsedSidebar = *p.CollapsedSidebar
	}
	if p.LandingPage != nil {
		prefs.LandingPage = *p.LandingPage
	}
	if p.RememberFilters != nil {
		prefs.RememberFilters = *p.RememberFilters
	}
	if p.RowsPerPage != nil {
		prefs.RowsPerPage = *p.RowsPerPage
	}
	if p.WrapLongValues != nil {
		prefs.WrapLongValues = *p.WrapLongValues
	}
	if p.Timezone != nil {
		prefs.Timezone = *p.Timezone
	}
	if p.Clock != nil {
		prefs.Clock = *p.Clock
	}
	if p.Timestamps != nil {
		prefs.Timestamps = *p.Timestamps
	}
	if p.AutoRefresh != nil {
		prefs.AutoRefresh = *p.AutoRefresh
	}
	if p.RefreshInterval != nil {
		prefs.RefreshInterval = *p.RefreshInterval
	}
	if p.LiveToasts != nil {
		prefs.LiveToasts = *p.LiveToasts
	}
	if p.MapBasemap != nil {
		prefs.MapBasemap = *p.MapBasemap
	}
	if p.MapClustering != nil {
		prefs.MapClustering = *p.MapClustering
	}
	if p.MapAnimation != nil {
		prefs.MapAnimation = *p.MapAnimation
	}
	if p.HighContrast != nil {
		prefs.HighContrast = *p.HighContrast
	}
	if p.LargeEvidenceText != nil {
		prefs.LargeEvidenceText = *p.LargeEvidenceText
	}
	if p.NotifySeverity != nil {
		prefs.NotifySeverity = *p.NotifySeverity
	}
	if p.NotifySound != nil {
		prefs.NotifySound = *p.NotifySound
	}
	if p.NotifyDesktop != nil {
		prefs.NotifyDesktop = *p.NotifyDesktop
	}
	if p.DefaultEventWindow != nil {
		prefs.DefaultEventWindow = *p.DefaultEventWindow
	}
	if p.PreserveFilters != nil {
		prefs.PreserveFilters = *p.PreserveFilters
	}
	if p.OpenDetailsNewTab != nil {
		prefs.OpenDetailsNewTab = *p.OpenDetailsNewTab
	}
}

type preferencesResponse struct {
	Preferences userPreferences `json:"preferences"`
}

// settingsIdentity resolves the caller and enforces the shared mutation
// guards. GET passes write=false (no CSRF or rate-limit cost); mutations
// pass write=true.
func (s *store) settingsIdentity(w http.ResponseWriter, r *http.Request, write bool) (authenticatedIdentity, bool) {
	if s == nil || s.settings == nil {
		http.Error(w, "settings service unavailable", http.StatusServiceUnavailable)
		return authenticatedIdentity{}, false
	}
	identity, ok := requireIdentity(w, r)
	if !ok {
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

// serveSettingsMe returns the caller's effective preferences and the ETag of
// the underlying document. The projection is refreshed best-effort first, so
// a first-ever request still answers with defaults instead of an error.
func (s *store) serveSettingsMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := s.settingsIdentity(w, r, false)
	if !ok {
		return
	}
	siteConfig, _ := s.settings.config.Get()
	s.settings.users.Upsert(identity, siteConfig.Behavior.DefaultTimezone)
	preferences, etag, found := s.settings.users.Preferences(identity.Subject)
	if !found {
		// The store is read-only (degraded or full disk): serve compiled
		// defaults rather than failing the page. Writes will report 503.
		preferences = defaultPreferencesWithSiteTimezone(siteConfig.Behavior.DefaultTimezone)
		_, etag = s.settings.users.inner.Get()
	}
	writePreferences(w, preferences, etag)
}

// servePreferencesPatch applies a typed partial update to the caller's own
// preferences.
func (s *store) servePreferencesPatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		w.Header().Set("Allow", http.MethodPatch)
		http.Error(w, "PATCH required", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := s.settingsIdentity(w, r, true)
	if !ok {
		return
	}
	if contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))); !strings.HasPrefix(contentType, "application/json") {
		http.Error(w, "Content-Type: application/json required", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPreferencesBody))
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	var patch preferencesPatch
	if !strictDecode(body, &patch) {
		http.Error(w, "invalid or unknown preference fields", http.StatusBadRequest)
		return
	}
	if patch.empty() {
		http.Error(w, "patch must set at least one preference field", http.StatusBadRequest)
		return
	}
	etag, err := s.settings.users.UpdatePreferences(identity, r.Header.Get("If-Match"), requestID(r), clientIP(r), func(p *userPreferences) error {
		patch.apply(p)
		return nil
	})
	if err != nil {
		s.settings.preferenceFailures.Add(1)
		writePreferenceError(w, err)
		return
	}
	preferences, _, _ := s.settings.users.Preferences(identity.Subject)
	writePreferences(w, preferences, etag)
}

// servePreferencesReset restores compiled defaults for the caller.
func (s *store) servePreferencesReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := s.settingsIdentity(w, r, true)
	if !ok {
		return
	}
	siteConfig, _ := s.settings.config.Get()
	etag, err := s.settings.users.ResetPreferences(identity, r.Header.Get("If-Match"), requestID(r), clientIP(r), siteConfig.Behavior.DefaultTimezone)
	if err != nil {
		s.settings.preferenceFailures.Add(1)
		writePreferenceError(w, err)
		return
	}
	preferences, _, _ := s.settings.users.Preferences(identity.Subject)
	writePreferences(w, preferences, etag)
}

// writePreferenceError maps store failures to the API contract from §6:
// conflicts, invalid values, missing projections, and degraded stores are
// distinguishable without parsing text.
func writePreferenceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errStaleRevision):
		http.Error(w, "preferences changed concurrently; reload and retry", http.StatusConflict)
	case errors.Is(err, errSettingsValidation):
		// Validation messages name fields and bounds, never values.
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	case errors.Is(err, errUnknownRecord):
		http.Error(w, "no settings record yet; reload the page first", http.StatusNotFound)
	case errors.Is(err, errStoreReadOnly):
		http.Error(w, "settings store is read-only; contact an administrator", http.StatusServiceUnavailable)
	default:
		http.Error(w, "preferences could not be saved", http.StatusInternalServerError)
	}
}

func writePreferences(w http.ResponseWriter, preferences userPreferences, etag string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	_ = json.NewEncoder(w).Encode(preferencesResponse{Preferences: preferences})
}

// requestID returns a per-request identifier for audit records. The
// dashboard sits behind Traefik, which does not assign one, so requests are
// identified by time and actor unless the proxy forwards an ID.
func requestID(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Request-Id"))
}

// clientIP reports the immediate peer. The dashboard is only reachable
// through the authenticating proxy on the public path, so spoofed forwarding
// headers are not trusted here; internal WireGuard callers are operators.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
