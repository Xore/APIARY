package main

// settings_services_api.go — the dashboard's Services pane API (#197):
//
//	GET  /api/settings/services                     live status for every
//	                                                  allowlisted container
//	POST /api/settings/services/{name}/{action}      start | stop | restart
//	GET  /api/settings/services/{name}/logs?lines=N  tail recent log output
//
// Every endpoint requires the same administrator guard as the rest of the
// settings surface (settings_admin_api.go's adminSettingsIdentity); actions
// additionally require a same-origin request and are audited exactly like a
// configuration mutation. The real allowlist and the real docker.sock access
// live only in hp-services-adapter (services-adapter/services-adapter.py) --
// this file only ever forwards a name and an action verb over the fixed
// AF_UNIX socket in services_control.go, and never gains any other path to
// Docker.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func (s *store) serveSettingsServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.adminSettingsIdentity(w, r, false); !ok {
		return
	}
	services, ok, reason := loadServicesStatus()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false, "reason": reason, "services": []serviceStatus{}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"available": true, "services": services})
}

// serveSettingsServiceItem handles the two per-container routes:
// POST .../{name}/{start,stop,restart} and GET .../{name}/logs.
func (s *store) serveSettingsServiceItem(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/api/settings/services/")
	name, action, found := strings.Cut(tail, "/")
	if !found || name == "" || action == "" {
		http.NotFound(w, r)
		return
	}
	if action == "logs" {
		s.serveSettingsServiceLogs(w, r, name)
		return
	}
	s.serveSettingsServiceAction(w, r, name, action)
}

func (s *store) serveSettingsServiceAction(w http.ResponseWriter, r *http.Request, name, action string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	identity, ok := s.adminSettingsIdentity(w, r, true)
	if !ok {
		return
	}
	succeeded, status, reason := performServiceAction(name, action)
	s.auditConfig(identity, r, "services."+action, []string{name}, map[bool]string{true: "success", false: "error"}[succeeded])
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if succeeded {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "name": name, "action": action})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": reason})
}

func (s *store) serveSettingsServiceLogs(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.adminSettingsIdentity(w, r, false); !ok {
		return
	}
	lines := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("lines")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			lines = parsed
		}
	}
	log, status, reason := fetchServiceLogs(name, lines)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if status != http.StatusOK {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": reason})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "lines": lines, "log": log})
}
