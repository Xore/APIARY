package main

import (
	"net/http"
	"os"
	"strings"
)

// requireAdmin protects evidence-changing and malware-download operations. The
// Traefik forward-auth middleware supplies this header; the dashboard is bound
// only to the WireGuard address and is not exposed directly to the Internet.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("DASHBOARD_REQUIRE_ADMIN")), "true") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Auth-Role")), "admin") {
		return true
	}
	http.Error(w, "administrator role required", http.StatusForbidden)
	return false
}
