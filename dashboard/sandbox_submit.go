package main

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// serveSandboxSubmit accepts only an existing capture hash. The dashboard
// writes no sample data and has no access to libvirt, Docker, or systemd; a
// root-owned host service consumes this narrow request spool.
func (s *store) serveSandboxSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !requireAdmin(w, r) {
		return
	}
	if !sameOriginRequest(r) {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	hash := strings.ToLower(strings.TrimSpace(r.FormValue("hash")))
	if !hashName.MatchString(hash) {
		http.Error(w, "invalid payload hash", http.StatusBadRequest)
		return
	}
	if _, err := s.payloadPath(hash); err != nil {
		http.Error(w, "captured payload not found", http.StatusNotFound)
		return
	}
	dir := getenv("SANDBOX_REQUEST_DIR", "/sandbox-requests")
	if dir == "" {
		http.Error(w, "sandbox web submission is disabled", http.StatusServiceUnavailable)
		return
	}
	request := filepath.Join(dir, hash+".request")
	f, err := os.OpenFile(request, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		err = f.Close()
	}
	if err != nil && !errors.Is(err, os.ErrExist) {
		http.Error(w, "sandbox request spool unavailable", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, "/payloads?analysis=queued&hash="+url.QueryEscape(hash), http.StatusSeeOther)
}

func sameOriginRequest(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "same-origin") {
		return true
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host) && (u.Scheme == "https" || u.Scheme == "http")
}
