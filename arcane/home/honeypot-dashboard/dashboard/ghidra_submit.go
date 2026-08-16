package main

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func ghidraRequestDir() string { return getenv("GHIDRA_REQUEST_DIR", "") }

// serveGhidraSubmit queues a captured payload for headless Ghidra analysis.
//
// Same shape and same trust boundary as serveSandboxSubmit: the dashboard
// accepts a hash, confirms the capture exists, and writes a marker file. It
// never reads the binary, never talks to the Ghidra REST service, and has no
// route to it — analysis/ghidra/worker/ghidra-worker.py is a host-side
// systemd unit that owns that side entirely.
//
// Unlike sandbox submission there is no dynamic/static decision to make.
// Ghidra disassembles anything with code in it, including the PE DLLs and
// documents the sandbox correctly refuses to detonate, and those are often
// exactly the samples where static analysis is the only thing on offer.
func (s *store) serveGhidraSubmit(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, maxActionFormBody)
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
	dir := ghidraRequestDir()
	if dir == "" {
		// The normal state until the host-side worker is deployed. Refusing
		// with a clear message beats queueing into a directory nothing reads.
		http.Error(w, "Ghidra analysis is not configured on this host", http.StatusServiceUnavailable)
		return
	}
	request := filepath.Join(dir, hash+".request")
	f, err := os.OpenFile(request, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		err = f.Close()
	}
	// O_EXCL makes a second click while a job is already queued a no-op rather
	// than an error — the same idempotence sandbox submission relies on.
	if err != nil && !errors.Is(err, os.ErrExist) {
		http.Error(w, "Ghidra request spool unavailable", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, ghidraReturnURL(r.FormValue("return"), hash), http.StatusSeeOther)
}

// ghidraReturnURL mirrors submitReturnURL and shares its open-redirect guard.
// The allowlist gains "/ghidra/" so a re-run started from a result page comes
// back to that result instead of being thrown to the payload inventory.
func ghidraReturnURL(raw, hash string) string {
	fallback := "/payloads?analysis=queued&hash=" + url.QueryEscape(hash) + "&target=ghidra"
	parsed, ok := safeReturnPath(raw, []string{"/ghidra/", "/ghidra", "/payload-analysis/", "/payloads"})
	if !ok {
		return fallback
	}
	query := parsed.Query()
	query.Set("analysis", "queued")
	query.Set("hash", hash)
	query.Set("target", "ghidra")
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String()
}
