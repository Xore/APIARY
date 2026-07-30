package main

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// sandboxTarget names a detonation backend. Each has its own request spool and
// its own host-side worker; the dashboard only decides which spool to write to.
type sandboxTarget string

const (
	targetWindows sandboxTarget = "windows"
	targetLinux   sandboxTarget = "linux"
)

// determineSandboxTarget classifies the payload exactly the way the payloads
// page already labels it, then picks a backend. Only Windows-native
// executables, DLLs, and scripts need the Windows guest; Linux and
// cross-platform samples already detonate correctly on the existing runner,
// which has the interpreters for them.
//
// The Dynamic check has to come first. Several classifications are both
// Windows-platform and static-only — an OLE document is the clearest case —
// and routing those by platform would queue a run the worker can never
// perform.
func determineSandboxTarget(data []byte) (sandboxTarget, bool) {
	c := classifyPayload(data)
	if !c.Dynamic {
		return "", false
	}
	if c.Platform == "Windows" {
		return targetWindows, true
	}
	return targetLinux, true
}

// sandboxRequestDir maps a target to its spool. An unset Windows spool means
// the Windows worker is not deployed on this host, which is the normal state
// before that stack exists; submissions for it are refused rather than
// silently redirected into the Linux spool, where the Linux runner would try
// to execute a PE file.
func sandboxRequestDir(target sandboxTarget) string {
	if target == targetWindows {
		return getenv("WINDOWS_SANDBOX_REQUEST_DIR", "")
	}
	return getenv("SANDBOX_REQUEST_DIR", "/sandbox-requests")
}

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
	path, err := s.payloadPath(hash)
	if err != nil {
		http.Error(w, "captured payload not found", http.StatusNotFound)
		return
	}
	head, err := readPayloadHead(path)
	if err != nil {
		http.Error(w, "captured payload is unreadable", http.StatusNotFound)
		return
	}
	target, dynamic := determineSandboxTarget(head)
	if !dynamic {
		http.Error(w, "this payload has no dynamic detonation path — see its static analysis instead", http.StatusBadRequest)
		return
	}
	dir := sandboxRequestDir(target)
	if dir == "" {
		http.Error(w, "the "+string(target)+" sandbox is not configured on this host", http.StatusServiceUnavailable)
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
	http.Redirect(w, r, submitReturnURL(r.FormValue("return"), hash, target), http.StatusSeeOther)
}

// readPayloadHead reads the same prefix the payloads listing classifies from.
// classifyPayload never inspects past 64 KiB, so this is the whole input to the
// decision, and reading exactly what the table read guarantees the button
// cannot route somewhere the row's own platform label contradicts.
func readPayloadHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, 64<<10)
	n, err := f.Read(head)
	if n == 0 && err != nil {
		return nil, err
	}
	return head[:n], nil
}

// submitReturnURL resolves where to send the browser after a queued request.
// Re-analysis is initiated from a sandbox run, so returning to /payloads would
// throw the investigation away. Only same-origin dashboard paths from a fixed
// allowlist are honored; anything else falls back to the payload inventory.
//
// The target rides along so the landing page can name the backend that was
// chosen. Two guests now accept work and they have very different queue depths,
// so "queued" alone no longer tells an analyst where to look.
func submitReturnURL(raw, hash string, target sandboxTarget) string {
	fallback := "/payloads?analysis=queued&hash=" + url.QueryEscape(hash) + "&target=" + url.QueryEscape(string(target))
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return fallback
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return fallback
	}
	allowed := false
	for _, prefix := range []string{"/sandbox/", "/payload-analysis/", "/payloads"} {
		if strings.HasPrefix(parsed.Path, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fallback
	}
	query := parsed.Query()
	query.Set("analysis", "queued")
	query.Set("hash", hash)
	query.Set("target", string(target))
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String()
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
