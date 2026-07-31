package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// githubAnalysisRequestDir mirrors sandboxRequestDir/ghidraRequestDir: an
// unset directory means the host-side publisher is not deployed here, which
// is the normal state before analysis/github/install-github-publisher.sh has
// been run. Submissions are refused rather than silently accepted into a
// spool nothing drains.
func githubAnalysisRequestDir() string { return getenv("GITHUB_ANALYSIS_REQUEST_DIR", "") }

// serveGitHubAnalysisSubmit queues a captured payload for publication to the
// public Xore/honeypot repository and its scanner pipeline.
//
// Same trust boundary as sandbox and Ghidra submission: the dashboard writes
// a marker file into a narrow spool and holds no GH_PAT, never calls git, and
// never talks to GitHub. analysis/github/process-github-requests.sh — root,
// host-side — owns everything past the marker, including whether the marker
// is honored at all: GITHUB_PUBLISH_ENABLED defaults to 0 there, so this
// handler queuing a request is not the same thing as a sample actually being
// pushed anywhere. See docs/github-analysis-integration-roadmap.md.
//
// The one place this diverges from sandbox/Ghidra submission: the consequence
// is external and irreversible (a public repository, third-party scanner
// APIs) rather than a local, disposable VM or a read-only disassembly, so an
// explicit confirm field is required in addition to admin + same-origin, and
// every submission — accepted or refused — is written to the audit log.
func (s *store) serveGitHubAnalysisSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !requireAdmin(w, r) {
		return
	}
	identity, _ := resolveIdentity(r)
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
	if r.FormValue("confirm") != "publish" {
		s.auditGitHubAnalysisSubmit(identity, r, hash, "missing_consent")
		http.Error(w, "confirmation required: this publishes the sample externally", http.StatusBadRequest)
		return
	}
	if _, err := s.payloadPath(hash); err != nil {
		s.auditGitHubAnalysisSubmit(identity, r, hash, "not_found")
		http.Error(w, "captured payload not found", http.StatusNotFound)
		return
	}
	dir := githubAnalysisRequestDir()
	if dir == "" {
		s.auditGitHubAnalysisSubmit(identity, r, hash, "not_configured")
		http.Error(w, "GitHub analysis publishing is not configured on this host", http.StatusServiceUnavailable)
		return
	}
	request := filepath.Join(dir, hash+".request")
	f, err := os.OpenFile(request, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		err = f.Close()
	}
	if err != nil && !errors.Is(err, os.ErrExist) {
		s.auditGitHubAnalysisSubmit(identity, r, hash, "spool_unavailable")
		http.Error(w, "GitHub analysis request spool unavailable", http.StatusServiceUnavailable)
		return
	}
	s.auditGitHubAnalysisSubmit(identity, r, hash, "queued")
	http.Redirect(w, r, githubAnalysisReturnURL(r.FormValue("return"), hash), http.StatusSeeOther)
}

// githubAnalysisReturnURL mirrors submitReturnURL/ghidraReturnURL and shares
// their open-redirect guard (see safeReturnPath in sandbox_submit.go).
func githubAnalysisReturnURL(raw, hash string) string {
	fallback := "/payloads?analysis=queued&hash=" + hash + "&target=github-analysis"
	parsed, ok := safeReturnPath(raw, []string{"/github-analysis/", "/payload-analysis/", "/payloads"})
	if !ok {
		return fallback
	}
	query := parsed.Query()
	query.Set("analysis", "queued")
	query.Set("hash", hash)
	query.Set("target", "github-analysis")
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String()
}

// auditGitHubAnalysisSubmit records every submission attempt, accepted or
// refused, reusing the existing settings audit sink rather than a second
// one — see #74. identity is best-effort: resolveIdentity fails open (an
// empty identity, no error surfaced here) when DASHBOARD_REQUIRE_ADMIN is
// unset, which is normal in tests and single-operator deployments; the
// event is still worth recording with whatever is known.
func (s *store) auditGitHubAnalysisSubmit(identity authenticatedIdentity, r *http.Request, hash, result string) {
	if s.settings == nil {
		return
	}
	s.settings.audit.log(auditEvent{
		Actor:     identity.Subject,
		Username:  identity.Username,
		RequestID: requestID(r),
		ClientIP:  clientIP(r),
		Action:    "github_analysis.submit",
		Fields:    []string{hash},
		Result:    result,
	})
}
