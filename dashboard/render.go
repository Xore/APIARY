package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
)

// pageMeta is embedded (anonymously) in every top-level page data struct so
// {{.Nonce}} resolves via Go's promoted-field lookup without every page
// author needing to remember to declare the field themselves (#58). It
// carries only the nonce today; it is the natural place for any future
// per-request rendering value every page needs.
type pageMeta struct {
	Nonce string
}

func (p *pageMeta) SetNonce(n string) { p.Nonce = n }

// nonceSetter is implemented by every *T whose T embeds pageMeta.
type nonceSetter interface {
	SetNonce(string)
}

// renderPage is the single call site every full-page HTML route uses: one
// nonce, one CSP (secHeaders), one Content-Type, one template execution.
// Centralising this (rather than repeating the four-line pattern at each of
// the dashboard's ~18 page routes) is what makes "every route sends the
// nonce-based CSP" a property of one function instead of an invariant every
// handler has to remember to uphold. data must be a pointer to a struct
// embedding pageMeta -- ExecuteTemplate dereferences pointers transparently,
// so the template author never needs to know or care.
func renderPage(w http.ResponseWriter, tmpl *template.Template, name string, data nonceSetter) {
	n := nonce()
	secHeaders(w, n)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data.SetNonce(n)
	tmpl.ExecuteTemplate(w, name, data)
}

func nonce() string {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(fmt.Sprintf("generate CSP nonce: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

// authFrameOrigin is the auth-backend origin the settings iframe embeds
// (scheme://host, no path), resolved once at startup -- see
// setAuthFrameOrigin. Empty when settings embedding is disabled (unset or
// invalid AUTH_ACCOUNT_URL; validatedAuthAccountURL already logs why and
// hides the settings menu item in that case, so this stays silent).
var authFrameOrigin string

// setAuthFrameOrigin derives authFrameOrigin from validatedAuthAccountURL's
// already-verified value, called once at startup (main.go) with the exact
// same string used for AuthAccountURL in the /api/whoami response, so
// there's one source of truth instead of parsing AUTH_ACCOUNT_URL twice.
//
// Without this, secHeaders' CSP had no frame-src directive at all, so it
// fell back to default-src 'self' -- which blocks framing any other origin,
// including auth-backend's own settings page. The browser's own console
// error names the exact mechanism: "Framing '...' violates ... directive:
// default-src 'self' ... Note that 'frame-src' was not explicitly set". A
// relaxed frame-ancestors on auth-backend's side (#196) can never fix this:
// frame-ancestors is the *embedded* page's opt-in for who may frame it;
// frame-src is the *embedding* page's own opt-in for what it may frame, and
// only the dashboard can set that for itself.
func setAuthFrameOrigin(accountURL string) {
	u, err := url.Parse(accountURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return
	}
	authFrameOrigin = u.Scheme + "://" + u.Host
}

func secHeaders(w http.ResponseWriter, nonceValue string) {
	frameSrc := "frame-src 'self'"
	if authFrameOrigin != "" {
		frameSrc += " " + authFrameOrigin
	}
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'nonce-"+nonceValue+"'; "+
			"style-src 'self' 'nonce-"+nonceValue+"'; "+
			"img-src 'self' data: https://tile.openstreetmap.org; "+
			"connect-src 'self' https://tile.openstreetmap.org; "+
			frameSrc+"; "+
			"font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}
